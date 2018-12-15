#!/usr/bin/env python


import socket
import struct
import time
import threading
import thread
import select


BUFFER_SIZE = 0xffff
APP_MAX_DELAY = 500 # miliseconds
DP_MAX_TIMEOUT = 5000 # 5 seconds

_NETWORK_ADDRESSES_CHECK_TIMEOUT = 5

MULTICAST_PORT = 3702
MULTICAST_IPV4_ADDRESS = "239.255.255.250"

UNICAST_UDP_REPEAT=2
UNICAST_UDP_MIN_DELAY=50
UNICAST_UDP_MAX_DELAY=250
UNICAST_UDP_UPPER_DELAY=500

MULTICAST_UDP_REPEAT=4
MULTICAST_UDP_MIN_DELAY=50
MULTICAST_UDP_MAX_DELAY=250
MULTICAST_UDP_UPPER_DELAY=500


class _StopableDaemonThread(threading.Thread):
    """Stopable daemon thread.

    run() method shall exit, when self._quitEvent.wait() returned True
    """
    def __init__(self):
        self._quitEvent = threading.Event()
        super(_StopableDaemonThread, self).__init__()
        self.daemon = True

    def schedule_stop(self):
        """Schedule stopping the thread.
        Use join() to wait, until thread really has been stopped
        """
        self._quitEvent.set()


class AddressMonitorThread(_StopableDaemonThread):
    def __init__(self, wsd):
        self._addrs = set()
        self._wsd = wsd
        super(AddressMonitorThread, self).__init__()
        self._updateAddrs()

    def _updateAddrs(self):
        addrs = set(_getNetworkAddrs())

        disappeared = self._addrs.difference(addrs)
        new = addrs.difference(self._addrs)

        for addr in disappeared:
            self._wsd._networkAddressRemoved(addr)

        for addr in new:
            self._wsd._networkAddressAdded(addr)

        self._addrs = addrs

    def run(self):
        while not self._quitEvent.wait(_NETWORK_ADDRESSES_CHECK_TIMEOUT):
            self._updateAddrs()


class NetworkingThread(_StopableDaemonThread):
    def __init__(self, observer):
        super(NetworkingThread, self).__init__()

        self.setDaemon(True)
        self._queue = []    # FIXME synchronisation

        self._knownMessageIds = set()
        self._iidMap = {}
        self._observer = observer

        self._poll = select.poll()

    @staticmethod
    def _makeMreq(addr):
        return struct.pack("4s4s", socket.inet_aton(MULTICAST_IPV4_ADDRESS), socket.inet_aton(addr))

    @staticmethod
    def _createMulticastOutSocket(addr):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(0)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        if addr is None:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.INADDR_ANY)
        else:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(addr))

        return sock

    @staticmethod
    def _createMulticastInSocket():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        sock.bind(('', MULTICAST_PORT))

        sock.setblocking(0)

        return sock

    def addSourceAddr(self, addr):
        """None means 'system default'"""
        try:
            self._multiInSocket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, self._makeMreq(addr))
        except socket.error:  # if 1 interface has more than 1 address, exception is raised for the second
            pass

        sock = self._createMulticastOutSocket(addr)
        self._multiOutUniInSockets[addr] = sock
        self._poll.register(sock, select.POLLIN)

    def removeSourceAddr(self, addr):
        try:
            self._multiInSocket.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, self._makeMreq(addr))
        except socket.error:  # see comments for setsockopt(.., socket.IP_ADD_MEMBERSHIP..
            pass

        sock = self._multiOutUniInSockets[addr]
        self._poll.unregister(sock)
        sock.close()
        del self._multiOutUniInSockets[addr]

    def addUnicastMessage(self, env, addr, port, initialDelay=0):
        msg = Message(env, addr, port, Message.UNICAST, initialDelay)

        self._queue.append(msg)
        self._knownMessageIds.add(env.getMessageId())

    def addMulticastMessage(self, env, addr, port, initialDelay=0):
        msg = Message(env, addr, port, Message.MULTICAST, initialDelay)

        self._queue.append(msg)
        self._knownMessageIds.add(env.getMessageId())

    def run(self):
        while not self._quitEvent.is_set() or self._queue:
            self._sendPendingMessages()
            self._recvMessages()

    def _recvMessages(self):
        for fd, event in self._poll.poll(0):
            sock = socket.fromfd(fd, socket.AF_INET, socket.SOCK_DGRAM)

            try:
                data, addr = sock.recvfrom(BUFFER_SIZE)
            except socket.error, e:
                time.sleep(0.01)
                continue

            env = parseEnvelope(data, addr[0])

            if env is None: # fault or failed to parse
                continue

            mid = env.getMessageId()
            if mid in self._knownMessageIds:
                continue
            else:
                self._knownMessageIds.add(mid)

            iid = env.getInstanceId()
            mid = env.getMessageId()
            if iid > 0:
                mnum = env.getMessageNumber()
                key = addr[0] + ":" + str(addr[1]) + ":" + str(iid)
                if mid is not None and len(mid) > 0:
                    key = key + ":" + mid
                if not self._iidMap.has_key(key):
                    self._iidMap[key] = iid
                else:
                    tmnum = self._iidMap[key]
                    if mnum > tmnum:
                        self._iidMap[key] = mnum
                    else:
                        continue

            self._observer.envReceived(env, addr)

    def _sendMsg(self, msg):
        data = createMessage(msg.getEnv())

        if msg.msgType() == Message.UNICAST:
            self._uniOutSocket.sendto(data, (msg.getAddr(), msg.getPort()))
        else:
            for sock in self._multiOutUniInSockets.values():
                sock.sendto(data, (msg.getAddr(), msg.getPort()))

    def _sendPendingMessages(self):
        """Method sleeps, if nothing to do"""
        if len(self._queue) == 0:
            time.sleep(0.1)
            return
        msg = self._queue.pop(0)
        if msg.canSend():
            self._sendMsg(msg)
            msg.refresh()
            if not (msg.isFinished()):
                self._queue.append(msg)
        else:
            self._queue.append(msg)
            time.sleep(0.01)

    def start(self):
        super(NetworkingThread, self).start()

        self._uniOutSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self._multiInSocket = self._createMulticastInSocket()
        self._poll.register(self._multiInSocket)

        self._multiOutUniInSockets = {}  # FIXME synchronisation

    def join(self):
        super(NetworkingThread, self).join()
        self._uniOutSocket.close()

        self._poll.unregister(self._multiInSocket)
        self._multiInSocket.close()




