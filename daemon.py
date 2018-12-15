#!/usr/bin/env python

import random
import time
import uuid


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

from .namespaces import *


class WSDiscovery:

    def __init__(self, uuid_=None):

        self._networkingThread = None
        self._serverStarted = False
        self._remoteServices = {}
        self._localServices = {}

        self._dpActive = False
        self._dpAddr = None
        self._dpEPR = None

        self._remoteServiceHelloCallback = None
        self._remoteServiceHelloCallbackTypesFilter = None
        self._remoteServiceHelloCallbackScopesFilter = None
        self._remoteServiceByeCallback = None

        if uuid_ is not None:
            self.uuid = uuid_
        else:
            self.uuid = uuid.uuid4().get_urn()

    def setRemoteServiceHelloCallback(self, cb, types=None, scopes=None):
        """Set callback, which will be called when new service appeared online
        and sent Hi message

        typesFilter and scopesFilter might be list of types and scopes.
        If filter is set, callback is called only for Hello messages,
        which match filter

        Set None to disable callback
        """
        self._remoteServiceHelloCallback = cb
        self._remoteServiceHelloCallbackTypesFilter = types
        self._remoteServiceHelloCallbackScopesFilter = scopes

    def setRemoteServiceByeCallback(self, cb):
        """Set callback, which will be called when new service appeared online
        and sent Hi message
        Service is passed as a parameter to the callback
        Set None to disable callback
        """
        self._remoteServiceByeCallback = cb

    def setRemoveServiceDisappearedCallback(self, cb):
        """Set callback, which will be called when new service disappears
        Service uuid is passed as a parameter to the callback
        Set None to disable callback
        """
        self._remoteServiceDisppearedCallback = cb

    def _addRemoteService(self, service):
        self._remoteServices[service.getEPR()] = service

    def _removeRemoteService(self, epr):
        if self._remoteServices.has_key(epr):
            del self._remoteServices[epr]

    def handleEnv(self, env, addr):
        if (env.getAction() == ACTION_PROBE_MATCH):
            for match in env.getProbeResolveMatches():
                self._addRemoteService(Service(match.getTypes(), match.getScopes(), match.getXAddrs(), match.getEPR(), 0))
                if match.getXAddrs() is None or len(match.getXAddrs()) == 0:
                    self._sendResolve(match.getEPR())

        elif env.getAction() == ACTION_RESOLVE_MATCH:
            for match in env.getProbeResolveMatches():
                self._addRemoteService(Service(match.getTypes(), match.getScopes(), match.getXAddrs(), match.getEPR(), 0))

        elif env.getAction() == ACTION_PROBE:
            services = self._filterServices(self._localServices.values(), env.getTypes(), env.getScopes())
            self._sendProbeMatch(services, env.getMessageId(), addr)

        elif env.getAction() == ACTION_RESOLVE:
            if self._localServices.has_key(env.getEPR()):
                service = self._localServices[env.getEPR()]
                self._sendResolveMatch(service, env.getMessageId(), addr)

        elif env.getAction() == ACTION_HELLO:
            #check if it is from a discovery proxy
            rt = env.getRelationshipType()
            if rt is not None and rt.getLocalname() == "Suppression" and rt.getNamespace() == NS_D:
                xAddr = env.getXAddrs()[0]
                #only support 'soap.udp'
                if xAddr.startswith("soap.udp:"):
                    self._dpActive = True
                    self._dpAddr = extractSoapUdpAddressFromURI(URI(xAddr))
                    self._dpEPR = env.getEPR()

            service = Service(env.getTypes(), env.getScopes(), env.getXAddrs(), env.getEPR(), 0)
            self._addRemoteService(service)
            if self._remoteServiceHelloCallback is not None:
                if self._matchesFilter(service,
                                        self._remoteServiceHelloCallbackTypesFilter,
                                        self._remoteServiceHelloCallbackScopesFilter):
                    self._remoteServiceHelloCallback(service)

        elif env.getAction() == ACTION_BYE:
            #if the bye is from discovery proxy... revert back to multicasting
            if self._dpActive and self._dpEPR == env.getEPR():
                self._dpActive = False
                self._dpAddr = None
                self._dpEPR = None

            self._removeRemoteService(env.getEPR())
            if self._remoteServiceByeCallback is not None:
                self._remoteServiceByeCallback(env.getEPR())

    def envReceived(self, env, addr):
        self.handleEnv(env, addr)

    def _sendResolveMatch(self, service, relatesTo, addr):
        service.incrementMessageNumber()

        env = SoapEnvelope()
        env.setAction(ACTION_RESOLVE_MATCH)
        env.setTo(ADDRESS_UNKNOWN)
        env.setMessageId(uuid.uuid4().get_urn())
        env.setInstanceId(str(service.getInstanceId()))
        env.setMessageNumber(str(service.getMessageNumber()))
        env.setRelatesTo(relatesTo)

        env.getProbeResolveMatches().append(ProbeResolveMatch(service.getEPR(), \
                                                              service.getTypes(), service.getScopes(), \
                                                              service.getXAddrs(), str(service.getMetadataVersion())))
        self._networkingThread.addUnicastMessage(env, addr[0], addr[1])

    def _sendProbeMatch(self, services, relatesTo, addr):
        env = SoapEnvelope()
        env.setAction(ACTION_PROBE_MATCH)
        env.setTo(ADDRESS_UNKNOWN)
        env.setMessageId(uuid.uuid4().get_urn())
        random.seed((int)(time.time() * 1000000))
        env.setInstanceId(_generateInstanceId())
        env.setMessageNumber("1")
        env.setRelatesTo(relatesTo)

        for service in services:
            env.getProbeResolveMatches().append(ProbeResolveMatch(service.getEPR(), \
                                                                  service.getTypes(), service.getScopes(), \
                                                                  service.getXAddrs(), str(service.getMetadataVersion())))

        self._networkingThread.addUnicastMessage(env, addr[0], addr[1], random.randint(0, APP_MAX_DELAY))

    def _sendProbe(self, types=None, scopes=None):
        env = SoapEnvelope()
        env.setAction(ACTION_PROBE)
        env.setTo(ADDRESS_ALL)
        env.setMessageId(uuid.uuid4().get_urn())
        env.setTypes(types)
        env.setScopes(scopes)

        if self._dpActive:
            self._networkingThread.addUnicastMessage(env, self._dpAddr[0], self._dpAddr[1])
        else:
            self._networkingThread.addMulticastMessage(env, MULTICAST_IPV4_ADDRESS, MULTICAST_PORT)

    def _sendResolve(self, epr):
        env = SoapEnvelope()
        env.setAction(ACTION_RESOLVE)
        env.setTo(ADDRESS_ALL)
        env.setMessageId(uuid.uuid4().get_urn())
        env.setEPR(epr)

        if self._dpActive:
            self._networkingThread.addUnicastMessage(env, self._dpAddr[0], self._dpAddr[1])
        else:
            self._networkingThread.addMulticastMessage(env, MULTICAST_IPV4_ADDRESS, MULTICAST_PORT)

    def _sendHello(self, service):
        service.incrementMessageNumber()

        env = SoapEnvelope()
        env.setAction(ACTION_HELLO)
        env.setTo(ADDRESS_ALL)
        env.setMessageId(uuid.uuid4().get_urn())
        env.setInstanceId(str(service.getInstanceId()))
        env.setMessageNumber(str(service.getMessageNumber()))
        env.setTypes(service.getTypes())
        env.setScopes(service.getScopes())
        env.setXAddrs(service.getXAddrs())
        env.setEPR(service.getEPR())

        random.seed((int)(time.time() * 1000000))

        self._networkingThread.addMulticastMessage(env, MULTICAST_IPV4_ADDRESS, MULTICAST_PORT, random.randint(0, APP_MAX_DELAY))

    def _sendBye(self, service):
        env = SoapEnvelope()
        env.setAction(ACTION_BYE)
        env.setTo(ADDRESS_ALL)
        env.setMessageId(uuid.uuid4().get_urn())
        env.setInstanceId(str(service.getInstanceId()))
        env.setMessageNumber(str(service.getMessageNumber()))
        env.setEPR(service.getEPR())

        service.incrementMessageNumber()
        self._networkingThread.addMulticastMessage(env, MULTICAST_IPV4_ADDRESS, MULTICAST_PORT)

    def start(self):
        'start the discovery server - should be called before using other functions'
        self._startThreads()
        self._serverStarted = True

    def stop(self):
        'cleans up and stops the discovery server'

        self.clearRemoteServices()
        self.clearLocalServices()

        self._stopThreads()
        self._serverStarted = False

    def  _networkAddressAdded(self, addr):
        self._networkingThread.addSourceAddr(addr)
        for service in self._localServices.values():
            self._sendHello(service)

    def _networkAddressRemoved(self, addr):
        self._networkingThread.removeSourceAddr(addr)

    def _startThreads(self):
        if self._networkingThread is not None:
            return

        self._networkingThread = NetworkingThread(self)
        self._networkingThread.start()

        self._addrsMonitorThread = AddressMonitorThread(self)
        self._addrsMonitorThread.start()


    def _stopThreads(self):
        if self._networkingThread is None:
            return

        self._networkingThread.schedule_stop()
        self._addrsMonitorThread.schedule_stop()

        self._networkingThread.join()
        self._addrsMonitorThread.join()

        self._networkingThread = None

    def _isTypeInList(self, ttype, types):
        for entry in types:
            if matchType(ttype, entry):
                return True

        return False

    def _isScopeInList(self, scope, scopes):
        for entry in scopes:
            if matchScope(scope.getValue(), entry.getValue(), scope.getMatchBy()):
                return True

        return False

    def _matchesFilter(self, service, types, scopes):
        if types is not None:
            for ttype in types:
                if not self._isTypeInList(ttype, service.getTypes()):
                    return False
        if scopes is not None:
            for scope in scopes:
                if not self._isScopeInList(scope, service.getScopes()):
                    return False
        return True

    def _filterServices(self, services, types, scopes):
        return [service for service in services \
                    if self._matchesFilter(service, types, scopes)]

    def clearRemoteServices(self):
        'clears remotely discovered services'

        self._remoteServices.clear()

    def clearLocalServices(self):
        'send Bye messages for the services and remove them'

        for service in self._localServices.values():
            self._sendBye(service)

        self._localServices.clear()

    def searchServices(self, types=None, scopes=None, timeout=3):
        'search for services given the TYPES and SCOPES in a given TIMEOUT'

        if not self._serverStarted:
            raise Exception("Server not started")

        self._sendProbe(types, scopes)

        time.sleep(timeout)

        return self._filterServices(self._remoteServices.values(), types, scopes)

    def publishService(self, types, scopes, xAddrs):
        """Publish a service with the given TYPES, SCOPES and XAddrs (service addresses)

        if xAddrs contains item, which includes {ip} pattern, one item per IP addres will be sent
        """

        if not self._serverStarted:
            raise Exception("Server not started")

        instanceId = _generateInstanceId()

        service = Service(types, scopes, xAddrs, self.uuid, instanceId)
        self._localServices[self.uuid] = service
        self._sendHello(service)

        time.sleep(0.001)

