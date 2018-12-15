#!/usr/bin/env python

"""

Base classes used by the rest of the modules:

 - URI
 - Scope
 - QName
 - ProbeResolveMatch
 - SoapEnvelope
 - Message
 - Service

"""

import urllib
import random
import time


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





class URI:

    def __init__(self, uri):
        uri = urllib.unquote(uri)
        i1 = uri.find(":")
        i2 = uri.find("@")
        self._scheme = uri[:i1]
        if i2 != -1:
            self._authority = uri[i1 + 1: i2]
            self._path = uri[i2 + 1:]
        else:
            self._authority = ""
            self._path = uri[i1 + 1:]

    def getScheme(self):
        return self._scheme

    def getAuthority(self):
        return self._authority

    def getPath(self):
        return self._path

    def getPathExQueryFragment(self):
        i = self._path.find("?")
        path = self.getPath()
        if i != -1:
            return path[:self._path.find("?")]
        else:
            return path

class QName:

    def __init__(self, namespace, localname):
        self._namespace = namespace
        self._localname = localname

    def getNamespace(self):
        return self._namespace

    def getLocalname(self):
        return self._localname

    def getFullname(self):
        return self.getNamespace() + ":" + self.getLocalname()

    def __repr__(self):
        return self.getFullname()


class Scope:

    def __init__(self, value, matchBy=None):
        self._matchBy = matchBy
        self._value = value

    def getMatchBy(self):
        return self._matchBy

    def getValue(self):
        return self._value

    def getQuotedValue(self):
        return self._value.replace(' ', '%20')

    def __repr__(self):
        if self.getMatchBy() == None or len(self.getMatchBy()) == 0:
            return self.getValue()
        else:
            return self.getMatchBy() + ":" + self.getValue()


class ProbeResolveMatch:

    def __init__(self, epr, types, scopes, xAddrs, metadataVersion):
        self._epr = epr
        self._types = types
        self._scopes = scopes
        self._xAddrs = xAddrs
        self._metadataVersion = metadataVersion

    def getEPR(self):
        return self._epr

    def getTypes(self):
        return self._types

    def getScopes(self):
        return self._scopes

    def getXAddrs(self):
        return self._xAddrs

    def getMetadataVersion(self):
        return self._metadataVersion

    def __repr__(self):
        return "EPR: %s\nTypes: %s\nScopes: %s\nXAddrs: %s\nMetadata Version: %s" % \
            (self.getEPR(), self.getTypes(), self.getScopes(),
             self.getXAddrs(), self.getMetadataVersion())


class SoapEnvelope:

    def __init__(self):
        self._action = ""
        self._messageId = ""
        self._relatesTo = ""
        self._relationshipType = None
        self._to = ""
        self._replyTo = ""
        self._instanceId = ""
        self._sequenceId = ""
        self._messageNumber = ""
        self._epr = ""
        self._types = []
        self._scopes = []
        self._xAddrs = []
        self._metadataVersion = "1"
        self._probeResolveMatches = []

    def getAction(self):
        return self._action

    def setAction(self, action):
        self._action = action

    def getMessageId(self):
        return self._messageId

    def setMessageId(self, messageId):
        self._messageId = messageId

    def getRelatesTo(self):
        return self._relatesTo

    def setRelatesTo(self, relatesTo):
        self._relatesTo = relatesTo

    def getRelationshipType(self):
        return self._relationshipType

    def setRelationshipType(self, relationshipType):
        self._relationshipType = relationshipType

    def getTo(self):
        return self._to

    def setTo(self, to):
        self._to = to

    def getReplyTo(self):
        return self._replyTo

    def setReplyTo(self, replyTo):
        self._replyTo = replyTo

    def getInstanceId(self):
        return self._instanceId

    def setInstanceId(self, instanceId):
        self._instanceId = instanceId

    def getSequenceId(self):
        return self._sequenceId

    def setSequenceId(self, sequenceId):
        self._sequenceId = sequenceId

    def getEPR(self):
        return self._epr

    def setEPR(self, epr):
        self._epr = epr

    def getMessageNumber(self):
        return self._messageNumber

    def setMessageNumber(self, messageNumber):
        self._messageNumber = messageNumber

    def getTypes(self):
        return self._types

    def setTypes(self, types):
        self._types = types

    def getScopes(self):
        return self._scopes

    def setScopes(self, scopes):
        self._scopes = scopes

    def getXAddrs(self):
        return self._xAddrs

    def setXAddrs(self, xAddrs):
        self._xAddrs = xAddrs

    def getMetadataVersion(self):
        return self._metadataVersion

    def setMetadataVersion(self, metadataVersion):
        self._metadataVersion = metadataVersion

    def getProbeResolveMatches(self):
        return self._probeResolveMatches

    def setProbeResolveMatches(self, probeResolveMatches):
        self._probeResolveMatches = probeResolveMatches




class Message:
    MULTICAST = 'multicast'
    UNICAST = 'unicast'

    def __init__(self, env, addr, port, msgType, initialDelay=0):
        """msgType shall be Message.MULTICAST or Message.UNICAST"""
        self._env = env
        self._addr = addr
        self._port = port
        self._msgType = msgType

        if msgType == self.UNICAST:
            udpRepeat, udpMinDelay, udpMaxDelay, udpUpperDelay = \
                    UNICAST_UDP_REPEAT, \
                    UNICAST_UDP_MIN_DELAY, \
                    UNICAST_UDP_MAX_DELAY, \
                    UNICAST_UDP_UPPER_DELAY
        else:
            udpRepeat, udpMinDelay, udpMaxDelay, udpUpperDelay = \
                    MULTICAST_UDP_REPEAT, \
                    MULTICAST_UDP_MIN_DELAY, \
                    MULTICAST_UDP_MAX_DELAY, \
                    MULTICAST_UDP_UPPER_DELAY

        self._udpRepeat = udpRepeat
        self._udpUpperDelay = udpUpperDelay
        self._t = (udpMinDelay + ((udpMaxDelay - udpMinDelay) * random.random())) / 2
        self._nextTime = int(time.time() * 1000) + initialDelay

    def getEnv(self):
        return self._env

    def getAddr(self):
        return self._addr

    def getPort(self):
        return self._port

    def msgType(self):
        return self._msgType

    def isFinished(self):
        return self._udpRepeat <= 0

    def canSend(self):
        ct = int(time.time() * 1000)
        return self._nextTime < ct

    def refresh(self):
        self._t = self._t * 2
        if self._t > self._udpUpperDelay:
            self._t = self._udpUpperDelay
        self._nextTime = int(time.time() * 1000) + self._t
        self._udpRepeat = self._udpRepeat - 1

class Service:

    def __init__(self, types, scopes, xAddrs, epr, instanceId):
        self._types = types
        self._scopes = scopes
        self._xAddrs = xAddrs
        self._epr = epr
        self._instanceId = instanceId
        self._messageNumber = 0
        self._metadataVersion = 1

    def getTypes(self):
        return self._types

    def setTypes(self, types):
        self._types = types

    def getScopes(self):
        return self._scopes

    def setScopes(self, scopes):
        self._scopes = scopes

    def getXAddrs(self):
        ret = []
        ipAddrs = None
        for xAddr in self._xAddrs:
            if '{ip}' in xAddr:
                if ipAddrs is None:
                    ipAddrs = _getNetworkAddrs()
                for ipAddr in ipAddrs:
                    if ipAddr != '127.0.0.1':
                        ret.append(xAddr.format(ip=ipAddr))
            else:
                ret.append(xAddr)
        return ret

    def setXAddrs(self, xAddrs):
        self._xAddrs = xAddrs

    def getEPR(self):
        return self._epr

    def setEPR(self, epr):
        self._epr = epr

    def getInstanceId(self):
        return self._instanceId

    def setInstanceId(self, instanceId):
        self._instanceId = instanceId

    def getMessageNumber(self):
        return self._messageNumber

    def setMessageNumber(self, messageNumber):
        self._messageNumber = messageNumber

    def getMetadataVersion(self):
        return self._metadataVersion

    def setMetadataVersion(self, metadataVersion):
        self._metadataVersion = metadataVersion

    def incrementMessageNumber(self):
        self._messageNumber = self._messageNumber + 1


