#!/usr/bin/env python

import urllib
from xml.dom import minidom
import StringIO
import random
import string
import socket
import struct
import time
import uuid
import threading
import thread
import sys
import select
import netifaces


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





def _parseSpaceSeparatedList(node):
    if node.childNodes:
        return [item.replace('%20', ' ') \
            for item in node.childNodes[0].data.split()]
    else:
        return []


def parseProbeMessage(dom):
    env = SoapEnvelope()
    env.setAction(ACTION_PROBE)
    env.setMessageId(dom.getElementsByTagNameNS(NS_A, "MessageID")[0].firstChild.data.strip())

    replyToNodes = dom.getElementsByTagNameNS(NS_A, "ReplyTo")
    if len(replyToNodes) > 0 and \
       isinstance(replyToNodes[0].firstChild, minidom.Text):
        env.setReplyTo(replyToNodes[0].firstChild.data.strip())

    env.setTo(dom.getElementsByTagNameNS(NS_A, "To")[0].firstChild.data.strip())

    typeNodes = dom.getElementsByTagNameNS(NS_D, "Types")
    if len(typeNodes) > 0:
        env.getTypes().extend(getTypes(typeNodes[0]))

    scopeNodes = dom.getElementsByTagNameNS(NS_D, "Scopes")
    if len(scopeNodes) > 0:
        env.getScopes().extend(getScopes(scopeNodes[0]))

    return env


def _parseAppSequence(dom, env):
    nodes = dom.getElementsByTagNameNS(NS_D, "AppSequence")
    if nodes:
        appSeqNode = nodes[0]
        env.setInstanceId(appSeqNode.getAttribute("InstanceId"))
        env.setSequenceId(appSeqNode.getAttribute("SequenceId"))
        env.setMessageNumber(appSeqNode.getAttribute("MessageNumber"))


def parseProbeMatchMessage(dom):
    env = SoapEnvelope()
    env.setAction(ACTION_PROBE_MATCH)

    env.setMessageId(dom.getElementsByTagNameNS(NS_A, "MessageID")[0].firstChild.data.strip())
    env.setRelatesTo(dom.getElementsByTagNameNS(NS_A, "RelatesTo")[0].firstChild.data.strip())
    env.setTo(dom.getElementsByTagNameNS(NS_A, "To")[0].firstChild.data.strip())

    _parseAppSequence(dom, env)

    pmNodes = dom.getElementsByTagNameNS(NS_D, "ProbeMatch")
    for node in pmNodes:
        epr = node.getElementsByTagNameNS(NS_A, "Address")[0].firstChild.data.strip()

        types = []
        typeNodes = node.getElementsByTagNameNS(NS_D, "Types")
        if len(typeNodes) > 0:
            types = getTypes(typeNodes[0])

        scopes = []
        scopeNodes = node.getElementsByTagNameNS(NS_D, "Scopes")
        if len(scopeNodes) > 0:
            scopes = getScopes(scopeNodes[0])

        xAddrs = []
        xAddrNodes = node.getElementsByTagNameNS(NS_D, "XAddrs")
        if len(xAddrNodes) > 0:
            xAddrs = getXAddrs(xAddrNodes[0])

        mdv = node.getElementsByTagNameNS(NS_D, "MetadataVersion")[0].firstChild.data.strip()
        env.getProbeResolveMatches().append(ProbeResolveMatch(epr, types, scopes, xAddrs, mdv))

    return env

def parseResolveMessage(dom):
    env = SoapEnvelope()
    env.setAction(ACTION_RESOLVE)

    env.setMessageId(dom.getElementsByTagNameNS(NS_A, "MessageID")[0].firstChild.data.strip())

    replyToNodes = dom.getElementsByTagNameNS(NS_A, "ReplyTo")
    if len(replyToNodes) > 0:
        env.setReplyTo(replyToNodes[0].firstChild.data.strip())

    env.setTo(dom.getElementsByTagNameNS(NS_A, "To")[0].firstChild.data.strip())
    env.setEPR(dom.getElementsByTagNameNS(NS_A, "Address")[0].firstChild.data.strip())

    return env

def parseResolveMatchMessage(dom):
    env = SoapEnvelope()
    env.setAction(ACTION_RESOLVE_MATCH)

    env.setMessageId(dom.getElementsByTagNameNS(NS_A, "MessageID")[0].firstChild.data.strip())
    env.setRelatesTo(dom.getElementsByTagNameNS(NS_A, "RelatesTo")[0].firstChild.data.strip())
    env.setTo(dom.getElementsByTagNameNS(NS_A, "To")[0].firstChild.data.strip())

    _parseAppSequence(dom, env)

    nodes = dom.getElementsByTagNameNS(NS_D, "ResolveMatch")
    if len(nodes) > 0:
        node = nodes[0]
        epr = node.getElementsByTagNameNS(NS_A, "Address")[0].firstChild.data.strip()

        typeNodes = node.getElementsByTagNameNS(NS_D, "Types")
        types = []
        if len(typeNodes) > 0:
            types = getTypes(typeNodes[0])

        scopeNodes = node.getElementsByTagNameNS(NS_D, "Scopes")
        scopes = []
        if len(scopeNodes) > 0:
            scopes = getScopes(scopeNodes[0])

        xAddrs = getXAddrs(node.getElementsByTagNameNS(NS_D, "XAddrs")[0])
        mdv = node.getElementsByTagNameNS(NS_D, "MetadataVersion")[0].firstChild.data.strip()
        env.getProbeResolveMatches().append(ProbeResolveMatch(epr, types, scopes, xAddrs, mdv))

    return env

def parseHelloMessage(dom):
    env = SoapEnvelope()
    env.setAction(ACTION_HELLO)

    env.setMessageId(dom.getElementsByTagNameNS(NS_A, "MessageID")[0].firstChild.data.strip())
    env.setTo(dom.getElementsByTagNameNS(NS_A, "To")[0].firstChild.data.strip())

    _parseAppSequence(dom, env)

    relatesToNodes = dom.getElementsByTagNameNS(NS_A, "RelatesTo")
    if len(relatesToNodes) > 0:
        env.setRelatesTo(relatesToNodes[0].firstChild.data.strip())
        env.setRelationshipType(getQNameFromValue( \
            relatesToNodes[0].getAttribute("RelationshipType"), relatesToNodes[0]))

    env.setEPR(dom.getElementsByTagNameNS(NS_A, "Address")[0].firstChild.data.strip())

    typeNodes = dom.getElementsByTagNameNS(NS_D, "Types")
    if len(typeNodes) > 0:
        env.setTypes(getTypes(typeNodes[0]))

    scopeNodes = dom.getElementsByTagNameNS(NS_D, "Scopes")
    if len(scopeNodes) > 0:
        env.setScopes(getScopes(scopeNodes[0]))

    xNodes = dom.getElementsByTagNameNS(NS_D, "XAddrs")
    if len(xNodes) > 0:
        env.setXAddrs(getXAddrs(xNodes[0]))

    env.setMetadataVersion(dom.getElementsByTagNameNS(NS_D, "MetadataVersion")[0].firstChild.data.strip())

    return env

def parseByeMessage(dom):
    env = SoapEnvelope()
    env.setAction(ACTION_BYE)

    env.setMessageId(dom.getElementsByTagNameNS(NS_A, "MessageID")[0].firstChild.data.strip())
    env.setTo(dom.getElementsByTagNameNS(NS_A, "To")[0].firstChild.data.strip())

    _parseAppSequence(dom, env)

    env.setEPR(dom.getElementsByTagNameNS(NS_A, "Address")[0].firstChild.data.strip())

    return env

def parseEnvelope(data, ipAddr):
    try:
        dom = minidom.parseString(data)
    except Exception as ex:
        #print >> sys.stderr, 'Failed to parse message from %s\n"%s": %s' % (ipAddr, data, ex)
        return None

    if dom.getElementsByTagNameNS(NS_S, "Fault"):
        #print >> sys.stderr, 'Fault received from %s:' % (ipAddr, data)
        return None

    soapAction = dom.getElementsByTagNameNS(NS_A, "Action")[0].firstChild.data.strip()
    if soapAction == ACTION_PROBE:
        return parseProbeMessage(dom)
    elif soapAction == ACTION_PROBE_MATCH:
        return parseProbeMatchMessage(dom)
    elif soapAction == ACTION_RESOLVE:
        return parseResolveMessage(dom)
    elif soapAction == ACTION_RESOLVE_MATCH:
        return parseResolveMatchMessage(dom)
    elif soapAction == ACTION_BYE:
        return parseByeMessage(dom)
    elif soapAction == ACTION_HELLO:
        return parseHelloMessage(dom)


