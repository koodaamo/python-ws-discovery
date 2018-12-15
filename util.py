


def _getNetworkAddrs():
    result = []

    for if_name in netifaces.interfaces():
        iface_info = netifaces.ifaddresses(if_name)
        if netifaces.AF_INET in iface_info:
            for addrDict in iface_info[netifaces.AF_INET]:
                addr = addrDict['addr']
                if addr != '127.0.0.1':
                    result.append(addr)
    return result


def _generateInstanceId():
    return str(random.randint(1, 0xFFFFFFFF))




def showEnv(env):
    print "-----------------------------"
    print "Action: %s" % env.getAction()
    print "MessageId: %s" % env.getMessageId()
    print "InstanceId: %s" % env.getInstanceId()
    print "MessageNumber: %s" % env.getMessageNumber()
    print "Reply To: %s" % env.getReplyTo()
    print "To: %s" % env.getTo()
    print "RelatesTo: %s" % env.getRelatesTo()
    print "Relationship Type: %s" % env.getRelationshipType()
    print "Types: %s" % env.getTypes()
    print "Scopes: %s" % env.getScopes()
    print "EPR: %s" % env.getEPR()
    print "Metadata Version: %s" % env.getMetadataVersion()
    print "Probe Matches: %s" % env.getProbeResolveMatches()
    print "-----------------------------"

