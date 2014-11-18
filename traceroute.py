from scapy.all import *

hostname = "google.com"

for i in range(1, 28):
    pkt = IP(dst=hostname, ttl=i) / UDP(dport=33434)
    reply = sr1(pkt, verbose=0)
    if reply is None:
        break;
    elif reply.type == 3:
        print "DONE! {0}".format(reply.src)
        break
    else:
        print "{0} hops away: {1}".format(i, reply.src)
