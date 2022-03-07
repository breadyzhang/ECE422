from scapy.all import *

import sys

def debug(s):
    print('#{0}'.format(s))
    sys.stdout.flush()

if __name__ == "__main__":
    conf.iface = sys.argv[1]
    ip_addr = sys.argv[2]

    my_ip = get_if_addr(sys.argv[1])
    
    # usage: interface, IP

    # SYN scan
    for port in range(1,1025):
        syn = TCP(flags = "S", dport = port)
        ip = IP(dst = ip_addr)
        response = sr1(ip/syn, timeout = 2, verbose=False)
        if response is None or not response.haslayer(TCP):
            continue
        elif response.getlayer(TCP).flags == 0x12:
            print("%s,%s" % (ip_addr,port))
            reset = TCP(flags = "R", dport = port)
            sr1(ip/reset, timeout = 2, verbose=False)
