from scapy.all import *
import os


flood_bias = 10
tcp_syns = dict()  # {ip: count}


def block_ip(ip):
    os.system('netsh advfirewall firewall add rule name="Block %s" dir=in action=block remoteip=%s' % (ip, ip))


def unblock_ip(ip):
    os.system('netsh advfirewall firewall delete rule name="Block ip"')


def handle_packet(p):
    # tcp port scan attack detection example
    if p.haslayer(TCP):
        ipaddr = p[IP].src
        if p[TCP].flags == 'S':
            if ipaddr in tcp_syns.keys():
                tcp_syns[ipaddr] += 1
                if tcp_syns[ipaddr] > flood_bias:
                    block_ip(ipaddr)
            else:
                tcp_syns[ipaddr] = 1


def main():
    # sniff(prn=handle_packet)
    block_ip('10.100.102.42')


if __name__ == '__main__':
    main()
