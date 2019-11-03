from scapy.all import *
import os
import thread
import time


flood_bias = 10
blocked_ips = list()
tcp_syns = dict()  # {ip: count}


def block_ip(ip):
    os.system('netsh advfirewall firewall add rule name="Block %s" dir=in action=block remoteip=%s' % (ip, ip))


def unblock_ip(ip):
    os.system('netsh advfirewall firewall delete rule name="Block %s"' % ip)


def handle_packet(p):
    # tcp port scan attack detection example
    if p.haslayer(TCP):
        ipaddr = p[IP].src
        if p[TCP].flags == 'S':
            if ipaddr in tcp_syns.keys():
                tcp_syns[ipaddr] += 1
                if tcp_syns[ipaddr] > flood_bias:
                    if ipaddr not in blocked_ips:
                        print 'TCP FLOODING DETECTED, BLOCKING'
                        block_ip(ipaddr)
                        blocked_ips.append(ipaddr)
            else:
                tcp_syns[ipaddr] = 1
            # print 'SYN #%s FROM %s' % (str(tcp_syns[ipaddr]), ipaddr)


def timeloop():
    # every 1 sec
    for ip in tcp_syns.keys():
        tcp_syns[ip] -= 1
        if tcp_syns[ip] < 0:
            tcp_syns[ip] = 0
    time.sleep(1)
    timeloop()


def main():
    thread.start_new(timeloop, ())
    sniff(prn=handle_packet)
    # unblock_ip('172.16.12.177')


if __name__ == '__main__':
    main()
