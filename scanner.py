
from scapy.all import *

import socket
import requests
import iptools


class Scanner (object):

    def __init__(self, address, masksize=24, **kwargs):
        """
        :param address: the network address to scan e.g. 10.100.102.1
        :param masksize: the subnet mask size e.g. 24 => 11111111.11111111.11111111.00000000
        :param kwargs: scapy keyword args
        """
        self.mask = 2**32 - 2**(32-masksize)
        self.network = iptools.ip2int(address) & self.mask
        self.scapykwargs = kwargs

        wildcard = 2**(32-masksize)
        print self.network
        print wildcard
        print self.network + wildcard
        hosts = [x + self.network for x in xrange(1, wildcard)]
        self.targets = list(map(iptools.int2ip, hosts))

        self.hosts = list()  # [{'ip': ..., 'mac': ..., 'name': ...}, ]

    def pingscan(self, **kwargs):
        """Performs a ping (arp) scan on the subnet hosts"""
        verbose = 'verbose' in kwargs.keys() and kwargs['verbose']
        if verbose:
            print 'Starting scan'

        ans, unans = srp([Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=target) for target in self.targets]
                         , multi=1, verbose=0, timeout=0.1, **self.scapykwargs)

        count = 0
        for snt, recvd in ans:
            if recvd:
                hostip = recvd[ARP].psrc
                hostmac = recvd[ARP].hwsrc
                self.hosts.append({'ip': hostip, 'mac': hostmac})
                count += 1
                if verbose:
                    print 'Scan report for %s\nHost is up (%.2fs latency)\nMAC Address: %s\n' \
                      % (hostip, recvd.time-snt.time, hostmac)

        if verbose:
            print 'Scan report for %s:\nHost is up.\nMAC Address: %s\n' \
                  % (conf.iface.ip, conf.iface.mac)  # This machine
            print 'Done: %s IP addresses (%s hosts up) scanned in %.2f seconds' \
                  % (len(self.targets), count+1, ans[1][-1].time - ans[0][0].time)

    def resolve_names(self, **kwargs):
        """Performs host name scans on already discovered ips"""
        if not self.hosts:
            raise IndexError('no hosts are given / previously discovered / up')

        verbose = 'verbose' in kwargs.keys() and kwargs['verbose']
        if verbose:
            print 'Starting name resolution'

        count = 0
        for host in self.hosts:
            try:
                name = socket.gethostbyaddr(host['ip'])[0]
                if not name:
                    continue
                host['name'] = name
                count += 1
                if verbose:
                    print "%s (%s)" % (name, host['ip'])
            except socket.herror:
                continue

        if verbose:
            print 'Done: %s hosts scanned, %s identified' % (len(self.hosts), count)

    def resolve_vendors(self, **kwargs):
        """Resolves vendor on already discovered mac addresses"""
        if not self.hosts:
            raise IndexError('no hosts are given / previously discovered / up')

        verbose = 'verbose' in kwargs.keys() and kwargs['verbose']
        if verbose:
            print 'Starting vendor lookup'

        count = 0
        for host in self.hosts:
            response = requests.get('http://macvendors.co/api/' + host['mac'])
            result = response.json()['result']
            host['vendor'] = 'unknown' if 'error' in result else result['company']
            if host['vendor'] != 'unknown':
                count += 1
            if verbose:
                print '%s (%s)' % (host['mac'].upper(), host['vendor'])

        if verbose:
            print 'Done: %s hosts scanned, %s identified' % (len(self.hosts), count)


if __name__ == '__main__':
    scanner = Scanner(conf.iface.ip, 23)
    scanner.pingscan(verbose=1); print '\n\n'
    scanner.resolve_names(verbose=1); print '\n\n'
    scanner.resolve_vendors(verbose=1)
