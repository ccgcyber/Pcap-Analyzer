#coding:UTF-8
__author__ = 'CCG'

from scapy.all import *
import time

class PcapDecode:
    def __init__(self):
        # ETHER:Read the Ethernet layer protocol configuration file
        with open('./app/utils/protocol/ETHER', 'r') as f:
            ethers = f.readlines()
        self.ETHER_DICT = dict()
        for ether in ethers:
            ether = ether.strip().strip('\n').strip('\r').strip('\r\n')
            self.ETHER_DICT[int(ether.split(':')[0])] = ether.split(':')[1]

        # IP:Read the IP layer protocol configuration file
        with open('./app/utils/protocol/IP', 'r') as f:
            ips = f.readlines()
        self.IP_DICT = dict()
        for ip in ips:
            ip = ip.strip().strip('\n').strip('\r').strip('\r\n')
            self.IP_DICT[int(ip.split(':')[0])] = ip.split(':')[1]

        # PORT:Read the application layer protocol port configuration file
        with open('./app/utils/protocol/PORT', 'r') as f:
            ports = f.readlines()
        self.PORT_DICT = dict()
        for port in ports:
            port = port.strip().strip('\n').strip('\r').strip('\r\n')
            self.PORT_DICT[int(port.split(':')[0])] = port.split(':')[1]

        # TCP:Read TCP layer protocol configuration file
        with open('./app/utils/protocol/TCP', 'r') as f:
            tcps = f.readlines()
        self.TCP_DICT = dict()
        for tcp in tcps:
            tcp = tcp.strip().strip('\n').strip('\r').strip('\r\n')
            self.TCP_DICT[int(tcp.split(':')[0])] = tcp.split(':')[1]

        # UDP:Read the UDP layer protocol configuration file
        with open('./app/utils/protocol/UDP', 'r') as f:
            udps = f.readlines()
        self.UDP_DICT = dict()
        for udp in udps:
            udp = udp.strip().strip('\n').strip('\r').strip('\r\n')
            self.UDP_DICT[int(udp.split(':')[0])] = udp.split(':')[1]

    # Resolve Ethernet layer protocol
    def ether_decode(self, p):
        data = dict()
        if p.haslayer(Ether):
            data = self.ip_decode(p)
            return data
        else:
            data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
            data['Source'] = 'Unknow'
            data['Destination'] = 'Unknow'
            data['Procotol'] = 'Unknow'
            data['len'] = len(corrupt_bytes(p))
            data['info'] = p.summary()
            return data

    # Parsing the IP layer protocol
    def ip_decode(self, p):
        data = dict()
        if p.haslayer(IP):  #2048:Internet IP (IPv4)
            ip = p.getlayer(IP)
            if p.haslayer(TCP):  #6:TCP
                data = self.tcp_decode(p, ip)
                return data
            elif p.haslayer(UDP): #17:UDP
                data = self.udp_decode(p, ip)
                return data
            else:
                if ip.proto in self.IP_DICT:
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['Source'] = ip.src
                    data['Destination'] = ip.dst
                    data['Procotol'] = self.IP_DICT[ip.proto]
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
                else:
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['Source'] = ip.src
                    data['Destination'] = ip.dst
                    data['Procotol'] = 'IPv4'
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
        elif p.haslayer(IPv6):  #34525:IPv6
            ipv6 = p.getlayer(IPv6)
            if p.haslayer(TCP):  #6:TCP
                data = self.tcp_decode(p, ipv6)
                return data
            elif p.haslayer(UDP): #17:UDP
                data = self.udp_decode(p, ipv6)
                return data
            else:
                if ipv6.nh in self.IP_DICT:
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['Source'] = ipv6.src
                    data['Destination'] = ipv6.dst
                    data['Procotol'] = self.IP_DICT[ipv6.nh]
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
                else:
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['Source'] = ipv6.src
                    data['Destination'] = ipv6.dst
                    data['Procotol'] = 'IPv6'
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
        else:
            if p.type in self.ETHER_DICT:
                data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                data['Source'] = p.src
                data['Destination'] = p.dst
                data['Procotol'] = self.ETHER_DICT[p.type]
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                return data
            else:
                data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                data['Source'] = p.src
                data['Destination'] = p.dst
                data['Procotol'] = hex(p.type)
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                return data

    # Parsing the TCP layer protocol
    def tcp_decode(self, p, ip):
        data = dict()
        tcp = p.getlayer(TCP)
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
        data['Source'] = ip.src + ":" + str(ip.sport)
        data['Destination'] = ip.dst + ":" + str(ip.dport)
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        if tcp.dport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[tcp.dport]
        elif tcp.sport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[tcp.sport]
        elif tcp.dport in self.TCP_DICT:
            data['Procotol'] = self.TCP_DICT[tcp.dport]
        elif tcp.sport in self.TCP_DICT:
            data['Procotol'] = self.TCP_DICT[tcp.sport]
        else:
            data['Procotol'] = "TCP"
        return data

    # Parsing the UDP layer protocol
    def udp_decode(self, p, ip):
        data = dict()
        udp = p.getlayer(UDP)
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
        data['Source'] = ip.src + ":" + str(ip.sport)
        data['Destination'] = ip.dst + ":" + str(ip.dport)
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        if udp.dport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[udp.dport]
        elif udp.sport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[udp.sport]
        elif udp.dport in self.UDP_DICT:
            data['Procotol'] = self.UDP_DICT[udp.dport]
        elif udp.sport in self.UDP_DICT:
            data['Procotol'] = self.UDP_DICT[udp.sport]
        else:
            data['Procotol'] = "UDP"
        return data
