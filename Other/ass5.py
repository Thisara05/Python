import socket
from struct import *
from ctypes import *

try:
    pn={'ICMP':1,'icmp':1, 'tcp':6, 'TCP':6, 'udp':17, 'UDP':17, 'arp':2054, 'ARP':2054, 'ipv6':34525, 'IPV6':34525}
    x=input("Enter protocol Name : ")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("enp0s3", 0))
    if pn[x]==2054:
        eth = pack('!3H3HH', int('BBBB',16) , int('BBBB',16), int('BBBB',16), int('AAAA',16), int('AAAA',16), int('AAAA',16), pn[x])
        arp_header = pack('!HHBBHHHH4sHHH4s', 1, 2048, 6, 4, 2, int('BBBB',16) , int('BBBB',16), int('BBBB',16), socket.inet_aton('1.1.1.1'), int('AAAA',16), int('AAAA',16), int('AAAA',16),socket.inet_aton('1.1.1.1') )
        eth2 = pack('!HHHHHHHHH', 0, 0, 0, 0, 0, 0, 0, 0, 0)
        s.send(eth+arp_header+eth2)
    elif pn[x]==34525:
        eth = pack('!3H3HH', int('BBBB',16) , int('BBBB',16), int('BBBB',16), int('AAAA',16), int('AAAA',16), int('AAAA',16), pn[x])
        ipv6_header = pack('!LHBB8H8H', ((((6<<8)+224)<<20)+0), 140, 50, 1, int('fe80',16), int('0',16), int('0',16), int('0',16), int('211',16), int('11ff',16), int('fe11',16), int('1111',16), int('ff02',16), int('0',16), int('0',16), int('0',16), int('0',16), int('0',16), int('0',16), int('5',16))
        eth2 = pack('!HHHHHHHHH', 0, 0, 0, 0, 0, 0, 0, 0, 0)
        s.send(eth+ipv6_header+eth2)
    else:
        eth = pack('!3H3HH', int('BBBB',16) , int('BBBB',16), int('BBBB',16), int('AAAA',16), int('AAAA',16), int('AAAA',16), 2048)
        ip_header = pack('!BBHHHBBH4s4s', ((4<<4)+5), 0, 0, 54321, 0, 255, pn[x], 0, socket.inet_aton('1.1.1.1'), socket.inet_aton('1.1.1.1'))
        eth2 = pack('!HHHHHHHHH', 0, 0, 0, 0, 0, 0, 0, 0, 0)
        if pn[x]==1:
            icmp_header = pack('!BBHL', 0, 0, int('ffff',16), 0)
            s.send(eth+ip_header+icmp_header+eth2)
        elif pn[x]==6:
            tcp_header = pack('!HHLLBBHHH', 80, 8080, 0, 0, ((5<<4)+0), int('00010000',2), 0, 0, 0)
            s.send(eth+ip_header+tcp_header+eth2)
        elif pn[x]==17:
            udp_header = pack('!HHHH', 80, 8080, 8, 0)
            s.send(eth+ip_header+udp_header+eth2)
except KeyboardInterrupt:
    print('Exit..........')
    ecit(1)
except KeyError:
    print('plese restart app & type correct protocol name.......')
    print('<ICMP> <TCP> <UDP> <ARP> <ipv6>')
    exit(1)
