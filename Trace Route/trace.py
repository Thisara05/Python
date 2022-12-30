#! /usr/bin/python3

import queue
import sys
import socket
from struct import *
import time
from datetime import datetime
from ctypes import *
import sys
from threading import Thread
import select

if len(sys.argv) < 2:
    print("Enter IP or Host name")
    exit(1)
des_ip = socket.gethostbyname(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
#ip_header = pack('!BBHHHBBH4s4s', (4<<4)+5,0,0,0,0,ttl,1,0,socket.inet_aton('0'),socket.inet_aton(des_ip))
icmp_header = pack('!BBHL', 8, 0, int('f7ff',16), 0)
#packet = ip_header + icmp_header
class IPV4(Structure):
    _fields_=[
            ("ihl", c_ubyte, 4),
            ("version", c_ubyte, 4),
            ("tos", c_ubyte),
            ("LEN", c_ushort),
            ("id", c_ushort),
            ("offset", c_ushort),
            ("TTL", c_ubyte),
            ("protocol_num", c_ubyte),
            ("sum", c_ushort),
            ("src", c_uint32),
            ("dst", c_uint32)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)
    
    def __init__(self, socket_buffer=None):
        self.ttl = self.TTL 
        self.len = socket.ntohs(self.LEN)
        self.s_ip = socket.inet_ntoa(pack("@I",self.src))

class ICMP(Structure):
    _fields_=[
            ("type", c_ubyte),
            ("code", c_ubyte),
            ("check", c_ushort)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self.ty = self.type
        self.cod = self.code

def gethost(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
        return host
    except:
        return ip

ttl=1
seq = 1
try:
    print(f'traceroute to {sys.argv[1]} ({gethost(des_ip)}), 30 hops max, 8 byte packets')
    #st = queue.Queue()
    #sp = queue.Queue() 
    #t1 = Thread(target=SEND, args=(sock,))
    #t1.setDaemon(True)
    #t1.start()
    count = 1
    while count != 30:
        #packet = ip_header + icmp_header
        #spacket=sp.get()
        #sock.sendto(packet,(des_ip,0))
        #stime = st.get()
        print(seq,end="\t")
        seq = seq + 1
        try:
            sock.sendto(pack('!BBHHHBBH4s4s', (4<<4)+5,0,0,0,0,ttl,1,0,socket.inet_aton('0'),socket.inet_aton(des_ip))+icmp_header,(des_ip,0))
            data = sock.recvfrom(65565)[0]
            ip = IPV4(data)
            #print(ip.s_ip,end=" ")
            print(gethost(ip.s_ip),end="  ")
            print(f'({ip.s_ip})',end="   ")
            
            for i in range(3):
                    sock.sendto(pack('!BBHHHBBH4s4s', (4<<4)+5,0,0,0,0,ttl,1,0,socket.inet_aton('0'),socket.inet_aton(des_ip))+icmp_header,(des_ip,0))
                    stime = datetime.now()
                    sock.settimeout(1)
                    data = sock.recvfrom(65565)[0]
                    etime = datetime.now()
                    icmp = ICMP(data[20:])
                    ip = IPV4(data)
                    if icmp.ty != 0:
                        #print(ip.len-20,end=' bytes from ')
                        #print(ip.s_ip,end=': ')
                        #print('icmp_seq=',end="")
                        #print(spacket,end=" ")
                        #print("ttl=",end='')
                        print(f'{round(int((etime-stime).microseconds)/1000,1)} ms',end=" ")
                        #print('time=',end="\t")
                    else:
                        print(f'{round(int((etime-stime).microseconds)/1000,1)} ms',end=" ")
                        count = 29
        except socket.timeout:
            print("\t*\t",end="\n")
            count=count+1
            ttl = ttl + 1
            continue
        print("")
        count=count+1
        ttl = ttl + 1

except KeyboardInterrupt:
    print("")
    print(f'\n---')
