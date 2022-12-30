import socket
from struct import *
from ctypes import *
from datetime import datetime
import os
import threading

class IPV4(Structure):
    _fields_=[
            ("ihl", c_ubyte, 4),
            ("version", c_ubyte, 4),
            ("tos", c_ubyte),
            ("len", c_ushort),
            ("id", c_ushort),
            ("offset", c_ushort),
            ("ttl", c_ubyte),
            ("protocol_num", c_ubyte),
            ("sum", c_ushort),
            ("src", c_uint32),
            ("dst", c_uint32)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self.sadd = socket.inet_ntoa(pack("@I",self.src))
        self.dadd = socket.inet_ntoa(pack("@I",self.dst))
        self.snd =[self.sadd,self.dadd]

class ICMP(Structure):
    _fields_=[
            ("type", c_ubyte),
            ("code", c_ubyte),
            ("check", c_ushort),
            ("id", c_ushort),
            ("Seq", c_ushort)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self.ty = self.type
        self.cod = self.code
        print(self.ty)
        print(self.cod)
        print(bin(socket.ntohs(self.id)))
        print(bin(self.id))
        self.seq = socket.ntohs(self.Seq)
        print(self.seq)

def checksum(msg):
    s=0
    for i in range(0,len(msg)-3,4):
        w = ord(msg[i])+(ord(msg[i+1])<<8)+(ord(msg[i+2])<<16)+(ord(msg[i+3])<<24)
        s = s + w
    s = (s>>32)+(s & 0xffffffff)
    s = s+(s>>32)
    s = ~s & 0xffffffff
    return s

def send(con,send):
    con.send(send.encode())

def bind(interface):
    #sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    #sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    #sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    #sock.bind((interface,0))
    while True:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((interface,0))
        #print(interface,end="\n")
        data = sock.recvfrom(65565)[0]
        if IPV4(data[14:]).protocol_num == 1:
            #print(data,end="\n")
            seq = ICMP(data[34:]).seq
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            packet = pack('!BBHHHBBH4s4s', (4<<4)+5,0,0,0,0,255,1,0,socket.inet_aton('0'),socket.inet_aton("192.168.1.10"))+pack('!BBHHH', 0, 0, 0, 1, seq)+data[42:]
            check = checksum(packet)
            sock.sendto(packet,("192.168.1.10",0))
        #if icmp:
        #elif tcp:
        #elif udp:
        #elif rap:
        
for i in os.listdir('/sys/class/net/'):
    if i != 'lo':
        threading.Thread(target=bind, args=(i,)).start()
        
#print(threading.activeCount()-1)
