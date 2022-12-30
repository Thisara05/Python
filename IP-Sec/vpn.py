#! /usr/bin/p ython3

import os
from fcntl import ioctl
from ctypes import *
import socket
from struct import *
from threading import Thread
from cryptography.fernet import Fernet

key = Fernet.generate_key() #this is your "password"
print(f"key {key}")
cipher_suite = Fernet(key)
print(f"cipher_suite {cipher_suite}")
encoded_text = cipher_suite.encrypt(b"Hello stackoverflow!")
print(f"encoded_text {encoded_text}")
decoded_text = cipher_suite.decrypt(encoded_text)
print(f"decoded_text {decoded_text}")

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNMODE = IFF_TUN

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
        self.d_ip = socket.inet_ntoa(pack("@I",self.dst))

def tun_open(devname):
    fd = os.open("/dev/net/tun",os.O_RDWR)
    ifr = pack("16sH",devname.encode(), IFF_TUN | IFF_NO_PI)
    ifs = ioctl(fd, TUNSETIFF, ifr)
    return fd

fd = tun_open("asa0")

def send():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    #sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    #sock.bind(("enp0s3",0))
    while True:
        data = os.read(fd,1600)
        ipheader = pack('!BBHHHBBH4s4s', ((4<<4)+5), 0, 0, 0, 0, 255, 50, 0, socket.inet_aton('192.168.1.1'), socket.inet_aton('192.168.1.2'))
        esp = pack('!HHHH',0,0,len(data),0)
        c = cipher_suite.encrypt(b"thisara")
        packet = ipheader 
        sock.sendto(packet,("192.168.1.2",0))
        print(data)
        ###print(cdata)
        print('\n\n')

def recv():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("enp0s3",0))
    while True:
        data = sock.recvfrom(65565)[0]
        print(IPV4(data[14:]).d_ip)
        #if ((IPV4(data[34:]).d_ip) == "10.0.1.1"):
        sock.sendto(data[42:],("asa0",0))
        print(data)

t1 = Thread(target=send,args=())
#t2 = Thread(target=recv,args=())
t1.start()
#t2.start()
