#! /usr/bin/python3

import queue
import sys
import socket
from struct import *
from time import *
from datetime import *
from ctypes import *
import sys
from threading import Thread


if len(sys.argv) < 2:
    print("Enter IP or Host name")
    exit(1)
try:
    des_ip = socket.gethostbyname(sys.argv[1])
    #des_ip = str(sys.argv[1])
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
except Exception as err:
    print(err)
    exit()
ip_header = pack('!BBHHHBBH4s4s', (4<<4)+5,0,0,0,0,255,1,0,socket.inet_aton('0'),socket.inet_aton(des_ip))
icmp_header = pack('!BBHL', 8, 0, int('f7ff',16), 0)
packet = ip_header + icmp_header
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

maxtime = 0
mintime = 1000
rpacket = 0
spacket = 0
tottime = 0
def SEND(sock):
    while True:
        global spacket
        global stime
        spacket = spacket + 1
        sock.sendto(packet,(des_ip,0))
        stime=datetime.now()
        sleep(1)
try:
    print(f'PING {sys.argv[1]} ({des_ip}) 56(84) bytes of data.')
    t1 = Thread(target=SEND, args=(sock,))
    t1.setDaemon(True)
    t1.start()
    while True:
        #packet = ip_header + icmp_header
        #sock.sendto(packet,(des_ip,0))
        data = sock.recvfrom(65565)[0]
        etime = datetime.now()
        icmp = ICMP(data[20:])
        if icmp.ty == 0:
            rpacket=rpacket+1
            ip = IPV4(data)
            print(ip.len-20,end=' bytes from ')
            print(ip.s_ip,end=': ')
            print('icmp_seq=',end="")
            print(spacket,end=" ")
            print("ttl=",end='')
            print(ip.ttl,end=" ")
            print('time=',end="")
            _time = round(int((etime-stime).microseconds)/1000,1)
            print(_time,end=" ms\n")
            if (_time < mintime):
                mintime = _time
            else:
                maxtime = _time
            tottime = tottime + _time
        elif icmp.ty == 3:
                if icmp.cod == 0:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Net is unreachable ]")
                elif icmp.cod == 1:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Host is unreachable ]")
                elif icmp.cod == 2:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Protocol is unreachable ]")
                elif icmp.cod == 3:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Port is unreachable ]")
                elif icmp.cod == 4:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Fragmentation required ]")
                elif icmp.cod == 5:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Source route failed ]")
                elif icmp.cod == 6:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Destination network is unknown ]")
                elif icmp.cod == 7:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Destination host is unknown ]")
                elif icmp.cod == 8:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Source host is isolated ]")
                elif icmp.cod == 9:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Communication with destination network is administratively prohibited ]")
                elif icmp.cod == 10:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Communication with destination host is administratively prohibited ]")
                elif icmp.cod == 11:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Destination network is unreachable for type of service ]")
                elif icmp.cod == 12:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Destination host is unreachable for type of service ]")
                elif icmp.cod == 13:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Communication is administratively prohibited ]")
                elif icmp.cod == 14:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Host precedence violation ]")
                elif icmp.cod == 15:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Precedence cutoff is in effect ]")
        elif icmp.ty == 4:
                ip = IPV4(data)
                print(ip.len-20,end=' bytes from ')
                print(ip.s_ip,end=': ')
                print("[ Source quench ]")
        elif icmp.ty == 5:
                if icmp.cod == 0:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Redirect datagram for the network or subnet ]")
                elif icmp.cod == 1:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print ("[ Redirect datagram for the host ]")
                elif icmp.cod == 2:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Redirect datagram for the type of service and network ]")
                elif icmp.cod == 3:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Redirect datagram for the type of service and host ]")
        elif icmp.ty == 8:
                ip = IPV4(data)
                print(ip.len-20,end=' bytes from ')
                print(ip.s_ip,end=': ')
                print("[ Echo ]")
        elif icmp.ty == 9:
                ip = IPV4(data)
                print(ip.len-20,end=' bytes from ')
                print(ip.s_ip,end=': ')
                print("[ Router advertisement ]")
        elif icmp.ty == 10:
                ip = IPV4(data)
                print(ip.len-20,end=' bytes from ')
                print(ip.s_ip,end=': ')
                print("[ Router selection ]")
        elif icmp.ty == 11:
                if icmp.cod == 0:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Time to Live exceeded in transit ]")
                elif icmp.cod == 1:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print ("[ Fragment reassembly time exceeded ]")
        elif icmp.ty == 12:
                if icmp.cod == 0:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Pointer indicates the error ]")
                elif icmp.cod == 1:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print ("[ Missing a required option ]")
                elif icmp.cod == 2:
                    ip = IPV4(data)
                    print(ip.len-20,end=' bytes from ')
                    print(ip.s_ip,end=': ')
                    print("[ Bad length ]")
        elif icmp.ty == 13:
                ip = IPV4(data)
                print(ip.len-20,end=' bytes from ')
                print(ip.s_ip,end=': ')
                print("[ Echo ]")
        elif icmp.ty == 14:
                ip = IPV4(data)
                print(ip.len-20,end=' bytes from ')
                print(ip.s_ip,end=': ')
                print("[ Timestamp reply ]")
        elif icmp.ty == 15:
                ip = IPV4(data)
                print(ip.len-20,end=' bytes from ')
                print(ip.s_ip,end=': ')
                print("[ Information request ]")
        elif icmp.ty == 16:
                ip = IPV4(data)
                print(ip.len-20,end=' bytes from ')
                print(ip.s_ip,end=': ')
                print("[ Information reply ]")
        elif icmp.ty == 17:
                ip = IPV4(data)
                print(ip.len-20,end=' bytes from ')
                print(ip.s_ip,end=': ')
                print("[ Address mask request ]")
        elif icmp.ty == 18:
                ip = IPV4(data)
                print(ip.len-20,end=' bytes from ')
                print(ip.s_ip,end=': ')
                print("[ Address mask reply ]")
        elif icmp.ty == 30:
                ip = IPV4(data)
                print(ip.len-20,end=' bytes from ')
                print(ip.s_ip,end=': ')
                print("[ Traceroute ]")
        else:
            print("")

except KeyboardInterrupt:
    print(f'\n--- {des_ip} ping statistics ---')
    print(f'{spacket} packets transmitted, {rpacket} received, {int(((spacket-rpacket)/spacket*100))}% packet loss, time {tottime} ms')
    try:
        print(f'rtt min/avg/max = {mintime}/{round((tottime/rpacket),2)}/{maxtime}')
    except ZeroDivisionError:
        print("")
except Exception as err:
    print(err)
    exit()
