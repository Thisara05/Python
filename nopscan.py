import socket
from struct import *
from ctypes import *
import os
import sys
import threading
import time
import random

class IPV4(Structure):
    _fields_=[
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
        
class TCP_UDP(Structure):
    _fields_=[
            ("s_port", c_ushort),
            ("d_port", c_ushort),
            ("sq", c_uint32),
            ("ak",c_uint32),
            ("flags",c_ushort)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self.sport = socket.ntohs(self.s_port)
        self.dport = socket.ntohs(self.d_port)

def send(packet,dadd):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)    
    sock.sendto(packet,(dadd,0))

def check_ip(sadd):
    for line in reversed(open("ip.conf").readlines()):
        line = line.split()
        if (line[0] == sadd):
            return True
        else:
            return False

def show(filename):
    c = 1
    print(f"\n----- SYN {filename[:5]} -----\n")
    for line in reversed(open(filename).readlines()):
        print(f'{c} {line}',end="")
        c = c + 1 
    print()

def add_ip(maxip):
    w = 1
    with open("ip.conf",'r') as f:
        for line in f.readlines():
            if str(line[:-1]) == str(maxip):
                w = 0
        if w == 1:
            write("ip.conf",maxip)

def write(filename,line):
    with open(filename,"a") as f:
        f.write(line)
        f.write("\n")

def delete(filename,line):
    c = 1 
    l = reversed(open(filename).readlines())
    with open ("tmp",'w') as f:
        for nl in l:
            if c != line:
                f.write(nl)
            c = c + 1
    l = reversed(open('tmp').readlines())
    with open (filename,'w') as f:
        for nl in l:
            f.write(nl)

def bind(interface):
    #time.sleep(2)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((interface,0))
    packet_c=0
    connection_attempts = {}
    while True:
        data = sock.recvfrom(65565)[0]
        r_n=random.randrange(0, 5)
        ip = IPV4(data[22:])
        tcp_udp=TCP_UDP(data[34:])
        ip_header = pack('!BBHHHBBH4s4s', (4<<4)+5,0,0,0,0,ip.ttl,ip.protocol_num,0,socket.inet_aton(ip.sadd),socket.inet_aton(ip.dadd))
        tcp_header = pack('!HH',tcp_udp.dport,tcp_udp.sport)
        packet = ip_header + data[34:]
        if ip.protocol_num == 6 or ip.protocol_num == 17:
            if ip.sadd in connection_attempts:
                if tcp_udp.flags == 608:
                    connection_attempts[ip.sadd]=connection_attempts[ip.sadd]+1
                packet_c=packet_c+1
            else:
                connection_attempts[ip.sadd] = 1
                packet_c=packet_c+1
            if packet_c>=10:
                max_key = next(iter(connection_attempts))
                for key in connection_attempts:
                    if connection_attempts[key] > connection_attempts[max_key]:
                        max_key = key
                if connection_attempts[max_key] >= 5:
                    print(f'\nSYN Attack Detected From {ip.sadd}',end="")
                    add_ip(max_key)
                packet_c=0
                connection_attempts = {}

            packet = ip_header + data[34:]
            if check_ip(ip.sadd):
                if r_n == 1:
                    ip_header2 = pack('!BBHHHBBH4s4s', (4<<4)+5,0,0,0,0,ip.ttl,ip.protocol_num,0,socket.inet_aton(ip.dadd),socket.inet_aton(ip.sadd))
                    packet = ip_header2 + tcp_header + data[38:]
                    if tcp_udp.dport==3389 or tcp_udp.dport==445 or tcp_udp.dport==135 or tcp_udp.dport==139:
                        print("",end="")
                    else:
                        send(packet,ip.sadd)
            else:
                send(packet,ip.dadd)
        else:
            send(packet,ip.dadd)

os.system('clear')
print("Welcome To SYN Detecter")
if os.path.isfile('ip.conf'):
    print("ip.conf \033[92mFound\033[0m")
else:
    print('ip.conf \033[91mNot Found\033[0m')
    with open("ip.conf",'w') as f:
        f.write("0.0.0.0\n")
    print('ip.conf \033[93mCreated\033[0m')
interface = os.listdir('/sys/class/net/')
for i in interface:
    if i != "lo":
        t = threading.Thread(target=bind, args=(i,))
        t.daemon=True
        t.start()
print(f'{threading.active_count()-1} Interface \033[92mFound\033[0m')
for c in range(25):
    print("!",end="")
    sys.stdout.flush()
    time.sleep(0.1)
print("\nEnter ? For Help\n")

consol = "SYN # "
while True:
    try:
        x = input(consol)
        y = x.split()
    except KeyboardInterrupt:
        print("\nExiting.....")
        exit()
    if consol == "SYN # ":
        if x == "?":
            print("\nadd <ip>  \t-   Add Suspicious IP\ndel <ip> \t-   Delete from Suspicious IPS\nshow \t\t-   Show List Of Suspicious IPS\nexit \t\t-   Exit SYN\n")
        elif x == "exit":
            print("Exiting.....")
            exit()
        elif len(y) == 0:
            continue
        elif y[0] == 'add':
            if len(y) < 2:
                print("Comand Incomplite")
                continue
            try:
                if(y[1] != "any"):
                    socket.inet_aton(y[1])
            except:
                print(f'"{y[1]}" Is Not A Valid IP address')
                continue
            write("ip.conf",y[1])
        elif x == "show":
            show("ip.conf")
#--------------------------------------------------------------------------
        elif y[0] == 'del':
            if len(y) < 2:
                print("Comand Incomplite")
                continue
            try:
                delete("ip.conf",int(y[1]))
            except:
                print(f'"{y[1]}" Is Not A Number')
                continue
        elif x == "exit":
            consol = "FW # "
        else:
            print(f'"{x}" Command Not Found')

