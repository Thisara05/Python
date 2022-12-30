import socket
from struct import *
from ctypes import *
from datetime import datetime

class ETHERNET(Structure):
    _fields_=[
            #("rmac", c_uint64,48),
            #("smac", c_uint64,48),
            ("type", c_ushort)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self._type = hex(socket.ntohs(self.type))

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
        self.protocol_map = {1:"ICMP",6:"TCP", 17:"UDP"}
        self.vr = self.version
        self.hl = self.ihl
        self.sadd = socket.inet_ntoa(pack("@I",self.src))
        self.dadd = socket.inet_ntoa(pack("@I",self.dst))

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

class ARP(Structure):
    _fields_=[
            ("htype", c_ushort),
            ("ptype", c_ushort),
            ("hlen", c_ubyte),
            ("plen", c_ubyte),
            ("oreq", c_ushort),
            ("smac", c_uint64, 48),
            ("sip", c_uint32),
            ("tmac", c_uint64, 48),
            ("tip", c_uint32)
            ]

class TCP(Structure):
    _fields_=[
            ("sport", c_ushort),
            ("dport", c_ushort),
            ("sqnum", c_uint32),
            ("ack", c_uint32),
            ("hl", c_ubyte, 4),
            ("rsv", c_ubyte, 4),
            ("fin", c_ubyte, 1),
            ("syn", c_ubyte, 1),
            ("res", c_ubyte, 1),
            ("pus", c_ubyte, 1),
            ("fack", c_ubyte, 1),
            ("urg", c_ubyte, 1),
            ("enc", c_ubyte, 1),
            ("con", c_ubyte, 1),
            ("check", c_ushort),
            ("upointer", c_ushort)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self.s_port = socket.ntohs(self.sport)
        self.d_port = socket.ntohs(self.dport)
        self.ac = socket.ntohl(self.ack)
        self.seq = socket.ntohl(self.sqnum)

class UDP(Structure):
    _fields_=[
            ("sport", c_ushort),
            ("dport", c_ushort),
            ("len", c_ushort),
            ("check", c_ushort)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self.s_port = socket.ntohs(self.sport)
        self.d_port = socket.ntohs(self.dport)
        self.leng = socket.ntohs(self.len)

class IPV6(Structure):
    _fields_=[
            ("version", c_ubyte, 4),
            ("traffic", c_ubyte),
            ("flabel", c_uint, 20),
            ("len", c_ushort),
            ("nexth", c_ubyte),
            ("hoplim", c_ubyte),
            ("src1", c_uint64),
            ("src2", c_uint64),
            ("dst1", c_uint64),
            ("dst2", c_uint64)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self.src = int(str(format(self.src2, '#066b')).replace('0b','') + str(format(self.src1,'#066b')).replace('0b',""),2)
        self.dst = int(str(format(self.src2, '#066b')).replace('0b','') + str(format(self.src1,'#066b')).replace('0b',""),2)

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

try:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("enp0s3",0))
except Exception as e:
    print(e)
    exit(1)
try:
    while True:
        now = datetime.now()
        ctime = now.strftime("%H:%M:%S%f")
        data = sock.recvfrom(65565)[0]
        #print(data)
        eth = ETHERNET(data[12:])
        #print(eth.r_mac)
        #print(eth.s_mac)
        #print(eth._type)
        #exit(1)


        ip = IPV4(data[14:])
        print(ctime,end="\t")
        print(ip.sadd,end ="\t")
        print("--> ",end = "  ")
        print(ip.dadd,end = "  \t")
        print(ip.protocol,end = "\t")
        #print(ip.vr)
        #print(ip.hl)
        if ip.protocol == "TCP":
            tcp = TCP(data[34:])
            print("sur_port",end=" : ")
            print (tcp.s_port,end="\t")
            print("dst_port",end=" : ")
            print (tcp.d_port,end="\t ACK_NUM : ")
            print (tcp.ac,end="\t SEQ_NUM : ")
            print (tcp.seq ,end="\t")
            if tcp.fack == 1:
                print("ACK",end="")
            if tcp.fin == 1:
                print("-FIN",end="")
            if tcp.syn == 1:
                print("-SYN",end="")
            if tcp.res == 1:
                print("-RES",end="")
            if tcp.pus == 1:
                print("-PUS",end="")
            if tcp.urg == 1:
                print("-URG",end="")
            if tcp.enc == 1:
                print("-ENC",end="")
            if tcp.con == 1:
                print("-CON",end="")
        if ip.protocol == "UDP":
            udp = UDP(data[34:])
            print("sur_port",end=" : ")
            print (udp.s_port,end="\t")
            print("dst_port",end=" : ")
            print (udp.d_port,end="\t LEN : ")
            print (udp.leng,end="")
        if ip.protocol == "ICMP":
            icmp = ICMP(data[34:])
            print("TYPE",end=" : ")
            print (icmp.ty,end="\t")
            print("CODE",end=" : ")
            print (icmp.cod,end="\t")
            if icmp.ty == 0:
                print("[ Echo Reply ]")
            if icmp.ty == 3:
                if icmp.cod == 0:
                    print("[ Net is unreachable ]")
                elif icmp.cod == 1:
                    print("[ Host is unreachable ]")
                elif icmp.cod == 2:
                    print("[ Protocol is unreachable ]")
                elif icmp.cod == 3:
                    print("[ Port is unreachable ]")
                elif icmp.cod == 4:
                    print("[ Fragmentation required ]")
                elif icmp.cod == 5:
                    print("[ Source route failed ]")
                elif icmp.cod == 6:
                    print("[ Destination network is unknown ]")
                elif icmp.cod == 7:
                    print("[ Destination host is unknown ]")
                elif icmp.cod == 8:
                    print("[ Source host is isolated ]")
                elif icmp.cod == 9:
                    print("[ Communication with destination network is administratively prohibited ]")
                elif icmp.cod == 10:
                    print("[ Communication with destination host is administratively prohibited ]")
                elif icmp.cod == 11:
                    print("[ Destination network is unreachable for type of service ]")
                elif icmp.cod == 12:
                    print("[ Destination host is unreachable for type of service ]")
                elif icmp.cod == 13:
                    print("[ Communication is administratively prohibited ]")
                elif icmp.cod == 14:
                    print("[ Host precedence violation ]")
                elif icmp.cod == 15:
                    print("[ Precedence cutoff is in effect ]")
            elif icmp.ty == 4:
                print("[ Source quench ]")
            elif icmp.ty == 5:
                if icmp.cod == 0:
                    print("[ Redirect datagram for the network or subnet ]")
                elif icmp.cod == 1:
                    print ("[ Redirect datagram for the host ]")
                elif icmp.cod == 2:
                    print("[ Redirect datagram for the type of service and network ]")
                elif icmp.cod == 3:
                    print("[ Redirect datagram for the type of service and host ]")
            elif icmp.ty == 8:
                print("[ Echo ]")
            elif icmp.ty == 9:
                print("[ Router advertisement ]")
            elif icmp.ty == 10:
                print("[ Router selection ]")
            elif icmp.ty == 11:
                if icmp.cod == 0:
                    print("[ Time to Live exceeded in transit ]")
                elif icmp.cod == 1:
                    print ("[ Fragment reassembly time exceeded ]")
            elif icmp.ty == 12:
                if icmp.cod == 0:
                    print("[ Pointer indicates the error ]")
                elif icmp.cod == 1:
                    print ("[ Missing a required option ]")
                elif icmp.cod == 2:
                    print("[ Bad length ]")
            elif icmp.ty == 13:
                print("[ Echo ]")
            elif icmp.ty == 14:
                print("[ Timestamp reply ]")
            elif icmp.ty == 15:
                print("[ Information request ]")
            elif icmp.ty == 16:
                print("[ Information reply ]")
            elif icmp.ty == 17:
                print("[ Address mask request ]")
            elif icmp.ty == 18:
                print("[ Address mask reply ]")
            elif icmp.ty == 30:
                print("[ Traceroute ]")
        else:
            print("")
except KeyboardInterrupt:
    print("")
    print("Exit...")
    exit(1)
