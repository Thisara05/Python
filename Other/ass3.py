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

