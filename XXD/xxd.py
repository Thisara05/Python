#! /usr/bin/python3
import sys
import os

def create_linearray():
    infile = sys.argv[1]
    x=0
    array=""
    _ascii=[]
    with open (infile,'r') as _file:
        for line in _file:
            line = line.replace("\n",'.')
            for l in line:
                if x!=15:
                    array = array + l
                    x=x+1
                else:
                    array=array + l
                    _ascii.append(array)
                    x=0
                    array = ""
    _ascii.append(array)
    return _ascii

def create_hexcode(_ascii):
    hexbit=[]
    _hex=[]
    for lines in _ascii:
        for l in lines:
            hexbit.append(format(ord(l),"x"))
        while len(hexbit) != 16:
            hexbit.append("  ")
        _hex.append(hexbit)
        hexbit=[]
    return _hex

def create_offset(_hex):
    count = 0
    offset = 0
    offset_array = []
    bit=""
    while count <= len(_hex) - 1:
        offsetbit = format(int(offset),"x")
        for i in range(8-len(offsetbit)):
            bit = bit + "0"
        bit = bit + str(offsetbit) + ": "
        offset_array.append(bit)
        bit=""
        count = count + 1
        offset = offset + 16
    return offset_array

def check_file():
    if os.path.isfile(sys.argv[1]):
        print("",end="")
    else:
        print("Please Enter Valide File",end="\n\n")
        exit()

def check_input():
    if len(sys.argv) == 2:
        print("\nReading " + str(sys.argv[1]),end="\n")
    else:
        print("\nFormat Error\n <Script Name> <Input File Name>\n")
        exit()

try:
    check_input()
    check_file()
    _ascii = create_linearray()
    _hex = create_hexcode(_ascii)
    _offset = create_offset(_hex)
    i=0
    c=1
    while True:
        print(_offset[i],end="")
        for x in _hex[i]:
            if c==0:
                print(x,end=" ")
                c=1
            else:
                print(x,end="")
                c=0
        print(_ascii[i])
        i = i + 1
except IndexError:
    print("")
except PermissionError:
    print("Cun't Opne File --> Permission Denied",end="\n\n")
