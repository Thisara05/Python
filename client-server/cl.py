import socket
from threading import Thread

def send(con):
    try:
        while True:
            send = input("")
            if send == "":
                send=" "
            con.send(send.encode())
    except:
        print("")
        print("Connection Close")
        sock.close()


def recv(con):
    while True:
        data = str(con.recv(1024))
        if data == "b''": 
            sock.close()
            exit()
        data = data.strip("b")
        print(data.strip("'"))

try:
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.connect(("127.0.0.1",8080))
    t1 = Thread(target=send,args=(sock,))
    t2 = Thread(target=recv,args=(sock,))
    t1.start()
    t2.start()
except:
    print("Connection Close")
    sock.close()
    exit()
