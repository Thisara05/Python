import sys
import socket
from threading import Thread

def recv(con):
    while True:
        data = str(con.recv(1024))
        if data == "b''":
            sock.close()
            exit()
        data = data.strip("b")
        print(data.strip("'"))
try:
    if len(sys.argv) < 3:
        print("Please Enter Correct Format\n<filename> <S or C> <IP Address> <Port>\nS for Server\nC for Client")
    else:
        SC = sys.argv[1]
        ip = sys.argv[2]
        po = int(sys.argv[3])
        if SC == "s" or SC == "S":
            sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((ip,po))
            sock.listen()
            con,add=sock.accept()
            t1 = Thread(target=recv,args=(con,))
            t1.daemon=True
            t1.start()
            while True:
                send = input("")
                if send == "":
                    send=" "
                con.send(send.encode())
        elif SC == "c" or SC == "C":
            sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.connect((ip,po))
            t1 = Thread(target=recv,args=(sock,))
            t1.daemon=True
            t1.start()
            while True:
                send = input("")
                if send == "":
                    send=" "
                sock.send(send.encode())
        else:
            print("Please Enter Correct Format\n<filename> <S or C> <IP Address> <Port>\nS for Server\nC for Client")

except KeyboardInterrupt:
    print("\nConnection Close")
    sock.close()

except Exception as d:
    print(d)
    print("Connection Close")
    sock.close()




