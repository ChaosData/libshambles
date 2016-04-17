import sys
import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((sys.argv[1], int(sys.argv[2])))

s.sendall("\x13BitTorrent protocol yo dawg (%s)" % sys.argv[3])
print sys.argv[3] + repr(s.recv(1024))
#s.sendall("hello there\n")
time.sleep(1)
s.sendall("hello world\n")
print sys.argv[3] + ": " + repr(s.recv(1024))

s.close()
