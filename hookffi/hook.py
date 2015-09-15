from ctypes import *
import sys
import socket
import time

libName = './hookffi.so'
hookffi = CDLL(libName)

class uds_data(Structure):
    _fields_ = [
        ("outer_sock", c_int),
        ("inner_sock", c_int),
        ("uds_client", c_int)]


HOOKFUNC = CFUNCTYPE(c_int, POINTER(uds_data))

def hook(uds_datap):
  outer_sock = socket.fromfd(uds_datap.contents.outer_sock, socket.AF_INET,
                              socket.SOCK_STREAM, 0)
  inner_sock = socket.fromfd(uds_datap.contents.inner_sock, socket.AF_INET,
                              socket.SOCK_STREAM, 0)
  custom_hook(outer_sock, inner_sock)
  hookffi.teardown(uds_datap)
  return 0


def custom_hook(outer_sock, inner_sock):
  print "hooked!"
  outer_sock.sendall("YO SERVER, THIS IS PYTHON!\n")
  outer_sock.close()
  inner_sock.sendall("YO CLIENT, THIS IS PYTHON!\n")
  inner_sock.close()





def main():
  if len(sys.argv) != 3:
    print "Usage: python hook.py <unix domain socket path> " \
          "<user to expose access>"
    sys.exit(1)

  path = sys.argv[1]
  uname = sys.argv[2]

  uds_server_sock = hookffi.setup_server(path)
  hookffi.allow_user(path, uname)

  cb = HOOKFUNC(hook)
  hookffi.register_hook(cb)

  data = uds_data()
  hookffi.start(uds_server_sock, byref(data))

if __name__ == "__main__":
  main()

