from ctypes import *
import sys

libName = './hookffi.so'
hookffi = CDLL(libName)

class uds_data(Structure):
    _fields_ = [
        ("outer_sock", c_int),
        ("inner_sock", c_int),
        ("uds_client", c_int)]


HOOKFUNC = CFUNCTYPE(c_int, POINTER(uds_data))


def hook(uds_datap):
  print "hooked"

  hookffi.close_forged_sockets_early(uds_datap)
  hookffi.teardown(uds_datap.contents.uds_client)

  return 0






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

