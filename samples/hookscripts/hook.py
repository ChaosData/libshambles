'''
 Copyright (c) 2015 NCC Group
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.
'''

from ctypes import *
import sys
import socket
import time
import struct

libName = './lib/hookffi.so'
hookffi = CDLL(libName)

class uds_data(Structure):
    _fields_ = [
        ("outer_sock", c_int),
        ("inner_sock", c_int),
        ("uds_client", c_int)]


HOOKFUNC = CFUNCTYPE(c_int, POINTER(uds_data))

get_injected_packet = hookffi.get_injected_packet
get_injected_packet.restype = POINTER(c_char)
get_injected_packet.argtypes = [POINTER(uds_data)]


def hook(uds_datap):
  outer_sock = socket.fromfd(uds_datap.contents.outer_sock, socket.AF_INET,
                              socket.SOCK_STREAM, 0)
  inner_sock = socket.fromfd(uds_datap.contents.inner_sock, socket.AF_INET,
                              socket.SOCK_STREAM, 0)
  size_packet = get_injected_packet(uds_datap)
  size = struct.unpack("=H", size_packet[:2])[0]
  packet = size_packet[2:2+size]
  custom_hook(outer_sock, inner_sock, packet)
  hookffi.teardown(uds_datap)
  return 0


def custom_hook(outer_sock, inner_sock, packet=""):
  try:
    print "hooked!"
    print "Client sent: " + repr(packet)

    #outer_sock.sendall(len(packet)*"Z")
    #outer_sock.sendall(packet.replace("hello", "goodbye"))

    #inner_sock.sendall("YOLO1\n")
    npacket = inner_sock.recv(4096)
    print "Client replied: " + repr(npacket)
    inner_sock.sendall("YOLO2\n")
    inner_sock.close()

    #outer_sock.sendall("#YOLOL!\n");
    rpacket = outer_sock.recv(4096)
    print "Server replied: " + repr(rpacket)
    outer_sock.sendall("#YOLOL!\n");
    outer_sock.close()
  except:
    print "except"
    pass


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
