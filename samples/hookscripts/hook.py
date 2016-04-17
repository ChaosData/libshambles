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
import sys, os
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
  custom_hook(outer_sock, inner_sock, uds_datap, packet)

  print "shutting down gracefully"
  time.sleep(2)
  hookffi.teardown(uds_datap)

  sys.exit(0)


from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from socket import AF_INET

class Echo(Protocol):
  def connectionMade(self):
    pass
  def dataReceived(self, data):
    print self.factory.name + ":recv => " + repr(data)
    #self.factory.echoer.transport.write(data)
    try:
      self.factory.echoer.send(data.replace("hello", "goodbye"))
    except:
      print "failed to send"
      hookffi.teardown(self.factory.uds_datap)
      os._exit(1)

      #try:
      #  reactor.callFromThread(reactor.stop)
      #except:
      #  print "failed to send & failed to stop"
      #  raise Exception("failed to send & failed to stop")
      #  pass
  def connectionLost(self, reason):
    print "connectionLost(%s)" % self.factory.name 
    #self.stopListening()
    #reactor.stop()
    hookffi.teardown(self.factory.uds_datap)
    os._exit(1)
    #sys.exit(0)
#    try:
#      reactor.callFromThread(reactor.stop)
#    except:
#      print "failed to stop"
#      pass

class EchoFactory(Factory):
  protocol = Echo
  def __init__(self, name, peer_port, uds_datap):
    self.echoer = peer_port
    self.name = name
    self.uds_datap = uds_datap

def custom_hook_new(outer_sock, inner_sock, uds_datap, packet=""):
  print "hooked!"
  print "Client sent: " + repr(packet)

  try:
    inner_sock.setblocking(False)
    outer_sock.setblocking(False)

    inner_port = reactor.adoptStreamConnection(
      inner_sock.fileno(), AF_INET, EchoFactory("inner", outer_sock, uds_datap)
    )

    outer_port = reactor.adoptStreamConnection(
      outer_sock.fileno(), AF_INET, EchoFactory("outer", inner_sock, uds_datap)
    )

    #inner_sock.close()
    #outer_sock.close()

    reactor.run()

    #stoppedDeferred = [inner_port.stopListening(), outer_sock.stopListening()]
  except Exception as e:
    print "except: " + str(e)

def custom_hook_old(outer_sock, inner_sock, foo, packet=""):
  try:
    print "hooked!"
    print "Client sent: " + repr(packet)

    #outer_sock.sendall(len(packet)*"Z")
    #outer_sock.sendall(packet.replace("hello", "goodbye"))

    inner_sock.sendall("YOLO1\n")
    npacket = inner_sock.recv(4096)
    print "Client replied: " + repr(npacket)
    inner_sock.sendall("YOLO2\n")
    inner_sock.close()

    outer_sock.sendall("#YOLOL!\n");
    rpacket = outer_sock.recv(4096)
    print "Server replied: " + repr(rpacket)
    outer_sock.sendall("#YOLOL!\n");
    outer_sock.close()
  except:
    print "except"

    pass


import signal
import errno

def signal_handler(signum, frame):
    raise socket.timeout("Timed out!")
signal.signal(signal.SIGALRM, signal_handler)

def custom_hook_(outer_sock, inner_sock, foo, packet=""):
  print "hooked!"
  print "client sent: " + repr(packet)

  #outer_sock.settimeout(2)
  #inner_sock.settimeout(2)
  #outer_sock.setblocking(0)
  #inner_sock.setblocking(0)

  d = 0
  data = []
  while True:
    print "loop"
    try:
      if d == 0:
        print "d == 0"
        signal.alarm(2)
        data = outer_sock.recv(1024)
        inner_sock.sendall(data)
      elif d == 1:
        print "d == 1"
        signal.alarm(2)
        data = inner_sock.recv(1024).replace("hello", "goodbye")
        #data = inner_sock.recv(1024)
        outer_sock.sendall(data)
      print str(d) + ":" + repr(data)
      if len(data) == 0:
        break
    except socket.timeout as e:
      data = []
      print "socket.timeout"
      print e
    except Exception as e:
      data = []
      print "Exception"
      if e.errno == errno.EINTR:
        print "EINTR"
        continue
      print e
      break
    if d == 1:
      d = 0
    else:
      d = 1
  try:
    inner_sock.close()
  except:
    pass
  try:
    outer_sock.close()
  except:
    pass
  
def custom_hook__(outer_sock, inner_sock, foo, packet=""):
  try:
    print "hooked!"
    print "Client sent: " + repr(packet)

    #outer_sock.sendall(len(packet)*"Z")
    #outer_sock.sendall(packet.replace("hello", "goodbye"))


    print "11111"

    inner_sock.sendall("YOLO inner1\n")
    npacket = inner_sock.recv(4096)
    print "inner: " + repr(npacket)
    inner_sock.sendall("YOLO inner2\n")
    inner_sock.close()

    print "22222"

    rpacket = outer_sock.recv(4096)
    print "outer: " + repr(rpacket)
    outer_sock.sendall("YOLO outer\n");
    rpacket = outer_sock.recv(4096)
    outer_sock.close()


  except Exception as e:
    print "except"
    print e

    pass


def custom_hook(outer_sock, inner_sock, foo, packet=""):
  try:
    print "hooked!"
    print "client sent: " + repr(packet)

    try:
      signal.alarm(2)    
      rpacket = outer_sock.recv(4096)
      print "outer: " + repr(rpacket)
      inner_sock.sendall(rpacket.replace("dawg", "doge"))
    except:
      pass

    npacket = inner_sock.recv(4096)
    print "inner: " + repr(npacket)
    outer_sock.sendall(npacket.replace("hello", "goodbye"));
    
    rpacket = outer_sock.recv(4096)
    print "outer: " + repr(rpacket)
    inner_sock.sendall(rpacket.replace("world", "moon"))

  except Exception as e:
    print "except"
    print e
  inner_sock.close()
  outer_sock.close()

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
