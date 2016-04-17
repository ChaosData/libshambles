#!/usr/bin/env python

# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor

import sys

class Echo(Protocol):
    def connectionMade(self):
        self._peer = self.transport.getPeer()

    def dataReceived(self, data):
        print str(self._peer) + ": " + repr(data)
        self.transport.write(data)


def main():
    f = Factory()
    f.protocol = Echo
    reactor.listenTCP(int(sys.argv[1]), f)
    reactor.run()

if __name__ == '__main__':
    main()
