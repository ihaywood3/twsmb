# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
base classes for SMB networking
"""

from __future__ import absolute_import, division

import struct
import binascii

from zope.interface import implementer

from twisted.internet import protocol, interfaces
from twisted.logger import Logger

log = Logger()

class SMBError(Exception):
    """SMB specific errors
    """
    def __init__(self, msg, ntstatus=0xC0000001):
        self.msg = msg
        self.ntstatus = ntstatus

    def __str__(self):
        return "%s 0x%08x" % (self.msg, self.ntstatus)

def u2nt_time(epoch):
    """
    Convert UNIX epoch time to NT filestamp
    quoting from spec: The FILETIME structure is a 64-bit value 
    that represents the number of 100-nanosecond intervals that
    have elapsed since January 1, 1601, Coordinated Universal Time
    """
    return long(epoch*10000000.0)+116444736000000000
    
def unpack(fmt, data):
    """
    a more ergonnomic struct.unpack,If data is longer than the fmt spec it copes
    remaining data returned as last data element

    @param fmt: format string as per L{struct.unpack}
    @type fmt: L{str}
    @param data: data to be unpacked, optionally more
    @type data: L{bytes}

    @rtype: L{tuple}
    """
    sz = struct.calcsize(fmt)
    ret = struct.unpack(fmt, data[:sz])
    ret = list(ret)
    ret.append(data[sz:])
    return tuple(ret)

class SMBPacketReceiver(protocol.Protocol):
    """
    basic SMB 2.0 packets over TCP have a 4-byte header: null byte 
    and 24-bit length field
    this base class processes these headers
    """
    def __init__(self):
        self.data = b''
        
    def dataReceived(self, data):
        self.data += data
        self._processData()
        
    def _processData(self):
        if len(self.data) < 5:
            return
        x, y = struct.unpack("!xBH", self.data[:4])
        size = (x << 16) + y
        if len(self.data) < size+4:
            return
        self.packetReceived(self.data[4:4+size])
        self.data = self.data[4+size:]
        self._processData()

    def sendPacket(self, data):
        """
        send data with 4 byte header
        
        @param dara: packet to send
        @type data: L{bytes}
        """
        size = len(data)
        assert size < 0xffffff
        x = (size & 0xff0000) >> 16
        y = size & 0xffff
        self.transport.write(struct.pack("!BBH", 0, x, y) + data)

    def packetReceived(self, packet):
        """
        called for each complete packet received over network
        override in descendants
         
        @param packet: raw packet data
        @type packet: L{bytes}
        """
        pass
