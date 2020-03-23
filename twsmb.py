# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""Implement Microsoft's Server Message Block protocol"""

from __future__ import absolute_import, division

import struct
import binascii

from zope.interface import implementer

from twisted.internet import protocol, interfaces

COMMANDS={
    0x00:'negotiate',
    0x01:'session_setup',
    0x02:'logoff',
    0x03;'tree_connect',
    0x04:'tree_disconnect',
    0x05:'create',
    0x06:'close',
    0x07:'flush',
    0x08:'read',
    0x09:'write',
    0x0A:'lock',
    0x0B:'ioctl',
    0x0C:'cancel',
    0x0D:'echo',
    0x0E:'query_directoty',
    0x0F:'change_notify',
    0x10:'query_info',
    0x11:'set_info',
    0x12:'oplock_break'}
INV_COMMANDS={v:k for k, v in COMMANDS.items()}

# the complete list of statuses is very large, so just
# add those actually used
STATUS_SUCCESS=0x00
STATUS_MORE_PROCESSING=0xC0000016
STATUS_NO_SUCH_FILE=0xC000000F
STATUS_UNSUCCESSFUL=0xC0000001
STATUS_NOT_IMPLEMENTED=0xC0000002
STATUS_INVALID_HANDLE=0xC0000008
STATUS_ACCESS_DENIED=0xC0000022
STATUS_END_OF_FILE=0xC0000011
STATUS_DATA_ERROR=0xC000003E
STATUS_QUOTA_EXCEEDED=0xC0000044
STATUS_FILE_LOCK_CONFLICT=0xC0000054 # generated on read/writes
STATUS_LOCK_NOT_GRANTED=0xC0000055 # generated when requesting lock
STATUS_LOGON_FAILURE=0xC000006D
STATUS_DISK_FULL=0xC000007F
STATUS_ACCOUNT_RESTRICTION=0xC000006E
STATUS_PASSWORD_EXPIRED=0xC0000071
STATUS_ACCOUNT_DISABLED=0xC0000072
STATUS_FILE_INVALID=0xC0000098
STATUS_DEVICE_DATA_ERROR=0xC000009C


FLAG_SERVER=0x01
FLAG_ASYNC =0x02
FLAG_RELATED=0x04
FLAG_SIGNED=0x08
FLAG_PRIORITY_MASK=0x70
FLAG_DFS_OPERATION=0x10000000
FLAG_REPLAY_OPERATION=0x20000000  

NEGOTIATE_SIGNING_ENABLED=0x0001
NEGOTIATE_SIGNING_REQUIRED=0x0002


class SMB(base.SMBPacketReceiver):
    """
    implement SMB protocol server-side
    """ 
    
    def packetReceived(self, packet):
        """
        receive a SMB packet with header. Unpacks the 
        header then calls the appropriate smb_XXX 
        method with data beyond the header.
        
        @param packet: the raw packet
        @type packet: L{bytes}
        """
        begin_struct = "<4sHH4sHHLLQ"
        begin_struct_len = struct.calcsize(begin_struct)        
        (protocol_id, hdr_size, self.credit_charge, 
        hdr_status, hdr_command, self.credit_request,
        self.hdr_flags, self.next_command,
        self.message_id) = struct.unpack(begin_struct, packet)
        self.is_async = (self.hdr_flags & FLAG_ASYNC) > 0
        self.is_related = (self.hdr_flags & FLAG_RELATED) > 0
        self.is_signed = (self.hdr_flags & FLAG_SIGNED) > 0
        # FIXME other flags 3.1 or too obscure
        if self.is_async:
            (self.async_id, self.session_id, 
            self.signature) = struct.unpack_from("<QQ16s", packet, begin_struct_len)
        else:
            (_reserved, self.tree_id, self.session_id,
            self.signature) = struct.unpack_from("<LLQ16s", packet, begin_struct_len)
            self.async_id = 0x00
        if self.factory.debug:
            print("HEADER")
            print()
            print("protocol ID     %r" % protocol_id)
            print("size            %d" % hdr_size)
            print("credit charge   %d" % self.credit_charge)
            print("status          %r" % hdr_status)
            print("command         %s (0x%02x)" % (COMMANDS[hdr_command], hdr_command))
            print("credit request  %d" % self.credit_request)
            s = ""
            if self.is_async:
                s += "ASYNC "
            if self.is_signed:
                s += "SIGNED "
            if self.is_related:
                s += "RELATED "
            print("flags           0x%x %s" % (self.hdr_flags, s))
            print("next command    0x%x" % self.next_command)
            print("message ID      0x%x" % self.message_id)
            print("session ID      0x%x" % self.session_id)
            if self.is_async:
                print("async ID        0x%x" % self.async_id)
            else:
                print("tree ID         0x%x" % self.tree_id)
            print("signature       %s" % binascii.hexlify(self.signature))            
                      
        getattr (self, 'smb_'+COMMANDS[hdr_command]) (packet[64:])
 
        if self.is_related and self.next_command > 0:
            self.packetReceived(packet[self.next_command:])
            
            
    def sendHeader(self, command, payload, status=STATUS_SUCCESS):
        """
        prepare and transmit a SMB header and payload
        so a full packet but focus of function on header construction

        @param command: command name
        @type command: L{str}
        
        @param payload: the after-header data
        @type payload: L{bytes}
        
        @param status: packet status, an NTSTATUS code
        @type status: L{int}
        """
        # FIXME credit and signatures not supportted
        flags = FLAG_SERVER
        if self.is_async:
            flags |= FLAG_ASYNC        
        header_data = struct.pack("<4sHHLHHLLQ", b'\xFESMB', 64, 0, status,
            COMMANDS.index(command), 0, flags, 0,self.message_id)
        if self.is_async:
            header_data += struct.pack("<QQ16x", self.async_id, self.session_id)
        else:
            header_data += struct.pack("<LLQ16x", 0, self.tree_id, self.session_id)
        self.sendPacket(header_data + payload)
        
    def smb_negotiate(self, payload):
        (neg_structure_size, dialect_count, security_mode,
        _reserved, capabilities, self.client_uuid  
        ) = struct.unpack("<HHHHL16s", payload)
        # capabilities is ignored as a 3.1 feature
        # as are final field complex around "negotiate contexts" 
        dialects = struct.unpack("<%dH" % dialect_count, payload, neg_structure_size)
        self.signing_enabled = (security_mode & NEGOTIATE_SIGNING_ENABLED) > 0
        # by spec this should never be false
        self.signing_required = (security_mode & NEGOTIATE_SIGNING_REQUIRED) > 0
        if self.factory.debug:
            print("NEGOTIATE")
            print()
            print("size            %d" % neg_structure_size)
            print("dialect count   %d" % dialect_count)
            s = ""
            if self.signing_enabled:
                s += "ENABLED "
            if self.signing_required:
                s += "REQUIRED"
            print("signing         0x%02x %s" % (security_mode, s))
            print("client UUID     %s" % self.client_uuid)
            print("dialects        %r" % (["0x%04x" % x for x in dialects],))
  
class SMBFactory(protocol.Factory):
    
    def __init__(self, debug=False):
        """
        @param debug: print dumps of all packets
        @type debug: L{bool}
        """
        protocol.Factory.__init__(self)    
        self.debug = debug
        
    def buildProtocol(self, addr):
        return SMB(self)