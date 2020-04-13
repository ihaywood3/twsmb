# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""Implement Microsoft's Server Message Block protocol"""

from __future__ import absolute_import, division

import struct
import binascii
import uuid
import time

import base

from zope.interface import implementer
from twisted.internet import protocol, interfaces
from twisted.logger import Logger

log = Logger()

COMMANDS=[
    'negotiate',
    'session_setup',
    'logoff',
    'tree_connect',
    'tree_disconnect',
    'create',
    'close',
    'flush',
    'read',
    'write',
    'lock',
    'ioctl',
    'cancel',
    'echo',
    'query_directory',
    'change_notify',
    'query_info',
    'set_info',
    'oplock_break']


# the complete list of NT statuses is very large, so just
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

MAX_READ_SIZE=0x20000
MAX_TRANSACT_SIZE=0x20000
MAX_WRITE_SIZE=0x20000


class SMB(base.SMBPacketReceiver):
    """
    implement SMB protocol server-side
    """ 
    
    def __init__(self, factory):
        base.SMBPacketReceiver.__init__(self)
        self.state = "START"
        self.factory = factory
        self.avatar = None
        aelf.signing_enabled = False
        self.signing_required = False
        self.message_id = 0
        self.tree_id = 0
        self.session_id = 0
        self.async_id = 0
        self.blob_manager = security_blob.BlobManager()
        
        
    def packetReceived(self, packet):
        """
        receive a SMB packet with header. Unpacks the 
        header then calls the appropriate smb_XXX 
        method with data beyond the header.
        
        @param packet: the raw packet
        @type packet: L{bytes}
        """
        protocol_id = packet[:4]
        if protocol_id == b"\xFFSMB":
            # its a SMB1 packet which we dont support with the exception
            # of the first packet, we try to offer upgrade to SMB2
            if self.state == "START":
                self.negotiate_response()
            else:
                self.transport.close()
                log.error("Got SMB1 packet while state = %r" % self.state)
            return                
        elif protocol_id != b"\xFESMB":
            self.transport.close()
            log.error("Unknown packet type")
            log.debug(repr(packet[:64]))
            return            
        begin_struct = "<4xHH4sHHLLQ"
        (hdr_size, self.credit_charge, 
        hdr_status, self.hdr_command, self.credit_request,
        self.hdr_flags, self.next_command,
        self.message_id, rem) = base.unpack(begin_struct, packet)
        self.is_async = (self.hdr_flags & FLAG_ASYNC) > 0
        self.is_related = (self.hdr_flags & FLAG_RELATED) > 0
        self.is_signed = (self.hdr_flags & FLAG_SIGNED) > 0
        # FIXME other flags 3.1 or too obscure
        if self.is_async:
            (self.async_id, self.session_id, 
            self.signature, rem) = base.unpack("<QQ16s", rem)
        else:
            (_reserved, self.tree_id, self.session_id,
            self.signature, rem) = base.unpack("<LLQ16s", rem)
            self.async_id = 0x00
        if self.factory.debug:
            print("HEADER")
            print()
            print("protocol ID     %r" % protocol_id)
            print("size            %d" % hdr_size)
            print("credit charge   %d" % self.credit_charge)
            print("status          %r" % hdr_status)
            print("command         %s (0x%02x)" % (COMMANDS[self.hdr_command], self.lhdr_command))
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
        try:              
            getattr (self, 'smb_'+COMMANDS[self.hdr_command]) (packet[64:])
        except IndexError:
            log.error("unknown command 0x%02x" % self.hdr_command)
            self.error_response(STATUS_NOT_IMPLEMENTED)
        except base.SMBError as e:
            log.error(str(e))
            self.error_response(e.ntstatus)
        if self.is_related and self.next_command > 0:
            self.packetReceived(packet[self.next_command:])
            
            
    def send_with_header(self, payload, command=None, status=STATUS_SUCCESS):
        """
        prepare and transmit a SMB header and payload
        so a full packet but focus of function on header construction

        @param command: command name or id, defaults to same as received packet
        @type command: L{str} or L{int}
        
        @param payload: the after-header data
        @type payload: L{bytes}
        
        @param status: packet status, an NTSTATUS code
        @type status: L{int}
        """
        # FIXME credit and signatures not supportted
        flags = FLAG_SERVER
        if self.is_async:
            flags |= FLAG_ASYNC
        if command is None:
            command = self.hdr_command
        if type(command) is str:
            command = COMMANDS.index(command)        
        header_data = struct.pack("<4sHHLHHLLQ", b'\xFESMB', 64, 0, status,
           command, 0, flags, 0,self.message_id)
        if self.is_async:
            header_data += struct.pack("<QQ16x", self.async_id, self.session_id)
        else:
            header_data += struct.pack("<LLQ16x", 0, self.tree_id, self.session_id)
        self.sendPacket(header_data + payload)
        
    def smb_negotiate(self, payload):
        (neg_structure_size, dialect_count, security_mode,
        _reserved, capabilities, self.client_uuid, _  
        ) = base.unpack("<HHHHL16s", payload)
        # capabilities is ignored as a 3.1 feature
        # as are final field complex around "negotiate contexts" 
        self.client_uuid = uuid.UUID(bytes_le=self.client_uuid)
        dialects = struct.unpack("<%dH" % dialect_count, 
            payload[neg_structure_size:neg_structure_size+(dialect_count*2)])
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
        # FIXME do something with dialects
        # currently server fixed at most basic possible: 0x0202
        self.negotiate_response()
    
    def error_response(self, ntstatus):
        self.send_with_header(b'\x09\0\0\0\0\0\0\0', status=ntstatus)
        # pre 3.1.1 no variation in structure
        
    def negotiate_response(self):
        blob = self.blob_manager.getInitalBlob()
        packet = struct.pack("<HHHH16sLLLLQQHHL", 65, 0, 0x0202, 0, 
            self.factory.server_uuid.bytes_le,
            0, MAX_TRANSACT_SIZE, MAX_READ_SIZE, MAX_WRITE_SIZE,  
            base.u2nt_time(time.time()), 
            base.u2nt_time(self.factory.server_start),
            128, #sec blob offset,
            len(blob),
            0)
        self.send_with_header(packet+blob, 'negotiate')
      $  


class SMBFactory(protocol.Factory):
    
    def __init__(self, debug=False):
        """
        @param debug: print dumps of all packets
        @type debug: L{bool}
        """
        protocol.Factory.__init__(self)    
        self.debug = debug
        self.server_uuid = uuid.uuid4()
        self.server_start = time.time()
        
    def buildProtocol(self, addr):
        return SMB(self)
