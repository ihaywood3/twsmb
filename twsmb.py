# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""Implement Microsoft's Server Message Block protocol"""

from __future__ import absolute_import, division

import struct
import binascii
import uuid
import time
from collections import namedtuple


import base
import security_blob
from realm import ISMBServer

from zope.interface import implementer
from twisted.internet import protocol, interfaces
from twisted.logger import Logger
from twisted.cred.checkers import ANONYMOUS


log = Logger()

SMBMind = namedtuple('SMBMind', 'session_id domain addr')

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

MAX_READ_SIZE=0x10000
MAX_TRANSACT_SIZE=0x10000
MAX_WRITE_SIZE=0x10000

SESSION_FLAG_IS_GUEST=0x0001
SESSION_FLAG_IS_NULL=0x0002
SESSION_FLAG_ENCRYPT_DATA=0x0004

NEGOTIATE_SIGNING_ENABLED=0x0001
NEGOTIATE_SIGNING_REQUIRED=0x0002

GLOBAL_CAP_DFS=0x00000001
GLOBAL_CAP_LEASING=0x00000002
GLOBAL_CAP_LARGE_MTU=0x00000004
GLOBAL_CAP_MULTI_CHANNEL=0x00000008
GLOBAL_CAP_PERSISTENT_HANDLES=0x00000010
GLOBAL_CAP_DIRECTORY_LEASING=0x00000020
GLOBAL_CAP_ENCRYPTION=0x00000040

MAX_DIALECT=0x02FF

class SMBConnection(base.SMBPacketReceiver):
    """
    implement SMB protocol server-side
    """ 
    
    def __init__(self, factory, addr):
        base.SMBPacketReceiver.__init__(self)
        log.debug("new SMBConnection from %r" % addr)
        self.addr = addr
        self.factory = factory
        self.avatar = None
        self.logout_thunk = None
        self.signing_enabled = False
        self.signing_required = False
        self.message_id = 0
        self.tree_id = 0
        self.session_id = 0
        self.async_id = 0
        self.first_session_setup = True 
        self.is_async =  False
        self.is_related = False
        self.is_signed = False
        self.blob_manager = security_blob.BlobManager(factory.domain)
        
        
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
            if self.avatar is None:
                log.debug("responding to SMB1 packet")
                self.negotiate_response()
            else:
                self.transport.close()
                log.error("Got SMB1 packet while logged in")
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
        log.debug("HEADER")
        log.debug("------")
        log.debug("protocol ID     %r" % protocol_id)
        log.debug("size            %d" % hdr_size)
        log.debug("credit charge   %d" % self.credit_charge)
        log.debug("status          %r" % hdr_status)
        log.debug("command         %s (0x%02x)" % (COMMANDS[self.hdr_command], self.hdr_command))
        log.debug("credit request  %d" % self.credit_request)
        s = ""
        if self.is_async:
            s += "ASYNC "
        if self.is_signed:
            s += "SIGNED "
        if self.is_related:
            s += "RELATED "
        log.debug("flags           0x%x %s" % (self.hdr_flags, s))
        log.debug("next command    0x%x" % self.next_command)
        log.debug("message ID      0x%x" % self.message_id)
        log.debug("session ID      0x%x" % self.session_id)
        if self.is_async:
            log.debug("async ID        0x%x" % self.async_id)
        else:
            log.debug("tree ID         0x%x" % self.tree_id)
        log.debug("signature       %s" % binascii.hexlify(self.signature))            
        try:
            func = 'smb_'+COMMANDS[self.hdr_command]
        except IndexError:
            log.error("unknown command 0x%02x" % self.hdr_command)
            self.error_response(STATUS_NOT_IMPLEMENTED)
        else:
            try:   
                if hasattr(self, func):
                    getattr (self, func) (packet[64:])
                else:
                   log.error("command '%s' either not implemented or not available as no session" % COMMANDS[self.hdr_command])
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
        elif type(command) is str:
            command = COMMANDS.index(command)        
        header_data = struct.pack("<4sHHLHHLLQ", b'\xFESMB', 64, 0, status,
           command, 1, flags, 0,self.message_id)
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
        log.debug("NEGOTIATE")
        log.debug("---------")
        log.debug("size            %d" % neg_structure_size)
        log.debug("dialect count   %d" % dialect_count)
        s = ""
        if self.signing_enabled:
            s += "ENABLED "
        if self.signing_required:
            s += "REQUIRED"
        log.debug("signing         0x%02x %s" % (security_mode, s))
        log.debug("client UUID     %s" % self.client_uuid)
        log.debug("dialects        %r" % (["%04x" % x for x in dialects],))
        self.negotiate_response(dialects)
    
    def error_response(self, ntstatus):
        self.send_with_header(b'\x09\0\0\0\0\0\0\0', status=ntstatus)
        # pre 3.1.1 no variation in structure
        
    def negotiate_response(self, dialects=None):
        log.debug("negotiate_response")
        blob = self.blob_manager.generateInitialBlob()
        if dialects is None:
            log.debug("no dialects data, using 0x0202")
            self.dialect = 0x0202
        else:
            self.dialect = sorted(dialects)[0]
            if self.dialect == 0x02FF:
                self.dialect = 0x0202
            if self.dialect > MAX_DIALECT:
                raise base.SMBError("min client dialect %04x higher than our max %04x" % (self.dialect, MAX_DIALECT))
            log.debug("dialect %04x chosen" % self.dialect)
        packet = struct.pack("<HHHH16sLLLLQQHHL", 
            65, 
            NEGOTIATE_SIGNING_ENABLED, 
            self.dialect, 
            0, 
            self.factory.server_uuid.bytes_le,
            GLOBAL_CAP_DFS, 
            MAX_TRANSACT_SIZE, MAX_READ_SIZE, MAX_WRITE_SIZE,  
            base.u2nt_time(time.time()), 
            base.u2nt_time(self.factory.server_start),
            128, #sec blob offset,
            len(blob),
            0)
        self.send_with_header(packet+blob, 'negotiate')
          
    def smb_session_setup(self, payload):
        (structure_size, flags, security_mode, capabilities,
         channel, blob_offset, blob_len, prev_session_id, _ 
         ) = base.unpack("<HBBIIHHQ", payload)
        blob = payload[blob_offset-64:blob_offset-64+blob_len]
        log.debug("SESSION SETUP")
        log.debug("-------------")
        log.debug("Size             %d"  % structure_size)
        log.debug("Security mode    0x%02x" % security_mode)
        log.debug("Capabilities     0x%08x" % capabilities)
        log.debug("Channel          0x%08x" % channel)
        log.debug("Prev. session ID 0x%016x" % prev_session_id)
        if self.first_session_setup:
            self.blob_manager.receiveInitialBlob(blob)
            reply_blob = self.blob_manager.generateChallengeBlob()
            self.session_setup_response(reply_blob, STATUS_MORE_PROCESSING)
            self.first_session_setup = False
        else:
            self.blob_manager.receiveResp(blob)
            if self.blob_manager.credential:
                log.debug("got credential: %r" % self.blob_manager.credential)
                d = self.factory.portal.login(self.blob_manager.credential,
                                      SMBMind(prev_session_id,
                                              self.blob_manager.credential.domain,
                                              self.addr),
                                      ISMBServer)
                d.addCallback(self._cb_login)
                d.addErrback(self._eb_login)    
            else:
                reply_blob = self.blob_manager.generateChallengeBlob()
                self.session_setup_response(reply_blob, STATUS_MORE_PROCESSING)
    
    def _cb_login(self, t):
        _, self.avatar, self.logout_thunk = t
        blob = self.blob_manager.generateAuthResponseBlob(True)
        log.debug("successful login")
        self.session_setup_response(blob, STATUS_SUCCESS)
        
    def _eb_login(self, failure):
        log.debug(failure.getTraceback())
        blob = self.blob_manager.generateAuthResponseBlob(False)
        self.session_setup_response(blob, STATUS_LOGON_FAILURE)
     
    def session_setup_response(self, reply_blob, ntstatus):
        log.debug("session_setup_response")
        flags = 0
        if self.blob_manager.credential == ANONYMOUS:
            flags |= SESSION_FLAG_IS_NULL
        packet = struct.pack("<HHHH", 9, flags, 72, len(reply_blob))  
        self.send_with_header(packet+reply_blob, 'session_setup', ntstatus)
    

    
        
class SMBFactory(protocol.Factory):
    
    def __init__(self, portal, domain="WORKGROUP"):
        """
        @param portal: the configured portal
        @type portal: L{twisted.cred.portal.Portal}
        
        @param domain: the server's Windows/NetBIOS domain nqme
        @type domain: L{str}
        """
        protocol.Factory.__init__(self)    
        self.domain = domain
        self.portal = portal
        self.server_uuid = uuid.uuid4()
        self.server_start = time.time()
        
    def buildProtocol(self, addr):
        return SMBConnection(self, addr)
