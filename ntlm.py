# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""Implement the NT Lan Manager (NTLMv2) challenge/response authentication
protocol
 """

from __future__ import absolute_import, division

from zope.interface import implementer, Interface

import struct
import time
import socket
import hmac
import hashlib

import base

import twisted.cred.credentials
from twisted.python.randbytes import secureRandom
from twisted.internet.defer import maybeDeferred
from twisted.logger import Logger

log = Logger()

NTLM_MESSAGES = ['invalid', 'negotiate', 'challenge', 'auth']
FLAGS = {
    'NegotiateUnicode'                :  0x00000001,
    'NegotiateOEM'                    :  0x00000002,
    'RequestTarget'                   :  0x00000004,
    'Unknown9'                        :  0x00000008,
    'NegotiateSign'                   :  0x00000010, 
    'NegotiateSeal'                   :  0x00000020,
    'NegotiateDatagram'               :  0x00000040,
    'NegotiateLanManagerKey'          :  0x00000080,
    'Unknown8'                        :  0x00000100,
    'NegotiateNTLM'                   :  0x00000200,
    'NegotiateNTOnly'                 :  0x00000400,
    'Anonymous'                       :  0x00000800,
    'NegotiateOemDomainSupplied'      :  0x00001000,
    'NegotiateOemWorkstationSupplied' :  0x00002000,
    'Unknown6'                        :  0x00004000,
    'NegotiateAlwaysSign'             :  0x00008000,
    'TargetTypeDomain'                :  0x00010000,
    'TargetTypeServer'                :  0x00020000,
    'TargetTypeShare'                 :  0x00040000,
    'NegotiateExtendedSecurity'       :  0x00080000,
    'NegotiateIdentify'               :  0x00100000,
    'Unknown5'                        :  0x00200000,
    'RequestNonNTSessionKey'          :  0x00400000,
    'NegotiateTargetInfo'             :  0x00800000,
    'Unknown4'                        :  0x01000000,
    'NegotiateVersion'                :  0x02000000,
    'Unknown3'                        :  0x04000000,
    'Unknown2'                        :  0x08000000,
    'Unknown1'                        :  0x10000000,
    'Negotiate128'                    :  0x20000000,
    'NegotiateKeyExchange'            :  0x40000000,
    'Negotiate56'                     :  0x80000000
}

DEFAULT_FLAGS={"NegotiateUnicode",
             "RequestTarget",
             "NegotiateNTLM",
             "NegotiateAlwaysSign",
             "NegotiateExtendedSecurity",
             "NegotiateTargetInfo",
             "NegotiateVersion",
             "Negotiate128",
             "NegotiateKeyExchange",
             "Negotiate56"}
             
             
def flags2set(flags):
    """
    convert C-style flags to Python set
    
    @param flags: the flags
    @type flags: L{int}
    
    @rtype: L{set} of L{str}
    """
    r = set()
    for k, v in FLAGS.items():
        if v | flags > 0: r.add(k)
    return r
    
def set2flags(s):
    """
    convert set to C-style flags
    
    @rtype: L{int}
    
    @type s: L{set} of L{str}
    """
    flags = 0
    for i in s: flags |= FLAGS[i]
    return flags
    
def avpair(code, data):
    """make an AVPAIR structure
    @param code: the attribute ID
    @type code: L{int}
    @param data: the value
    @type value: L{bytes}, or L{str} which is converted UTF-16
    @rtype: L{bytes}
    """
    if type(data) is str:
        data = data.encode("utf-16le")
    elif len(data) % 2 > 0:
        data += b'\0'
    return struct.pack("<HH", code, len(data)) + data
    

AV_EOL=0x0000
AV_COMPUTER_NAME=0x0001
AV_DOMAIN_NAME=0x0002
# only first three are required
AV_DNS_COMPUTER_NAME=0x0003
AV_DNS_DOMAIN_NAME=0x0004
AV_TREE_NAME=0x0005
AV_FLAGS=0x0006
AV_TIMESTAMP=0x0007
AV_SINGLE_HOST=0x0008
AV_TARGET_NAME=0x0009
AV_CHANNEL_BINDINGS=0x000A

  
SERVER_VERSION=(6, 0, 1) 
# major version 6 = Vista, roughly speaking what this emulates

 
class NTLMManager(object):
    """
    manage the NTLM subprotocol
    
    @ivar credential: the user cred, available after the AUTH token received
                      None prior to this
    @type credential: L{IUsernameHashedPassword}
    """
    
    def __init__(self, domain):
        """
        @param domain: the server NetBIOS domain
        @type domain: L{str}
        """
        self.credential = None
        self.flags = DEFAULT_FLAGS
        self.server_domain= domain
        
    def receiveToken(self, token):
        """
        receive client token once unpacked from overlying protocol
        
        @type token: L{bytes}
        """
        self.token = token
        if len(token) < 36:
            log.debug(token)
            raise base.SMBError("token too small")
        sig, msg_id, rem = base.unpack("<8sL", token)
        if sig != b'NTLMSSP\0':
            log.debug(repr(token[:16]))
            raise base.SMBError("No valid NTLM token header")
        try:
            getattr (self, 'ntlm_'+NTLM_MESSAGES[msg_id]) (rem)
        except IndexError:
            raise base.SMBError("invalid message id %d" % msg_id)
            
    def ntlm_invalid(self, data):
        raise base.SMBError("invalid message id 0")
        
    def ntlm_challenge(self, data):
        raise base.SMBError("invalid to send NTLM challenge to a server")
        
    def ntlm_negotiate(self, data):
        (flags, domain_len, domain_max_len, domain_offset,
        workstation_len, workstation_max_len, workstation_offset,
        v_major, v_minor, v_build, v_protocol, _
        ) = base.unpack("<LHHLHHLBBHxxxB", data)
        flags = flags2set(flags)
        log.debug("NTLM NEGOTIATE")
        log.debug("--------------")
        log.debug("Flags           %r" % flags)
        if 'NegotiateVersion' in flags:
            log.debug("Version         %d.%d (%d) 0x%02x" % (
            v_major, v_minor, v_build, v_protocol))
        if not 'NegotiateUnicode' in flags:
            raise base.SMBError("clients must use Unicode")
        if 'NegotiateOemDomainSupplied' in flags and domain_len > 0:
            self.client_domain = \
            self.token[domain_len:domain_len+domain_offset].decode('utf-16le')
            log.debug("Client domain   %r" % self.client_domain)
        else:
            self.client_domain = None
        if 'NegotiateOemWorkstationSupplied' in flags and workstation_len > 0:
            self.workstation = self.token[workstation_len:workstation_len+workstation_offset].decode('utf-16le')
            log.debug("Workstation     %r" % self.workstation)
        else:
            self.workstation = None
        self.flags = DEFAULT_FLAGS & flags
        if 'NegotiateAlwaysSign' not in self.flags:
            self.flags -= {'Negotiate128', 'Negotiate56'}
        if 'RequestTarget' in self.flags:
            self.flags.add('TargetTypeServer')
            
            
    def getChallengeToken(self):
        """generate NTLM CHALLENGE token
        
        @rtype: L{bytes}
        """
        FORMAT= '<8sIHHII8s8xHHIBBHxxxB'
        header_len=struct.calcsize(FORMAT)
        if 'RequestTarget' in self.flags:
            target = socket.gethostname().encode('utf-16le')
        else:
            target = b''
        if 'NegotiateTargetInfo' in self.flags:
            targetinfo = avpair(AV_COMPUTER_NAME, socket.gethostname()) + \
                avpair(AV_DOMAIN_NAME, self.server_domain) + \
                avpair(AV_DNS_COMPUTER_NAME, socket.getfqdn()) + \
                avpair(AV_TIMESTAMP, struct.pack("<Q", base.u2nt_time(time.time()))) + \
                avpair(AV_EOL, b'')
        else:
            targetinfo = b''
        if 'NegotiateVersion' in self.flags:
            v_protocol = 0x0F
            v_major, v_minor, v_build = SERVER_VERSION
        else:
            v_major = v_minor = v_build = v_protocol = 0
        self.challenge = secureRandom(8)            
        header = struct.pack(FORMAT, b"NTLMSSP\0", 0x0002,
            len(target), len(target), header_len,
            set2flags(self.flags),
            self.challenge,
            len(targetinfo), len(targetinfo), header_len+len(target),
            v_major, v_minor, v_build, v_protocol)
        return header+target+targetinfo
        
        
    def ntlm_auth(self, data):
        # note authentication isn't checked here, it's just unpacked and 
        # loaded into the credential object
        (lmc_len, lmc_maxlen, lmc_offset,
        ntc_len, ntc_maxlen, ntc_offset,
        domain_len, domain_maxlen, domain_offset,
        user_len, user_maxlen, user_offset,
        workstation_len, workstation_max_len, workstation_offset,
        ersk_len, ersk_maxlen, ersk_offset,
        # Encrypted Random Session Key
        flags,
        v_major, v_minor, v_build, v_protocol,
        mic, _) = base.unpack("<HHIHHIHHIHHIHHIHHIIBBHxxxB16s", data)
        flags = flags2set(flags)
        lm = {}
        if lmc_len > 0:
            raw_lm_response = self.token[lmc_offset:lmc_offset+lmc_len]
            lm['response'], lm['client_challenge'] = struct.unpack("16s8s", raw_lm_response)
        nt = {}
        if ntc_len > 0:
            raw_nt_response = self.token[ntc_offset:ntc_offset+ntc_len]
            nt['temp'] = raw_nt_response[16:]
            (nt['response'], resp_type, hi_resp_type,
            nt['time'], nt['client_challenge'], nt['avpairs']
            ) = base.unpack("<16sBB6xQ8s4x", raw_nt_response)
            if resp_type != 0x01:
                log.warn("NT response not valid type")  
        if not nt and not lm:
            raise smb.SMBError("one of LM challenge or NT challenge must be provided")
        if domain_len > 0:
            client_domain = self.token[domain_offset:domain_offset+domain_len]
            client_domain = client_domain.decode('utf-16le')
        else:
            client_domain = None
        if user_len > 0:
            user = self.token[user_offset:user_offset+user_len]
            user = user.decode('utf-16le')
        else:
            raise smb.SMBError("username is required") 
       if workstation_len > 0:
            workstation = self.token[workstation_offset:workstation_offset+workstation_len]
            workstation = workstation.decode('utf-16le')
        else:
            workstation = None
        if ersk_len > 0 and 'NegotiateKeyExchange' in flags:
            ersk = self.token[ersk_offset:ersk_offset+ersk_len]
        else:
            ersk = None
        self.ersk = ersk
        log.debug("NTLM AUTH")
        log.debug("---------")
        if 'NegotiateVersion' in flags:
            log.debug("Version         %d.%d (%d) 0x%02x" % (
            v_major, v_minor, v_build, v_protocol))
        log.debug("Flags           %r" % flags)
        log.debug("User            %r" % user)
        log.debug("Workstation     %r" % workstation)
        log.debug("Client domain   %r" % client_domain)
        log.debug("LM response     %r" % lm)
        log.debug("NT response     %r" % nt)
        log.debug("ERSK            %r" % ersk)
        self.credential = NTLMCredential(user, client_domain, lm, nt, self.challenge)
 

 
@implementer(twisted.cred.credentials.IUsernameHashedPassword)
class NTLMCredential(object):
    """
    A NTLM credential, unverified initially
    """
    def __init__(self, user, domain, lm, nt, challenge):
        self.username = user
        self.domain = domain
        self.lm = lm
        self.nt = nt
        self.challenge = challenge
        
    def checkPassword(self, password):
        # code adapted from pysmb ntlm.py
        d = hashlib.new("md4")
        d.update(password.encode('UTF-16LE'))
        ntlm_hash = d.digest()   # The NT password hash
        response_key = hmac.new(ntlm_hash, (self.username.upper() + self.domain).encode('UTF-16LE'), 'md5').digest()  # The NTLMv2 password hash. In [MS-NLMP], this is the result of NTOWFv2 and LMOWFv2 functions 
        if self.lm:
            new_resp = hmac.new(response_key, self.challenge + self.lm['client_challenge'], 'md5').digest() 
            if new_resp != self.lm['response']:
                return False
        if self.nt:
            new_resp = hmac.new(response_key, self.challenge + self.nt['temp'], 'md5').digest()
            if new_resp != self.nt['response']:
                return False
        assert self.nt or self.lm
        return True
