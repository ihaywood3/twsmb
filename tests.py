import sys
import os.path
sys.path.append(os.path.expanduser("~/twsmb")) # FIXME trial won't add to path

import struct
import time
import threading
import tempfile
import pdb
import io

import twsmb
import base

# Mike Teo's pysmb: used to make test connections
from smb.SMBConnection import SMBConnection

from twisted.trial import unittest
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor

class SMBTest(unittest.TestCase):

    def test_base_unpack(self):
        data = struct.pack("!HBH", 525, 24, 17) + b'bob'
        r = base.unpack("!HBH", data)
        self.assertEqual(r, (525, 24, 17, b'bob'))

    def test_smb_packet_receiver(self):
        pr = base.SMBPacketReceiver()   
        pr.transport = io.BytesIO()
        def recv(x): 
            global rdata
            rdata = x
        pr.packetReceived = recv
        # send fake packet
        pr.sendPacket(b'bur ble')
        r = pr.transport.getvalue()
        self.assertEqual(r, b'\0\0\0\x07bur ble')
        # receive fake packet
        pr.dataReceived(b'\0\0\0\x03abc')
        self.assertEqual(rdata, b'abc')

def backgd(self):
    time.sleep(1)
    conn = SMBConnection("user", "password", "client", "server",
         use_ntlm_v2 = True,
         sign_options = 0,
         is_direct_tcp = True)
    try:
        conn.connect("127.0.0.1", 8445)
        file_obj = tempfile.NamedTemporaryFile()
        file_attributes, filesize = conn.retrieveFile('smbtest', '/foo.txt', file_obj)
        file_obj.close()
        conn.close()
        time.sleep(1)
    finally:
        reactor.stop()


def run_pysmb(self):
    endpoint = TCP4ServerEndpoint(reactor, 8445)
    endpoint.listen(twsmb.SMBFactory(debug=True))
    backgd_thread = threading.Thread(target=backgd)
    backgd_thread.start()
    reactor.run()

if __name__=='__main__':
    #run_pysmb()
    pdb.set_trace()
    backgd()
        
