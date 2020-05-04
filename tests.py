#!/usr/bin/python3

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
from realm import TestRealm

# Mike Teo's pysmb: used to make test connections
from smb.SMBConnection import SMBConnection

from twisted.cred import portal, checkers, credentials
from twisted.trial import unittest
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor
from twisted.logger import globalLogBeginner, textFileLogObserver, Logger
from twisted.internet.protocol import ProcessProtocol 
from twisted.internet.defer import Deferred
from twisted.python.failure import Failure

log = Logger()
observers = [textFileLogObserver(sys.stdout)]
globalLogBeginner.beginLoggingTo(observers)


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

def backgd():
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


def run_pysmb():
    endpoint = TCP4ServerEndpoint(reactor, 8445)
    endpoint.listen(twsmb.SMBFactory(None))
    backgd_thread = threading.Thread(target=backgd)
    backgd_thread.start()
    reactor.run()

class ChatNotFinished(Exception): pass

class ChatProcess(ProcessProtocol):
    def __init__(self, chat):
        self.chat = chat
        self.d = Deferred()
        self.matches = []
         
     
    def outReceived(self, data):
        data = data.decode("utf-8")
        print(data)
        if self.chat:
            prompt, reply = self.chat[0]
            m = re.search(prompt, data)
            if m:
                self.matches.append(m)
                if reply:
                    for i in range(1, 10):
                        t = "\\%d" % i
                        if t in reply:
                            reply = reply.replace(t, m.group(i))
                    self.transport.write(reply.encode('utf-8'))
                else:
                    self.transport.closeStdin()
                del self.chat[0]
                 
    def errReceived(self, data):
        print(data.decode("utf-8"))
 
    def processEnded(self, status):
        if status.value.exitCode != 0:
            self.d.errback(status)
        elif self.chat:
            try:
                raise ChatNotFinished()
            except:
                self.d.errback(Failure())
        else:
            self.d.callback(self.matches)


def spawn(chat, args, usePTY=True):
    pro = ChatProcess(chat)
    reactor.spawnProcess(pro, args[0], args, usePTY=usePTY)
    return pro.d 
 
class SambaClientTests(unittest.TestCase): 
    def setUp(self):
        # Start the server
        r = TestRealm()
        p = portal.Portal(r)
        users_checker = checkers.InMemoryUsernamePasswordDatabaseDontUse()
        self.username = "user"
        self.password = "test-password"
        users_checker.addUser(self.username, self.password)
        p.registerChecker(users_checker, credentials.IUsernameHashedPassword)
        self.factory = twsmb.SMBFactory(p)
        self.port = port = reactor.listenTCP(
            445, self.factory)
        self.addCleanup(port.stopListening)
        self.addCleanup(r.shutdown)

    def test_login(self):
        return spawn([], ["/usr/bin/smbclient", 
                          "\\\\mintbox\\x", self.password,
                          "-m", "SMB2",
                          "-U", self.username,
                          "-I", "127.0.0.1",
                          "-d", "10"],
                         usePTY=True)













