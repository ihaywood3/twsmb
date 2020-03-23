from twisted.trial import unittest

import time
import smb
import threading
import tempfile
from smb.SMBConnection import SMBConnection

from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor

class SMBTest(unittest.TestCase):

    def test_with_pysmb(self):
        def backgd():
             time.sleep(1)
             conn = SMBConnection("user", "password", "client", "server",
                 use_ntlm_v2 = True,
                 sign_options = 0,
                 is_direct_tcp = True)
             conn.connect("127.0.0.1", 445)
             file_obj = tempfile.NamedTemporaryFile()
             file_attributes, filesize = conn.retrieveFile('smbtest', '/foo.txt', file_obj)
             file_obj.close()
             conn.close()
             time.sleep(1)
             reactor.stop()
         endpoint = TCP4ServerEndpoint(reactor, 445)
         endpoint.listen(smb.SMBFactory())
         backgd_thread = threading.Thread(target=backgd)
         backgd_thread.start()
         reactor.run()
        