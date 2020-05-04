# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""Implement a base class for L{twisted.cred} Realms.
This contains an "avatar pool" which is required as the spec stipulates
clients can re-establish sessions after a severed connection
"""

from __future__ import absolute_import, division

import time

from base import SMBError

from zope.interface import implementer, Interface, Attribute
from twisted.logger import Logger
from twisted.cred.portal import IRealm
from twisted.internet.defer import maybeDeferred
from twisted.internet.task import LoopingCall

log = Logger()

MAX_COUNTER=2**64 - 1

POOL_CLEAN_INTERVAL=600
POOL_AVATAR_EXPIRY=1200

@implementer(IRealm)
class SMBBaseRealm:

    """base class for all realms for use with SMB server
    Holds avatar pool so can be retrieved by prev_session_id
    """
    
    def __init__(self):
        self.pool = {}
        self.counter = 1
        self.loop = LoopingCall(self.clean_pool)
        self.loop.start(POOL_CLEAN_INTERVAL, False)
        
    def chainedRequestAvatar(self, avatarId, mind, *interfaces):
        """descendants override this
        same signature as L{twisted.cred.portal.IRealm.requestAvatar}
        """
        pass
        
    def requestAvatar(self, avatarId, mind, *interfaces):
        if mind.session_id == 0:
            self.counter += 1
            if self.counter >= MAX_COUNTER:
                self.counter = 1
            while self.counter in self.pool:
                self.counter += 1    
                if self.counter >= MAX_COUNTER:
                    self.counter = 1
            d = maybeDeferred(self.chainedRequestAvatar, avatarId, mind, *interfaces)
            d.addCallback(self._cb_avatar, self.counter)
            return d
        else:
            try:
                node = self.pool[mind.session_id]
            except KeyError:
                raise SMBError("session no longer available")
            node.activate()
            return (ISMBServer, node.avatar, lambda: self.logout(mind.session_id))
            
    def _cb_avatar(self, t, session_id):
        interface, avatar, inner_logout = t
        avatar.session_id = session_id
        self.pool[session_id] = Node(avatar, inner_logout)
        return (interface, avatar, lambda: self.logout(session_id))

    def logout(self, session_id):
        """notify the pool and an avatar of a formal (planned) logout
        """
        self.pool[session_id].inner_logout()
        del self.pool[session_id]
        
    def connectionLost(self, session_id):
        """notify pool a connection has been lost without logout
        """
        try:
            self.pool[session_id].deactivate()
        except KeyError:
            pass
            
    def clean_pool(self):
        """remove avatars absndoned for so long reconnection is unlikely
        """
        now = time.time()
        for i in self.pool.keys():
            if self.pool[i].expired(now):
                self.pool[i].inner_logout()
                del self.pool[i]
     
     
     
    def shutdown(self):
        """shutdown loop timer """
        self.loop.stop()    
                
                
class Node:
    """member of the pool, holds avatar and timer for expiry
    """
    
    def __init__(self, avatar, inner_logout):
        self.avatar = avatar
        self.inner_logout = inner_logout
        self.inactive_time = None
     
    def activate(self):
        """mark node as acfive, i.e. stop the clock
        """
        self.inactive_time = None

    def deactivate(self):
        """mark node as inactive, i.e. start the clock
        """
        self.inactive_time = time.time()

    def expired(self, now):
        """test if deactivated too long
        @param now: current time, to avoid repeatingly calling L{time.time()}
        @type now: float
        @rtype: bool
        """
        return self.inactive_time and now - self.inactive_time > POOL_AVATAR_EXPIRY
 
class TestRealm(SMBBaseRealm):
    def chainedRequestAvatar(self, avatarId, mind, interfaces):
        log.debug("avatarId=%r mind=%r" % (avatarId, mind))
        return (ISMBServer, TestAvatar(), lambda: None)

class ISMBServer(Interface):
    """
    A SMB server avatar, contains a number of "shares" (filesystems/printers/
    IPCs) 
    """
    
    session_id = Attribute("the assigned int64 session ID")


@implementer(ISMBServer)   
class TestAvatar():
    """
    a test avatar that illustrates functionality applications need to 
    implement
    """
    
    pass