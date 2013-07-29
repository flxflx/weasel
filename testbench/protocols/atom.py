'''
Created on 01.11.2012

@author: Felix

Classes used for describing a certain protocol run.
Moved here from protocol.py:SCRIPT as workaround for pickle bug.
'''

class _BASE:
    def __init__(self, jitEmitter, label):
        self.label = label
        self.jitEmitter = jitEmitter

class RECV(_BASE):
    def __init__(self, buffSize=1024, recvAll=False, timeout=None, jitEmitter=None, label="", mandatory=True):
        _BASE.__init__(self, jitEmitter, label)
        self.buffSize = buffSize
        self.recvAll = recvAll
        self.timeout = timeout
        self.label = label
        self.mandatory = mandatory
        
class SEND(_BASE):
    def __init__(self, jitEmitter = None, label=""):
        _BASE.__init__(self, jitEmitter, label)
        
class DATA(_BASE):
    def __init__(self, data, jitEmitter=None, label=""):
        self.data = data
        _BASE.__init__(self, jitEmitter, label)
        
class WAIT(_BASE):
    def __init__(self, timeout, jitEmitter = None, label=""):
        _BASE.__init__(self, jitEmitter, label)
        self.timeout = timeout
        
class START_RECORDING(_BASE):
    def __init__(self, jitEmitter = None, label=""):
        _BASE.__init__(self, jitEmitter, label)
        
class STOP_RECORDING(_BASE):
    def __init__(self, jitEmitter = None, label=""):
        _BASE.__init__(self, jitEmitter, label)