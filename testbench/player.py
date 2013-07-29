'''
Created on 17.12.2012

@author: Felix
'''

class ServerInvoker:
    """
    Invokes the remote server.
    """
    _RECORD_PROTOCOL_CHUNK_DELAY = 0
    _MAX_TRIES_CONNECT = 20
    
    def __init__(self, protoProcessor, transport):
        
        self.protoProcessor = protoProcessor
        self.protoProcessor.reset()
        self.t = transport
    
    def playFirst(self, verbose=False):
            
        # play protocol run till first START_RECORDING element
        if verbose:
            print "[i] Playing prologue of protocol."
        
        if not self.t.connect(maxTriesConnect=self._MAX_TRIES_CONNECT):
            raise Exception("Cannot connect to remote server application.")
        return self.protoProcessor.play(self.t)
        # interrupt gdb to set breakpoints
        
    def playSecond(self, verbose=False):
        # proceed with the already started protocolrun
        success = self.protoProcessor.play(self.t, chunkDelay=self._RECORD_PROTOCOL_CHUNK_DELAY)
        # kill the debugee and make the debug-loop exit
        self.t.close()
        return success
