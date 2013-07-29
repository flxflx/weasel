'''
Created on 27.01.2013

@author: Felix
'''
import time

class TransportLayer:
    """
    Abstract interface
    """
    def __init__(self, host, port, verbose=False):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.reset()
    
    def connect(self):
        raise NotImplemented()
        
    def send(self):
        raise NotImplemented()
    
    def recv(self, l):
        raise NotImplemented()
    
    def recvTimeout(self, l, timeout):
        raise NotImplemented()
    
    def close(self):
        raise NotImplemented()
    
    def addDatagram(self, d):
        raise NotImplemented()
    
    def setLastResponse(self, d):
        self.lastResp = d
        
    def getLastResponse(self):
        return self.lastResp
    
    def reset(self):
        raise NotImplemented()
    
class TcpIp(TransportLayer):
    
    _PAUSE_CONNECT = 0.5
    
    def reset(self):
        self.buff = ""
        
    def addDatagram(self, d):
        if self.verbose:
            print "[p] Adding data %s." % d
        self.buff += d
    
    def connect(self, maxTriesConnect=1):
        
        i = 0
        import socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                self.s.connect((self.host, self.port))
            except:
                i += 1
                if i == maxTriesConnect:
                    return False
                
                time.sleep(self._PAUSE_CONNECT*i)
            else:
                return True
            
    def send(self):
        if self.verbose:
            print "[p] Sending %s." % self.buff
        return self.sendRaw(self.buff)
            
    def sendRaw(self, data):
        try:
            r = self.s.send(data)
        except:
            if self.verbose:
                print "[p] Error while sending data. Stopping protocol run..."
            return False
        return r == len(data)
    
    def recv(self, l):
        return self.s.recv(l)
    
    def recvTimeout(self, l, timeout, recvAll=False):
        resp = self._recvTimeout(l, timeout)
        if resp is None:
            if self.verbose:
                print "[p] Receive timed-out."
            return None 
        if recvAll and resp is not None:
            while True:
                tmp = self.recvTimeout(l, 0)
                if tmp is None:
                    break
                resp += tmp
        if self.verbose:
            print "[p] Received %s." % resp
        return resp
    
    def _recvTimeout(self, l, timeout):
        r = None
        self.s.settimeout(timeout)
        try:
            r = self.s.recv(l)
        except: # NOTE: For some weird reason we cannot only catch socket.error exceptions at this point. So we catch 'em all ;~ 
            pass
        self.s.settimeout(None)
        return r
    
    def close(self):
        return self.s.close()

import myparamiko

class SSHTrans(TransportLayer):
    
    class SERVICE_NAME:
        USER_AUTH = 'ssh-userauth'
        CONNECTION = 'ssh-connection'
    
    class DummyAuthHandler(myparamiko.AuthHandler):

        def _dummy_parse_service_accept(self, *args):
            self.transport.active = False
            
        def __init__(self, transport):
            self.transport = transport
            # overwrite real handler in order to get control 
            self._handler_table[myparamiko.common.MSG_SERVICE_ACCEPT] = self._dummy_parse_service_accept
    
    def __init__(self, serviceName, *arg):
        TransportLayer.__init__(self, *arg)
        self.serviceName = serviceName
        
    def connect(self, maxTriesConnect=1):
        
        # establish SSH-TRANS
        self.t = myparamiko.Transport((self.host, self.port))
        if self.verbose:
            # enable debug logging of paramiko
            import logging
            logging.basicConfig(level=logging.DEBUG)
            self.t.packetizer.set_hexdump(True)
        
        # setup SSH-AUTH session
        self.t.start_client()
        ah = self.DummyAuthHandler(self.t)
        self.t.auth_handler = ah

        ## request the specified service
        m = myparamiko.Message()
        m.add_byte(chr(myparamiko.common.MSG_SERVICE_REQUEST))
        m.add_string(self.serviceName)
        self.sendRaw(m)
        self.t.join()
        return True
    
    def send(self):
        """
        Sends a SSH-TRANS message to the server.
        @param message: The message to send
        @type message: myparamiko.Message
        """
        return self.sendRaw(self.message)
    
    def sendRaw(self, message):
        if self.verbose:
            print "[p] Sending SSH-TRANS message:"
            print str(message)
        self.t.packetizer.send_message(message)
        return True
    
    def recv(self, l=-1):
        c,m = self.t.packetizer.read_message()
        if self.verbose:
            print "[p] Received message (type %d):" % c
            print str(m)
        return m
    
    def addDatagram(self, d):
        self.message.add_bytes(d)
    
    def reset(self):
        self.message = myparamiko.Message()
    
    def close(self):
        self.t.close()
        
    def recvTimeout(self, l, timeout, recvAll=False):
        # TODO: Not implemented yet. Does it even make sense?
        return self.recv(l)

import socket
import select
from sys import stdout

class TelnetTrans(TransportLayer):
    
    _PAUSE_CONNECT  = 0.1
    _PEEK_TIMEOUT   = 1
    
    _WILL           = 251
    _WONT           = 252
    _DO             = 253
    _DONT           = 254
    _IAC            = 255
    
    _OPT_SGA        = 3
    _PREDS          = [_WILL, _WONT, _DO, _DONT]

    # We will only accept option SGA (suppress go ahead, duplex).
    _RESP_SGA = {_DO: _WILL, _WILL: _DO,   _DONT: _WONT, _WONT: _DONT}
    _RESP_DEF = {_DO: _WONT, _WILL: _DONT, _DONT: _WONT, _WONT: _DONT}

    _prettyProtocol = {
            255: 'IAC',
            254: 'DONT',
            253: 'DO',
            252: 'WONT',
            251: 'WILL',
            250: 'SB',
            240: 'SE'
            }
        
    _prettyOption = {
             0:  'binary',
             1:  'echo',
             2:  'rcp',     # prepare to connect
             3:  'sga',     # suppress go ahead - we always want this! (full-duplex)
             4:  'nams',    # approx. message size
             5:  'status',
             6:  'tm',      # timing mark
             7:  'rcte',    # remote controlled transm. and echo
             8:  'naol',    # negotiate about line width
             9:  'naop',    # " page size
             10: 'naocrd',  # " cr disposition
             11: 'naohts',  # " horiz. tabstops
             12: 'naohtd',  # " horiz. tab disp.
             13: 'naoff',   # " formfeed disp.
             14: 'naovts',  # " vert. tabstops
             15: 'naovtd',  # " vert. tab disp.
             16: 'naolfd',  # " lf disp.
             17: 'xasxii',  # extended ascii cs
             18: 'logout',
             19: 'bm',      # byte macro
             20: 'det',     # data entry terminal
             21: 'supdup',  # supdup protocol
             22: 'supdupoutput',
             23: 'sndloc',  # send location
             24: 'ttype',   # terminal type
             25: 'eor',     # end of record
             26: 'tuid',    # tacas user identification
             27: 'outmrk',  # output marking
             28: 'ttyloc',  # terminal location #
             29: 'vt370regime',
             30: 'x3pad',
             31: 'naws',    # window size
             32: 'tspeed',  # terminal speed
             33: 'lflow',   # remote flow control
             34: 'linemode',
             35: 'xdisploc',
             36: 'old_environ',
             37: 'authentication',
             38: 'encrypt',
             39: 'new_environ'
            }

    def connect(self, maxTriesConnect=1):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        i = 0
        while True:
            try:
                self.s.connect((self.host, self.port))
            except:
                i += 1
                if i == maxTriesConnect:
                    return False

                time.sleep(self._PAUSE_CONNECT*i)
            else:
                self._forwardToAuth()
                self.s.setblocking(False)
                return True

    def _peekByte(self):
        (readable, _, _) = select.select([self.s], [], [], self._PEEK_TIMEOUT)
        if readable:
            d = self.s.recv(1)
            if d != '':
                return ord(d)
            self._done = True
        return None

    def _printCommand(self, command):
        if command in self._prettyProtocol:
            stdout.write(self._prettyProtocol[command] + ' ')
            return
        stdout.write(chr(command))

    def _printOption(self, option):
        if option in self._prettyOption:
            stdout.write(self._prettyOption[option] + ' \n')
            return
        stdout.write(chr(option))

    def _forwardToAuth(self):
        self._done = False
        while True:
            cmd = self._peekByte()
            if self._done or not cmd:
                return

            if cmd == self._IAC:
                pred = self._peekByte()
                if pred in self._PREDS:
                    if self.verbose:
                        self._printCommand(pred)
                    
                    opt = self._peekByte()
                    self.s.send(chr(self._IAC))
                    if self.verbose:
                        self._printOption(opt)

                    resp = self._RESP_DEF
                    if opt == self._OPT_SGA:
                        resp = self._RESP_SGA

                    self.s.send(chr(resp[pred]))
                    self.s.send(chr(opt))
                    
            elif self.verbose:
                stdout.write(str(chr(cmd)))

    def send(self):
        return self.sendRaw(self.data)

    def sendRaw(self, data):
        self.s.send(data)

    def recv(self, l=-1):
        self.s.recv(l)

    def addDatagram(self, d):
        self.data += d

    def reset(self):
        self.data = b''

    def close(self):
        if self.s:
            self.s.close()

    def recvTimeout(self, l, timeout, recvAll=False):
        # TODO: recvAll
        (readable, _, _) = select.select([self.s], [], [], timeout)
        if readable:
            return self.s.recv(l)

