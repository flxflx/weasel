'''
Created on 27.01.2013

@author: Felix
'''

from myparamiko import common
import transport
import protocol
import atom
import struct

###########

class COMPILER:
    
    @staticmethod
    def STRING(s):
        d = struct.pack('>I', len(s)) + s
        return atom.DATA(d)
    
    @staticmethod
    def BOOLEAN(b):
        d = b and "\x01" or "\x00"
        return atom.DATA(d)
    
    @staticmethod
    def BYTE(b):
        return atom.DATA(chr(b))
    
    @staticmethod
    def AUTH(authData):
        pw = authData[0]
        return COMPILER.STRING(pw)
    
class AUTH:
    
    NAME = "SSH-AUTH"
    
    class PRIV_LEVEL:
        UNAUTH = 0
        AUTH = 1
        _SENTINEL = 2
            
    class PROTOCOL_STRING:
        CMD_PUBK, CMD_HOST, CMD_NONE, CMD_PW, _SENTINEL = range(5)
        
    _DUMMY_ARGUMENT = "dummy123"
    _INVALID_COMMAND = "w00t"
    _TIMEOUT_RECV = 60.0
    
    # mandatory attributes
    PRIV_LEVELS_WITH_AUTH = [PRIV_LEVEL.AUTH]
    PROTOCOL_STRINGS = range(PROTOCOL_STRING._SENTINEL)
    PRIV_LEVELS = range(PRIV_LEVEL._SENTINEL)
    PORT = 22
    #######################
        
    @staticmethod
    def getTransportLayer(host, port, verbose):
        return transport.SSHTrans(transport.SSHTrans.SERVICE_NAME.USER_AUTH, host, port, verbose)
    
    @staticmethod
    def getDefaultPrivLevelCmd():
        return AUTH.PRIV_LEVEL.UNAUTH
    
    @staticmethod
    def getCompiler(authData, recordingTimeSpan=None):
        
        authName, authPw = authData[AUTH.PRIV_LEVEL.AUTH]
                
        proto = protocol.Description(AUTH.NAME)
            
        proto.newLevel("SSH_MSG_USERAUTH_REQUEST")
        proto.addElement(protocol.Static(common.MSG_USERAUTH_REQUEST, compiler=COMPILER.BYTE))
                         
        proto.newLevel("username")
        proto.addElement(protocol.Static(authName, compiler=COMPILER.STRING))
        
        proto.newLevel("service name")
        proto.addElement(protocol.Static("ssh-connection", compiler=COMPILER.STRING))
        
        proto.newLevel("method name")
        # NOTE: We just take the 'password' method into account from here on, as we're currently not planning to really implement the others.
        proto.addElement(protocol.Cmd(values=["password"], compiler=COMPILER.STRING, applicables=[AUTH.PROTOCOL_STRING.CMD_PW]))
        proto.addElement(protocol.Cmd(values=["hostbased"], compiler=COMPILER.STRING, applicables=[AUTH.PROTOCOL_STRING.CMD_HOST]))
        proto.addElement(protocol.Cmd(values=["publickey"], compiler=COMPILER.STRING, applicables=[AUTH.PROTOCOL_STRING.CMD_PUBK]))
        proto.addElement(protocol.Cmd(values=["none"], compiler=COMPILER.STRING, applicables=[AUTH.PROTOCOL_STRING.CMD_NONE]))
        proto.addElement(protocol.InvalidCmd("invalid", compiler=COMPILER.STRING))
        
        proto.newLevel("arg0")
        proto.addElement(protocol.Static(False, compiler=COMPILER.BOOLEAN, applicables=[AUTH.PROTOCOL_STRING.CMD_PUBK, AUTH.PROTOCOL_STRING.CMD_PW]))
        
        proto.newLevel("arg1")
        proto.addElement(protocol.Auth(privLevels=[AUTH.PRIV_LEVEL.AUTH], values=(authPw,), compiler=COMPILER.AUTH, applicables=[AUTH.PROTOCOL_STRING.CMD_PW]))
        proto.addElement(protocol.Static(AUTH._DUMMY_ARGUMENT, compiler=COMPILER.STRING, privLevels=[AUTH.PRIV_LEVEL.UNAUTH], applicables=[AUTH.PROTOCOL_STRING.CMD_PUBK, AUTH.PROTOCOL_STRING.CMD_HOST,AUTH.PROTOCOL_STRING.CMD_PW]))
        
        proto.newLevel("arg2")
        proto.addElement(protocol.Static(AUTH._DUMMY_ARGUMENT, compiler=COMPILER.STRING, privLevels=[AUTH.PRIV_LEVEL.UNAUTH], applicables=[AUTH.PROTOCOL_STRING.CMD_PUBK, AUTH.PROTOCOL_STRING.CMD_HOST]))
        
        proto.newLevel("arg3")
        proto.addElement(protocol.Static(AUTH._DUMMY_ARGUMENT, compiler=COMPILER.STRING, privLevels=[AUTH.PRIV_LEVEL.UNAUTH], applicables=[AUTH.PROTOCOL_STRING.CMD_HOST]))
        
        proto.newLevel("arg4")
        proto.addElement(protocol.Static(AUTH._DUMMY_ARGUMENT, compiler=COMPILER.STRING, privLevels=[AUTH.PRIV_LEVEL.UNAUTH], applicables=[AUTH.PROTOCOL_STRING.CMD_HOST]))
        
        proto.newLevel("arg5")
        proto.addElement(protocol.Static(AUTH._DUMMY_ARGUMENT, compiler=COMPILER.STRING, privLevels=[AUTH.PRIV_LEVEL.UNAUTH], applicables=[AUTH.PROTOCOL_STRING.CMD_HOST]))
        
        proto.newLevel("send request")
        proto.addElement(protocol.Send())
        
        proto.newLevel("receive response")
        proto.addElement(protocol.Recv())
        
        return protocol.Compiler(proto, recordingTimeSpan)
