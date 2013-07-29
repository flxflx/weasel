'''
Created on 19.06.2012

@author: Felix

Contains all commands specified in RFC 939 (http://www.ietf.org/rfc/rfc959.txt).
'''
import protocol
import atom
import transport

class FTP:
    
    NAME = "FTP"
    
    class PRIV_LEVEL:
        NO_AUTH = 0
        ANONYMOUS = 1
        AUTH = 2
        _SENTINEL = 3
            
    class PROTOCOL_STRING:
        CMD_ARG_0 = 0
        CMD_ARG_1 = 1
        CMD_ARG_2 = 2
        _SENTINEL = 3
        
    PROTOCOL_STRINGS = range(PROTOCOL_STRING._SENTINEL)
    PRIV_LEVELS = range(PRIV_LEVEL._SENTINEL)
    PRIV_LEVELS_WITH_AUTH = [PRIV_LEVEL.ANONYMOUS, PRIV_LEVEL.AUTH]
    
    _DUMMY_ARGUMENT = "dummy123"
    _INVALID_COMMAND = "w00t"
    
    TIMEOUT = 0.5
    PORT = 21
    
    @staticmethod
    def getDefaultPrivLevelCmd():
        return FTP.PRIV_LEVEL.AUTH
    
    @staticmethod
    def getTransportLayer(host, port, verbose):
        return transport.TcpIp(host, port, verbose)
    
    @staticmethod
    def getCompiler(authData, recordingTimeSpan=None):
        
        proto = protocol.Description("FTP")
            
        def FTP_STATEMENT_COMPILER(data):
            s = "%s\r\n" % data
            return (atom.DATA(s),atom.SEND(),atom.RECV())
        
        def LOGIN_COMPILER(loginData):
            u = FTP_STATEMENT_COMPILER("USER %s" % loginData[0])
            p = FTP_STATEMENT_COMPILER("PASS %s" % loginData[1])
            r = atom.RECV(recvAll=True, timeout=FTP.TIMEOUT, mandatory=False)
            return (u,p,r)
        
        proto.newLevel("GRAB BANNER")
        proto.addElement(protocol.Recv())
        
        proto.newLevel("AUTHENTICATE")
        for privLevel in authData:
            userAuth, passAuth = authData[privLevel]
            proto.addElement(protocol.Auth(privLevels=[privLevel], values=(userAuth, passAuth), importantValuesIndex=[0,1], compiler=LOGIN_COMPILER))
        
        proto.newLevel("COMMANDS")
        
                # authenticated only
        cmds = [protocol.Cmd(privLevels=[FTP.PRIV_LEVEL.AUTH, FTP.PRIV_LEVEL.ANONYMOUS], applicables=[FTP.PROTOCOL_STRING.CMD_ARG_0],
                          values = ["CDUP","PASV", "ABOR", "PWD", "STAT"]),
                
                protocol.Cmd(privLevels=[FTP.PRIV_LEVEL.AUTH, FTP.PRIV_LEVEL.ANONYMOUS], applicables=[FTP.PROTOCOL_STRING.CMD_ARG_1],
                          values = ["CWD", "SMNT", "MKD", "STRU", "MODE", "RETR", "STOR", "STOU", "APPE", "ALLO", "REST", "RNFR", "RNTO", "DELE", "RMD", "LIST", "NLST", "SITE", "HELP", "REST"]), # "PORT",
                
                protocol.Cmd(privLevels=[FTP.PRIV_LEVEL.AUTH, FTP.PRIV_LEVEL.ANONYMOUS], applicables=[FTP.PROTOCOL_STRING.CMD_ARG_2],
                          values = ["TYPE"]),
                
                # not authenticated only
                protocol.Cmd(privLevels=[FTP.PRIV_LEVEL.NO_AUTH, FTP.PRIV_LEVEL.AUTH, FTP.PRIV_LEVEL.ANONYMOUS], applicables=[FTP.PROTOCOL_STRING.CMD_ARG_1],
                          values = ["USER", "PASS"]),
                # all
                protocol.Cmd(privLevels=[FTP.PRIV_LEVEL.AUTH, FTP.PRIV_LEVEL.ANONYMOUS, FTP.PRIV_LEVEL.NO_AUTH], applicables=[FTP.PROTOCOL_STRING.CMD_ARG_0],
                          values = ["REIN", "SYST", "HELP", "NOOP", "QUIT", "ACCT"]), #"QUIT" removed because gdbserver used to occasionally break on this one
                
                # the invalid command
                protocol.InvalidCmd(value=FTP._INVALID_COMMAND)
                ]
        
        for cmd in cmds:
            proto.addElement(cmd)
            
        """
        NOTE: The following levels are only one possible way to model the protocol. Instead, one could just use custom compilers for each string.
        """
        for i in range(1, len(FTP.PROTOCOL_STRINGS)):
            proto.newLevel()
            proto.addElement(protocol.Static(value=" ", applicables=FTP.PROTOCOL_STRINGS[i:]))
            proto.newLevel()
            proto.addElement(protocol.Static(value=FTP._DUMMY_ARGUMENT, applicables=FTP.PROTOCOL_STRINGS[i:]))
            
        proto.newLevel()
        proto.addElement(protocol.Static(value="", compiler=FTP_STATEMENT_COMPILER, applicables=FTP.PROTOCOL_STRINGS))
        
        return protocol.Compiler(proto, recordingTimeSpan)