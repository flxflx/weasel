
import transport
import protocol
import atom

class Telnet:
    
    NAME = 'Telnet-SkipInit'
    
    class PRIV_LEVEL:
        NO_AUTH,    \
        AUTH,       \
        _SENTINEL   = range(3)
    
    class PROTOCOL_STRING:
        CMD_TELNET, \
        CMD_SHELL,  \
        _SENTINEL   = range(3)
    
    _IAC                    = 255
    _WILL                   = 251
    _WONT                   = 252
    _DO                     = 253
    _DONT                   = 254
    _PREDS                  = [_WILL, _WONT, _DO, _DONT]
    _DUMMY_ARGUMENT         = 100
    
    PROTOCOL_STRINGS        = range(PROTOCOL_STRING._SENTINEL)
    PRIV_LEVELS             = range(PRIV_LEVEL._SENTINEL)
    PRIV_LEVELS_WITH_AUTH   = [PRIV_LEVEL.AUTH]
    
    PORT = 23
    _RECV_TIMEOUT           = 1
    _RECV_TIMEOUT_LONG      = 15
    
    _INVALID_COMMAND        = b'\xff\x60'
    
    @staticmethod
    def _DATA_FORMATTER(data):
        special = chr(Telnet._IAC)
        escaped = data.replace(special, special * 2)
        return (atom.DATA(escaped), atom.SEND(), atom.WAIT(Telnet._RECV_TIMEOUT_LONG / 5), atom.RECV(recvAll=True, timeout=Telnet._RECV_TIMEOUT))
    
    @staticmethod
    def _COMMAND_COMPILER(data):
        special = chr(Telnet._IAC)
        escaped = special + data.replace(special, special * 2)
        return (atom.DATA(escaped), atom.SEND(), atom.WAIT(Telnet._RECV_TIMEOUT_LONG / 5), atom.RECV(recvAll=True, timeout=Telnet._RECV_TIMEOUT_LONG))

    @staticmethod
    def _AUTH_COMPILER((authName, authPass)):
        fmtName = Telnet._DATA_FORMATTER(authName + '\n')
        fmtPass = Telnet._DATA_FORMATTER(authPass + '\n')
        return (fmtName, fmtPass)

    @staticmethod
    def getDefaultPrivLevelCmd():
        return Telnet.PRIV_LEVEL.AUTH
    
    @staticmethod
    def getTransportLayer(host, port, verbose):
        return transport.TelnetTrans(host, port, verbose)
    
    @staticmethod
    def getCompiler(authData, recordingTimeSpan=None):
        authName, authPass = authData[Telnet.PRIV_LEVEL.AUTH] 
        proto = protocol.Description(Telnet.NAME)
        
        proto.newLevel('AUTH')
        proto.addElement(protocol.Auth(privLevels=[Telnet.PRIV_LEVEL.AUTH],
                                       values=(authName, authPass),
                                       compiler=Telnet._AUTH_COMPILER))
        
        proto.newLevel('COMMANDS')
        proto.addElement(protocol.Cmd(values=['id\n'], privLevels=[Telnet.PRIV_LEVEL.AUTH], compiler=Telnet._DATA_FORMATTER,
                                      applicables=[Telnet.PROTOCOL_STRING.CMD_SHELL]))
        
        for pred in Telnet._PREDS:
            proto.addElement(protocol.Cmd(values=[chr(pred)], compiler=Telnet._COMMAND_COMPILER,
                                          applicables=[Telnet.PROTOCOL_STRING.CMD_TELNET]))
                                          
        proto.addElement(protocol.InvalidCmd(value=chr(Telnet._DUMMY_ARGUMENT), compiler=Telnet._COMMAND_COMPILER))
        
        proto.newLevel('ARGS')
        proto.addElement(protocol.Static(chr(1), compiler=Telnet._DATA_FORMATTER,
                                         applicables=[Telnet.PROTOCOL_STRING.CMD_TELNET]))
    
        return protocol.Compiler(proto, recordingTimeSpan)
        