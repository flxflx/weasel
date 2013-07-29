'''
Created on 03.08.2012

@author: Felix

Demo description of the IRC protocol. Only contains commands as specified at http://www.irchelp.org/irchelp/rfc/rfc.html. Grown-up IRC server like UnrealIRCd might have quite alot of additional commands (especially for opers).
Note how the process of registering in level one is modeled using a custom compiler and a jit-emitter (for jit-generating the appropriate PONG reply).
All actual commands are modeled without the use of custom compilers. With the help of a custom compiler for commands it would be possible to omit the last three levels though.
Such a compiler would look like this:

def IRC_COMMAND_COMPILER(data):
    cmd, numArgs = data
    for i in range(numArgs):
        cmd += " %s" % 'arg'
    return (atom.DATA(cmd + "\n"), atom.SEND(), atom.RECV())
    
A corresponding command definition would then look like the following:

x = protocol.Cmd(privLevels=[IRC.PRIV_LEVEL.ADMIN, IRC.PRIV_LEVEL.REGISTERED], applicables=[IRC.PROTOCOL_STRING.STRING0],
                      values = [("WHOIS",1), ("TIME",0)])
                      
Note how commands like "OPER" are specified at multiple locations (here: admin-login and command for registered users).

Commands are always specified with the least possible amount of arguments even if the count of arguments decides the functionality (e.g. "TOPIC" with one argument gets the topic of a channel, while the same command with two arguments sets the topic of a channel).
'''
import protocol
import atom
import transport

# pickle friendly but ugly func definitions outside IRC class
_RECV_TIMEOUT = 0.1
_RECV_TIMEOUT_LONG = 10

def PING_JIT_EMITTER(self, lastResp):
    if lastResp is None:
        return None
    
    v = lastResp.split(" ")[-1]
    return (atom.DATA("PONG %s" % v), atom.SEND())
    
def PRE_REGISTER_JIT_EMITTER(self, lastResp):
    # At least for unrealircd we need to grab the 'unknown host' message at this point.
    if IRC._UNREAL_IRCD_BANNER in lastResp and not IRC._UNREAL_IRCD_HOSTNAME_RESOLVE in lastResp:
        return (atom.RECV(mandatory=False, timeout=_RECV_TIMEOUT),)
    
def IRC_REGISTER_COMPILER(data):
    pw, nick, user = data 
    return (atom.DATA("PASS %s\n" % pw, jitEmitter=PRE_REGISTER_JIT_EMITTER), atom.SEND(), atom.DATA("NICK %s\n" % nick), atom.SEND(), atom.RECV(timeout=_RECV_TIMEOUT, mandatory=False), atom.DATA("USER %s\n" % user, jitEmitter=PING_JIT_EMITTER), atom.SEND(), atom.RECV(recvAll=True), atom.WAIT(1), atom.RECV(timeout=0, recvAll=True, mandatory=False)) 

def IRC_CMD_COMPILER(data, recvTimeout=1.0):
    cmd = data[0]
    for arg in data[1:]:
        cmd += " %s" % arg
    cmd += "\n"
    return (atom.DATA(cmd), atom.SEND(), atom.RECV(recvAll=True, timeout=_RECV_TIMEOUT_LONG))

def IRC_AUTH_COMPILER(data):
    return IRC_CMD_COMPILER(("OPER",) + data, None) # set socket to blocking so we won't kill the authentication in the middle

class IRC:

    NAME = "IRC"
    
    class PRIV_LEVEL:
        UNREGISTERED = 0
        REGISTERED = 1
        ADMIN = 2
        _SENTINEL = 3
            
    class PROTOCOL_STRING:
        CMD_ARG_0 = 0
        CMD_ARG_1 = 1
        CMD_ARG_2 = 2
        CMD_ARG_3 = 3
        CMD_ARG_4 = 4
        _SENTINEL = 5
        
    _DUMMY_ARGUMENT = "w00t"
    _INVALID_COMMAND = "w00t"
    
    # mandatory attributes
    PRIV_LEVELS_WITH_AUTH = [PRIV_LEVEL.ADMIN]
    PROTOCOL_STRINGS = range(PROTOCOL_STRING._SENTINEL)
    PRIV_LEVELS = range(PRIV_LEVEL._SENTINEL)
    PORT = 6667
    #######################
    
    # Application specific constants
    _UNREAL_IRCD_BANNER = "Looking up your hostname"
    _UNREAL_IRCD_HOSTNAME_RESOLVE = "resolve"
    
    @staticmethod
    def getDefaultPrivLevelCmd():
        return IRC.PRIV_LEVEL.ADMIN
    
    @staticmethod
    def getTransportLayer(host, port, verbose):
        return transport.TcpIp(host, port, verbose)
    
    @staticmethod
    def getCompiler(authData, recordingTimeSpan=None):
        
        proto = protocol.Description("IRC")
            
        # grab banner
        proto.newLevel("GRAB BANNER")
        proto.addElement(protocol.Recv())
        
        proto.newLevel("REGISTER")
        proto.addElement(protocol.Static(privLevels=[IRC.PRIV_LEVEL.REGISTERED, IRC.PRIV_LEVEL.ADMIN], 
                                         value=("password", "nickname", "username host server :realname"), 
                                         compiler=IRC_REGISTER_COMPILER))
        
        proto.newLevel("BECOME OPER: AUTH-PHASE")
        adminUser, adminPw = authData[IRC.PRIV_LEVEL.ADMIN]
        adminPwInvalid = adminPw[::-1] 
        proto.addElement(protocol.Auth(privLevels=[IRC.PRIV_LEVEL.ADMIN], values=(adminUser, adminPw), importantValuesIndex=[1], compiler=IRC_AUTH_COMPILER, invalidItem=adminPwInvalid))
        
        proto.newLevel("JOIN CHANNEL") 
        proto.addElement(protocol.Static(privLevels=[IRC.PRIV_LEVEL.REGISTERED, IRC.PRIV_LEVEL.ADMIN], 
                                         value=("JOIN", "#" + IRC._DUMMY_ARGUMENT), 
                                         compiler=IRC_CMD_COMPILER))
        
        proto.newLevel("COMMANDS")
                # admin only
        cmds = [protocol.Cmd(privLevels=[IRC.PRIV_LEVEL.ADMIN], applicables=[IRC.PROTOCOL_STRING.CMD_ARG_0],
                          values = ["TRACE"]),
                protocol.Cmd(privLevels=[IRC.PRIV_LEVEL.ADMIN], applicables=[IRC.PROTOCOL_STRING.CMD_ARG_1],
                          values = ["CONNECT"]),
                protocol.Cmd(privLevels=[IRC.PRIV_LEVEL.ADMIN], applicables=[IRC.PROTOCOL_STRING.CMD_ARG_2],
                          values = ["KICK", "KILL"]),
                
                # registered only
                protocol.Cmd(privLevels=[IRC.PRIV_LEVEL.REGISTERED], applicables=[IRC.PROTOCOL_STRING.CMD_ARG_2],
                          values = ["OPER"]),
        
                # registered and admin
                protocol.Cmd(privLevels=[IRC.PRIV_LEVEL.REGISTERED, IRC.PRIV_LEVEL.ADMIN], applicables=[IRC.PROTOCOL_STRING.CMD_ARG_0],
                          values = ["VERSION", "STATS", "LINKS", "TIME", "ADMIN", "INFO", "NAMES", "WHO", "LIST"]),
        
                protocol.Cmd(privLevels=[IRC.PRIV_LEVEL.ADMIN, IRC.PRIV_LEVEL.REGISTERED], applicables=[IRC.PROTOCOL_STRING.CMD_ARG_1],
                          values = ["WHOIS", "WHOWAS", "JOIN", "PART", "TOPIC"]),
        
                protocol.Cmd(privLevels=[IRC.PRIV_LEVEL.REGISTERED, IRC.PRIV_LEVEL.ADMIN], applicables=[IRC.PROTOCOL_STRING.CMD_ARG_2],
                          values = ["PRIVMSG", "NOTICE", "MODE", "INVITE"]),
        
                # unregistered 
                protocol.Cmd(privLevels=[IRC.PRIV_LEVEL.UNREGISTERED], applicables=[IRC.PROTOCOL_STRING.CMD_ARG_3],
                          values = ["SERVER"]),
        
                protocol.Cmd(privLevels=[IRC.PRIV_LEVEL.UNREGISTERED], applicables=[IRC.PROTOCOL_STRING.CMD_ARG_4],
                          values = ["USER"]),
        
                protocol.Cmd(privLevels=[IRC.PRIV_LEVEL.UNREGISTERED], applicables=[IRC.PROTOCOL_STRING.CMD_ARG_1],
                          values = ["PASS"]),
        
                # commands for all priv-levels
                #protocol.Cmd(applicables=[IRC.PROTOCOL_STRING.CMD_ARG_0],
                #dd          values = ["QUIT"]),
        
                protocol.Cmd(applicables=[IRC.PROTOCOL_STRING.CMD_ARG_1],
                          values = ["NICK", "PONG"]),
                # and finally the invalid command
                protocol.InvalidCmd(value=IRC._INVALID_COMMAND)
                ]
        
        for cmd in cmds:
            proto.addElement(cmd)
            
        """
        NOTE: The following levels are only one possible way to model the protocol. Instead, one could just use custom compilers for each string.
        """
        for i in range(1, len(IRC.PROTOCOL_STRINGS)):
            proto.newLevel()
            proto.addElement(protocol.Static(value=" ", applicables=IRC.PROTOCOL_STRINGS[i:]))
            proto.newLevel()
            proto.addElement(protocol.Static(value=IRC._DUMMY_ARGUMENT, applicables=IRC.PROTOCOL_STRINGS[i:]))
            
        proto.newLevel()
        proto.addElement(protocol.Static(value=[""], compiler=IRC_CMD_COMPILER, applicables=IRC.PROTOCOL_STRINGS))
        
        return protocol.Compiler(proto, recordingTimeSpan)
