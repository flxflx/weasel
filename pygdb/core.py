'''
Created on 27.03.2012

@author: Felix
'''
import socket
import re
import time
import threading
import copy

import instruction
import environment
from tools.memCache import MemCache

from globals import *

# exceptions
class ExceptionWithText(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
    
class SocketNotInitialized(ExceptionWithText):
    pass
    
class InvalidThread(Exception):
    def __str__(self):
        return "The supplied tid is not recognized."
    
class MemoryAccessViolation(ExceptionWithText):
    pass
    
class CouldNotStartDebugee(Exception):
    def __str__(self):
            return "The remote stub could not start the debugee using the given commandline."
        
class CouldNotFollowFork(Exception):
    def __str__(self):
            return "Failed to follow a newly created fork."
        
class InvalidCommand(Exception):
    def __str__(self):
            return "Stub says it didn't get what you want."

class InvalidArguments(ExceptionWithText):
    pass
    
class InvalidState(ExceptionWithText):
    pass         

# OS's
class OS:
    WINDOWS = 0
    LINUX = 1
    VXWORKS = 2
    LYNXOS = 3
        
# GDB consts
class GDB:
    
    @staticmethod
    def _compressCharSequence(char, n):
        ret = ""
        while n > 0:
            if n < GDB.COMPRESSION.LENGTH_MIN:
                ret += n*char
                break
            
            n -= 1
            if n in GDB.COMPRESSION.FORBIDDEN_LENGTHS:
                nTmp = GDB.COMPRESSION.LENGTH_FALLBACK
                n -= GDB.COMPRESSION.LENGTH_FALLBACK
            else:
                nTmp = min(n,GDB.COMPRESSION.LENGTH_MAX)
                n -= GDB.COMPRESSION.LENGTH_MAX
                
            ret += char + '*' + chr(nTmp+GDB.COMPRESSION.LENGTH_OFFSET)
        return ret
                
    @staticmethod
    def compressString(s):
        """
        Compresses a string using GDB's run-length encoding scheme.
        @param s: The uncompressed string
        @return: The compressed string
        """
        if len(s) == 0:
            return ""
        
        compressed = ""
        lenSeq = 1
        charSeq = s[0]
        for i in range(1,len(s)):
            if s[i] != charSeq:
                # sequence broken -> copy
                compressed += GDB._compressCharSequence(charSeq, lenSeq)            
                lenSeq = 1
                charSeq = s[i]                
            else:
                lenSeq += 1
                
        compressed += GDB._compressCharSequence(charSeq, lenSeq)
        return compressed
    
    @staticmethod
    def validateMessage(m):
        if m[-3] != GDB.END_MESSAGE:
            return False
        
        checksum = int(m[-2:],16)
        return checksum == GDB.calcChecksum(m[1:-3])
        
    @staticmethod
    def uncompressString(s):
        """
        Uncompresses a run-length encoded byte-string.
        @param s: The compressed string
        @return: The uncompressed string
        """
        uncompressed = ""
        i = 0
        while i < len(s):
            iseq = s.find("*",i)
            if iseq == -1:
                # we're done
                uncompressed += s[i:]
                break
            
            # copy till repeat sequence
            uncompressed += s[i:iseq]
            
            # unroll sequence
            ## check for escaping
            rawN = s[iseq+1]
            offset = 0 
            n = ord(rawN) - GDB.COMPRESSION.LENGTH_OFFSET
            
            uncompressed += s[iseq-1]*n
            i = iseq + 2 + offset
            
        return uncompressed
    
    @staticmethod 
    def escapeString(s):
        """
        Escapes a binary string GDB-style.
        """
        escaped = ""
        for c in s:
            if c in GDB.ENCODING.FORBIDDEN_CHARS:
                escaped += GDB.ENCODING.ESCAPE_CHAR + chr(ord(c)^ord(GDB.ENCODING.XOR_VALUE))
            else:
                escaped += c
                
        return escaped
    
    @staticmethod
    def unescapeString(s):
        """
        Unescapes a '}' encoded byte-string.
        @param s: The escaped string
        @return: The unescaped string
        """
        unescaped = ""
        i = 0
        while i < len(s):
            j = s.find(GDB.ENCODING.ESCAPE_CHAR, i)
            if j != -1:
                unescaped += s[i:j]
                # unescape
                unescaped += chr(ord(s[j+1]) ^ ord(GDB.ENCODING.XOR_VALUE))
                i = j+2
            else:
                unescaped += s[i:]
                break
        return unescaped
    
    @staticmethod
    def decodeBinaryString(s):
        """
        Decodes an escaped and compressed binary string received from the remote stub.
        @param s: The encoded string
        @return: The decoded string
        """
        return GDB.unescapeString(GDB.uncompressString(s))
                
    @staticmethod
    def calcChecksum(x):
        cs = 0
        for c in x:
            cs += ord(c)
        return cs & 0xFF
    
    CMD_FORMAT = "$%s#%02x"    
    MIN_LEN_RESPONSE = len("$#XX")
    ACK = "+"
    ARGUMENT = ";%s"
    FIRST_ARGUMENT = ":%s"
    LEN_ERROR_MSG = 3
    END_MESSAGE = "#"
    START_MESSAGE = "$"
    THREAD_SINGLE_PROCESS = "%x"
    THREAD_MULTI_PROCESS = "p%x.%x"
    
    class THREADS:
        ALL = -1
        ANY = 0
        
    class ENCODING:
        ESCAPE_CHAR = "}"
        XOR_VALUE = "\x20"
        FORBIDDEN_CHARS = "#$}"
    
    class COMPRESSION:
        LENGTH_OFFSET = 29
        LENGTH_MAX = 125 - LENGTH_OFFSET
        LENGTH_MIN = 3
        FORBIDDEN_LENGTHS = [7,6]
        LENGTH_FALLBACK = 5
        
    class REGEX:
        COMPRESSED_VALUE = "([\\da-f]+(\\*[ -~])?[\\da-f]*)+"
        PROCESS_THREAD_ID = "<thread id=\"p(?P<pid>[a-f0-9]+)\\.(?P<tid>[a-f0-9]+)\""
    
    class RESPONSE:
        OK = "OK"
        NOT_SUPPORTED = ""
        ERROR = "E"
        NOT_FOUND = "0"
        FOUND = "1"
        
        class STOP:
            SIGNAL_SHORT = "S"
            SIGNAL = "T"
            EXIT = "W"
            TERMINATE = "X"
            SYSCALL = "F"
            
        class RAW_DATA:
            LAST_PACKET = "l"
            MORE_TO_COME = "m"
            
    class CMD:
        SET_BP_SOFT = "Z0,%x,%d"
        REMOVE_BP_SOFT = "z0,%x,%d"
        READ_MEMORY = "m%x,%x"
        WRITE_MEMORY = "M%x,%x:%s"
        SEARCH_MEMORY = "qSearch:memory:%x;%x;%s"
        READ_REGISTERS = "g"
        WRITE_REGISTERS = "G%s"
        SET_CMD_THREAD_CONTEXT = "H%s%s"
        START_NO_ACK_MODE = "QStartNoAckMode"
        ATTACH = "vAttach;%x"
        DETACH = "D;%x"
        SUPPORTED_FEATURES = "qSupported"
        RUN = "vRun;%s"
        KILL = "vKill;%x"
        DISABLE_ASLR = "QDisableRandomization:%d"
        ENABLE_NON_STOP_MODE = "QNonStop"
        GET_THREAD_ID = "qC"
        INTERPRETER_COMMAND = "qRcmd,"
        PASS_SIGNALS = "QPassSignals"
        GET_HALTING_REASON = "?"
        GET_SUPPORTED_CONTINUE_MODES = "vCont?"
        
        # apparently not widely supported
        READ_REGISTER = "p%x"
        WRITE_REGISTER = "P%x=%s"
        INTERRUPT = "\x03"
        
        RESTART = "R00"
        ENABLE_EXTENDED_MODE = "!"
        class VCONT:
            PREFIX = "vCont" #format is `vCont[;action[:thread-id]]...' 
            
            CONTINUE = "c"
            CONTINUE_SIGNAL = "C %s"
            STEP = "s"
            STEP_SIGNAL = "S %s"
            STOP = "t"
            
        class XFER:
            READ_AUXILIARY_VECTOR = "qXfer:auxv:read"
            READ_THREADS = "qXfer:threads:read"
            SUFFIX_0 = "::%x,%x"
            
    class SIGNAL:
        HUP = 1
        INT = 2
        QUIT = 3
        ILL = 4
        TRAP = 5
        ABRT = 6
        EMT = 7
        FPE = 8
        KILL = 9
        BUS = 10
        SEGV = 11
        SYS = 12
        PIPE = 13
        ALRM = 14
        TERM = 15
        URG = 16
        STOP = 17
        TSTP = 18
        CONT = 19
        CHLD = 20
        
class _Thread:
    def __init__(self, tid):
        self.tid = tid
        self.clearUnprocessedEvent()
        self.reset()
    
    # call this whenever a thread is resumed
    def reset(self):
        self._registers = []
        self.registersChanged = False
        
    def setRegisters(self, registers, registersChanged=True):
        self._registers = registers
        self.registersChanged = registersChanged
        
    def setRegister(self, index, value):
        self._registers[index] = value
        self.registersChanged = True
        
    def getRegisters(self):
        return self._registers
    
    def getTidGdbFormatted(self):
        return GDB.THREAD_MULTI_PROCESS % (self.pid, self.tid)
    
    def pushUnprocessedEvent(self, event):
        self.unprocessedEvent = event
        
    def popUnprocessedEvent(self):
        event = self.unprocessedEvent
        self.clearUnprocessedEvent()
        return event
    
    def clearUnprocessedEvent(self):
        self.unprocessedEvent = None
 
class Event:
    
    # consts
    NO_THREAD = -2
    UNDEFINED_ADDR = -1
    
    regexPC = None
    regexThread = None
    regexThreadSingle = None
    regexCore = None
    regexProcess = None
    
    def __str__(self):
        s = ""
        s += "type: %s (%d)" % (self.type, self.signalType)
        s += self._pid is not None and ", pid: %x" % self._pid or ""
        s += self.tid is not None and ", tid: %x" % self.tid or ""
        s += self.tid is not None and ", tid: %x" % self.tid or ""
        return s
    
    def __init__(self, raw, cpu, environment):
        
        self.type = raw[0]
        self.addr = self.UNDEFINED_ADDR # needs to be set by the respective event-handler
        eventStr = raw[1:]
        self.isThreadBound = False
        self.isProcessBound = False
        self.tid = None
        self._pid = None
        if self.type == GDB.RESPONSE.STOP.SIGNAL_SHORT or self.type == GDB.RESPONSE.STOP.SIGNAL:
        
            #check if re were already compiled, if not do so
            if Event.regexPC is None:
                Event.regexPC = re.compile("%02x:%s;" % (cpu.getPcIndex(), GDB.REGEX.COMPRESSED_VALUE))
            
            if Event.regexThread is None:
                Event.regexThread = re.compile("thread:p%s\\.%s;" % (GDB.REGEX.COMPRESSED_VALUE, GDB.REGEX.COMPRESSED_VALUE))
                
            if Event.regexThreadSingle is None:
                Event.regexThreadSingle = re.compile("thread:%s;" % GDB.REGEX.COMPRESSED_VALUE)
                
            if Event.regexCore is None:
                Event.regexCore = re.compile("core:%s;" % GDB.REGEX.COMPRESSED_VALUE)
                
            self.signalType = int(eventStr[:2],16)
            eventStr = eventStr[2:]
            
            m = Event.regexPC.search(eventStr)
            if m:
                self.pc = cpu.registerHexStringToValue(m.group(1))
                    
            m = Event.regexThread.search(eventStr)
            if m is not None:
                self._pid = int(m.group(1),16)
                self._tid = int(m.group(3),16)
                self.isThreadBound = True
                self.isProcessBound = True
            else: # check for a single thread notation
                m = Event.regexThreadSingle.search(eventStr) 
                if m is not None:
                    self._pid = int(m.group(1),16)
                    self._tid = GDB.THREADS.ANY
                    self.isProcessBound = True
                
            if self.isProcessBound:
                self.tid = environment.packThreadId(self._pid, self._tid)
                                
        elif self.type == GDB.RESPONSE.STOP.EXIT: # try process-only
            if Event.regexProcess is None:
                Event.regexProcess = re.compile("process:%s" % GDB.REGEX.COMPRESSED_VALUE)
                
            m = Event.regexProcess.search(eventStr)
            if m is not None:
                self._pid = int(m.group(1),16)
                self.isProcessBound = True
        
        self.pid = self._pid # to not break legacy code we keep _pid
                
    def setAddress(self, addr):
        self.addr = addr
                
class _Breakpoint:
    
    def __init__(self, callback, self0):
        self.callback = callback
        self.self0 = self0
        
class _RangeBreakpoint(_Breakpoint):
    
    def __init__(self, addrStart, addrEnd, callback, self0):
        _Breakpoint.__init__(self, callback, self0)
        self.addrStart = addrStart
        self.addrEnd = addrEnd
        self.originalBytes = None
        
    def inRange(self, addr):
        return addr >= self.addrStart and addr <= self.addrEnd
    
    def setOriginalBytes(self, originalBytes):
        self.originalBytes = originalBytes
                
class _ExceptionHandler:
    
    def __init__(self, exception, callback, addrMin=0, addrMax=0):
        self.exception = exception
        self.addrMin = addrMin
        if addrMax == 0:
            self.addrMax = addrMin
        else:
            self.addrMax = addrMax
            
        self.fullRange = addrMax == 0 and addrMin == 0
        self.callback = callback
        
class _Process:

    def __init__(self, pid, sizeBreakpoint):
        self.pid = pid
        self.breakpoints = {}
        self.breakpointsInternal = {}
        self.removedBreakpoints = []
        self.breakpointsReturn = {} # for keeping track of return breakpoints
        self.breakpointRanges = []
        self.originalBytes = {}
        self.sizeBreakpoint = sizeBreakpoint#
        self.flushMemCache()
        self.father = None
        
    def setFather(self, father):
        self.father = father
        
    def getFather(self):
        return self.father
        
    def flushMemCache(self):
        self.memCache = MemCache()
        
    def addBreakpoint(self, addr, breakpoint, internal=False):
        if isinstance(breakpoint,int):
            print "wtf"
        if internal:
            self.breakpointsInternal[addr] = breakpoint
        else:
            self.breakpoints[addr] = breakpoint
            
    def addReturnBreakpoint(self, addr):
        
        if addr not in self.breakpointsReturn:
            self.breakpointsReturn[addr] = 0
        
        self.breakpointsReturn[addr] += 1
        
    def addBreakpointRange(self, breakpointRange):
        self.breakpointRanges.append(breakpointRange)
              
    def removeBreakpoint(self, addr, internal=False, bpCallback=None):
        if internal:
            if addr not in self.breakpointsInternal:
                return False
            
            if bpCallback is not None and self.breakpointsInternal[addr].callback != bpCallback:
                return False
            
            self.breakpointsInternal.pop(addr)
        else:
            if addr not in self.breakpoints:
                return False
            
            if bpCallback is not None and self.breakpoints[addr].callback != bpCallback:
                return False
            
            self.breakpoints.pop(addr)
        self.removedBreakpoints.append(addr)
        return True
    
    def removeReturnBreakpoint(self, addr):
        
        self.breakpointsReturn[addr] -= 1
        if self.breakpointsReturn[addr] == 0:
            self.breakpointsReturn.pop(addr)
            
    def removeBreakpointRange(self, addrStart, addrEnd):
        [breakpointRange for breakpointRange in self.breakpointRanges if not (breakpointRange.addrStart == addrStart and breakpointRange.addrEnd == addrEnd)]
        removedBr = None
        for i in range(len(self.breakpointRanges)):
            br = self.breakpointRanges[i] 
            if br.addrStart == addrStart and br.addrEnd == addrEnd:
                removedBr = br
                break
        
        if removedBr is not None:
            self.breakpointRanges = self.breakpointRanges[:i] + self.breakpointRanges[i+1:]
        return removedBr
            
    def hasBreakpoint(self, addr):
            
        if self.hasBreakpointRange(addr):
            return True
        
        return addr in self.breakpoints or addr in self.breakpointsInternal or addr in self.breakpointsReturn
    
    def hasBreakpointRange(self, addr):
        for bpr in self.breakpointRanges:
            if bpr.inRange(addr):
                return True
            
        return False
    
    def getBreakpoint(self, addr):
        if addr in self.breakpointsInternal:
            return self.breakpointsInternal[addr]
        
        if addr in self.breakpointsReturn:
            return self.breakpointsReturn[addr]
        
        if addr in self.breakpoints:
            return self.breakpoints[addr]
        
        for breakpointRange in self.breakpointRanges:
            if breakpointRange.inRange(addr):
                return breakpointRange
            
        return None
            
    def getOriginalBytesBreakpoint(self, addr):
        
        if addr in self.originalBytes:
            return self.originalBytes[addr]
        
        bp = self.getBreakpoint(addr)
        if bp is None or not isinstance(bp, _RangeBreakpoint):
            raise InvalidState()
         
        offset = addr - bp.startAddr
        return bp.originalBytes[offset:offset + self.sizeBreakpoint]
    
class Configuration:
    
    _SIGNALS_TO_PASS_DEFAULT = [GDB.SIGNAL.ALRM, GDB.SIGNAL.CHLD]
    
    def __init__(self, host, port, commandLine = None, pid = None, nonStopMode = False,  addrForkPointer = None, addrForkFunc = None, disableASLR = True, tryNoAckMode = True, signalsToPass = None):
        self.host = host
        self.port = port
        self.commandLine = commandLine
        self.pid = pid
        self.nonStopMode = nonStopMode
        self.addrForkPointer = addrForkPointer
        self.addrForkFunc = addrForkFunc
        self.disableASLR = disableASLR
        self.tryNoAckMode = tryNoAckMode
        self.signalsToPass = signalsToPass or self._SIGNALS_TO_PASS_DEFAULT
            
class PyGdb:
        
    # consts
    ## public
    class CONTINUE:
        RUN = 0
        RUN_NO_CLEANUP = 1 # should be used in case the pc was changed in the handler routine
        RUN_KEEP_BREAKPOINT = 2 # should be used in case pc wasn't moved but a possible breakpoint should be kept
        STOP = 3
    
    ## private
    _SIZE_RECV_BUFFER = 1024
    _SIZE_MEM_CACHE_UNIT = 256
    _TIME_CHUNK = 0.1
    _FEATURES = ["multiprocess"]
    
    _FORK_TRESHOLD = _TIME_CHUNK
    _EVEN_TIMEOUT = _TIME_CHUNK
    _KILL_TIMEOUT = _TIME_CHUNK*5
    
    class _DEFAULT_EXCEPTION_CALLBACKS:
        @staticmethod
        def _dispatchBp(pygdb, bp, event):
            if isinstance(bp, int):
                print "Wtf"
            if bp.callback is None:
                    howToContinue = pygdb.CONTINUE.RUN_NO_CLEANUP
            else:
                if bp.self0:
                    howToContinue = bp.callback(bp.self0, pygdb, event)
                else:
                    howToContinue = bp.callback(pygdb, event)
            # howToContinue not set? Set to default...
                if howToContinue is None:
                    howToContinue = pygdb.CONTINUE.RUN
                    
            if howToContinue == pygdb.CONTINUE.STOP:
                # make the debug-loop exit
                pygdb.goOn = False
            elif howToContinue == pygdb.CONTINUE.RUN_NO_CLEANUP or pygdb.getPC(event.tid) != event.addr:
                log(DEBUG_LEVEL.ALL, "[i] Continuing without cleaning-up after breakpoint handler returned. Event addr: %x, current pc: %x." % (event.addr, pygdb.getPC(event.tid)))
                # we kill all queued events for the corresponding thread, since they are outdated anyway for RUN_NO_CLEANUP
                pygdb.threads[event.tid].clearUnprocessedEvent()
                
            elif howToContinue == pygdb.CONTINUE.RUN:
                # re-step actual instruction
                # NOTE: We do not need to temporarly remove the current breakpoint, since PyGDB.stepInto() gently takes care of this for us.
                log(DEBUG_LEVEL.ALL, "[i] Cleaning-up after breakpoint handler returned before continuing.") 
                pygdb.stepInto(event.tid, True)
                
            elif howToContinue == pygdb.CONTINUE.RUN_KEEP_BREAKPOINT:
                # just as above, but we wann keep our breakpoint
                log(DEBUG_LEVEL.ALL, "[i] Cleaning-up after breakpoint handler returned before continuing (keeping breakpoint at pc-1).") 
                pygdb.stepInto(event.tid, True)
                # pygdb._setBreakpointRaw(event.addr, event._pid)
            else:
                raise NotImplemented
                   
        # GDB.SIGNAL.TRAP
        @staticmethod
        def trap(pygdb, event):
            if not hasattr(event, "pc"):
                # Gdbserver is sometimes so nice to give us x86 packets instead of x64. In this case, we manually update the event.
                event.pc = pygdb.getPC(event.tid)
                
            effectiveAddr = pygdb.cpu.getAddressBreakpoint(event.pc)
            # set pc back
            pygdb.setPC(effectiveAddr, event.tid)
            event.setAddress(effectiveAddr)
            log(DEBUG_LEVEL.SOME, "[e] Got signal at %x in thread %x." % (effectiveAddr, event.tid))
            
            """
            Internal breakpoints mask user breakpoints. This is not nice but necessary.
            """ 
            process = pygdb.processes[event._pid]
            bp = process.getBreakpoint(effectiveAddr)
            if bp is None:
                if effectiveAddr in process.removedBreakpoints:
                    # just adjust pc and continue
                    pygdb.setPC(effectiveAddr, event.tid)
                else:
                    log(DEBUG_LEVEL.IMPORTANT,"[i] Received trap signal at %x in thread %x that does not correspond to any breakpoint set by this PyGdb instance:" % (event.pc, event.tid))
                    raise InvalidState("Got unknown breakpoint event.")
                return
            
            PyGdb._DEFAULT_EXCEPTION_CALLBACKS._dispatchBp(pygdb, bp, event)  
        
        # GDB.SIGNAL.TERM
        @staticmethod
        def terminated(pygdb, event):
            # remove thread
            pygdb.threads.remove(event.tid)
            log(DEBUG_LEVEL.SOME,"[e] Thread %d terminated." % event.tid)
        
        # GDB.SIGNAL.ALRM
        @staticmethod
        def alarm(pygdb, event):    
            log(DEBUG_LEVEL.IMPORTANT, "[e] Alarm clock signal received for thread %x." % event.tid)
                
        # GDB.SIGNAL.INT
        @staticmethod
        def interrupt(pygdb, event):
            log(DEBUG_LEVEL.IMPORTANT, "[e] Interrupt signal received for thread %x." % event.tid)
            pygdb.goOn = False
                
        @staticmethod
        def illegalInstr(pygdb, event):
            log(DEBUG_LEVEL.IMPORTANT,"[e] Thread %x executed an illegal instruction." % event.tid)
        
        @staticmethod
        def segFault(pygdb, event):
            log(DEBUG_LEVEL.IMPORTANT, "[e] Thread %x seg-faulted at %x." % (event.tid, event.pc))
            pygdb.goOn = False
    ##
    
    def __init__(self, host, port, cpu, env = None, commandLine = None, pid = None, nonStopMode = False,  addrForkPointer = None, addrForkFunc = None, disableASLR = True, tryNoAckMode = True, signalsToPass = None):
        """
        Immediately connects to the given remote stub.
        @param host: The host to connect to.
        @param port: The port where GDB is listening.
        @param cpu: The cpu type.
        @param commandLine: [OPTIONAL] The command-line to start the debugee, if not given it is assumed that the remote stub is already attached to a debugee.
        @param pid: [OPTIONAL] The process id to attach to. 
        @param nonStopMode: [OPTIONAL] Flag indicating whether non-break mode should be used (TODO, not implemented yet). Default is false.
        @param addrForkPointer: [OPTIONAL] The address of a pointer to fork() (prefered over addrForkFunc since it is more accurate).
        @param addrForkFunc: [OPTIONAL] The address of fork() (or GetProcAddress() or whatsoever). Supplying this automatically enables fork-following. Should not be rebased.
        @param env: [OPTIONAL] The OS environment of the target. Default is POSIX. 
        @param disableASLR: [OPTIONAL] Tries to disable ASLR (turned on by default). Not included in gdbserver for Debian/Ubuntu, so its likely not supported on many platforms.
        @param passAlarmClockSignal: [OPTIONAL] Automatically pass annoying alarm-clock signals to the debugee.
        @param tryNoAckMode: [OPTIONAL] Tries to communicate with the remote stub in no-ack-mode which is by magnitudes faster. 
        """
        
        self.cpu = cpu
        self.exceptionHandlers = {}
        self.goOn = True
        self.dieOnProcessExit = False
        self.threadDebugLoop = None
        self.eventDebugLoopEntered = threading.Event()
        self.eventDebugeeRunning = threading.Event()
        self.eventProcessingEvent = threading.Event()
        self.useCacheForBreakpoints = False
        
        self.config = Configuration(host, port, commandLine, pid, nonStopMode,  addrForkPointer, addrForkFunc, disableASLR, tryNoAckMode, signalsToPass)
        
        # set-up default handlers
        self.registerExceptionHandler(GDB.SIGNAL.TRAP, self._DEFAULT_EXCEPTION_CALLBACKS.trap)
        self.registerExceptionHandler(GDB.SIGNAL.TERM, self._DEFAULT_EXCEPTION_CALLBACKS.terminated)
        self.registerExceptionHandler(GDB.SIGNAL.ALRM, self._DEFAULT_EXCEPTION_CALLBACKS.alarm)
        self.registerExceptionHandler(GDB.SIGNAL.INT, self._DEFAULT_EXCEPTION_CALLBACKS.interrupt)
        self.registerExceptionHandler(GDB.SIGNAL.ILL, self._DEFAULT_EXCEPTION_CALLBACKS.illegalInstr)
        self.registerExceptionHandler(GDB.SIGNAL.SEGV, self._DEFAULT_EXCEPTION_CALLBACKS.segFault)
        
        self._connect()
                
        if env is None:
            self.environment = environment.Posix()
        else:
            self.environment = env
        
        if self.config.addrForkPointer is not None or self.config.addrForkFunc is not None: 
            log(DEBUG_LEVEL.IMPORTANT, "[i] Follow-fork turned on.")
        else:
            log(DEBUG_LEVEL.IMPORTANT, "[!] Warning: No address of fork function specified. The debugger will not follow forks.")
            
        self._initProcess() # must be last
        
    def _connect(self):
        
        self.lastEventsProcessed = []
        self.eventsUnprocessed = [] 
        self.noAckMode = False # default
        
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.config.host, self.config.port))
        
        # start extended mode
        if self._sendCmdRespOK(GDB.CMD.ENABLE_EXTENDED_MODE):
            if DEBUG <= DEBUG_LEVEL.IMPORTANT:
                log(DEBUG_LEVEL.IMPORTANT, "[i] Connected to remote GDB server.")
                        
        if self.config.tryNoAckMode:
            # try to break ack mode
            if self._sendCmdRespOK(GDB.CMD.START_NO_ACK_MODE):
                if DEBUG <= DEBUG_LEVEL.ALL:
                    log(DEBUG_LEVEL.ALL, "[i] Turned no-ack-mode on.")
                self.noAckMode = True 
            else:
                self.noAckMode = False
        
        # Check features of remote stub.
        featuresremoteStub = self._exchangeFeatures(self._FEATURES)
        self._supportsReadThreads = GDB.CMD.XFER.READ_THREADS in featuresremoteStub
        suportedContinueModes = self.getSupportedContinueModes()
        log(DEBUG_LEVEL.ALL, "[i] The remote stub supports the following continue modes: %s" % suportedContinueModes)
        
        if not self._disableASLR(self.config.disableASLR):
            log(DEBUG_LEVEL.IMPORTANT, "[!] Failed to disable address-space randomization.")
            
        if self.config.commandLine is not None:
            # kill a probably already running debugee
            self.kill(GDB.THREADS.ALL)
            # start denbugee
            self.load(self.config.commandLine)
            
        elif self.config.pid is not None:
            self.kill(GDB.THREADS.ALL)
            self.attach(self.config.pid)
            
    def _initProcess(self):
        self.threads = {} # keys are (pid << SIZE_TID) | tid
        self.followedFork = False # will be set to true in case a fork is followed
        self.cmdContexts = {}
        
        if self._supportsReadThreads:
            self.initialPid, tid = self.getAllThreads()[0] # we just take the first process/thread
        else:
            initialEvent = self.getHaltingReason()
            # is this a legit first event?
            if initialEvent._pid is None or initialEvent._tid is None:
                self._sendCmdRaw(GDB.CMD.RESTART)
                initialEvent = self.getHaltingReason()
                if initialEvent._pid is None or initialEvent._tid is None:
                    raise InvalidState("Still did not get tid and pid after reset of debugee.")
                
            self.initialPid = initialEvent._pid
            tid = initialEvent._tid
        
        self.pid = self.initialPid # the primary pid
        self.initialPtid = self.environment.packThreadId(self.initialPid, tid)
        self.ptid = self.initialPtid
        
        self.processes = {self.pid:_Process(self.pid, self.cpu.getBreakpointKind())}
        self._setCmdThreadContext(self.initialPid, tid)
        
        if not self.passSignals(self.config.signalsToPass):
            log(DEBUG_LEVEL.IMPORTANT, "[!] Failed to make the remote stub pass signals.")
            
        self.addrForkFuncs = []
        addrForkFunc = None 
        self.addrForkPointer = None
        
        if self.config.addrForkPointer is not None:  
            self.addrForkPointer = self.environment.rebaseCodeAddr(self, self.config.addrForkPointer, self.pid)
        
        if self.config.addrForkFunc is not None:
            addrForkFunc = self.environment.rebaseCodeAddr(self, self.config.addrForkFunc, self.pid)
            
        elif self.addrForkPointer is not None:
            addrForkFunc = self.cpu.getPointerAt(self, self.addrForkPointer, self.pid)
        
        if addrForkFunc is not None:
            self.addrForkFuncs.append(addrForkFunc)
            self._setBreakpointInternal(addrForkFunc, self._FORK_HANDLER, pid=GDB.THREADS.ALL)
        else:
            log(DEBUG_LEVEL.IMPORTANT, "[i] Could not determine address of fork() (or the targets system's equivalent). Debugger will not follow forks.")
                          
    @staticmethod
    def _FORK_HANDLER(self, event):
        """
        Static handler for forks.
        """
        MAX_TRIES_STOP = 5
        
        log(DEBUG_LEVEL.SOME, "[i] Debugee is about to fork.")
        
        pid, tid = self.environment.unpackThreadId(event.tid)
        self._setCmdThreadContext(pid, tid)
        
        # write looping instruction to fork's return address
        retAddr = self.cpu.getFunctionReturnAddress(self, event.tid)
        jmpPC = self.cpu.getOpcodeJmpPC()
        origBytes = self.readMemory(retAddr, len(jmpPC), False, pid=pid)
        self.writeMemory(retAddr, jmpPC, pid=pid)
                
        # single-step over the breakpoint
        self.stepOver(event.tid)
        
        tries = 0
        while tries < MAX_TRIES_STOP:
            tries += 1
            # continue the father process
            self._cont(event.tid)
            
            # stop the father process
            time.sleep(self._FORK_TRESHOLD)
            self.stopThread(event.tid)
                
            stopAddr = self.getPC(event.tid)
            if stopAddr != retAddr:
                log(DEBUG_LEVEL.ALL, "[i] Thread %x standing now at %x, should be %x. Continuing..." % (event.tid, stopAddr, retAddr))
                continue
            
            log(DEBUG_LEVEL.ALL, "[i] Thread %x standing now at correct return-address at %x." % (event.tid, stopAddr))
            break
            
            
        if tries == MAX_TRIES_STOP:
            log(DEBUG_LEVEL.IMPORTANT, "[e] Failed to stop forking process. Maybe it is dead. Quitting...")
            return self.CONTINUE.STOP     
            
            
        pidFork = self.environment.getForkProcessId(self, event.tid)
        log(DEBUG_LEVEL.IMPORTANT, "[i] Debugee forked to process %x. About to follow it." % pidFork)
        
        
        # clone the father process; we need to make a deep-copy here, because we need to have our own breakpoint lists etc (since bp lists are not static)
        oldProcess = self.processes[pid]
        newProcess = copy.deepcopy(oldProcess)
        newProcess.setFather(oldProcess)
            
        # now fix the father process
        self.writeMemory(retAddr, origBytes, pid=pid)
        self.setPC(retAddr, event.tid)
        
        # finally attach to newly created child process.
        if self.attach(pidFork):
            log(DEBUG_LEVEL.IMPORTANT, "[i] Successfully attached to forked process.")
        else:
            log(DEBUG_LEVEL.IMPORTANT, "[!] Failed to attach to new fork. Maybe PyGdb._FORK_TRESHOLD is too low?")
            raise CouldNotFollowFork()
        
        # never move this
        tidFork = self.getCurrentThreadId()[1]
        
        """
        PLEASE NOTE: The following call to getBaseAddrCode is important in order to make the environment cache the base address. 
        Otherwise attempts to rebase addresses will fail after the process died. The tracer.Tracer class does this for example.
        """
        
        self.pid = pidFork
        self.ptid = self.environment.packThreadId(pidFork, tidFork)
        
        # adjust the clone
        newProcess.pid = pidFork
        self.processes[pidFork] = newProcess
        
        # fix the child process
        self._setCmdThreadContext(pidFork, tidFork)
        self.writeMemory(retAddr, origBytes)
        self.setPC(retAddr, self.ptid)
        if not self.passSignals(self.config.signalsToPass):
                log(DEBUG_LEVEL.IMPORTANT, "[!] Failed to make the remote stub pass signals.")
                        
        # check if in the current environment a child automatically inherits all breakpoints from its father
        if not self.environment.forkInheritsBreakpoints():
            # if not set them manually
            for addr in newProcess.breakpoints:
                self._setBreakpointRaw(addr, pidFork)
            for addr in newProcess.breakpointsInternal:
                self._setBreakpointRaw(addr, pidFork)
            for bpRange in newProcess.breakpointRanges:
                self._setBreakpointRangeRaw(bpRange)
            
        self.followedFork = True
        
        # finally check if the pointer to fork() changed
        if self.addrForkPointer is not None:
            newAddrForkFunc = self.cpu.getPointerAt(self, self.addrForkPointer, oldProcess.pid)
            if newAddrForkFunc not in self.addrForkFuncs:
                log(DEBUG_LEVEL.SOME, "[i] Adding new fork() address %x." % newAddrForkFunc)
                self.addrForkFuncs.append(newAddrForkFunc)
                self._setBreakpointInternal(newAddrForkFunc, self._FORK_HANDLER, pid=GDB.THREADS.ALL)
        
        log(DEBUG_LEVEL.ALL, "[i] Finished following fork (%x to %x)." % (pid, pidFork))
        return self.CONTINUE.RUN_NO_CLEANUP
             
    def _sendRaw(self, data):
        log(DEBUG_LEVEL.ALL, "[e] Sending: " + data)
        result = self.s.send(data) 
        return result
    
    def _recvRaw(self, buffSize):
        data = self.s.recv(buffSize)    
        log(DEBUG_LEVEL.ALL, "[e] Received: " + data)   
        return data
    
    def _sendAck(self):
        if not self.noAckMode:
            self._sendRaw(GDB.ACK)
            
    def _acquireLockIO(self):
        self.lockIO.acquire(True)
    
    def _releaseLockIO(self):
        self.lockIO.release
        
    def _recvRespRaw(self):
        resp = self._recvRaw(PyGdb._SIZE_RECV_BUFFER)
        while not GDB.validateMessage(resp):
            tmp = self._recvRaw(PyGdb._SIZE_RECV_BUFFER)
            if len(tmp) == 0:
                return None
            resp += tmp
            
        self._sendAck()
        if len(resp) < GDB.MIN_LEN_RESPONSE:
            return resp
        
        return GDB.decodeBinaryString(resp[1:-3]) 
            
    def _sendCmdRaw(self, cmd, prependInterrupt=False):
        cmdString = prependInterrupt and GDB.CMD.INTERRUPT or "" + GDB.CMD_FORMAT % (cmd, GDB.calcChecksum(cmd))    
        self._sendRaw(cmdString)
        
        # receive ack
        if not self.noAckMode:
            if self._recvRaw(len(GDB.ACK)) != GDB.ACK:
                return False
        
        return True
    
    def _sendCmdRespOK(self, cmd):
        if not self._sendCmdRaw(cmd):
            return False
            
        resp = self._recvRespRaw()
        if resp != GDB.RESPONSE.OK:
            return False
        
        return True
                 
    def _getNextDebugEvent(self, timeout=None):
        """
        Gets the next yet unprocessed debug-event. Can be used in blocking (default) or non blocking mode.
        @param timeout: [OPTIONAL] Timeout for the corresponding recv() operation. 'None' means 'blocking'.
        @return: An object of type Event in case any events are waiting. None in the opposite case. 
        """
        event = self._readDebugEvent(timeout)
        if event is not None:
            return event
       
        return self._unqueueEvent()
        
    def _readDebugEvent(self, timeout=None):
        """
        Reads the next debug-event from the control socket.
        @param timeout: [OPTIONAL] Timeout for the corresponding recv() operation. 'None' means 'blocking'.
        @return: An object of type Event on success. None in any other case. 
        """
        self.s.settimeout(timeout)
        while True:
            try:
                resp = self._recvRespRaw()
            except: #NOTE: This is dirty but apparently necessary in order to catch socket errors in python 
                self.s.settimeout(None)
                return None
            else:
                if len(resp) > 0:
                    break 
        
        log(DEBUG_LEVEL.ALL, "[e] Received raw debug event: %s" % resp)
        
        # clear the corresponding event
        self.eventDebugeeRunning.clear()
        
        # flush the cmd context
        self._flushCmdThreadContexts()
            
        # reset to blocking
        if timeout is not None:
            self.s.settimeout(None)
        
        e = Event(resp, self.cpu, self.environment)
        if e.tid is not None:
            self.ptid = e.tid
                
        return e
    
    def _waitForParticularSignal(self, signalType, tid, pcRange = None, timeout=None):
        """
        Waits out-of-band for a particular signal. Should only be used in rare cases (like follow-fork). If used uncautiously, this can very well break your debugging session.
        @param signalType: The type of signal to wait for.
        @param tid: The thread to evaluate.
        @param pcRange: [OPTIONAL] A tuple of addresses between which the signal has to occur. If not specified every address will be considered as match.
        @param timeout: [OPTIONAL] Timeout for waiting for debug-events.
        @return: Flag indicating success. 
        """
        firstRound = True
        while firstRound or self.goOn:
            if firstRound:
                firstRound = False
            else:
                self._cont(tid)
            e = self._readDebugEvent(timeout)
            if e is None:
                return False
            # is this the event we're looking for?
            if (e.type == GDB.RESPONSE.STOP.SIGNAL_SHORT or e.type == GDB.RESPONSE.STOP.SIGNAL) and (e.tid == tid or tid == GDB.THREADS.ALL or tid == GDB.THREADS.ANY):
                if e.signalType == signalType:
                    if pcRange is None:
                        return True
                    else:
                        if e.pc >= pcRange[0] and e.addr <= pcRange[1]:
                            return True
            # if the exception did not match, add it to list of unprocessed events.
            self._processDebugEvent(e)
            
        return False
            
    def _processDebugEvent(self, event):
        
        self.eventProcessingEvent.set()
        
        eventHandled = False
    
        if event.isProcessBound:
            self.pid = event._pid
            self.ptid = event.tid
            
            # check if thread is already known
            if event.isThreadBound:
                if event.tid not in self.threads:
                    self.threads[event.tid] = _Thread(event.tid)

        else:
            log(DEBUG_LEVEL.SOME, "[e] Received a global debug event.")
            
        
        if event.type == GDB.RESPONSE.STOP.SIGNAL_SHORT or event.type == GDB.RESPONSE.STOP.SIGNAL:
            
            # check for registered exception handlers
            if event.signalType in self.exceptionHandlers:
                for handler in self.exceptionHandlers[event.signalType]:
                    if handler.fullRange:
                        handler.callback(self, event)
                        eventHandled = True
                    elif event.pc >= handler.addrMin and event.pc <= handler.addrMax:
                        handler.callback(self, event)
                        eventHandled = True
                    else:
                        log(DEBUG_LEVEL.IMPORTANT, "[e] No handler installed for received exception of type %x. Continuing anyway ...")
                        eventHandled = True
                          
        elif event.type == GDB.RESPONSE.STOP.EXIT:
            log(DEBUG_LEVEL.IMPORTANT, "[e] Process %x exited." % event._pid)
            # delete the process
            self.processes.pop(event._pid)
            # delete all corresponding threads
            self.threads = {ptid:self.threads[ptid] for ptid in self.threads if (self.environment.unpackThreadId(ptid)[0] != event._pid)}
            # are there still processes left?
            
            if self.dieOnProcessExit:
                return False
            
            if len(self.processes) != 0:
                eventHandled = True
                self.ptid = self.threads.keys()[-1]
                self.pid = self.environment.unpackThreadId(self.ptid)[0]
                # set the new process context
                self._setCmdThreadContext(pid=self.pid)
            
        elif event.type == GDB.RESPONSE.STOP.TERMINATE:
            log(DEBUG_LEVEL.IMPORTANT, "[e] Process %d terminated." % event.tid)
            self.threads.pop(event.tid)
            if len(self.threads) != 0:
                eventHandled = True
                if self.ptid == event.tid:
                    self.ptid = self.threads.keys()[-1]
            
        elif event.type == GDB.RESPONSE.STOP.SYSCALL:
            log(DEBUG_LEVEL.IMPORTANT, "[e] Got a syscall exception.")
            
        if eventHandled:
                self.lastEventsProcessed.append(event)
        
        self.eventProcessingEvent.clear()
        return eventHandled
    
    def _debugLoop(self):
        
        # the main loop
        debugeeAlive = True
        firstLoop = True
        while debugeeAlive and self.goOn:
            if firstLoop:
                self.eventDebugLoopEntered.set()
                firstLoop = False
            
            debugEvent = self._getNextDebugEvent(timeout=0)
            if debugEvent is None: 
              
                if len(self.lastEventsProcessed) != 0: 
                    lastEvent = self.lastEventsProcessed.pop()
                    if lastEvent.tid is not None:
                        # resume the thread the last event occured in
                        self._cont(lastEvent.tid)
                    else:
                        # looks like the last event was a global one -> resume everything
                        self._cont()
                
                debugEvent = self._getNextDebugEvent()
                
            log(DEBUG_LEVEL.ALL, "[e] Going to process debugging event of type %s in central debugging loop." % debugEvent.type)
            debugeeAlive = self._processDebugEvent(debugEvent)
            
        log(DEBUG_LEVEL.IMPORTANT, "[e] Leaving the debug-loop. Debugee alive: %s, go-on: %s" % (str(debugeeAlive), str(self.goOn)))
            
    def _updateThread(self, thread):
        if thread.registersChanged:
            self._setRegistersRaw(thread.tid, thread.getRegisters())
            
    def _cont(self, tid=GDB.THREADS.ALL):
        # legacy method
        self._resume(GDB.CMD.VCONT.CONTINUE, tid)
            
    def _singlestep(self, packedTid):
        if packedTid not in self.threads:
            raise InvalidThread()
        
        pid, tid = self.environment.unpackThreadId(packedTid)
        nativeSingleStep = self.cpu.supportsNativeSingleStep()
        
        if nativeSingleStep:
            # issue singlestep for given thread
            contAction = GDB.CMD.VCONT.STEP
        else:
            nextPc = self.cpu.getNextPC(self, packedTid)
            pc = self.getPC(packedTid)
            log(DEBUG_LEVEL.ALL, "[i] Performing manual single-step in thread %x at %x. Next instruction is at %x." % (packedTid, pc, nextPc))
            bpAlreadyPresent = self.processes[pid].hasBreakpoint(nextPc)
            if not bpAlreadyPresent:
                self.setBreakpoint(nextPc, pid=pid)    
            contAction = GDB.CMD.VCONT.CONTINUE
        
        # check thread's registers for changes
        self._resume(contAction, packedTid)
            
        """
        Now we continue the debugees until we get the desired single-step/bp exception in the desired thread.
        Note that we are in sort of a bad situation here, since we cannot distinguish between single-step and bp events :<
        So we do not handle single-step/bp exceptions and only queue events different from these. 
        """
        while True:
            event = self._readDebugEvent()
            queueEvent = True
            correctEvent = False
            if event.signalType == GDB.SIGNAL.TRAP:
                if not nativeSingleStep:
                    event.setAddress(self.cpu.getAddressBreakpoint(event.pc))
                
                    if event.pid == pid:
                        if event.addr == nextPc:
                            if not bpAlreadyPresent: 
                                queueEvent = False
                            
                            if event._tid == tid: 
                                correctEvent = True
                                
                elif event.tid == packedTid:
                    correctEvent = True
                    queueEvent = False
            
            if queueEvent:
                if not nativeSingleStep:
                    log(DEBUG_LEVEL.IMPORTANT, "[i] Queuing an event at %x (expected %x) in thread %x (expected thread %x) for later processing while doing a single-step." % (event.addr, nextPc, event.tid, packedTid))
                else:
                    log(DEBUG_LEVEL.IMPORTANT, "[i] Queuing an event at %x in thread %x (expected thread %x) for later processing while doing a single-step." % (event.addr, event.tid, packedTid))
                log(DEBUG_LEVEL.IMPORTANT, "\t%s" % str(event))
                self._queueEvent(event)
             
            if correctEvent:
                break
            
            log(DEBUG_LEVEL.ALL, "[i] Did not get the desired event while single-stepping. Continuing...")
            self._cont(packedTid)
        
        if not nativeSingleStep and not bpAlreadyPresent:
            self.removeBreakpoint(nextPc, pid)
            
        log(DEBUG_LEVEL.ALL, "[i] Successfully single-stepped to %x." % event.pc)
        
    def _queueEvent(self, event):
        self.threads[event.tid].pushUnprocessedEvent(event)
        
    def _unqueueEvent(self):
        for thread in self.threads.values():
            event = thread.popUnprocessedEvent()
            if event is not None:
                return event
            
        return None
        
    def _resumeRaw(self, action, packedTid):
        pid, tid = self.environment.unpackThreadId(packedTid)
        """
        REMOVED FOR TESTING PURPOSES, TODO: reintroduce properly
        if pid == -1:
            for p in self.processes:
                self._sendCmdRaw(GDB.CMD.VCONT.PREFIX + (GDB.ARGUMENT % action + ":" + GDB.THREAD_MULTI_PROCESS % (p,-1)))
        else:
            self._sendCmdRaw(GDB.CMD.VCONT.PREFIX + (GDB.ARGUMENT % action + ":" + GDB.THREAD_MULTI_PROCESS % (pid,tid)))
        """
        if action == GDB.CMD.VCONT.STEP:
            #log(DEBUG_LEVEL.SOME, "[i] Single-stepping debugee at %x." % self.getPC(packedTid))
            self._sendCmdRaw(GDB.CMD.VCONT.PREFIX + (GDB.ARGUMENT % action + ":" + GDB.THREAD_MULTI_PROCESS % (pid,tid)))
        else:
            #log(DEBUG_LEVEL.SOME, "[i] Continuing debugee at %x." % self.pid)
            self._sendCmdRaw(GDB.CMD.VCONT.PREFIX + (GDB.ARGUMENT % action))
            
        # set debugee running event
        self.eventDebugeeRunning.set()
            
    def _resume(self, action, packedTid):
        
        if packedTid == GDB.THREADS.ALL or not self.config.nonStopMode:
            # resume everything
            # update all threads registers
            for thread in self.threads.values():
                self._updateThread(thread)
                thread.reset()
                
        elif packedTid in self.threads:
            # update thread's registers for changes
                thread = self.threads[packedTid]
                self._updateThread(thread)
                thread.reset()
        else:
            raise InvalidThread()
        
        self._resumeRaw(action, packedTid)
        
    def _setBreakpointRaw(self, addr, pid):
        
        log(DEBUG_LEVEL.SOME, "[i] Going to set a breakpoint at %x in process %x." % (addr, pid))
        self._setCmdThreadContext(pid=pid)
        process = self.processes[pid]
        opBp = self.cpu.getOpcodeBreakpoint()
        # get original bytes
        if addr not in process.originalBytes:
            opOrig = self.readMemory(addr, len(opBp), cache=self.useCacheForBreakpoints, pid=pid, fetchLargerRegion=self.useCacheForBreakpoints)
            if opOrig is None:
                return False
            process.originalBytes[addr] = opOrig
            
        opOrig = process.originalBytes[addr]
        return self.writeMemory(addr, opBp, pid)
    
    def _removeBreakpointRaw(self, addr, pid):
        log(DEBUG_LEVEL.SOME, "[i] Going to remove a breakpoint at %x in process %x." % (addr, pid))
        self._setCmdThreadContext(pid=pid)
        opOrig = self.processes[pid].getOriginalBytesBreakpoint(addr)
        return self.writeMemory(addr, opOrig, pid)
    
    def _flushCmdThreadContexts(self):
        self.cmdContexts = {}
        
    def _setCmdThreadContext(self, pid, tid=GDB.THREADS.ANY, flush=False):
        
        """
        if pid == GDB.THREADS.ALL:
            log(DEBUG_LEVEL.IMPORTANT, "[!] Invalid attempt to change process context to -1.")
            return False
        """
        if flush:
            self._flushCmdThreadContexts()
        cmd = "g"
        t = (pid, tid)
        if cmd in self.cmdContexts:
            if (tid == GDB.THREADS.ANY and self.cmdContexts[cmd][0] == pid) or (self.cmdContexts[cmd] == t):
                return True
        
        self.cmdContexts[cmd] = t
            
        thread = GDB.THREAD_MULTI_PROCESS % t            
        if not self._sendCmdRespOK(GDB.CMD.SET_CMD_THREAD_CONTEXT % (cmd, thread)):
            log(DEBUG_LEVEL.IMPORTANT, "[!] Failed to set context for succeeding operation %s." % cmd)
            return False

        return True
    
    def _getRegistersRaw(self, tid):
        (_pid, _tid) = self.environment.unpackThreadId(tid)
        self._setCmdThreadContext(_pid, _tid)
        self._sendCmdRaw(GDB.CMD.READ_REGISTERS)
        tmp = self._recvRespRaw()
        resp = GDB.uncompressString(tmp) 
        
        log(DEBUG_LEVEL.ALL, "[i] Got the following compressed register string: %s" % tmp)
        log(DEBUG_LEVEL.ALL, "[i] Uncompressed the following register string: %s" % resp)
            
        return resp    
    
    def _setRegister(self, thread, regId, value):
        registers = self.getRegisters(thread)
        if registers[regId] != value:
            registers[regId] = value
            self.setRegisters(registers, thread)    
        
    def _setRegistersRaw(self, tid, values):
        (_pid, _tid) = self.environment.unpackThreadId(tid)
        self._setCmdThreadContext(_pid, _tid)
        
        regString = ""
        for value in values:
            regString += self.cpu.toRegisterHexString(value)
            
        self._sendCmdRespOK(GDB.CMD.WRITE_REGISTERS % regString)
        
    def _registerExceptionHandler(self, handler):
        if handler.exception not in self.exceptionHandlers:
            self.exceptionHandlers[handler.exception] = []
            
        self.exceptionHandlers[handler.exception].append(handler)
        
    def _readMemory(self, addr, size, pid):
        self._setCmdThreadContext(pid=pid)
        self._sendCmdRaw(GDB.CMD.READ_MEMORY % (addr, size))
        log(DEBUG_LEVEL.SOME, "[i] Requested %d bytes from %x." % (size, addr))
        resp = self._recvRespRaw()
        if len(resp) == GDB.LEN_ERROR_MSG:
            if resp[0] == GDB.RESPONSE.ERROR:
                log(DEBUG_LEVEL.IMPORTANT, "[!] Failed to read %d bytes from %x." % (size, addr))
                return None
        tmp = GDB.uncompressString(resp)
        log(DEBUG_LEVEL.SOME, "[i] Got %d bytes from %x after decompressing." % (len(tmp), addr))
        return tmp.decode("hex")
    
    def _flushCaches(self):
        if DEBUG == DEBUG_LEVEL.ALL:
            print "[i] Flushing caches."
        for thread in self.threads.values():
            thread.reset()
            
        for p in self.processes.values():
            p.flushMemCache()
        
    def _setBreakpointInternal(self, addr, callback=None, self0=None, pid=GDB.THREADS.ANY):
        """
        Sets a breakpoint.
        @param addr: The address to set the breakpoint at (needs to be already rebased). You can use pygdb.environment.rebaseCodeAddr() to rebase an address.
        @param callback: [OPTIONAL] A callback that should be called in case the breakpoint is hit. Note: This only makes sense in blocking-mode where pygdb.start() was called.
        @param self0: [OPTIONAL] Argument to pass to the given callback function as 'self' object.
        @param pid: [OPTIONAL] The process to set this breakpoint in. Default is GDB.THREADS.ALL.  
        """
        pids = self._getEffectivePids(pid)
        bp = _Breakpoint(callback, self0)
        worked = True
        for p in pids:
            if not self._setBreakpointRaw(addr, p):
                worked = False
            self.processes[p].addBreakpoint(addr, bp, internal=True)
        return worked
    
    def _removeBreakpointInternal(self, addr, pid=GDB.THREADS.ANY):
        pids = self._getEffectivePids(pid)
        worked = True
        for p in pids:
            process = self.processes[p] 
            process.removeBreakpoint(addr, internal=True)
            if not process.hasBreakpoint(addr):
                if not self._removeBreakpointRaw(addr, p):
                    worked = False 
        return worked
    
    def _exchangeFeatures(self, ownFeatures):
        if len(ownFeatures) > 0:
            cmd = GDB.CMD.SUPPORTED_FEATURES + GDB.FIRST_ARGUMENT % ownFeatures[0] + "+"
            for feature in ownFeatures[1:]:
                cmd += GDB.ARGUMENT % feature + "+"
                
            self._sendCmdRaw(cmd)
            resp = self._recvRespRaw()
            log(DEBUG_LEVEL.ALL, "[i] The remote stub supports: %s" % resp)
            return resp
        
    def _disableASLR(self, disable):
        v = disable and 1 or 0
        return self._sendCmdRespOK(GDB.CMD.DISABLE_ASLR % v)
    
    def _enableNonStopMode(self):
        """
        Only experimental.
        """
        self._sendCmdRespOK(GDB.CMD.ENABLE_NON_STOP_MODE)
        
    def _readXfer(self, cmd):
        resp = ""
        while True:
            self._sendCmdRaw(cmd % (len(resp), self._SIZE_RECV_BUFFER))
            r = self._recvRespRaw()
            if len(r) == 0:
                raise InvalidState("Got a response of zero size from the remote-side in reaction to an xfer query.")
            resp += r[1:]
            if r[0] == GDB.RESPONSE.RAW_DATA.LAST_PACKET:
                break
            
            if r[0] != GDB.RESPONSE.RAW_DATA.MORE_TO_COME:
                raise InvalidState("Got unexpected response while reading xfer data: %s. You should maybe restart your remote gdbserver." % r)
        return resp
    
    def _translateBreakpoints(self, breakpoints, oldBaseAddr, newBaseAddr, pid):
        """
        Translates a given dictionary of breakpoints. Resets breakpoints at new addresses.
        @param breakpoints: The dictionary to translate.
        @param oldBaseAddr: The old base address
        @param newBaseAddr: The new base address
        @param pid: The pid of the process to translate the breakpoints for.
        @return: The translated dictionary.
        """
        newBreakpoints = {}
        for oldAddr in breakpoints:
            newAddr = oldAddr - oldBaseAddr + newBaseAddr
            self._setBreakpointRaw(newAddr, pid)
            newBreakpoints[newAddr] = breakpoints[oldAddr]
            
        return newBreakpoints
    
    def _translateBreakpointRanges(self, breakpointRanges, oldBaseAddr, newBaseAddr, pid):
        
        newBprs = []
        for oldBpr in breakpointRanges:
            bpr = copy.copy(oldBpr)
            bpr.addrStart = bpr.addrStart - oldBaseAddr + newBaseAddr
            bpr.addrEnd = bpr.addrEnd - oldBaseAddr + newBaseAddr
            self._setBreakpointRangeRaw(bpr, pid)
            newBprs.append(bpr)
            
        return newBprs
    
    def _getEffectivePids(self, pid):
        if pid == GDB.THREADS.ANY:
            pids = [self.pid]
        elif pid == GDB.THREADS.ALL:
            pids = self.processes.keys()
        else:
            pids = [pid]
            
        return pids
    
    def _dumpPCContext(self, tid):
        pid = self.environment.unpackThreadId(tid)[0]
        return self.readMemory(self.getPC(tid)-20, 40, pid=pid).encode("hex")
    
    def getSupportedContinueModes(self):
        self._sendCmdRaw(GDB.CMD.GET_SUPPORTED_CONTINUE_MODES)
        return self._recvRespRaw()

    ## the API
    def setRegisters(self, values, tid = GDB.THREADS.ANY):
        tid = tid == GDB.THREADS.ANY and self.ptid or tid
        if not tid in self.threads:
            raise InvalidThread()
        
        self.threads[tid].setRegisters(values)
    
    def getRegisters(self, tid = GDB.THREADS.ANY):
        # first check if we have already cached registers
        tid = tid == GDB.THREADS.ANY and self.ptid or tid
        if tid in self.threads:
            registers = self.threads[tid].getRegisters()
            if len(registers) > 0:
                return registers
            
        resp = self._getRegistersRaw(tid)          
        registers = []
        registerWidth = self.cpu.getNativeRegisterWidth()
        registerChars = registerWidth/8*2
        for i in range(len(resp)/registerChars):
            tmp = resp[i*registerChars:(i+1)*registerChars]
            registers.append(self.cpu.registerHexStringToValue(tmp))
            
        # cache registers
        if not tid in self.threads:
            self.threads[tid] = _Thread(tid)
            
        self.threads[tid].setRegisters(registers, False)  
        return registers       
    
    def getRegister(self, regName, tid = GDB.THREADS.ANY):
        regId = self.cpu.getBasicRegisterIndex(regName)
        return self.getRegisterIndex(regId, tid)
    
    def getRegisterIndex(self, regIndex, tid = GDB.THREADS.ANY):
        regs = self.getRegisters(tid)
        return regs[regIndex]
              
    def enableCacheForBreakpoints(self, enable):
        """
        Enables caching for breakpoints. May improve speed when a larger amount of breakpoints is to be set. Will make trouble in case of self-modifying code.
        @param enable: Boolean flag indicating whether or not to use caching for breakpoints.
        """
        self.useCacheForBreakpoints = enable      
          
    def setBreakpoint(self, addr, callback=None, self0=None, pid=GDB.THREADS.ALL):
        """
        Sets a breakpoint.
        @param addr: The address to set the breakpoint at (needs to be already rebased). You can use pygdb.environment.rebaseCodeAddr() to rebase an address.
        @param callback: [OPTIONAL] A callback that should be called in case the breakpoint is hit. Note: This only makes sense in blocking-mode where pygdb.start() was called.
        @param self0: [OPTIONAL] Argument to pass to the given callback function as 'self' object.
        @param pid: [OPTIONAL] The process to set this breakpoint in. Default is GDB.THREADS.ALL.  
        @return: Boolean value indication success.
        """
        pids = self._getEffectivePids(pid)    
        worked = True
        bp = _Breakpoint(callback, self0)
        for p in pids:
            worked = worked and self._setBreakpointRaw(addr, p)
            self.processes[p].addBreakpoint(addr, bp)
        return worked
    
    def setBreakpoints(self, addresses, callback=None, self0=None, pid=GDB.THREADS.ALL):
        """
        Traffic-optimized version of setBreakpoint for setting multiple breakpoints with same handler (reduces the amount of process-switches).
        @param addresses: List of addresses to set a breakpoint at.
        @param callback: [OPTIONAL] A callback that should be called in case the breakpoint is hit. Note: This only makes sense in blocking-mode where pygdb.start() was called.
        @param self0: [OPTIONAL] Argument to pass to the given callback function as 'self' object.
        @param pid: [OPTIONAL] The process to set this breakpoint in. Default is GDB.THREADS.ALL. 
        """
        pids = self._getEffectivePids(pid)    
        worked = True
        bp = _Breakpoint(callback, self0)
        for p in pids:
            for addr in addresses:
                if not self._setBreakpointRaw(addr, p):
                    worked = False
                self.processes[p].addBreakpoint(addr, bp)
        return worked
    
    def _discardAllPendingDebugEvents(self):
        while True:
            event = self._getNextDebugEvent(timeout=0)
            if event is None:
                break
            
            log(DEBUG_LEVEL.IMPORTANT, "[i] Discarded debug-event: " + str(event))
            
    def _getBreakpointAddressesRange(self, addrStart, addrEnd):
    
        sizeBp = self.cpu.getBreakpointKind()
        addresses = range(addrStart, addrEnd)[::sizeBp]
        return addresses
    
    def setBreakpointRange(self, addrStart, addrEnd, callback=None, self0=None, pid=GDB.THREADS.ALL):
        """
        Overwrites the entire given region with breakpoints.
        @param addrStart: The start address of the region to set breakpoints in (needs to be already rebased). You can use pygdb.environment.rebaseCodeAddr() to rebase an address.
        @param addrEnd: The end address of the region to set breakpoints in (needs to be already rebased). You can use pygdb.environment.rebaseCodeAddr() to rebase an address.
        @param callback: [OPTIONAL] A callback that should be called in case the breakpoint is hit. Note: This only makes sense in blocking-mode where pygdb.start() was called.
        @param self0: [OPTIONAL] Argument to pass to the given callback function as 'self' object.
        @param pid: [OPTIONAL] The process to set this breakpoint in. Default is GDB.THREADS.ALL. 
        """
        pids = self._getEffectivePids(pid)
        success = True
        for p in pids:
            bpr = _RangeBreakpoint(addrStart, addrEnd, callback, self0)
            success = self._setBreakpointRangeRaw(bpr, p) and success
            self.processes[p].addBreakpointRange(bpr)
        return success
    
    def _setBreakpointRangeRaw(self, bpr, pid):
        
        log(DEBUG_LEVEL.SOME, "[i] Going to set a range breakpoint from %x to %x in process %x." % (bpr.addrStart, bpr.addrEnd, pid))
        sizeRange = bpr.addrEnd - bpr.addrStart
        origMem = self.readMemory(bpr.addrStart, sizeRange, pid=pid)
        bpr.setOriginalBytes(origMem)
        opcodeBp = self.cpu.getOpcodeBreakpoint()
        newMem = (sizeRange // len(opcodeBp))*opcodeBp
        if not self.writeMemory(bpr.addrStart, newMem, pid):
            log(DEBUG_LEVEL.IMPORTANT, "[e] Failed to overwrite range (%x,%x) with breakpoints." % (bpr.addrStart, bpr.addrEnd))
            return False
        return True
        
    def removeBreakpoints(self, addresses, pid=GDB.THREADS.ALL, bpCallback=None):
        """
        Traffic-optimized version of removeBreakpoint for removing multiple breakpoints with same handler (reduces the amount of process-switches).
        @param addresses: List of addresses to set a breakpoint at.
        @param bpCallback: [OPTIONAL] If given, each breakpoint is only removed for the given handler.
        @param pid: [OPTIONAL] The process to remove breakpoints from. Default is GDB.THREADS.ALL. 
        """
        pids = self._getEffectivePids(pid)    
        worked = True
        for p in pids:
            for addr in addresses:
                if not self.processes[p].removeBreakpoint(addr, bpCallback=bpCallback):
                    continue
                if not self._removeBreakpointRaw(addr, p):
                    worked = False
        return worked
        
    def removeBreakpoint(self, addr, pid=GDB.THREADS.ALL, bpCallback=None):
        """
        Removes a breakpoint.
        @param addr: The address of the breakpoint to remove.
        @param pid: [OPTIONAL] The process to remove this breakpoint from. Default is GDB.THREADS.ALL.
        @param bpCallback: [OPTIONAL] If given, each breakpoint is only removed for the given handler.
        """
        pids = self._getEffectivePids(pid)
        worked = True
        for p in pids:
            process = self.processes[p] 
            if not process.removeBreakpoint(addr, bpCallback=bpCallback):
                continue
            if not process.hasBreakpoint(addr):
                if not self._removeBreakpointRaw(addr, p):
                    worked = False 
        return worked
    
    def removeBreakpointRange(self, addrStart, addrEnd, pid=GDB.THREADS.ALL, bpCallback=None):
        """
        Removes all breakpoints in the range between the given start and end address (rebased).
        @param addrStart: The start address of the region.
        @param addrEnd: The end address of the region.
        @param bpCallback: [OPTIONAL] If given, each breakpoint is only removed for the given handler.
        @param pid: [OPTIONAL] The process to remove breakpoints from. Default is GDB.THREADS.ALL.
        """
        log(DEBUG_LEVEL.SOME, "[i] Going to remove the range breakpoint from %x to %x in process %x." % (addrStart, addrEnd, pid))
        pids = self._getEffectivePids(pid)
        for p in pids:
            bpr = self.processes[p].removeBreakpointRange(addrStart, addrEnd)
            if bpr is None:
                continue
            
            if not self.writeMemory(addrStart, bpr.originalBytes, p):
                log(DEBUG_LEVEL.IMPORTANT, "[e] Failed to restore breakpoint range (%x,%x)." % (addrStart, addrEnd))
        
        return True
    
    def setPC(self, addr, tid=GDB.THREADS.ANY):
        regId = self.cpu.getPcIndex()
        self._setRegister(tid, regId, addr)
        
    def getPC(self, tid=GDB.THREADS.ANY):
        # TODO: Proper default tid!! Doesn't work like this.
        regId = self.cpu.getPcIndex()
        return self.getRegisters(tid)[regId]
    
    def setRegister(self, thread, regName, value):
        regId = self.cpu.getBasicRegisterIndex(regName)
        self._setRegister(thread, regId, value)
        
    def detach(self, pid=GDB.THREADS.ANY):
        """
        Detach from the current process.
        @return: Flag indicating success.
        """
        return self._sendCmdRespOK(GDB.CMD.DETACH % pid)
        
    def attach(self, pid):
        """
        Attach to a new process.
        @param pid: The id of the process to attach to.
        @return: Boolean flag indicating success
        """
        if DEBUG <= DEBUG_LEVEL.IMPORTANT:
            print "[i] Attaching to new process %x." % pid
            
        self._sendCmdRaw(GDB.CMD.ATTACH % pid)
        resp = self._recvRespRaw()
        if resp[0] == GDB.RESPONSE.ERROR:
            return False
    
        self._flushCaches()
        return True
    
    def load(self, commandLine):
        """
        Loads a debugee using the given commandline.
        @param commandLine: The commandline.
        """
        args = commandLine.split(" ")
        tmp = GDB.CMD.RUN % args[0].encode("hex")
        for arg in args[1:]:
            tmp += GDB.ARGUMENT % arg.encode("hex")
            
        self._sendCmdRaw(tmp)
        resp = self._recvRespRaw()
        if resp[0] == GDB.RESPONSE.ERROR:
            raise CouldNotStartDebugee()
    
    @staticmethod
    def _startWrapper(self, dummy):
        self.start(False)
        
    def start(self, threaded=True):
        """
        Start the debugee in blocking-manner. All debug-events will be processed and callbacks will be called. Returns when the debugee exits or an externally induced interrupt is encountered.
        @param threaded: [OPTIONAL] 'True' will start the debug-loop in a separate thread, resulting in an immediate return of the method call. Please note, that most of PyGdb's methods are not particularly thread-safe. You should not call any other method than PyGdb.stop once you started a debug-loop in a different thread.
        In some cases using PyGdb.run() instead of PyGdb.start(True) is the better choice. 
        """
        if threaded:
            self.eventDebugLoopEntered.clear()
            tt = threading.Thread(target=PyGdb._startWrapper, args=(self, 1))
            tt.start()
            self.threadDebugLoop = tt
            self.eventDebugLoopEntered.wait() # wait for debug loop to really begin, we don't want any race-conditions.
            return tt
            
        self.lastEventsProcessed = []
        self.goOn = True
        self._cont(GDB.THREADS.ALL)
        self._debugLoop()
        
    def stop(self, waitForDebugLoop=True):
        """
        Stops the debugee and terminates a debug-loop currently running in a separate thread.
        @param waitForDebugLoop: [OPTIONAL] Boolean value indication wether to wait for the debug-loop to exit.
        TODO: This isn't really thread-safe - but works most of the time ;-)
        """
        log(DEBUG_LEVEL.IMPORTANT, "[i] Going to stop the debugee...")
        self.goOn = False
        time.sleep(1)
        if self.eventDebugeeRunning.isSet() and not self.eventProcessingEvent.isSet():
            print "meep"
            self.interrupt(False)
            
        if waitForDebugLoop and self.threadDebugLoop is not None:
            print "moop"
            self.threadDebugLoop.join(timeout=self._KILL_TIMEOUT)
            if self.threadDebugLoop.isAlive():
                self.stop(waitForDebugLoop)
        
    def reset(self, keepBp=False, pidInheritBp=None, hard=False):
        """
        Resets the debugging session.
        @param pidInheritBp: [OPTIONAL] Process to inherit bps from. Only comes into effect if keepBp is true.
        @param hard: [OPTIONAL] If true, a completely new connection to the remote stub is established.
        """
        log(DEBUG_LEVEL.IMPORTANT, "[i] Resetting debugee (hard: %s, keeping breakpoints: %s)." % (str(hard), str(keepBp)))
        # kill all processes that have forked
        """
        for pid in self.processes:
            if pid != self.initialPid:
                self.kill(pid)
        """    
        if keepBp:
            _pidInheritBp = pidInheritBp or self.pid
            tmpBreakpoints = self.processes[_pidInheritBp].breakpoints
            tmpBreakpointRanges = self.processes[_pidInheritBp].breakpointRanges
            oldBaseAddr = self.environment.getBaseAddrCode(self, _pidInheritBp)
        
        if hard:
            self.s.close()
            self._connect()
        else:
            # discard all possibly waiting debug-events
            self._discardAllPendingDebugEvents()
        
        self.environment.reset()
        self._sendCmdRaw(GDB.CMD.RESTART)
        self._initProcess()
        
        # translate breakpoints into the resetted process' address space layout and set them again
        if keepBp:
            newBaseAddr = self.environment.getBaseAddrCode(self, self.pid)
            self.processes[self.pid].breakpoints = self._translateBreakpoints(tmpBreakpoints, oldBaseAddr, newBaseAddr, self.pid)
            self.processes[self.pid].breakpointRanges = self._translateBreakpoints(tmpBreakpointRanges, oldBaseAddr, newBaseAddr, self.pid)
            
    def cont(self, packedTid=GDB.THREADS.ALL):
        """
        Continues the debugee (or a given thread). Use this if instead of start() if you want use pygdb in a sequential program with no callbacks. Returns after each debug-event.
        @param packedTid: [Optional] The thread/process to continue
        @return: The debug-event that caused the debugee to halt.
        """
        #if thread <= 0:
        #    raise NotImplemented("Single-stepping for all or random threads is not implemented yet.")
        self._cont(packedTid) 
        debugEvent = self._getNextDebugEvent()
        if DEBUG == DEBUG_LEVEL.ALL:
            print "[e] Received debug event after continuing."
        self._processDebugEvent(debugEvent)
        # lastEvent = self.lastEventsProcessed.pop() 
        # while lastEvent.type != GDB.SIGNAL.S
        
        return debugEvent
    
    # non blocking
    def run(self, packedTid=GDB.THREADS.ALL):
        self._cont(packedTid)
        
    def readMemory(self, addr, size, cache=False, pid=GDB.THREADS.ANY, fetchLargerRegion=False):
        """
        @param addr: The rebased address to read from.
        @param size: The amount of bytes to read.
        @param cache: [OPTIONAL] Boolean value indicating whether an attempt should be made to read memory from the local cache instead from the remote target's memory.
        @param pid: [OPTIONAL] The process to read from.
        @return: A string of length 'size' in case of succes, None in case of failure. 
        """
        log(DEBUG_LEVEL.ALL, "[i] Going to read %d bytes from %x." % (size,addr))
        memory = None
        # check if the mem access should make use of caching
        if pid == GDB.THREADS.ANY:
            _pid = self.pid
        else:
            _pid = pid
            
        if cache:
            memory = self.processes[_pid].memCache.getRange(addr, size)
            if memory is not None:
                return memory
                
        # DEBUG
        fetchLargerRegion = False
        #######
                
        if fetchLargerRegion:
            _size = self._SIZE_MEM_CACHE_UNIT * (size // self._SIZE_MEM_CACHE_UNIT +1)
        else:
            _size = size
              
        memory = self._readMemory(addr, _size, _pid)
        self.processes[_pid].memCache.setRange(addr, memory)
        
        return memory[:size]
    
    def writeMemory(self, addr, data, pid=GDB.THREADS.ANY):
        if pid == GDB.THREADS.ANY:
            _pid = self.pid
        else:
            _pid = pid
        
        self.processes[_pid].memCache.setRange(addr, data)
        self._setCmdThreadContext(pid=_pid)
        log(DEBUG_LEVEL.ALL, "[i] Going to write %d bytes to %x." % (len(data), addr))
        result = self._sendCmdRespOK(GDB.CMD.WRITE_MEMORY % (addr, len(data), data.encode("hex")))
        if not result:
            log(DEBUG_LEVEL.IMPORTANT, "[!] Failed to write %d bytes to %x" % (len(data), addr))
        return result
    
    def searchMemory(self, addr, length, byteString, pid=GDB.THREADS.ANY):
        """
        Searches a process' memory range for a sequence of bytes.
        @param addr: The VA to start searching at.
        @param length: The length of the range to search.
        @param byteString: The bytes to look for.
        @param pid: [OPTIONAL] The id of the process to search.
        @return: None on error or negative result, otherwise the first VA the bytes were encountered at.
        """
        self._setCmdThreadContext(pid)
        self._sendCmdRaw(GDB.CMD.SEARCH_MEMORY % (addr, length, GDB.escapeString(byteString)))
        resp = self._recvRespRaw()
        if resp[0] == GDB.RESPONSE.ERROR:
            log(DEBUG_LEVEL.SOME, "[!] Failed to search for data in range %x+%x." % (addr, length))
            return None
        
        if resp[0] == GDB.RESPONSE.NOT_FOUND:
            log(DEBUG_LEVEL.SOME, "[!] Did not find data in range %x+%x." % (addr, length))
            return None
        
        return int(resp[2:],16)
        
    def stopThread(self, packedTid, timeout=None):
        """
        Stops the debugee or a single given thread (in non-stopping mode only, not supported yet, TODO).
        @param packedTid: [Optional] The thread/process to break. Only evaluated in non-stopmode which is currently (?) not supported.
        @param timeout: [OPTIONAL] Timeout after which to stop wating for the interrupt signal.
        """
        """
        if self.config.nonStopMode:
            if packedTid == -1:
                self._sendCmdRaw(GDB.CMD.VCONT.PREFIX + (GDB.CMD.VCONT.ACTION % GDB.CMD.VCONT.STOP))
            else:
                self._sendCmdRaw(GDB.CMD.VCONT.PREFIX + (GDB.CMD.VCONT.ACTION % GDB.CMD.VCONT.STOP + GDB.CMD.VCONT.THREAD_ID % thread))
        else:
        """
        # process and resume pending events
        while True:
            pendingEvent = self._getNextDebugEvent(self._TIME_CHUNK)
            if pendingEvent is None:
                break
            
            self._processDebugEvent(pendingEvent)
            if pendingEvent.tid == packedTid or pendingEvent.type == GDB.RESPONSE.STOP.EXIT:
                return True
            
            self._cont(packedTid)
            
        # in break-mode we can only break all processes/threads!
        self.interrupt(False)
        if self._waitForParticularSignal(GDB.SIGNAL.INT, GDB.THREADS.ANY, timeout=timeout):
            return True
        
        return False 
    
    def interrupt(self, catchException=True):
        """
        Issues an interrupt in the debugee and halts it. If you just want to halt the debugee, you should use PyGDB.break(). 
        @param catchException: Flag indicating if the exception corresponding to the interrupt should be caught automatically. This should be set to False i case you want to break a pygdb instance runnung in a different thread (see traceRecorder._record() for an example).
        """
        log(DEBUG_LEVEL.ALL, "[i] Interrupting the debugee.")
        self._sendRaw(GDB.CMD.INTERRUPT)
        # get corresponding debug event
        if catchException:
            event = self._readDebugEvent()
            return event.type == GDB.SIGNAL.INT
            
    def registerExceptionHandler(self, exception, callback, minAddr = 0, maxAddr = 0):
        self._registerExceptionHandler(_ExceptionHandler(exception, callback, minAddr, maxAddr)) 
        
    def stepOver(self, tid=None, cleanUpBreakpoint=True, stayInImage=False):
        """
        Step over the current instruction (do not enter calls). 
        @param tid: [OPTIONAL] The id of the thread in which context to step.
        @param cleanUpBreakpoint: [OPTIONAL] A flag indicating whether a breakpoint clean-up should be done in case pc-1 has a breakpoint set on.
        @param stayInImage: [OPTIONAL] If set, error is returned if step went outside the debugees initial image.
        @return: A tupel consisting of a boolean flag indicating the success of the operation, the address of the next instruction and the address the corresponding step-into operation lead-to. In case of a negative success the last debug event of the thread is not processed yet.  
        """
        tid = tid or self.ptid
        log(DEBUG_LEVEL.SOME, "[i] Going to step over next instruction in thread %x." % tid)
        addr = self.getPC(tid)
        pid = self.environment.unpackThreadId(tid)[0]
        
        # check if instruction is a call and if conditional if the corresponding condition is met (e.g. check if a call is about to get executed)
        characteristics = self.cpu.getInstrCharacteristics(self, tid, addr)
        enterCall = False
        if characteristics & instruction.CHARACTERISTIC.CALL != 0:
            if characteristics & instruction.CHARACTERISTIC.CONDITIONAL != 0:
                enterCall = self.cpu.evaluateCondInstr(self, tid, addr)
            else:
                enterCall = True
        
        self.stepInto(tid, cleanUpBreakpoint)
        stepIntoAddr = self.getPC(tid)
        if stayInImage:
            if not self.environment.addrBelongsToImage(self, stepIntoAddr):
                return (False, stepIntoAddr, stepIntoAddr)
            
        # did we step into a sub-func?
        success = True
        if enterCall:
            # if so, break on the return address and continue debugee
            retAddr = self.cpu.getFunctionReturnAddress(self, tid)
            self._setBreakpointRaw(retAddr, pid)
            self.processes[pid].addReturnBreakpoint(retAddr)
            
            retPC = self.cpu.getAddressBreakpoint(retAddr)
            self._cont(tid)
            if self._waitForParticularSignal(GDB.SIGNAL.TRAP, tid, (retPC, retPC)):
                self.processes[pid].removeReturnBreakpoint(retAddr)
                if not self.processes[pid].hasBreakpoint(retAddr):
                    self._removeBreakpointRaw(retAddr, pid)
                self.setPC(retAddr, tid)
            else:
                success = False
                
            return (success, retAddr, stepIntoAddr)
        return (success, stepIntoAddr, stepIntoAddr)
    
    def hasBreakpoint(self, addr, pid=GDB.THREADS.ANY):
        if pid == GDB.THREADS.ANY:
            _pid = self.pid
        else:
            _pid = pid
           
        return self.processes[_pid].hasBreakpoint(addr)
    
    def getOriginalBytesBreakpoint(self, addr, pid=GDB.THREADS.ANY):
        if pid == GDB.THREADS.ANY:
            _pid = self.pid
        else:
            _pid = pid
            
        return self.processes[_pid].getOriginalBytesBreakpoint(addr)
    
    def stepInto(self, tid=None, cleanUpBreakpoint=True):
        """
        Execute the current instruction and return (enter calls).
        @param tid: [OPTIONAL] The id of the thread in which context to step.
        @param cleanUpBreakpoint: [OPTIONAL] A flag indicating whether a breakpoint clean-up should be done in case pc-1 has a breakpoint set on. 
        """
        tid = tid or self.ptid
        log(DEBUG_LEVEL.ALL, "[i] Going to step into next instruction in thread %x." % tid)
        # bpAddr is the address of a possible breakpoint
        addr = self.getPC(tid)
        pid = self.environment.unpackThreadId(tid)[0]
        if cleanUpBreakpoint and (self.processes[pid].hasBreakpoint(addr)):
            # 1st remove breakpoint temporarly
            self._removeBreakpointRaw(addr, pid)
            # 2nd single-step last instruction
            self._singlestep(tid)
            # 3rd reset breakpoint
            self._setBreakpointRaw(addr, pid)
        else:
            self._singlestep(tid)
            
    def kill(self, pid = GDB.THREADS.ALL):
        """
        Kills the debugee.
        """
        pids = self._getEffectivePids(pid)
        worked = True
        for p in pids:
            if not self._sendCmdRespOK(GDB.CMD.KILL % p):
                worked = False
                
        return worked
        
    def processPendingDebugEvents(self):
        """
        Checks in a non-blocking manner for pending debug events and processes them. Currently used for cleaning-up before a fork.
        @return: Flag indicating whether any events were found pending.
        """
        foundPending = False
        while True:
            e = self._getNextDebugEvent(timeout=0)
            if e is None:
                break
            self._processDebugEvent(e)
            foundPending = True
        return foundPending
            
    def followsForks(self):
        """
        @return A flag indicating if the PyGdb instance follows forks.
        """
        return self.addrForkFuncRaw is not None
    
    def getCurrentThreadId(self):
        """
        Returns the currently active thread id.
        @return: The thread id in form of a tupel (pid,tid).
        """
        self._sendCmdRaw(GDB.CMD.GET_THREAD_ID)
        raw = self._recvRespRaw()
        i = raw.find(".")
        pid = int(raw[3:i], 16)
        tid = int(raw[i+1:], 16)
        return (pid, tid)
    
    def interpreterCmd(self, command):
        """
        Directly send a GDB command to the remote stub's interpreter. Does NOT give you a gdb shell. 
        """
        o = ""
        self._sendCmdRaw(GDB.CMD.INTERPRETER_COMMAND + command.encode("hex"))
        while True:
            resp = self._recvResp()
            if resp[0] == GDB.RESPONSE.ERROR:
                raise InvalidCommand()
            if resp == GDB.RESPONSE.OK or len(resp) <= 1:
                return o
            else:
                o += resp[1:].decode("hex")
                
    def passSignals(self, signals):
        cmd = GDB.CMD.PASS_SIGNALS + GDB.FIRST_ARGUMENT % ("%02x" % signals[0])
        for signal in signals[1:]:
            cmd += GDB.ARGUMENT % ("%02x" % signal)
        return self._sendCmdRespOK(cmd)
    
    def getRawAuxiliaryVector(self, pid=GDB.THREADS.ANY):
        self._setCmdThreadContext(pid)
        return self._readXfer(GDB.CMD.XFER.READ_AUXILIARY_VECTOR + GDB.CMD.XFER.SUFFIX_0)
        
    
    def getAllThreads(self):
        xml = self._readXfer(GDB.CMD.XFER.READ_THREADS + GDB.CMD.XFER.SUFFIX_0).split("\n")
        threads = []
        if not hasattr(self, "regexPidTid"):
            self.regexPidTid = re.compile(GDB.REGEX.PROCESS_THREAD_ID)
        for line in xml:
            m = self.regexPidTid.search(line)
            if m is not None:
                threads.append((int(m.group("pid"),16), int(m.group("tid"),16)))
            
        return threads
    
    def getPidFromTid(self, tid):
        """
        Gets the process id corresponding to a (packed) tid.
        @param tid: The (packed) tid
        @return: The corresponding process id
        """
        return self.environment.unpackThreadId(tid)[0]

        
    def getHaltingReason(self):
        """
        Queries the remote stub for the last halting reason.
        @return: The event that caused the debugee to halt.
        @rtype: Event
        """
        
        # Hackerish
        c = 0
        while True:
            self._sendCmdRaw(GDB.CMD.GET_HALTING_REASON)
            event = self._readDebugEvent(timeout=self._TIME_CHUNK)
            if event is None:
                c += 1
                continue
            
            # ok, we have our event, now clean up
            for i in range(c):
                self._readDebugEvent()
                
            break
        return event 
    
    def disableFollowFork(self):
        """
        Disables the following of forks.
        """
        for addrForkFunc in self.addrForkFuncs:
            self._removeBreakpointInternal(addrForkFunc, pid=GDB.THREADS.ALL)
            
    def enableDieOnProcessExit(self, enable):
        self.dieOnProcessExit = enable
        
    
            
            
        
        
        
                    
        
        
        
        
            
            
        
            
        
        
            
        
        
        
        
    
    
            
        
        
            
            
    
             
        
        
        