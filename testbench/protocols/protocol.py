'''
Created on 25.04.2012

@author: Felix
'''
import copy
import atom
import tools

class _Element:
    @staticmethod
    def _DEFAULT_COMPILER(value):
        return atom.DATA(value)
    
    def __init__(self, privLevels=[], applicables=[], compiler=None):
        """
        @param privLevels: The privilege level of the element. Default is [] (all).
        @param applicables: The protocol strings that this element is applicable to. Default is [] (all).
        @param encoder: An optional callback function to encode the given value on invocation. The default encoder just returns the given value.
        """
        self.privLevels = privLevels
        self.applicables = applicables
        if not compiler:
            self.compiler = self._DEFAULT_COMPILER
        else:
            self.compiler = compiler
            
    def reset(self):
        pass

class _StaticElement(_Element): 
    def __init__(self, value, privLevels=[], applicables=[], compiler=None):
        """
        @param value: Values that is to be passed to the encoder function on the element's invocation. 
        """
        _Element.__init__(self, privLevels, applicables, compiler)
        self.value = value
    
    def get(self):
        """
        @return: A tuple of the compiled script and the corresponding value/name of the element.
        """
        return (self.compiler(self.value), self.value)
        
class _DynamicElement(_Element):
    """
    A dynamic protocol element.
    """
    @staticmethod
    def _DEFAULT_GENERATOR(values, encoder):
        for v in values:
            yield (encoder(v), v)
    
    def __init__(self, values=[], privLevels=[], applicables=[], compiler=None, generator=None):
        """
        @param values: Values that are to be passed to the generator function on the element's invocation. Default is [].
        @param generator: [OPTIONAL] iterator that generates the protocol element's different possible values. On invocation a generator is passed the values parameter. The default generator just yields the elements of the values parameter. 
        """
        _Element.__init__(self, privLevels, applicables, compiler)
        
        self._generator = generator or self._DEFAULT_GENERATOR     
        self.values = values
        self.reset()
        
    def reset(self):
        self.generator = self._generator(self.values, self.compiler)
        
    def getNext(self):
        """
        @return: A tuple of the compiled script and the corresponding value/name of the element.
        """
        return self.generator.next()
    
    def get(self, i=0):
        """
        @return: A tuple of the compiled script and the corresponding value/name of the element.
        """
        return (self.compiler(self.values[i]), self.values[i])
    
    def size(self):
        return len(self.values)
    
        
class Auth(_DynamicElement):
    """
    An auth element of a protocol.
    """
    INVALID_AUTH_ITEM = "INVALID"

    def __init__(self, values, privLevels=[], applicables=[], compiler=None, generator=None, importantValuesIndex=None, invalidItem=None):
        """
        @param values: A tuple of arbitrary length containing valid credentials, e.g. ('user', 'password').
        @param importantValuesIndex: A list of indexes of important credential-items. For each important item an invalid protocol script is compiled, where the original value is replaced by an invalid one.  
        """
        # add the valid auth-data
        _values = [values]
        # add the invalid auth-data
        _importantValuesIndex = importantValuesIndex or range(len(values))
        
        # generate the invalid data
        _invalidItem = invalidItem or Auth.INVALID_AUTH_ITEM 
        for i in _importantValuesIndex:
            tmp = values[:i] + (_invalidItem,) + values[i + 1:]
            _values.append(tmp)
        _DynamicElement.__init__(self, _values, privLevels, applicables, compiler, generator)
    
class Cmd(_DynamicElement):
    """
    A command element of a protocol.
    """
    pass
    
class InvalidCmd(Cmd):
    """
    A command invalid for a certain command-level.
    """
    def __init__(self, value, privLevels=[], applicables=[], compiler=None):
        Cmd.__init__(self, values=[value], privLevels=privLevels, applicables=applicables, compiler=compiler)
        
    def getNext(self):
        return self.get() # invalid commands are never done :-)
        
class Arg(_StaticElement):
    """
    A command argument element of a protocol.
    """ 
    pass
    
class Delim(_StaticElement):
    """
    A static element of a protocol.
    """
    pass

class Static(_StaticElement):
    """
    A static element of a protocol.
    """
    pass
    
class _Meta(_StaticElement):
    """
    A meta element of protocol (such as Recv or Send)
    """
    def __init__(self, label="", privLevels=[], applicables=[], compiler=None):
            _compiler = compiler or self._COMPILER
            _StaticElement.__init__(self, label, privLevels, applicables, _compiler)
            
class Send(_Meta):
    """
    A send meta element of a protocol. Sends all data that is in the current traffic buffer.
    """
    @staticmethod
    def _COMPILER(value):
        return atom.SEND(label=value)
    
class Recv(_Meta):
    """
    A recv meta element of a protocol. Tells the protocol processor to receive data from the target host.
    """
    @staticmethod
    def _COMPILER(value):
        return atom.RECV(label=value)
        
class RecvAll(_Meta):
    """
    Tells the protocol processor to receive multiple frames.
    """
    @staticmethod
    def _COMPILER(value):
        return atom.RECV(label=value, recvAll=True)
    
class RecvNonBlocking(_Meta):
    @staticmethod
    def _COMPILER(value):
        return atom.RECV(label=value, nonBlocking=True)
    
class RecvTimeout(_Meta):
    
    def __init__(self, timeout, label="", privLevels=[], applicables=[]):
        compiler = lambda value : atom.RECV(label=value, timeout=timeout)
        _Meta.__init__(self, label, privLevels, applicables, compiler)
        
class Description:
    """
    Description of a protocol.
    """
    DEFAULT_PROTOCOL_STRING = 0
    
    def __init__(self, name):
        """
        @param name: The name of the protocol description.
        """
        import sets
        
        self.name = name
        self.levels = []
        self.privLevels = sets.Set()
        self.protoStrings = sets.Set()
        self.newLevel()
        
    def newLevel(self, name=None):
        """
        Adds a new level to the description of a protocol.
        """
        self.levels.append([])
        
    def addElement(self, elem):
        """
        Adds a new element to the current level of the protocol
        @param elem: The element to add.
        """
           
        # check element for new privLevels and protocol strings
        for pl in elem.privLevels:
            self.privLevels.add(pl)
            
        for ps in elem.applicables:
            self.privLevels.add(ps) 
             
        self.levels[-1].append(elem)
        
class ErrCompilingScript(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
        
class Compiler:
    """
    Compiles a protocol description to various protocol run scripts.
    """
    
    def __init__(self, protoDescr, delayStopRecording=None):
        """
        @param protoDescr: A protocol description.
        @param delayStopRecording: [OPTIONAL] Amount of time to wait after the last send() before the recording should be stopped. 
        This value is application dependent. If not set, the protocol-socket will be closed after the last send and recording will go on until the session-process exits.
        This works usually well for server applications that fork. 
        @type protoDescr: Description
        """
        self.protoDescr = protoDescr
        self.delayStopRecording = delayStopRecording
    
    def reset(self):
        for level in self.protoDescr.levels:
            for elem in level:
                elem.reset()
    
    @staticmethod
    def _unpackScript(s):
        if isinstance(s, atom._BASE):
            return [s]
        
        r = []
        for x in s:
            if isinstance(x, tuple):
                r += Compiler._unpackScript(x)
            else:
                r.append(x)
        return r
    
    @staticmethod 
    def _insertStartRecordingMarker(x):
        """
        Inserts a start-recording marker either in front of the last send or (if no send is present) at the end of the (sub) script.
        @param x: Either a single atomic protocol-element or a packed script.
        """
        unpackedScript = Compiler._unpackScript((x))
        i = 1
        while i <= len(unpackedScript) and not isinstance(unpackedScript[-i], atom.SEND):
            i += 1
        if i <= len(unpackedScript):
            unpackedScript = unpackedScript[:-i] + [atom.START_RECORDING()] + unpackedScript[-i:]
        else:
            unpackedScript.append(atom.START_RECORDING())
        return unpackedScript
    
    @staticmethod
    def _finalizeScript(script, delayStopRecording):
        """
        Inserts a stop-recording marker after the first send/recv after the start-recording marker.
        @param The script to finalize
        @return The finalized script
        """
        unpackedScript = Compiler._unpackScript(script)
        
        # find start-recording marker
        iStartRecording = tools.findFirst(unpackedScript, itemType=atom.START_RECORDING)
        assert iStartRecording >= 0
        # find next send
        iSend = tools.findFirst(unpackedScript, itemType=atom.SEND, offset=iStartRecording)
        assert iSend >= 0
        # find next recv
        iRecv = tools.findFirst(unpackedScript, itemType=atom.RECV, offset=iSend)
        assert iRecv >= 0
        
        # insert stop-recording marker
        if delayStopRecording is not None:
            # insert wait before stop-recording marker
            unpackedScript = unpackedScript[:iRecv + 1] + [atom.WAIT(timeout=delayStopRecording), atom.STOP_RECORDING()] + unpackedScript[iRecv + 1:]
        else:
            # do not wait, but tell the stop-recording marker to close the protocol-socket
            unpackedScript = unpackedScript[:iRecv + 1] + [atom.STOP_RECORDING()] + unpackedScript[iRecv + 1:]
            
        return unpackedScript
        
        """
        if delayStopRecording is not None:
            unpackedScript += [atom.WAIT(timeout=delayStopRecording), atom.STOP_RECORDING()]      
        else:
            unpackedScript += [atom.STOP_RECORDING()]
        return unpackedScript
        """
        
    def getPrivLevels(self):
        return self.protoDescr.privLevels
    
    def getProtocolStrings(self):
        return self.protoDescr.applicables
    
    _NAME_AUTH = "auth"
    _NAME_WRONG_AUTH = "wrong_auth"
    
    def compileAuthValidFirst(self, privLevel):
        """
        Compiles the first and valid authentication run for the given privlevel.
        Subsequent calls to compileAuthNext return invalid authentication runs (valid authentication elements are replaced by invalid ones subsequently)
        """
        self.authRunsIndex = 0
        self.authRun = []
        self.reset()
        authFound = False
        for level in self.protoDescr.levels:
            for elem in level:
                if privLevel in elem.privLevels or len(elem.privLevels) == 0:
                    # check if the element is of type auth
                    self.authRun.append(elem)
                    if isinstance(elem, Auth):
                        authFound = True
                        
                    break
            
        if not authFound:
            raise ErrCompilingScript("No applicable auth-element found.")
        return self.compileAuthNext(privLevel)
    
    def compileAuthNext(self, privLevel):
        """
        Compiles a minimal authentication run for the given privilege level. 
        You should call first compileAuthValidFirst to get a script for a valid authentication and then subsequently call this method in order to get invalid scripts. 
        @param privLevel: The privilege level to compile the script for.
        @return: A ready to use protocol processor. 'None' in the case that there is no "next" auth-run to compile.
        """
        script = []
        for elem in self.authRun:
            if isinstance(elem, Auth):
                try:
                    scriptAuth, nameAuth = elem.getNext()
                    script += Compiler._insertStartRecordingMarker(scriptAuth)
                except StopIteration:
                    return None
            else:
                script.append(elem.get()[0])
        
        name = (self.authRunsIndex == 0 and Compiler._NAME_AUTH or (Compiler._NAME_WRONG_AUTH + str(self.authRunsIndex))) + ":%s" % str(privLevel)
        self.authRunsIndex += 1 
        return Processor(Compiler._finalizeScript(script, self.delayStopRecording), name=name)
                  
    @staticmethod
    def _getApplicableLevelElements(level, privLevel, string, filterGood=None, filterBad=None):
        # filter construct is ugly, but works...
        explicitPrivLevel = set()
        explicitString = set()
        undefinedPrivLevel = set()
        undefinedString = set()
        
        # sort elements according to their properties
        for elem in level:
            if filterBad and isinstance(elem, filterBad):
                if filterGood is not None:
                    if not isinstance(elem, filterGood):
                        continue
                else:
                    continue
            if privLevel in elem.privLevels:
                explicitPrivLevel.add(elem)
            if string in elem.applicables:
                explicitString.add(elem)
            if len(elem.applicables) == 0:
                undefinedString.add(elem)
            if len(elem.privLevels) == 0:
                undefinedPrivLevel.add(elem)
        
        correctPrivLevel = explicitPrivLevel | undefinedPrivLevel
        
        # 1st: Check for elements with both explicitly correct string/privlevel set.
        applicableElements = correctPrivLevel.intersection(explicitString)
        if len(applicableElements) == 0:
            # 2nd: Check for elements with no specific string set 
            applicableElements = correctPrivLevel.intersection(undefinedString)

        return [x for x in applicableElements]
        
    def compileCmdFirst(self, privLevel, string):
        """
        Compiles the first command of the given string for the given privilege level. Use compileCmdNext to get compiled runs for all commands. 
        @param privLevel: The privilege level to compile the runs for
        @param string: The protocol string to follow
        @return: A protocol processor
        """
        self.cmdRuns = []
        self.cmdRunsIndex = 0
        self.reset()
        for level in self.protoDescr.levels:
            tmp = Compiler._getApplicableLevelElements(level, privLevel, string, filterBad=InvalidCmd) # exclude InvalidCmd objects
            if len(tmp) != 0:
                self.cmdRuns.append(tmp) 
        return self.compileCmdNext()
    
    def compileCmdNext(self):
        """
        Compiles the next command.
        @return: A protocol processor
        """
        tmp = Compiler._compileCmd(self.cmdRuns, self.cmdRunsIndex, self.delayStopRecording)
        if tmp is None:
            return tmp
        cmdProcessor, self.cmdRunsIndex = tmp
        
        return cmdProcessor
    
    def compileCmdInvalid(self, privLevel, string):
        """
        Compiles an invalid command for the given privilege-level and string.
        @param privLevel: The privilege level to compile the runs for
        @param string: The protocol string to follow
        @return: A protocol processor
        """
        run = []
        for level in self.protoDescr.levels:
            run.append(Compiler._getApplicableLevelElements(level, privLevel, string, filterGood=InvalidCmd, filterBad=Cmd)) # exclude Cmd objects
        return Compiler._compileCmd(run, 0, self.delayStopRecording)[0]
        
    @staticmethod
    def _compileCmd(cmdRuns, i, delayStopRecording):
        script = []
        cmdFound = False
        for level in cmdRuns:
            # any level but the one containing the actual commands should only have one element
            if len(level) == 0:
                continue
            
            if isinstance(level[0], Cmd):
                cmdFound = True
                while True:
                    if i >= len(level):
                        return None
                    try:
                        scriptCmd, nameCmd = level[i].getNext()
                    except StopIteration:
                        i += 1
                    else:
                        script += Compiler._insertStartRecordingMarker(scriptCmd)
                        break   
            else:
                script.append(level[0].get()[0])
        if not cmdFound:
            raise ErrCompilingScript("No applicable command found to compile (did you maybe forget to specify an invalid command?).") 
        return (Processor(Compiler._finalizeScript(script, delayStopRecording), name=nameCmd), i)
                
class Processor:
    """
    Processes a compiled protocol description.
    """             
    def __init__(self, script, name=None):
        """
        @param script: A compiled protocol description.
        @type script: list
        @param name: The name of the protocol run. E.g. the name of the command it belongs to.
        """
        self.origScript = script
        self.name = name
        self.reset()
        
    def add(self, element):
        """
        Adds an additional element to the compiled script. Currently in progress replays are not affected. Call Processor.reset() to flush newly added elements.
        """
        self.origScript.append(element)
        
    def reset(self):
        """
        Resets the processor's state.
        """
        self.script = copy.copy(self.origScript)
    
    def play(self, t, chunkDelay=None):
        """
        Plays back the corresponding  compiled protocol script.
        @param t: The transport-layer to use.
        @param verbose: The verbose level.
        @param chunkDelay: Amount of time to wait before sending a protocol-chunk (can be useful to avoid deadlocks).
        @return: boolean value indicating success
        """
        import time
        while len(self.script) != 0:
            if chunkDelay is not None:
                time.sleep(chunkDelay)
                
            elem = self.script.pop(0)
            if elem.jitEmitter:
                jitScript = elem.jitEmitter(elem, t.getLastResponse())
                if jitScript is not None:
                    # play jit-script
                    tmpScript = self.script
                    self.script = Compiler._unpackScript(jitScript)
                    if not self.play(t, chunkDelay):
                        # an error occurred
                        return False
                    
                    self.script = tmpScript
                    
            # check for pseudo-blocks
            if isinstance(elem, atom.START_RECORDING) or isinstance(elem, atom.STOP_RECORDING):
                # just stop playing in case we get a stop-recording/start-recording
                # only place to exit the loop gracefully
                return True
                    
            if isinstance(elem, atom.DATA):
                t.addDatagram(elem.data)  
                    
            elif isinstance(elem, atom.SEND):
                if not t.send():
                    return False
                t.reset()
        
            elif isinstance(elem, atom.RECV):
                resp = t.recvTimeout(elem.buffSize, elem.timeout, elem.recvAll)
                if resp is None and elem.mandatory:
                    return False
                t.setLastResponse(resp)
                
            elif isinstance(elem, atom.WAIT):
                time.sleep(elem.timeout)
                
        return True
    
class _Run:
    
    def __str__(self):
        return self.protoProc.name
    
    def __len__(self):
        if self.trace is not None:
            return len(self.trace)
        return 0
    
    def __init__(self, protoProc, traces, traceSelector=None, diGraph=None):
        self.protoProc = protoProc
        
        if isinstance(traces, list):
            self.traces = traces
    
            if traceSelector is not None:
                self.trace = traceSelector(self.traces)
            else:
                self.trace = None
                
        else:
            self.trace = traces
                
        self.update()
            
    def update(self):
        if not self.trace is None:
            self.diGraph = self.trace.getDigraph()
        else: 
            self.diGraph = None
    
class RunFunc(_Run):
    """
    Encapsulation class for a function trace.
    """
    def __init__(self, protoProc, traces, callStack=None, traceSelector=None):
        _Run.__init__(self, protoProc, traces, traceSelector)
        self.callStack = callStack or []
        
    def addCallStack(self, callStack):
        self.callStack += callStack
        
class RunBb(_Run):
    """
    Encapsulation class for a basic block trace.
    """
    pass
                        
    
