'''
Created on 14.05.2012

@author: Felix
'''

import time
from globals import DEBUG, DEBUG_LEVEL, log
from core import PyGdb, GDB
import instruction
from trace import FunctionTrace, BasicBlockTrace, Trace, CallStack

class InvalidTracerState(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class AddressOutOfRange(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
    
DEBUG_LEVEL_TRACE_EVENTS = DEBUG_LEVEL.IMPORTANT

class _Tracer: 
    """
    Base-class for tracers. All tracers should inherit from this.
    """
    
    def _getNormalizedEventAddress(self, event):
        return self.undoRebasing and self.pygdb.environment.unrebaseCodeAddr(self.pygdb, event.addr, event._pid) or event.addr
    
    def __init__(self, pygdb, maxHits=-1):
        """
        @param pygdb: The PyGdb instance to use
        @param maxHits: [OPTIONAL] The maximum amount of hits before a checkpoint is cleared
        """
        self.pygdb = pygdb
        self.traces = {}
        
    def _done(self):
        """
        Gets called when a recording session is done.
        """
        # overwrite me
        return    
        
    def reset(self):
        """
        Resets the tracer.
        """
        self.traces = {}
        
    def setup(self):
        """
        Sets the tracer up. Most tracers will install breakpoints on this method call.
        """
        pass
            
    def start(self):
        """
        Starts the recording session. Non-blocking.
        @return: The thread of the debug-loop.
        """        
        # go go go
        self.reset()
        return self.pygdb.start(True)
        
    def stop(self):
        """
        Stops the recording session.
        """
        self.pygdb.stop(True)
        self._done()
        
    def getTraces(self, undoRebasing = False):
        """
        Gets the recorded traces.
        @param undoRebasing: [OPTIONAL] Translate all probably rebased addresses of the traces back. When this is set please make sure, that the Tracer's PyGdb instance is still valid.
        @return: The recorded traces.
        """
        if not undoRebasing:
            return [t for t in self.traces.values()]
        
        traces = []
        for tid in self.traces:
            pid = self.pygdb.getPidFromTid(tid)
            translator = lambda addr : self.pygdb.environment.unrebaseCodeAddr(self.pygdb, addr, pid)
            t = self.traces[tid]
            t.translate(translator)
            traces.append(t)
        return traces
            
class Checkpoint:
    
    def __init__(self, addr, maxHits):
        self.addr = addr
        self.maxHits = maxHits
        self.hits = {}
        
    def hit(self, pid):
        if pid not in self.hits:
            self.hits[pid] = 0
        self.hits[pid] += 1
        if self.maxHits == -1:
            return True
        return self.hits[pid] < self.maxHits
    
class SimpleTracer(_Tracer):

    def __init__(self, pygdb, checkpoints, maxHits=-1):
        _Tracer.__init__(self, pygdb, maxHits)
        self.checkpoints = checkpoints
        self.maxHits = maxHits
        
    def setup(self):
        self._setupCheckpoints(self.checkpoints, self.maxHits)
              
    def _setupCheckpoints(self, checkpoints, maxHits):
        t0 = time.time()
        self.checkpoints = {}
        for addr in checkpoints:
            self.checkpoints[addr] = Checkpoint(addr, maxHits)
        
        self.replug()
        log(DEBUG_LEVEL.SOME, "[i] Setting %d trace breakpoints took %f seconds." % (len(checkpoints),time.time() - t0))
            
    def unplug(self):
        self.pygdb.removeBreakpoints(self.checkpoints.keys(), bpCallback=self._defaultBpHandler)
        
    def replug(self):
        self.pygdb.setBreakpoints(self.checkpoints.keys(), self._defaultBpHandler, self, GDB.THREADS.ALL)
    
    @staticmethod 
    def _defaultBpHandler(self, pygdb, event):
        pid = event.pid
        if event.tid not in self.traces:
            self.traces[event.tid] = Trace(event.tid)
        
        addr = self.undoRebasing and pygdb.environment.unrebaseCodeAddr(pygdb, event.addr, event.pid) or event.addr
        self.traces[event.tid].addWaypoint(addr)
        log(DEBUG_LEVEL.IMPORTANT, "[e] Waypoint hit at address %08x. Continuing ..." % addr)
        
        # remove breakpoint if it was hit too often
        if not self.checkpoints[addr].hit(pid):
            pygdb.removeBreakpoint(addr, pid)
            log(DEBUG_LEVEL.IMPORTANT, "[i] Removed breakpoint %x after too many hits." % (addr))

        return PyGdb.CONTINUE.RUN    
    
class _RetBp:
    
    def __init__(self):
        
        self.refs = {}
        
    def add(self, tid):
        if tid not in self.refs:
            self.refs[tid] = 0
            
        self.refs[tid] += 1
        
    def sub(self, tid, n=1):
        assert tid in self.refs
        assert self.refs[tid] >= n
         
        self.refs[tid] -= n
        
        if self.refs[tid] == 0:
            self.refs.pop(tid)
    
    def hasRefs(self):
        return len(self.refs)
            
class FunctionTracer(SimpleTracer):

    def __init__(self, pygdb, checkpoints, maxHits=-1):
        self._defaultBpHandler = self._callHandler # overwrite default bp handler
        SimpleTracer.__init__(self, pygdb, checkpoints, maxHits)
        self.retBps = {} # reference counters for return breakpoints
        
    @staticmethod 
    def _callHandler(self, pygdb, event):
        pid = event.pid
        if pid not in self.retBps:
            self.retBps[pid] = {}
        
        funcAddr = event.addr
        retAddr = pygdb.cpu.getFunctionReturnAddress(pygdb, event.tid)
        outerFuncAddr = pygdb.environment.getNearestFunction(pygdb, retAddr, pid)
        
        # is this the first event for the thread?    
        if event.tid not in self.traces:
            # if so, create the corresponding FunctionTrace
            self.traces[event.tid] = FunctionTrace(event.tid, outerFuncAddr)
        else:
            trace = self.traces[event.tid]
            lastCall = self.traces[event.tid].getTopmostOpenCall()
            assert lastCall is not None
            
            # check if the return address on the stack is plausible
            if outerFuncAddr is None:
                # if not, use the return address of the logical caller
                log(DEBUG_LEVEL.SOME, "[i] Function %x has no sane return address (ret: %x,  logical parent: %x). Trying to merge return address with parent function..." % (funcAddr, retAddr, lastCall.addr ))
                if lastCall.retAddr == FunctionTrace.VIRTUAL_STARTING_NODE:
                    log(DEBUG_LEVEL.SOME, "[i] Apparently function %x is a callback called from outside the target image. We just keep the return address." % funcAddr)
                else:
                    retAddr = lastCall.retAddr
                
            # check if the function returns to the expected function
            elif not outerFuncAddr == lastCall.addr:
                if retAddr == lastCall.retAddr:
                    # do nothing :-)
                    # lastCall is probably just a proxy func
                    pass
                elif len(trace.openCallsStack) > 1:
                    # do nothing
                    # probably just some weird proxying
                    pass
                else:
                    # things are a bit more complicated...
                    # Apparently our virtual outer function has returned without us noticing.
                    # So we are going to close the virtual outer function, making it non virtual...
                    log(DEBUG_LEVEL.SOME, "[i] The return address (%x) of function %x suggests, that the outermost function returned. Going to create a new outer most function (%x)." % (retAddr, funcAddr, outerFuncAddr))
                    # at this point, there should only one open call left
                    dummyRetValues = []
                    ## FunctionTrace.VIRTUAL_STARTING_NODE is always the return address of the starting node. So we call a ret for this one.
                    closedCalls = trace.ret(FunctionTrace.VIRTUAL_STARTING_NODE, dummyRetValues)
                    assert closedCalls == 1
                    
                    # ...and install a new outer function.
                    trace.insertStartingNode(outerFuncAddr)                    

        self.traces[event.tid].call(funcAddr, retAddr)
        
        # check if this is a new return breakpoint
        if retAddr not in self.retBps[pid]:
            self.retBps[pid][retAddr] = _RetBp()
            pygdb.setBreakpoint(retAddr, self._retHandler, self, pid)
            
        # add reference to return breakpoint
        self.retBps[pid][retAddr].add(event.tid) 
        
        log(DEBUG_LEVEL.SOME, "[e] Function at address %08x called. Continuing ..." % funcAddr)
                
        # remove breakpoint if it was hit too often
        if not self.checkpoints[funcAddr].hit(pid):
            pygdb.removeBreakpoint(funcAddr, pid)
            self.traces[event.tid].removedBreakpoints.append(funcAddr)
            
            log(DEBUG_LEVEL.SOME, "[i] Removed function breakpoint %x from process %d after too many hits." % (funcAddr, pid))
                  
        return PyGdb.CONTINUE.RUN
        
    @staticmethod 
    def _retHandler(self, pygdb, event):
        pid = event.pid
        if event.tid not in self.traces:
            return PyGdb.CONTINUE.RUN
            
        log(DEBUG_LEVEL.SOME, "[e] Function returned to %08x. Continuing ..." % event.addr)
        
        retAddr = event.addr
        retValues = pygdb.cpu.getFunctionReturnValues(pygdb, event.tid)
        # check if return breakpoint really belongs to this thread
        closedCalls = self.traces[event.tid].ret(retAddr, retValues)
        self.retBps[pid][retAddr].sub(event.tid, closedCalls)
        
        # check if there are still any references to the return breakpoint
        if not self.retBps[pid][retAddr].hasRefs():
            # remove breakpoint
            self.retBps[pid].pop(retAddr)
            pygdb.removeBreakpoint(retAddr, pid)
        
        return PyGdb.CONTINUE.RUN
    
    def getCurrentCallStack(self, tid):
        if not tid in self.traces:
            # could be the case when there is no call-stack yet (i.e. we're in the top-func, can happen when tracing Pure-FTPd)
            return [] 
        return self.traces[tid].getCurrentCallStack()
    
    def unplug(self):
        SimpleTracer.unplug(self)
        # unplug return breakpoints
        for pid in self.retBps:
            self.pygdb.removeBreakpoints(self.retBps[pid].keys(), bpCallback=self._retHandler)
        
    def replug(self):
        SimpleTracer.replug(self)
        # replug return breakpoints
        for pid in self.retBps:
            self.pygdb.setBreakpoints(self.retBps[pid].keys(), self._retHandler, self, pid)
    
    
class _Branch:
    
    def __init__(self, addr, characteristics):
        self.addr = addr
        if characteristics & instruction.CHARACTERISTIC.CALL == 0 and characteristics & instruction.CHARACTERISTIC.JMP == 0:
            raise Exception("Illegal instruction-type")
        
        self.characteristics = characteristics
        
class CondBranch(_Branch):
    
    def __init__(self, addr, characteristics, condTrueTaken = False, condFalseTaken = False):
        _Branch.__init__(self, addr, characteristics)
        self.condTrueTaken = condTrueTaken
        self.condFalseTaken = condFalseTaken
        self.condTrueAddr = None
        self.condFalseAddr = None
        
    def condTaken(self, cond, addr):
        """
        Specifies that the given condition was taken.
        @param cond: The condition.
        @type cond: bool
        """
        if cond: 
            if not self.condTrueTaken:
                self.condTrueTaken = True
                self.condTrueAddr = addr
        elif not self.condFalseTaken:
            self.condFalseTaken = True
            self.condFalseAddr = addr
        
    def isFullyEvaluated(self):
        """
        Checks if the conditional branch was executed for both possible conditions (true or false) during runtime.
        @return: True or false.
        """
        return self.condFalseTaken and self.condTrueTaken
    
    def getCondAddr(self, cond):
        if cond == True:
            return self.condTrueAddr
        elif cond == False:
            return self.condFalseAddr
        return None 
    
class DynamicBranch(_Branch):
    
    def __init__(self, addr, characteristics, basicBlock):
        _Branch.__init__(self, addr, characteristics)
        self.branches = []
        self.basicBlock = basicBlock
        
class _BasicBlockExit:
        
        def __init__(self, exitBb):
            self.bb = exitBb
            self.wasTaken = False
            
        def taken(self):
            self.wasTaken = True
        
class BasicBlock:
    
    DYNAMIC_EXIT = -1
    
    class TYPE:
        GENERIC = 0
        START_BLOCK = 1
        END_BLOCK = 2
        VIRTUAL = 4
        ADJACENT_TO_VIRTUAL = 8
        SINGLE_EXIT = 16
        IN_DELAY_SLOT = 32
        
    def __str__(self):
        s = "Basic-block\r\n"
        s += "type: %d\r\n" % self.type
        s += "nExits: %d\r\n" % self.nExits
        s += "start: %x\r\n" % self.startAddr
        if self.endAddr is not None:
            s += "end: %x\r\n" % self.endAddr
        else:
            s += "end: Not specified\r\n"
             
        s += "Known exits:\r\n"
        for knownExit in self.knownExits.values():
            s += "\t%x (type %d)\r\n" % (knownExit.bb.startAddr, knownExit.bb.type)
            
        return s
    
    def __init__(self, startAddr, endAddr=None, knownPredecessors=None, knownExits=None, nExits=None, t=0):
        
        self.startAddr = startAddr
        self.endAddr = endAddr
        self.type = t
        self.isSplit = False
        self.calls = {}
        self.fullyTraced = False
        
	# list is used to store all possible exits of an BB (originally to identify addresses of suspicious edges)
	# added by andre
        self.possibleExits = list()

        if knownExits is not None:
            self.knownExits = {bb.startAddr : _BasicBlockExit(bb) for bb in knownExits}
        else:
            self.knownExits = {}
    
        self.knownPredecessors = knownPredecessors or []
            
        self.timesEndAddrSet = 0
        
        self.setNExits(nExits)
        
    def setNExits(self, n):
        self.nExits = n
        if n == 1:
            self.addType(BasicBlock.TYPE.SINGLE_EXIT)
            
    def addCall(self, addr, addrCallee):
        if addr not in self.calls:
            self.calls[addr] = []
        self.calls[addr].append(addrCallee)
    
    def addExit(self, nextBb):
        
        if nextBb is None:
            return
        
        if nextBb.startAddr not in self.knownExits:
            self.knownExits[nextBb.startAddr] = _BasicBlockExit(nextBb)
            
    def exitTaken(self, addr):
        
        if addr in self.knownExits:
            self.knownExits[addr].taken()
        
    def setEndAddr(self, endAddr):
        self.endAddr = endAddr
        self.timesEndAddrSet += 1

    def isCompletelyDefined(self):
        if self.nExits is None:
            return False
        
        if len(self.knownExits) < self.nExits:
            return False
        
        for knownExit in self.knownExits.values():
            if not knownExit.wasTaken:
                return False
            
        return True
        
    def isFullyTraced(self):
        return self.fullyTraced
    
    def setFullyTraced(self):
        self.fullyTraced = True
    
    def addType(self, additionalType):
        self.type |= additionalType
        
    def split(self, addr, endAddr=-1):
        """
        Splits the basic block into two. This function shall only be used in the case of the latter discovery of a jump into the midst of an already defined basic block.
        Creates two new basic blocks that are saved to self.hiBb and self.loBb. 
        @param addr: The address where to split the block. The address of the first instruction of the new basic block. 
        """
        if not (addr >= self.startAddr and addr <= self.endAddr):
            raise AddressOutOfRange("The supplied address lies not within the basicblock")
        
        if self.isSplit:
            log(DEBUG_LEVEL_TRACE_EVENTS, "[!] Going to split a basic block that was already split (address: %x)." % addr)
            # dispatch to lower level bbs
            if addr < self.loBb.startAddr:
                return self.hiBb.split(addr, endAddr)
            else:
                return self.loBb.split(addr, endAddr)
        
        if (endAddr == -1):
            newEndAddr = addr -1 # TODO: rather hackish, unfortunately we do not know the size of the previous instruction
        else:
            newEndAddr = endAddr    
        
        self.loBb = BasicBlock(addr, self.endAddr, nExits=self.nExits)
        self.loBb.knownExits = self.knownExits
        self.hiBb = BasicBlock(self.startAddr, newEndAddr, nExits=1)
        self.hiBb.addExit(self.loBb)
        
        # now distribute flags
        hiType = (self.type & self.TYPE.ADJACENT_TO_VIRTUAL) | (self.type & self.TYPE.START_BLOCK) | self.TYPE.SINGLE_EXIT 
        self.hiBb.addType(hiType)
        loType = (self.type & self.TYPE.END_BLOCK) | (self.type & self.TYPE.SINGLE_EXIT)
        self.loBb.addType(loType)
        
        self.isSplit = True
        return (self.hiBb, self.loBb)
        
    def translate(self, translator):
        
        bbTranslator = lambda x: translator(x) or x
        self.startAddr = bbTranslator(self.startAddr)
        self.endAddr = bbTranslator(self.endAddr)
        self.calls = {bbTranslator(addr) : [bbTranslator(addrCallee) for addrCallee in self.calls[addr]] for addr in self.calls}
        
    def getAllCalls(self):
        ret = []
        for calls in self.calls.values():
            ret += calls
        return ret

class BasicBlockTracer(_Tracer):
    """
    Control-flow tracer for a single function.
    """
    
    EXAMINE_DYNAMIC_BRANCHES = False # TODO: ugly
    
    def __init__(self, pygdb, function, maxHits=-1, requiredCallStack=None, functionTracer=None, breakOnEntireFunction=None):
        """
        @param pygdb: The pygdb instance to use.
        @param function: Address of the function to trace.
        @param maxHits: The number of hits before ignoring a basic block. 
        @param requiredCallStack: [OPTIONAL] If given, the given function will only be traced in case the certain call-stack is encountered. If not given and breakOnEntireFunction is not given, breakpoints will be set on the entire function.
        @param functionTracer: [OPTIONAL] Must be supplied whenever requiredCallStack is supplied.  
        @type functionTracer: FunctionTracer
        @param breakOnEntireFunction: [OPTIONAL] If false only the function's entry-point is monitored as possible entry. If true every instruction is a valid entry (requires symbols).
        """
        _Tracer.__init__(self, pygdb, maxHits)
        self.basicBlocks = {}
        self.virtBasicBlocks = {}
        self.condBranches = {}
        self.dynamicBranches = {}
        self.function = function
        self.functionTracer = None
        self.requiredCallStack = None
        self.activeThread = None
        self.activeProcess = None
        
        if breakOnEntireFunction is None:
            self.breakOnEntireFunction = (requiredCallStack is None)
        else:
            self.breakOnEntireFunction = breakOnEntireFunction 
        
        if self.breakOnEntireFunction:
            # So an empty call-stack is supplied...
            # In this case we break on any address inside the given function since it is likely, that execution won't start at the beginning of the function but after a call inside it.
            # E.g. in the case of a command dispatcher function it is likely that the application currently waits in a listen() call inside the command dispatcher function.
            self.functionEnd = self.function + self.pygdb.environment.getSizeOfFunction(self.pygdb.environment.unrebaseCodeAddr(self.pygdb, self.function))
        elif requiredCallStack is not None and functionTracer is not None:
            rcs = CallStack(requiredCallStack)
            self.functionTracer = functionTracer
            self.requiredCallStack = rcs
                
    def _setupKnownPointsOfInterest(self, pid=GDB.THREADS.ALL):
        # set breakpoints on other already known points of interest
        self.pygdb.setBreakpoints(self.condBranches.keys(), self._eventDispatcher, self, pid)
        self.pygdb.setBreakpoints(self.basicBlocks.keys(), self._eventDispatcher, self, pid)
        self.pygdb.setBreakpoints(self.virtBasicBlocks.keys(), self._eventDispatcher, self, pid)
        self.pygdb.setBreakpoints(self.dynamicBranches.keys(), self._eventDispatcher, self, pid)            
            
    def _teardownKnownPointsOfInterest(self, pid=GDB.THREADS.ALL):
        
        self.pygdb.removeBreakpoints(self.condBranches.keys(), bpCallback=self._eventDispatcher, pid=pid)
        self.pygdb.removeBreakpoints(self.basicBlocks.keys(), bpCallback=self._eventDispatcher, pid=pid)
        self.pygdb.removeBreakpoints(self.virtBasicBlocks.keys(), bpCallback=self._eventDispatcher, pid=pid)
        self.pygdb.removeBreakpoints(self.dynamicBranches.keys(), bpCallback=self._eventDispatcher, pid=pid)
                
    def setup(self):
        
        if self.functionTracer is not None:
            self.functionTracer.setup()
            
        self._hookTargetFunction()
                
    def _hookTargetFunction(self):
        if self.breakOnEntireFunction:
            self.pygdb.setBreakpointRange(self.function, self.functionEnd, self._bpDispatcher, self, GDB.THREADS.ALL)
        else:
            self.pygdb.setBreakpoint(self.function, self._bpDispatcher, self, GDB.THREADS.ALL)
            
    def _unhookTargetFunction(self):
        if self.breakOnEntireFunction:
            self.pygdb.removeBreakpointRange(self.function, self.functionEnd, GDB.THREADS.ALL, self._bpDispatcher)
        else:
            self.pygdb.removeBreakpoint(self.function, GDB.THREADS.ALL, bpCallback=self._bpDispatcher)
            
    def _unplugFunctionTracer(self):
        self.functionTracer.unplug()
        
    def _replugFunctionTracer(self):
        
        if not self.breakOnEntireFunction and self.functionTracer is not None:
            self.functionTracer.replug()
            # overwrite breakpoint at function to trace
            self.pygdb.setBreakpoint(self.function, self._bpDispatcher, self, GDB.THREADS.ALL)
        
    def findBasicBlock(self, addr):
        """
        Finds the basic block that contains the given address.
        @param addr: The address to look for.
        @return: The basic block that contains the address. If not matching basic block was found, None is returned.
        """
        if addr in self.basicBlocks:
            return self.basicBlocks[addr], True
        
        for bb in self.basicBlocks.values():
            if (addr >= bb.startAddr and addr <= bb.endAddr):
                return bb, False
             
        return None, False
    
    def _done(self):
        self.finalizeAllTraces()
    
    def finalizeAllTraces(self):
        """
        Checks alls traces for late-split basic blocks and adds missing implicit waypoints for those. 
        This function is necessary since the basic block tracer does not disassebmle a function and only discovers bracnhes through single-stepping. 
        """
        for trace in self.traces.values():
            trace.finalize()    
        
    def _createBasicBlock(self, addr, t=BasicBlock.TYPE.GENERIC):
        """
        Convenience function for creating new basic blocks. Splits an already existing block if necessary and does further clean-up.
        @param addr: The address at which the new basic block is to be created.
        @param t: The type of the basic-block to create.
        @return: The newly created basic block
        """
        existingBb, exactMatch = self.findBasicBlock(addr) 
        if existingBb:
            if exactMatch:
                newBb = existingBb
            else:
                hiBb, loBb = existingBb.split(addr)
                # replace old basic block with new high basic block
                self.basicBlocks[existingBb.startAddr] = hiBb
                # self.basicBlocks[addr] = existingBb.loBb
                newBb = loBb
        else:
            newBb = BasicBlock(addr, t)
        return newBb
        
    def _setActiveThread(self, event):
        self.activeThread = event.tid
        self.activeProcess = event.pid
        
        self._unhookTargetFunction()
        self._setupKnownPointsOfInterest(self.activeProcess)
        
    def _unsetActiveThread(self):
        self._teardownKnownPointsOfInterest(self.activeProcess)
        
        self.activeThread = None
        self.activeProcess = None
        
        # XXX: Rather hackish, but....
        self.breakOnEntireFunction = False
        ###############################
        self._hookTargetFunction()
        
    def _addBasicBlock(self, bb):
        assert self.activeProcess is not None
        if not bb.startAddr in self.basicBlocks:
            self.basicBlocks[bb.startAddr] = bb
            # only add breakpoint if basic block is not adjacent to a virtual basic block (no bp needed in that case)
            if bb.type & BasicBlock.TYPE.ADJACENT_TO_VIRTUAL == 0:
                self.pygdb.setBreakpoint(bb.startAddr, self._eventDispatcher, self, self.activeProcess)
               
    def _addVirtualBasicBlock(self, vbb, bpAddr=None):
        assert self.activeProcess is not None
        if bpAddr is None:
            bpAddr = vbb.startAddr

        if not vbb.startAddr in self.virtBasicBlocks:
            self.virtBasicBlocks[bpAddr] = vbb
            self.pygdb.setBreakpoint(bpAddr, self._eventDispatcher, self, self.activeProcess)
        
    def _addCondBranch(self, cb):
        assert self.activeProcess is not None
        if not cb.addr in self.condBranches:
            log(DEBUG_LEVEL_TRACE_EVENTS, "[i] Creating a new CB at %x." % cb.addr)
            self.condBranches[cb.addr] = cb
            self.pygdb.setBreakpoint(cb.addr, self._eventDispatcher, self, self.activeProcess)
            
    def _addDynamicBranch(self, db):
        assert self.activeProcess is not None
        if not db.addr in self.dynamicBranches:
            self.dynamicBranches[db.addr] = db
            self.pygdb.setBreakpoint(db.addr, self._eventDispatcher, self, self.activeProcess)
            
    def _removeCondBranch(self, addr):
        # a conditional branch is the only checkpoint type that is at some point removed
        assert self.activeProcess is not None
        self.condBranches.pop(addr)
        # if this is the last reference to that address, remove the breakpoint
        if addr not in self.basicBlocks and addr not in self.virtBasicBlocks:
            self.pygdb.removeBreakpoint(addr, self.activeProcess, bpCallback=self._eventDispatcher)
        
    def _bbEntryHandler(self, pygdb, startBb, tid):
        """
        Traces until it reaches an ret-instruction or enters an already catalogued basic-block.
        TODO: Consider likely-delay slots!
        """
        
        continueMode = PyGdb.CONTINUE.RUN
        bb = startBb
        while (bb is not None) and not bb.isFullyTraced():
            
            log(DEBUG_LEVEL_TRACE_EVENTS, "[i] Entering bb %x" % bb.startAddr) 
            
            nextBb = None
            nextAddr = bb.startAddr
            
            while True:
                addr = nextAddr
                
                # Is this the first instruction of the basic block?
                characteristics = pygdb.cpu.getInstrCharacteristics(pygdb, tid, addr)
                conditional = characteristics & instruction.CHARACTERISTIC.CONDITIONAL != 0
                jmp = characteristics & instruction.CHARACTERISTIC.JMP != 0
                dynamicBranch = characteristics & instruction.CHARACTERISTIC.DYNAMIC_BRANCH != 0 and BasicBlockTracer.EXAMINE_DYNAMIC_BRANCHES
                call = characteristics & instruction.CHARACTERISTIC.CALL != 0
                ret = characteristics & instruction.CHARACTERISTIC.RET != 0
                functionEnds = pygdb.cpu.isEndOfFunction(pygdb, tid, characteristics)
                
                if conditional:
                    condition = pygdb.cpu.evaluateCondInstr(pygdb, tid, addr)
                    
                # first check if we hit a ret instruction
                # TODO: What happens in the case of a conditional return?
                
                def functionEnd(bb):
                    bb.addType(BasicBlock.TYPE.END_BLOCK)
                    # no exits to other basic blocks in case of a ret
                    bb.setNExits(0)
                    
                if ret or functionEnds:
                    functionEnd(bb)
                    break
                
		# get (if exists) the next addresses of the true and false conditional branche (to store in the possibleExits list of the BB)
		# added by andre
                true_addr = pygdb.cpu.getNextPC(pygdb, tid, cond=True)
                false_addr = pygdb.cpu.getNextPC(pygdb, tid, cond=False)

                # Now already step to the next instruction.
                if call:
                    stepSuccess, nextAddr, stepIntoAddr = pygdb.stepOver(tid, stayInImage=False)
                else:
                    stepSuccess, nextAddr, stepIntoAddr = pygdb.stepOver(tid, stayInImage=True)
                    
                log(DEBUG_LEVEL_TRACE_EVENTS, "[i] Stepped to instruction %x in bb %x" % (nextAddr,bb.startAddr))
                
                if not stepSuccess:
                    # this condition can happen if the debugger is killed just when we're trying to step
                    # we just end for now...
                    log(DEBUG_LEVEL.IMPORTANT, "[!] Failed to step instruction. We therefore just assume the function ends at %x." % addr)
                    functionEnd(bb)
                    break
                
                # check if we jumped into another function. This is equivalent to a ret.
                if jmp and nextAddr in pygdb.environment.getFunctionsRebased(pygdb):
                    functionEnd(bb)
                    break
                
                # check if we jumped out of our image. This is as well equivalent to a ret.
                if not pygdb.environment.addrBelongsToImage(pygdb, nextAddr):
                    functionEnd(bb)
                    break
                
                # so we manipulated the pc, we need to change the continue type
                continueMode = PyGdb.CONTINUE.RUN_NO_CLEANUP
                # now evaluate the instruction we just stepped over
                    
                if characteristics & instruction.CHARACTERISTIC.HAS_DELAY_SLOT != 0:
                    # we have a delay slot, this a special case
                    # if the delay slot does not contain a conditional instruction everything is fine
                    # else we need to create a new virtual basic block
                    addrDelaySlot = pygdb.cpu.getAddressDelaySlot(addr)
                    characteristicsDelaySlot = pygdb.cpu.getInstrCharacteristics(pygdb, tid, addrDelaySlot)
                    
                    if characteristicsDelaySlot & instruction.CHARACTERISTIC.IMPLICIT_BRANCH != 0:
                        # in case of an implicit conditional branch to a virtual basic block, the current basic block only has one real exit
                        bb.setNExits(2)
                        condictionDelaySlot = pygdb.cpu.evaluateCondInstr(pygdb, tid, addrDelaySlot)
                        
                        # create the next concrete basic block
                        nextBb = self._createBasicBlock(nextAddr)
                        
                        # now add the virtual basic block
                        if addr not in self.virtBasicBlocks:
                            vbbDS = BasicBlock(startAddr=addrDelaySlot, endAddr=addrDelaySlot, knownExits=[nextBb], nExits=1, t=(BasicBlock.TYPE.VIRTUAL | BasicBlock.TYPE.IN_DELAY_SLOT))
                            self._addVirtualBasicBlock(vbbDS, addr)
                            
                        if condictionDelaySlot:
                            self.addWaypoint(vbbDS, tid)
                            
                        break
                            
                if call:
                    bb.addCall(addr, stepIntoAddr)
                        
                if dynamicBranch:
                    
                    db = DynamicBranch(addr, characteristics, bb)
                    self._addDynamicBranch(db)
                    if jmp:
                        bb.setNExits(BasicBlock.DYNAMIC_EXIT)
                        nextBb = self._createBasicBlock(nextAddr)
                        break
                        
                elif conditional:
                    # in case of a conditional instruction, this is the last instruction of the basicblock
                    bb.setNExits(2)
                    # check if this an implicit conditional instruction
                    if characteristics & instruction.CHARACTERISTIC.IMPLICIT_BRANCH != 0:
                        # create new basic block directly after the conditional instruction
                        nextBb = BasicBlock(nextAddr, t=BasicBlock.TYPE.ADJACENT_TO_VIRTUAL)
                        
                        # now add the virtual basic block
                        if addr not in self.virtBasicBlocks:
                            vbb = BasicBlock(startAddr=addr, endAddr=addr, knownPredecessors = [bb], knownExits=[nextBb], nExits=1, t=BasicBlock.TYPE.VIRTUAL)
                            self._addVirtualBasicBlock(vbb)
                        else:
                            vbb = self.virtBasicBlocks[addr]
                            
                        bb.addExit(vbb)
                        bb.setEndAddr(addr)
                        
                        if condition:
                            # smuggle the vbb in
                            ## add current bb
                            self._addBasicBlock(bb)
                            self._addWaypoint(bb, tid)
                            
                            ## set current bb to vbb, such that it is added in the next step
                            bb = vbb
                        
                    elif jmp:
			# add true and false conditional branch to possibleExits list of BB
			# added by andre
                        bb.possibleExits.append(false_addr)
                        bb.possibleExits.append(true_addr)

                        cb = CondBranch(addr, characteristics)
                        self._addCondBranch(cb)
                        self.condBranches[addr].condTaken(condition, nextAddr)
                        nextBb = self._createBasicBlock(nextAddr)
                        
                    else:
                        raise InvalidTracerState("This state should never be reached. Address: %x" % addr) 
                    
                    break
                elif jmp:
                    # unconditional jump
                    bb.setNExits(1)
                    # before creating a new bb, check if we branched into an already existing basic block
                    nextBb = self._createBasicBlock(nextAddr)
                    break
            
                # finally check if we stepped on an already known bb
                elif nextAddr in self.basicBlocks:
                    bb.setNExits(1)
                    nextBb = self.basicBlocks[nextAddr]
                    break
                
            log(DEBUG_LEVEL_TRACE_EVENTS, "[i] Completely traced bb %x" % bb.startAddr)
            bb.addExit(nextBb)
            bb.setEndAddr(addr)
            bb.setFullyTraced()
            self._addBasicBlock(bb)
            self._addWaypoint(bb, tid)
            bb = nextBb
        
        return continueMode
    
    def _addWaypoint(self, bb, tid):
        lastBb = self._getLastBb(tid)
        if lastBb is not None:
            lastBb.exitTaken(bb.startAddr)
            
        self.traces[tid].addWaypoint(bb)
        
    def _getLastBb(self, tid):
        return self.traces[tid].getLastWaypoint()
        
    def _virtCondBranchHandler(self, pygdb, event):
        
        log(DEBUG_LEVEL_TRACE_EVENTS, "Vbb hit at %x" % event.addr)
        vbb = self.virtBasicBlocks[event.addr]
        self._processVirtCondBranch(pygdb, vbb, event.tid)
        
        # add adjacent bb
        if len(vbb.knownExits) != 1:
            raise InvalidTracerState("A virtual basic-block was encountered that has not exactly one exit. This should never be the case.")
        
        nextBb = vbb.knownExits.values()[0].bb
        self._processBb(pygdb, nextBb, event.tid)
        
        return PyGdb.CONTINUE.RUN_KEEP_BREAKPOINT
    
    def _virtCondBranchInDelaySlotHandler(self, pygdb, event):
        """
        TODO: Currently not in use! Think about how to best represent cond. instruction in delay slots on graph-level. 
        The best solution is probably to treat delay slots as distinct basic blocks. This way the real order of instructions would not be messed up.
        """
        willExecute = True
        characteristics = pygdb.cpu.getInstrCharacteristics(pygdb, event.tid, event.addr)
        if characteristics & instruction.CHARACTERISTIC.DELAY_SLOT_LIKELY != 0:
            willExecute = pygdb.cpu.evaluateCondInstr(pygdb, event.tid, event.addr)
            
        if willExecute:
            addrDelaySlot = pygdb.cpu.getAddressDelaySlot(event.addr)
            log(DEBUG_LEVEL_TRACE_EVENTS, "Vbb hit in delay-slot at %x" % addrDelaySlot)
            vbbDS = self.virtBasicBlocks[addrDelaySlot]
            self._processVirtCondBranch(pygdb, vbbDS, event.tid)
        
        return PyGdb.CONTINUE.RUN_KEEP_BREAKPOINT
    
    def _processVirtCondBranch(self, pygdb, vbb, tid):
        
        condition = pygdb.cpu.evaluateCondInstr(pygdb, tid, vbb.startAddr)
        if condition:
            self._addWaypoint(vbb, tid)
        
    def _condBranchHandler(self, pygdb, event):
        
        """
        TODO: Dirty dirty hack, revert to release 'PROFTPD FULL AUTH' in order to clean this method up.
        """
        log(DEBUG_LEVEL_TRACE_EVENTS, "[e] Cb hit at %x" % event.addr)
        
        # evaluate condition
        cb = self.condBranches[event.addr]
        assert cb.characteristics & instruction.CHARACTERISTIC.FAR_BRANCH == 0
        
        condition = pygdb.cpu.evaluateCondInstr(pygdb, event.tid, event.addr)
        log(DEBUG_LEVEL_TRACE_EVENTS, "[i] Condition of CB at %x is %s." % (cb.addr, str(condition))) 
        
        if cb.getCondAddr(condition) is None:
            log(DEBUG_LEVEL_TRACE_EVENTS, "[i] Cb is now fully evaluated, removing bp.")
            pygdb.removeBreakpoint(event.addr, GDB.THREADS.ALL)
            pygdb.stepInto(event.tid, False)
            nextAddr = pygdb.getPC(event.tid)
            
            newBb = self._createBasicBlock(nextAddr)
            return self._bbEntryHandler(pygdb, newBb, event.tid)
        else:
            # get next addr for the opposite condition
            nextAddr = pygdb.cpu.getNextPC(pygdb, event.tid, not condition)
            if nextAddr is None:
                # fallback
                log(DEBUG_LEVEL_TRACE_EVENTS, "[i] Cb is not fully evaluated yet. Could not determine other address.")
                return PyGdb.CONTINUE.RUN_KEEP_BREAKPOINT
            
            log(DEBUG_LEVEL_TRACE_EVENTS, "[i] Cb is not fully evaluated yet. Other adress is %x." % nextAddr)
            pygdb.removeBreakpoint(event.addr, GDB.THREADS.ALL)
            newBb = self._createBasicBlock(nextAddr)
            self._addBasicBlock(newBb)
            lastBb = self.traces[event.tid].getLastWaypoint()
            lastBb.addExit(newBb)
        
            return PyGdb.CONTINUE.RUN_KEEP_BREAKPOINT
    
    def _dynamicBranchHandler(self, pygdb, event):
        
        log(DEBUG_LEVEL_TRACE_EVENTS, "Dcb hit at %x" % event.addr)
        pygdb.stepInto(event.tid, True)
        nextAddr = pygdb.getPC(event.tid)
        db = self.dynamicBranches[event.addr] 
        if db.characteristics & instruction.CHARACTERISTIC.CALL != 0:
            db.basicBlock.addCall(event.addr, nextAddr)
        else:
            db.basicBlock.addExit(nextAddr)
            if db.characteristics & instruction.CHARACTERISTIC.FAR_BRANCH == 0:
                newBb = BasicBlock(pygdb.getPC(event.tid))
                self._addBasicBlock(newBb)
                return self._bbEntryHandler(pygdb, newBb, event.tid)
            
        return PyGdb.CONTINUE.RUN_KEEP_BREAKPOINT
    
    def _bbHandler(self, pygdb, event):
        
        bb = self.basicBlocks[event.addr]
        log(DEBUG_LEVEL_TRACE_EVENTS, "[e] Hit known bb %x in %x" % (bb.startAddr, event.tid))
        if bb.isFullyTraced():
            log(DEBUG_LEVEL_TRACE_EVENTS, "[i] Bb was already fully traced. Continuing...")
            self._processBb(pygdb, bb, event.tid)
            return PyGdb.CONTINUE.RUN_KEEP_BREAKPOINT
        else:
            log(DEBUG_LEVEL_TRACE_EVENTS, "[i] Bb was not fully traced yet. Doing so now...")
            continueMode = self._bbEntryHandler(pygdb, bb, event.tid)
            return continueMode
    
    def _processBb(self, pygdb, bb, tid):
        self._addWaypoint(bb, tid)
            
    def _isKnownAddr(self, addr):
        return (addr in self.condBranches) or (addr in self.basicBlocks) or (addr in self.virtBasicBlocks) or (addr in self.dynamicBranches) 
        
    @staticmethod
    def _bpDispatcher(self, pygdb, event):
        
        # TODO: Dirty workaround for gdbserver screw up
        # pygdb.enableDieOnProcessExit(True)
        ###############################################
        
        log(DEBUG_LEVEL_TRACE_EVENTS, "[e] Tracer got notified of event at %x in thread %x." % (event.addr, event.tid))
        if event.tid not in self.traces:
            self.traces[event.tid] = BasicBlockTrace(event.tid)
        
        # check if this is a first time hit
        if self.breakOnEntireFunction: 
            pass
        else:
            # check for this being the entry event of the to be traced function
            if not event.addr == self.function:
                raise InvalidTracerState("_bpDispatcher should only be entered through its entry-point (in case breakOnEntireFunction is False).")
            
            if self.requiredCallStack is not None and self.functionTracer is not None:
                currentCallStack = self.functionTracer.getCurrentCallStack(event.tid)
                # check if the required callstack fits to the current callstack
                if not self.requiredCallStack.fitsInto(currentCallStack):
                    # this is not the callstack we wanted
                    # clear own breakpoints and hand the event to the function tracer
                    self._teardownKnownPointsOfInterest(event.pid)
                    return FunctionTracer._callHandler(self.functionTracer, pygdb, event)
                
                # this is the callstack we wanted, temporarily set own breakpoints and unplug the function tracer and start tracing on basic block level
                
                self._unplugFunctionTracer()
                        
        self._setActiveThread(event)
        
        if not self._isKnownAddr(event.addr):
            # TODO: little hack to prevent occasional deadlocks while tracing funcs in OpenSSH 
            pygdb.disableFollowFork()
            #
            newBb = self._createBasicBlock(event.addr, BasicBlock.TYPE.START_BLOCK)
            continueMode = self._bbEntryHandler(pygdb, newBb, event.tid)
            self._aboutToContinue(event.tid)
            return continueMode
        
        else:
            # dispatch the event
            return BasicBlockTracer._eventDispatcher(self, pygdb, event)
    
    def _aboutToContinue(self, tid):
        lastBb = self._getLastBb(tid)
        if lastBb.type & BasicBlock.TYPE.END_BLOCK != 0:
            self._unsetActiveThread()
            log(DEBUG_LEVEL_TRACE_EVENTS, "[i] Basic-block %x was the last one in the function. Continuing..." % lastBb.startAddr)
        
    @staticmethod
    def _eventDispatcher(self, pygdb, event):
    
        assert event.tid == self.activeThread
            
        # The tracer has its own virtual debug-loop.
        # TODO: Dispatch to _virtCondBranchInDelaySlotHandler as well
        continueMode = PyGdb.CONTINUE.RUN_KEEP_BREAKPOINT
            
        # _bbEntryHandler is the only handler that probably will step, so we call it as last one and pass its returned continue mode
        if event.addr in self.condBranches:
            continueMode = self._condBranchHandler(pygdb, event)
        elif event.addr in self.virtBasicBlocks:
            continueMode = self._virtCondBranchHandler(pygdb, event)
        elif event.addr in self.basicBlocks:
            continueMode = self._bbHandler(pygdb, event)
        elif event.addr in self.dynamicBranches:
            continueMode = self._dynamicBranchHandler(pygdb, event)
        else:
            raise InvalidTracerState("Dunno how to process event")
        
        self._aboutToContinue(event.tid)
            
        return continueMode
        
        
        
    
