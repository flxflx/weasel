'''
Created on 08.08.2012

@author: Felix
'''
import copy
from sets import Set
from tools import findSubLists, findFirst
import tracer

class Trace:
    VIRTUAL_STARTING_NODE = 0
    
    def __len__(self):
        return len(self.way)
    
    def _cmp__(self, other):
        ls = len(self.way)
        lo = len(other.way)
        return ls < lo and -1 or ls > lo and 1 or 0
    
    def __init__(self, thread):
        self.thread = thread
        self.way = []
        self.items = Set()
        
    def addWaypoint(self, addr, prepend=False):
        i = (not prepend) and 1 or 0
        self.way.insert(len(self.way)*i, addr)
        self.items.add(addr)
        
    def getLastWaypoint(self):
        if len(self.way) == 0:
            return None
        
        return self.way[-1]
        
    def __str__(self):
        s = "Trace thread %x:\r\n" % self.thread
        for i in range(len(self.way)):
            addr = self.getWaypointAddress(i)
            tmp = isinstance(addr, unicode) and addr or "%x" % addr
            s += "%s -> " % tmp 
        return s
    
    def getWay(self):
        return self.way
    
    def getWaypointAddress(self, step):
        """
        Gets the address of the n-th step. This method should be overwritten if the way attribute stores anything else than plain addresses.
        @param step: The step to get the address for.
        """    
        return self.way[step]
    
    def _fillDigraph(self, digr):
        if len(self.way) == 0:
            return
         
        # add root node
        digr.add_node(self.getWaypointAddress(0))
        for i in range(1,len(self.way)):
            addr = self.getWaypointAddress(i)
            edge = (self.getWaypointAddress(i-1), addr)
            
            if not digr.has_node(addr):
                digr.add_node(addr)
                
            if not digr.has_edge(edge):
                digr.add_edge(edge, label=[i-1])
            else:
                label = digr.edge_label(edge)
                label.append(i-1)
                digr.set_edge_label(edge,label=label)
            
    def getDigraph(self):
        """
        Returns the trace in the form of a directed graph (instance of pygraph.classes.digraph).
        @return: The directed graph.
        """
        try:
            from pygraph.classes.digraph import digraph
        except ImportError:
            print "Please install the python-graph library to use this feature."
            raise ImportError()
        
        digr = digraph()
        self._fillDigraph(digr)
        return digr
    
    def getVirtualStartingNode(self):
        return self.VIRTUAL_STARTING_NODE
    
    def getNormalizedSequence(self, depth=-1):
        """
        Returns the trace in the form of a normalized sequence. Read normalized here as "ready to work on". 
        A normalized function call sequence would be of the form (D, A, B, A, C, A, C, A, D) if D calls A, calls B, returns, calls C, returns, calls C, returns, returns.
        A normalized sequence for a simple trace is just the trace itself (D, A, B, C, C)
        @param depth: [OPTIONAL] The depth of the sequence. '-1' means "full depth". Only has effect for trace-types with an explicit tree-like order (e.g. function-traces).  
        @return: The normalized sequence (list). 
        """
        return self.getWay()
    
    def translate(self, translator):
        """
        Makes the trace translate all its addresses using the given translator.
        @param translator: A callback function expecting exactly one argument (the to be translated address) and returning exactly one value (the translated address).
        """
        t = Trace._normalizeTranslator(translator)
        self.way = [t(x) for x in self.way]
        
    @staticmethod
    def _normalizeTranslator(translator):
        if isinstance(translator, dict):
            return lambda x : x in translator and translator[x] or None
        return translator
    
    def getTracesBetween(self, start, end):
        """
        Returns the traces between the given "start" and "end" items (including both ends).
        @param start: The start-item
        @param end: The end-item
        @return: A list of zero, one or multiple new trace objects. Multiple trace objects are returned in case there are multiple sequences starting with "start" and ending with "end". 
        """
        subWays = findSubLists(self.way, start, end)
        traces = []
        for subWay in subWays:
            newTrace = copy.copy(self)
            self.way = subWay[1:-1] # cut-off the first an the last
            traces.append(newTrace)
        return traces
    
class CallStack:
    
    def __len__(self):
        return self.rawCallStack.__len__()
    
    def __iter__(self):
        return self.rawCallStack.__iter__()
    
    def __getitem__(self, key):
        return self.rawCallStack.__getitem__(key)
    
    def __init__(self, rawCallStack):
        """
        @param rawCallStack: The callstack in raw form, top/left to down/right
        @type rawCallStack: List
        """
        
        self.rawCallStack = rawCallStack
        
    def fitsInto(self, otherCallStack):
        """
        Checks if the call-stack fits into the given call-stack.
        E.g. a->b->c would fit into x->y->a->b->c but not into x->a->b->c->y.
        @param otherCallStack: The other call-stack to check against.
        @return: Boolean flag
        """
        if len(otherCallStack) < len(self):
            return False
        
        for i in range(len(self)):
            if self[-(i+1)] != otherCallStack[-(i+1)]:
                return False
        
        return True
                
class Call:
    
    def __eq__(self, other):
        if isinstance(other, Call):
            return self.addr == other.addr and self.retAddr == other.retAddr
        else:
            return other == self.addr
        
    def __init__(self, addr, retAddr):
        self.addr = addr
        self.retAddr = retAddr
        self.retValues = None
        
    def translate(self, translator):
        self.addr = translator(self.addr)
        self.retAddr = translator(self.retAddr)
        
    def setRetValues(self, retValues):
        self.retValues = retValues
        
class Return:
    
    def __eq__(self, other):
        return self.call == other
    
    def __init__(self, call):
        self.call = call
        
    def translate(self, translator):
        pass
        
class FunctionTrace(Trace):
            
    def __init__(self, thread, startingNode=None):
        Trace.__init__(self, thread)
        self.openCallsStack = []
        self.eventStack = []
        self.removedBreakpoints = []
        
        _startingNode = startingNode or FunctionTrace.VIRTUAL_STARTING_NODE
        self.insertStartingNode(_startingNode)
        
                
    def call(self, addr, retAddr, prepend=False):
        i = (not prepend) and 1 or 0
        call = Call(addr, retAddr)
        
        self.openCallsStack.insert(len(self.openCallsStack)*i, call)
        self.eventStack.insert(len(self.eventStack)*i, call)
            
        self.addWaypoint(addr, prepend)
    
    # returns true if this was a "real" return address 
    def ret(self, retAddr, retValues):
        closedCalls = 0
        while len(self.openCallsStack) > 0 and self.openCallsStack[-1].retAddr == retAddr:
            lastCall = self.openCallsStack.pop()
            lastCall.setRetValues(retValues)
            self.eventStack.append(Return(lastCall))
            closedCalls += 1
        
        return closedCalls
        
    def __str__(self):
        tabs = 0
        s = "Trace thread %d:\r\n" % self.thread
        for event in self.eventStack:
            if isinstance(event, Call):
                tmp = (isinstance(event.addr, int) or isinstance(event.addr, long)) and "%x" % event.addr or event.addr
                s += "\t"*tabs + ("%s:" % tmp)
                if event.retAddr is not None:
                    s += "%x\r\n" % event.retAddr
                else:
                    s += "%s\r\n" % "(unknown)"
                tabs += 1
            else:
                tabs -= 1       
        return s
    
    @staticmethod
    def _addDiedges(digr, node, eventStack, i):
        # add self
        if not digr.has_node(node):
            digr.add_node(node)
        
        if len(eventStack) == 0:
            return i

        event = eventStack.pop(0)
        while not isinstance(event, Return):
            # add subnode
            subnode = event.addr
            j = FunctionTrace._addDiedges(digr, subnode, eventStack, i+1)
            # add corresponding edge
            edge = (node,subnode)
            if not digr.has_edge(edge):
                digr.add_edge(edge, label=[i])
            else:
                label = digr.edge_label(edge)
                label.append(i)
                digr.set_edge_label(edge,label=label)
                
            i = j
            if len(eventStack) == 0:
                break
            event = eventStack.pop(0)    
        return i
            
    def _fillDigraph(self, digr):    
        eventStack = copy.copy(self.eventStack)
        if len(eventStack) == 0:
            return digr
        startingNode = eventStack.pop(0)
        FunctionTrace._addDiedges(digr, startingNode.addr, eventStack, 0)
        return digr
    
    def getNormalizedSequence(self, maxDepth=-1):
        eventStack = copy.copy(self.eventStack)
        # insert dummy in front of event stack
        if len(eventStack) == 0:
            return []
        startingEvent = eventStack.pop(0)
        seq = [startingEvent.addr]
        i = 0
        while i < len(eventStack) and i >= 0:
            event = eventStack[i]
            if isinstance(event, Call):
                # call
                if i <= maxDepth or maxDepth == -1:
                    seq.append(event.addr)
                i += 1
            else:
                # ret
                # remove ret and corresponding call
                eventStack = eventStack[:i-1] + eventStack[i+1:]
                i -= 1
        return seq
    
    def translate(self, translator):
        t = Trace._normalizeTranslator(translator)
        Trace.translate(self, t)
        for item in self.eventStack:
            item.translate(t)
            
        self.startingNode = t(self.startingNode)
        
            
    def _updateWay(self):
        self.way = []
        for item in self.eventStack:
            if isinstance(item, Call):
                self.way.append(item.addr)
            
    def getTracesBetween(self, start, end):
        
        traces = []
        iCallStart = findFirst(self.eventStack, start, Call)
        while iCallStart in range(len(self.eventStack)):
            iCallEnd = findFirst(self.eventStack, end, Call, iCallStart+1)
            if iCallEnd not in range(len(self.eventStack)):
                break
            
            # now walk the event-stack, looking for the corresponding ret event
            i = iCallEnd+1
            openCalls = 1
            while i in range(len(self.eventStack)) and openCalls > 0:
                event = self.eventStack[i]
                if isinstance(event, Call):
                    openCalls += 1
                else:
                    openCalls -= 1
                    
                i += 1
            
            iRetEnd = i-1
            newTrace = self.getSubTrace(iCallStart, iRetEnd)
            traces.append(newTrace)
            iCallStart = findFirst(self.eventStack, start, Call, iCallStart+1)
            
        return traces
    
    def getSubTrace(self, indexStart, indexEnd):
        
        newTrace = copy.copy(self)
        if indexEnd == -1:
            newTrace.eventStack = self.eventStack[indexStart:]
        else:
            newTrace.eventStack = self.eventStack[indexStart:indexEnd+1]
            
        if len(newTrace.eventStack) > 0:
            newTrace.startingNode = newTrace.eventStack[0].addr
        else:
            newTrace.startingNode = FunctionTrace.VIRTUAL_STARTING_NODE
            
        newTrace._updateWay()
        return newTrace
    
    def insertStartingNode(self, addr):
        """
        Adds a topmost starting node.
        """
        self.startingNode = addr
        self.call(self.startingNode, FunctionTrace.VIRTUAL_STARTING_NODE, prepend=True)
             
    def getWaysBetween(self, start, end):
        """
        Gets all direct call-stacks from one function to another (including both ends)
        @param start: The function to start at; If None, then the virtual starting node of the trace is used.
        @param end: The function to end at
        @return: A list of call-stacks
        """
        start = start or self.startingNode
        ways = []
        iStart = findFirst(self.eventStack, start, Call, 0)
        while iStart in range(len(self.eventStack)):
            iEnd = findFirst(self.eventStack, end, Call, iStart)
            while iEnd in range(len(self.eventStack)):
                way = []
                wayValid = True
                for i in range(iStart, iEnd+1):
                    event = self.eventStack[i] 
                    if isinstance(event, Call):
                        way.append(event.addr)
                    else:
                        # check if ret and last call belong together
                        if len(way) == 0:
                            raise Exception("Invalid state: Encountered a ret (call: %x, ret-addr: %x) without any open calls. iStart: %d (%x), iEnd: %d (%x), i: %d" % (event.call.addr, event.call.retAddr, iStart, start, iEnd, end, i))
                        
                        if event.call.addr != way[-1]:
                            raise Exception("Invalid state: Latest call (%x) and ret (%x) events do not match." % (way[-1], event.call.addr))
                        way.pop()
                    
                    # Did we hit the end of the start function?    
                    if len(way) == 0:
                        wayValid = False
                        break
                
                if wayValid:
                    ways.append(way)
                
                if len(way) >= 2:
                    lastCaller = way[-2]  
                    iEndLasterCaller = findFirst(self.eventStack, lastCaller, Return, iEnd+1)
                    if iEndLasterCaller == -1:
                        return ways
                
                    iEnd = findFirst(self.eventStack, end, Call, iEndLasterCaller)
                else:
                    iEnd = findFirst(self.eventStack, end, Call, iEnd+1)
                    
            iStart = findFirst(self.eventStack, start, Call, iStart+1)
            
        return ways
    
    def getTracesWithCallStack(self, callstack):
        
        start = callstack[0]
        end = callstack[-1]
        subTraces = []
        iStart = findFirst(self.eventStack, start, Call, 0)
        while iStart in range(len(self.eventStack)):
            iEnd = findFirst(self.eventStack, end, Call, iStart)
            while iEnd in range(len(self.eventStack)):
                way = []
                wayValid = True
                for i in range(iStart, iEnd+1):
                    event = self.eventStack[i] 
                    if isinstance(event, Call):
                        way.append(event.addr)
                    else:
                        way.pop()
                        
                    if len(way) == 0:
                        wayValid = False
                        break
                
                # compare given callstack with current callstack
                if wayValid and len(callstack) == len(way):
                    equal = True
                    for i in range(len(callstack)):
                        if callstack[i] != way[i]:
                            equal = False
                            break
                        
                    if equal:
                        # create subtrace
                        iEndRet = findFirst(self.eventStack, end, Return, iEnd)
                        subTraces.append(self.getSubTrace(iEnd, iEndRet))
                
                iEnd = findFirst(self.eventStack, end, Call, iEnd+1)
            iStart = findFirst(self.eventStack, start, Call, iStart+1)
            
        return subTraces
            
    def getVirtualStartingNode(self):
        return self.startingNode
    
    def getCurrentCallStack(self):
        """
        Gets the current call-stack of the trace.
        @rtype: List
        """
        
        cs = []
        for event in self.eventStack:
            if isinstance(event, Call):
                cs.append(event.addr)
            elif len(cs) > 0:
                cs.pop()
                
        return cs
    
    def getCalls(self):
        return [event for event in self.eventStack if isinstance(event, Call)]
    
    def getFunctionReturnValues(self):
        retValues = {}
        
        for event in self.eventStack:
            if not isinstance(event, Call):
                continue
            
            if event.retValues is None:
                continue
            
            if event.addr not in retValues:
                retValues[event.addr] = []
                
            if event.retValues not in retValues[event.addr]: 
                retValues[event.addr].append(event.retValues)
            
        return retValues   
    
    def getTopmostOpenCall(self):
        if len(self.openCallsStack) == 0:
            return None
        
        return self.openCallsStack[-1]
            
            
class BasicBlockTrace(Trace):
    
    def __init__(self, thread):
        Trace.__init__(self, thread)
        self.basicBlocks = {}
    
    def finalize(self):
        """
        Checks all visited basic blocks for late-splits and updates the "way" list accordingly.
        """
        newWay = copy.copy(self.way)
        i = 0
        n = len(newWay)
        while i < n:
            # was the block possibly split?
            bb = newWay[i]
            if bb.isSplit:
                # ok the current bb was split at some point
                newWay = newWay[:i] + [bb.hiBb, bb.loBb] + newWay[i+1:]
                n += 1
            else:
                i += 1
        self.way = newWay
        
    def normalize(self, bbAddresses):
        """
        Splits basic blocks at the given addresses. This is useful for normalizing a set of bb traces.
        @param bbAddresses: Set of bb start addresses
        """
        
        for bbAddr in bbAddresses:
            bb, exactMatch = self.findBasicBlock(bbAddr)
            if bb is None or exactMatch:
                # Addr is not contained in any bb or is an exact hit.
                # => No split needed.
                continue
            
            bb.split(bbAddr)
            
        self.finalize()
        
    def getAddressesNonVirtualBBs(self):
        """
        Gets the start addresses of all known non-virtual bbs.
        """
        return [bb.startAddr for bb in self.basicBlocks.values() if (bb.type & tracer.BasicBlock.TYPE.VIRTUAL == 0)]
        
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
        
    def addWaypoint(self, bb):
        Trace.addWaypoint(self, bb)
        self.basicBlocks[bb.startAddr] = bb
        
    def getWaypointAddress(self, step):
        return self.way[step].startAddr
    
    def translate(self, translator):
        t = Trace._normalizeTranslator(translator)
        for x in self.way:
            x.translate(t)
            
    def getDigraph(self):
        from tools import sortDictionary
        digr = Trace.getDigraph(self)
        for bb in self.way:
            calls = sortDictionary(bb.calls)[1]
            digr.add_node_attribute(bb.startAddr, ("calls",calls))
            digr.add_node_attribute(bb.startAddr, ("type", bb.type))
            
        return digr
    
    def getNormalizedSequence(self):
        return [bb.startAddr for bb in self.way]
    
    def getBasicBlock(self, addr):
        return self.basicBlocks[addr]
    
    def getUntakenEdges(self):
        branches = []
        for bb in self.basicBlocks.values():
            if not bb.isCompletelyDefined:
                branches.add(bb.endAddr)
                
        return branches
            