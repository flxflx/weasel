'''
Created on 10.08.2012

@author: Felix
'''

from testbench import protocols, ServerTraceRecorder
from analysis.algorithms import DecisionNodeFinding, ThreadSelection, PreFiltering, PostFiltering
from analysis.results import DecisionFunc, DecisionBb, ImplementationBb, ImplementationFunc
from tools import sortDictionary, writeNamedDotFile
from testbench.protocols.protocol import RunFunc
import sets
import time

class WieselConsts:
    
    NAME_INVALID = "!INVALID"
    FILE_NAME_AUTH_OUTPUT = "priv%d_%d"
    FILE_NAME_CMD_OUTPUT = "ps%d_%s"
    _TRESHOLD_SCORE = 0.1
    _INDEX_VALID_AUTH = 0
    _NORMALIZED_STARTING_NODE = 0
    
    TAG_SECONDARY = "SECONDARY"
    
    
class Wiesel(WieselConsts):
    
    class Statistics:
        
        class Range:
            
            def __str__(self):
                return "%d - %d" % (self.min, self.max)
            
            def __init__(self, minimum, maximum):
                self.min = minimum
                self.max = maximum
                
            def check(self, value):
                if self.max is None or self.max < value:
                    self.max = value
                    
                if self.min is None or self.min > value:
                    self.min = value
                    
        def __str__(self):
            
            tag = "STATISTICS"
            s = "%s\r\n" % tag
            s += "%s\r\n" % ('#'*len(tag))
            s += "Elapsed time: %f\r\n" % (time.time() - self.startingTime)
            s += "Basic block traces: %d\r\n" % self.basicBlockTraces
            s += "Function traces: %d (excluding reference traces)\r\n" % self.functionTraces
            s += "Excluded functions:\r\n"
            for func in self.funcsToExclude:
                s += "\t%s\r\n" % self._getFuncName(func)
                
            s += "Included functions:\r\n"
            for func in self.funcsToInclude:
                s += "\t%s\r\n" % self._getFuncName(func)
                
            s += "Range number function calls: %s\r\n" % str(self.rangeNumberCalls)
            s += "Unique function calls: %d\r\n" % len(self.uniqueCalls)
            return s
                    
        def _getFuncName(self, func):
            if self.names is not None and func in self.names:
                    name = self.names[func]
            else:
                name = "%x" % func
            return name
        
        def __init__(self, names=None):
            self.basicBlockTraces = 0
            self.functionTraces = 0
            self.funcsToInclude = []
            self.funcsToExclude = []
            self.rangeNumberCalls = self.Range(None,None)
            self.uniqueCalls = sets.Set()
            self.names = names
            self.startingTime = time.time()
            
        def addFunctionTraces(self, funcTraces):
            for funcTrace in funcTraces:
                self.addFunctionTrace(funcTrace)
            
        def addFunctionTrace(self, funcTrace):
            self.functionTraces += 1
            self.rangeNumberCalls.check(len(funcTrace.trace))
            self.uniqueCalls |= sets.Set(funcTrace.diGraph.nodes())
            
        def setFuncsToExclude(self, funcsToExclude):
            self.funcsToExclude = funcsToExclude
            
        def setFuncsToInclude(self, funcsToInclude):
            self.funcsToInclude = funcsToInclude
            
        def addBasicBlockTrace(self, bbTrace):
            self.basicBlockTraces += 1
    
    def __init__(self, pygdb, hostApp, portApp, protocol, protocolCompiler, verbose = False, maxHitsFunction=5, funcsExclude=[]):
        self.pygdb = pygdb
        self.hostApp = hostApp
        self.portApp = portApp
        self.proto = protocol
        self.comp = protocolCompiler
        self.verbose = verbose
        self.names = None
        self.maxHitsFunction = maxHitsFunction
        self.tr = ServerTraceRecorder(self.pygdb, protocol.getTransportLayer(self.hostApp, self.portApp, self.verbose))
        self.funcsExclude = funcsExclude
        self._resetStatistics()
        
    def _resetStatistics(self):
        
        self.statistics = Wiesel.Statistics(self.getNames())
        
    ## Convenience methods ##
                
    @staticmethod
    def _getCallsFromBasicBlock(traces, addrBb, exclusive=False):
        import sets
        calls = {}
        for stringTraces, traceInvalid in traces:
            if exclusive:
                callsInvalid = sets.Set(traceInvalid[0].basicBlocks[addrBb].getAllCalls())
            for name in stringTraces:
                for trace in stringTraces[name]:
                    bbCalls = trace.basicBlocks[addrBb].getAllCalls()
                    if exclusive:
                        calls[name] = list(sets.Set(bbCalls).difference(callsInvalid))
                    else:
                        calls[name] = bbCalls
                    
        return calls
        
    @staticmethod
    def _normalizeScores(scores):
        s = 0
        for val in scores.values():
            s += val
        
        if s != 0:
            for key in scores.keys():
                scores[key] /= s
                
    @staticmethod
    def _printScores(candidates, values):
        for i in range(len(candidates)):
            print "%x (%f)," % (candidates[i], values[i]),
            
        print ""
                       
    @staticmethod
    def _filterScores(results, tresholdScore):
        Wiesel._normalizeScores(results)
        keysToPop = []
        for key in results.keys():
            if results[key] < tresholdScore:
                keysToPop.append(key)
                
        for key in keysToPop:
            results.pop(key)
            
    @staticmethod
    def _combineScores(scores):
        combined = {}
        for s in scores:
            for item in s:
                if item not in combined:
                    combined[item] = 0
                combined[item] += s[item]/len(scores)
                
        return combined
        
    @staticmethod
    def _evaluateTraces(traces, fixPointTrace, algorithms, tresholdScore, filterAlgorithms=None):
        """
        Evaluates a set of traces using the given set of algorithms and a given fix-point trace.
        @param traces: The traces to evaluate
        @param fixPointTrace: The fix-point trace
        @param algorithms: The algorithms to use
        @param tresholdScore: The treshold-score to use for filtering
        @param filterAlgorithms: [OPTIONAL] Algorithms to use for pre-filtering.
        @return: A dictionary containing the identified candidate nodes and their respective scores (all nodes with a score below the given treshold-score are filtered out).
        """
        if filterAlgorithms is not None:
            for algorithm in filterAlgorithms:
                traces = algorithm(traces)
                
        scores = {}
        for algorithm in algorithms:
            scoresTmp = algorithm(traces, fixPointTrace)
            for func in scoresTmp:
                if func not in scores:
                    scores[func] = 0     
                scores[func] += scoresTmp[func]
        # filter-out all zero-scores
        Wiesel._filterScores(scores, tresholdScore)
        return scores
    
    ## Generic trace processing and collecting methods ##
    
    def _getFunctionRecorder(self, fileIoAction=None, basePathTraceData=None, tag=""):
        return lambda protoProcessor, unrebaseTraces: self.tr.recordCallgraph(protoProcessor, unrebaseTraces=unrebaseTraces, verbose=self.verbose, traceSelector=ThreadSelection.a0Single, basePathTraceData=basePathTraceData, fileIoAction=fileIoAction, maxHits=self.maxHitsFunction, tag=tag)
    
    def _getBasicBlockRecorder(self, addrFunc, callStack=None, fileIoAction=None, basePathTraceData=None, tag=""):
        return lambda protoProcessor, unrebaseTraces: self.tr.recordFlowgraph(addrFunc, protoProcessor, unrebaseTraces=unrebaseTraces, verbose=self.verbose, requiredCallStack=callStack, traceSelector=ThreadSelection.a0Single, basePathTraceData=basePathTraceData, fileIoAction=fileIoAction, maxHitsCallStack=self.maxHitsFunction, tag=tag)
    
    def _collectBasicBlockTraces(self, protocolProcs, recorder):
        protocolRuns = []
        bbAddresses = sets.Set()
        
        for protocolProc in protocolProcs:
            run = recorder(protocolProc, unrebaseTraces=True)
            protocolProc.reset()
            self.statistics.addBasicBlockTrace(run)
            if run is not None:
                protocolRuns.append(run)
            else:
                print "Failed to record a basic-block trace for the protocol-run %s." % protocolProc.name
            
            # update set of known bb addresses
            for trace in run.traces:
                bbAddresses |= sets.Set(trace.getAddressesNonVirtualBBs())
        
        # normalize all recorded traces to the set of known basic blocks
        for run in protocolRuns:
            for trace in run.traces:
                trace.normalize(bbAddresses)

            run.update()
        
        return protocolRuns
    
    def getNames(self):
        return self.pygdb.environment.getNames()
    
    def _getBasicBlockTraces(self, protocolProcs, addrFunc, callStack=None, fileIoAction=None, basePathTraceData=None):
        """
        Top function for getting basic block traces from already existing protocol-runs for a certain function/call-stack.
        """
        
        # DEBUG
        #print "Getting %d basic-block traces for func %x for callstack:" % (len(protocolProcs), addrFunc)
        #print callStack
        #######
        recorder = self._getBasicBlockRecorder(addrFunc, callStack, fileIoAction, basePathTraceData)
        return self._collectBasicBlockTraces(protocolProcs, recorder)
         
    ## Generic analysis methods ##
       
    ## HERE COMES THE ALL NEW A-WEAZEL ALGO! 
    ## might be hackerish, should maybe partitioned when done
                
    def A_WEAZEL(self, protoRuns, fileIoAction=None, basePathTraceData=None, recursionDepth=0, funcsToExclude=[], funcsToInclude=[]):
        
        """
        The final algorithm for the identification of decision and handling functionality.
        @todo: unify variable naming ("name" instead of "addr" etc.)
        @rtype: List of DecisionFunc
        """
        class Group:
            
            def __init__(self, exFunc):
                
                self.decisionFunc = exFunc.callStack[-2]    
                self.refExFunc = exFunc
                self.exFuncs = [exFunc]
                self.protoRuns = [exFunc.protoRun]
                self.closed = False
                
            def addExclusiveFunction(self, exFunc):
                """
                Adds an exclusive function to the group. It is checked whether the given ex-func fits into the group.
                @param exFunc: The ex-func to add
                @return: Boolean flag indicating success.
                """
                if self.closed:
                    return False
                
                if self.refExFunc.callStackSingatureLength > len(exFunc.callStack):
                    return False
                
                # Check if the ex-func shares a call-stack with the reference trace.
                for i in range(self.refExFunc.callStackSingatureLength):
                    if self.refExFunc.callStack[-(i+1)] != exFunc.callStack[-(i+1)]:
                        return False
                    
                if exFunc not in self.exFuncs:
                    self.exFuncs.append(exFunc)
                    
                if exFunc.protoRun not in self.protoRuns:
                    self.protoRuns.append(exFunc.protoRun)
                                        
                return True
            
            def close(self):
                """
                Closes the group and updates call-stacks of protocol-runs.
                """
                self.closed = True
                self.refCallStack = self.refExFunc.callStack[-self.refExFunc.callStackSingatureLength:]
                
            def getRefCallStackDecisionFunc(self):
                """
                @return: List (possibly empty) in case the decision func has a callstack, None in case the decision func has no callstack at all. 
                """
                
                if not self.closed:
                    return None
                
                return self.refCallStack[:-2]
            
            def getRefCallStackExclusiveFunc(self):
                
                if not self.closed:
                    return None
                
                return self.refCallStack[:-1]
            
            def dominatesRefCallStackDecisionFunc(self, otherGroup):
                
                ownCallStack = self.getRefCallStackDecisionFunc()
                otherCallStack = otherGroup.getRefCallStackDecisionFunc()
                
                if ownCallStack is None or otherCallStack is None:
                    return ownCallStack == otherCallStack
                
                if len(ownCallStack) < len(otherCallStack):
                    return False
            
                for i in range(len(otherCallStack)):
                    if ownCallStack[-(i+1)] != otherCallStack[-(i+1)]:
                        return False
                
                return True
            
            def isDecisionFuncTop(self):
                # TODO: Does this work with Pure-FTPd?
                return (len(self.refExFunc.callStack) == 2)
                    
        class ExclusiveFunction:
            
            def __init__(self, name, callStack, callStackSingatureLength, protoRun):
                """
                @param name: The addr/name of the sub-function
                @param callStack: The respective call-stack (without the sub-function itself)
                @param callStackSingatureLength: Number of functions on the call-stack that need to be checked in order to identify this specific sub-function call. 
                @param protoRun: The respective protocol-run
                """
                self.name = name
                self.callStack = protoRun.callStack + callStack #TODO: was old code faulty or good for something?
                self.protoRun = protoRun
                self.callStackSingatureLength = callStackSingatureLength
                             
        # Group proto-runs according to exclusive function calls.
        sCommonFuncs = sets.Set(protoRuns[0].diGraph.nodes())
        for protoRun in protoRuns[1:]:
            sCommonFuncs = sCommonFuncs.intersection(protoRun.diGraph.nodes())
            
        # create set of functions to ignore
        sExcludeFuncs = sets.Set(funcsToExclude)
        sIncludeFuncs = sets.Set(funcsToInclude)
            
        # now determine exclusive functions
        exFuncs = []
        for protoRun in protoRuns:
            sFuncs = sets.Set(protoRun.diGraph.nodes())
            sExFuncs = (sFuncs - (sCommonFuncs - sIncludeFuncs)) - sExcludeFuncs
            
            # remove the starting node of each run
            sExFuncs.discard(protoRun.trace.startingNode)
            
            # first get sub-traces for all identified exclusive functions
            topExFuncs = {}
            for exFunc in sExFuncs:
                ways = protoRun.trace.getWaysBetween(None, exFunc)
                    
                # filter out functions dominated by other function 
                waysUndominated = []
                for way in ways:
                    wayDominated = False
                    for func in way[:-1]:
                        if func in sExFuncs:
                            wayDominated = True
                            break
                    if not wayDominated:
                        waysUndominated.append(way)
                
                if len(waysUndominated) > 0:
                    topExFuncs[exFunc] = waysUndominated
            
            # DEBUG
            #print "\t" * recursionDepth + "top-ex-funcs:"
            #for x in topExFuncs: print "\t" * recursionDepth + "%x" % x
            #######
            
            for topExFunc in topExFuncs:
                # Find out how many levels of call-stack back tracing are needed in order to unambiguously differentiate between all ways.
                ways = topExFuncs[topExFunc]
                for iWay in range(len(ways)):
                    # get a set of all indexes without iWay
                    tmp = range(len(ways))
                    tmp.pop(iWay)
                    sIOtherWays = sets.Set(tmp) 
                    way = ways[iWay]
                    # walk the callstack backwards and check for differences
                    level = 0
                    for i in range(len(way)-1)[::-1]:
                        level += 1
                        # are there still identical callstacks
                        if len(sIOtherWays) == 0:
                            break
                        
                        # check for all remaining callstacks
                        iOtherWays = list(sIOtherWays)
                        for iOtherWay in iOtherWays:
                            otherWay = ways[iOtherWay]
                            if i not in range(len(otherWay)) or otherWay[i] != way[i]:
                                sIOtherWays.remove(iOtherWay)
                             
                    callStack = way
                    exFuncs.append(ExclusiveFunction(topExFunc, callStack, level, protoRun))
                    
        # now group the identified exclusive functions
        ## sort exFuncs according to the respective call-stack signature lengths
        tmp = {i:exFuncs[i].callStackSingatureLength for i in range(len(exFuncs))}
        import tools
        exFuncIndexes, nop = tools.sortDictionary(tmp)
        
        groups = []
        decisionFuncs = {}
        for iExFunc in exFuncIndexes[::-1]:
            exFunc = exFuncs[iExFunc]                
            fitsInExistingGroup = False
            for group in groups:
                fitsInExistingGroup = group.addExclusiveFunction(exFunc)
                if fitsInExistingGroup:
                    # DEBUG
                    # print "\t" * recursionDepth +  "Ex-func %x fits in group of ex-func %x (df %x)" % (exFunc.name, group.refExFunc.name, group.decisionFunc)
                    #######
                    break
            
            # If the current ex-func does not fit into any existing group, create a new group for it.
            if not fitsInExistingGroup:
                newGroup = Group(exFunc)
                groups.append(newGroup)
                if newGroup.decisionFunc not in decisionFuncs:
                    decisionFuncs[newGroup.decisionFunc] = DecisionFunc(newGroup.decisionFunc)
                    
                decisionFuncs[newGroup.decisionFunc].addGroup(newGroup)
                
        # DEBUG
        # print "\t"*recursionDepth + "Identified the following decision funcs:"
        # for df in decisionFuncs:
        #    print "\t"*recursionDepth + "\t%x" % df
        #######
            
        # Finally analyze the decision functions.
        for df in decisionFuncs.values():
            bbProtoRuns = []
            # Analyze each group.
            
            # NOTE: That groups are already ordered by the length of their call-stack traces!
            # This is important for deciding if a decision func needs to be traced on bb level for a certain group or not.
            
            for iGroup in range(len(df.groups)):
                group = df.groups[iGroup]
                group.close()
                # If an ex-func is only accessed by a single protocol-run, we assume the ex-func to be a concrete implementation function (e.g. a cmd handler).
                # Recursion ends in this case.
                if len(group.protoRuns) == 1:
                    df.addEdge(group.protoRuns[0], ImplementationFunc(group.refExFunc.name))
                else:
                    subProtoRuns = []
                    for exFunc in group.exFuncs:
                        # TODO: The following should return traces not including the given call-stack
                        subCgTraces = exFunc.protoRun.trace.getTracesWithCallStack(exFunc.callStack)
                        subCgTrace = subCgTraces[0] # Note how we necessarily always get exactly one subtrace here.
                        subCallStack = group.getRefCallStackExclusiveFunc()
                        subProtoRun = protocols.protocol.RunFunc(exFunc.protoRun.protoProc, subCgTrace, subCallStack)
                        subProtoRuns.append(subProtoRun)
                               
                    addrExFunc = group.refExFunc.name
                    # Recursively invoke the algorithm for all groups.
                    # DEBUG
                    # print "\t"* recursionDepth + "Invoking A-WEAZEL for exfunc %x with %d proto-runs." % (addrExFunc, len(subProtoRuns))
                    #######
                    processingGraphs = self.A_WEAZEL(subProtoRuns, fileIoAction, basePathTraceData, recursionDepth+1, funcsToInclude=funcsToInclude, funcsToExclude=funcsToExclude)
                    
                    # check if any sub-processing graphs were identified
                    if len(processingGraphs) == 0:
                        # if not, the ex-func is a multi protocol run implementation function
                        multiIf = ImplementationFunc(addrExFunc)
                        # get protocol processors 
                        protoProcs = sets.Set()
                        for protoRun in subProtoRuns: protoProcs.add(protoRun.protoProc)
                        
                        implBbProtoRuns = self._getBasicBlockTraces(list(protoProcs), addrExFunc, group.getRefCallStackExclusiveFunc(), fileIoAction, basePathTraceData)
                        
                        isDecisionFunc, bbGraphs = Wiesel.A_WEAZEL_BB(implBbProtoRuns) 
                        multiIf.addBbGraphs(bbGraphs, implBbProtoRuns)
                        processingGraphs = [multiIf]
                        
                    # check if the ex-func is a 'special' one (i.e. was found to exhibit different return values for different protocol runs)
                    if addrExFunc in funcsToInclude and addrExFunc not in funcsToExclude:
                        # if so, check if the ex-func was already identified as decider
                        alreadyIdentified = False
                        for topDecisionFunc in processingGraphs:
                            if topDecisionFunc.addr == addrExFunc:
                                alreadyIdentified = True
                                break
                            
                        if not alreadyIdentified:
                            # if it was not already identified, make it the top node and record bb traces
                            intermediateDf = DecisionFunc(addrExFunc)
                            intermediateDf.addEdges(subProtoRuns, processingGraphs)
                            intermediateBbProtoRuns = self._getBasicBlockTracesAWeazel(subProtoRuns, intermediateDf.addr, group.getRefCallStackExclusiveFunc(), fileIoAction, basePathTraceData)
                            # TODO: aggregate bb-traces
                            r = Wiesel.A_WEAZEL_BB(intermediateBbProtoRuns)
                            if r is not None: 
                                isRealDecisionFunc, bbGraphs = r         
                                intermediateDf.addBbGraphs(bbGraphs, intermediateBbProtoRuns)
                                intermediateDf.setAttribute(DecisionFunc.SPECIFIC_ATTRIBUTES.IMPORTANT, str(isRealDecisionFunc))
                                
                            # swap processing graphs
                            processingGraphs = [intermediateDf]
                            
                    # add the generated processing graphs to the node of the decision function
                    df.addEdges(subProtoRuns, processingGraphs)
                
                # Check if the decision-func was already traced for the given call-stack
                callStackAlreadyTraced = False
                for iPrevGroup in range(iGroup):
                    if df.groups[iPrevGroup].dominatesRefCallStackDecisionFunc(group):
                        callStackAlreadyTraced = True
                        
                if not callStackAlreadyTraced and not df.addr in funcsToExclude:
                    # Aggregate traces of all protocol-runs through the decision-function
                    bbProtoRuns += self._getBasicBlockTracesAWeazel(protoRuns, df.addr, group.getRefCallStackDecisionFunc(), fileIoAction, basePathTraceData)
            
            r = Wiesel.A_WEAZEL_BB(bbProtoRuns)
            if r is not None: 
                isRealDecisionFunc, bbGraphs = r         
                df.addBbGraphs(bbGraphs, bbProtoRuns)
                df.setAttribute(DecisionFunc.SPECIFIC_ATTRIBUTES.IMPORTANT, str(isRealDecisionFunc))
            else:
                print "Failed to analyze %x on bb-level." % df.addr
            
        return decisionFuncs.values()
    
    def _getBasicBlockTracesAWeazel(self, protoRuns, addrDf, callStack, fileIoAction, basePathTraceData):
        protoProcs = sets.Set()
        for protoRun in protoRuns: protoProcs.add(protoRun.protoProc)
        return self._getBasicBlockTraces(list(protoProcs), addrDf, callStack, fileIoAction, basePathTraceData)
        
    @staticmethod
    def A_WEAZEL_BB(protoRuns):
        """
        Sub-algorithm of A-WEAZEL analyzing bb-traces of decision-functions.
        @param protoRuns: The basic-block protocol-runs to analyze.
        @type protoRuns: List of ProtocolRunBb
        @return: A graph of decision and implementation bbs
        @rtype: List of DecisionBb
        """
        # Which node is present in which protocol-run?
        notEmptyProtoRuns = [protoRun for protoRun in protoRuns if protoRun.diGraph is not None]
        if len(notEmptyProtoRuns) == 0:
            print "Got only empty proto-runs in A_WEAZEL_BB. There seems to be something wrong with your tracer (srsly)."
            return None
         
        allNodesWeight = {}
        for protoRun in notEmptyProtoRuns:
            for node in protoRun.diGraph.nodes():
                if node not in allNodesWeight:
                    allNodesWeight[node] = 0
                    
                allNodesWeight[node] += 1
            
        # Now get the nodes with the least weight for each protocol-run.
        foundImplementation = False
        decisionNodes = {}     
        for protoRun in notEmptyProtoRuns:
            nodesWeight = {}
            for node in protoRun.diGraph.nodes():
                nodesWeight[node] = allNodesWeight[node]
                
            nodes, weights = sortDictionary(nodesWeight)
            minWeight = weights[0]
            nodesMinWeight = [nodes[i] for i in range(len(weights)) if weights[i] == minWeight]
            
            # Find all nodes with higher weight that lead to the minimal weight nodes.
            for nodeMW in nodesMinWeight:
                nodeMWIncidents = protoRun.diGraph.incidents(nodeMW)
                 
                for nodeMWIncident in nodeMWIncidents:
                    if nodesWeight[nodeMWIncident] > minWeight:
                        if not nodeMWIncident in decisionNodes:
                            decisionNodes[nodeMWIncident] = DecisionBb(nodeMWIncident)
                            
                        foundImplementation = True
                        decisionNodes[nodeMWIncident].addEdge(protoRun, ImplementationBb(nodeMW))
                        
        # Finally add those decision nodes in which not all possible decisions were made during runtime.
        class IncompleteDecisionBbCandidate:
            
            def __init__(self, addr, nExits):
                self.addr = addr
                self.nExits = nExits is not None and nExits or 0
                self.exits = []
                
            def addExit(self, exit):
                if exit not in self.exits:
                    self.exits.append(exit)
                    
            def isCompletelyDefined(self):
                return len(self.exits) == self.nExits
                
        incompleteDecisionBbCandidates = {}
        for protoRun in notEmptyProtoRuns:
            for bb in protoRun.trace.basicBlocks.values():
                if not bb.isCompletelyDefined():
                    if bb.startAddr not in incompleteDecisionBbCandidates:
                        incompleteDecisionBbCandidates[bb.startAddr] = IncompleteDecisionBbCandidate(bb.startAddr, bb.nExits)
                        
                    for knownExit in bb.knownExits.values():
                        incompleteDecisionBbCandidates[bb.startAddr].addExit(knownExit.bb.startAddr)
                elif bb.startAddr in incompleteDecisionBbCandidates:
                    incompleteDecisionBbCandidates.pop(bb.startAddr)
                        
        
        for decisionBb in incompleteDecisionBbCandidates.values():
            if not decisionBb.isCompletelyDefined():
                if decisionBb.addr not in decisionNodes:
                    decisionNodes[decisionBb.addr] = DecisionBb(decisionBb.addr)
                
                decisionNodes[decisionBb.addr].setAttribute(DecisionBb.SPECIFIC_ATTRIBUTES.SUSPICIOUS_EDGES, "%d" % (decisionBb.nExits - len(decisionBb.exits)))     
                
        return foundImplementation, decisionNodes.values()
                 
    ## Cmds ##
    def analyzeCmd(self, fileIoAction=None, basePathTraceData=None, protoStrings=None):
        
        protoRuns, protoRunInvalid = self._getTracesCmd(self._getFunctionRecorder(fileIoAction, basePathTraceData), protoStrings=protoStrings)
        protoRunsAll = [protoRunInvalid] + protoRuns
        protoRunsRef, protoRunInvalidRef = self._getTracesCmd(self._getFunctionRecorder(fileIoAction, basePathTraceData, tag=Wiesel.TAG_SECONDARY), protoStrings=protoStrings)
        protoRunsAllRef = [protoRunInvalidRef] + protoRunsRef
        
        for protoRunsOfInterest, funcsToInclude, funcsToExclude in self._preProcessing(protoRunsAll, protoRunsAllRef):
            
            # do statistics
            self._resetStatistics()
            self.statistics.setFuncsToExclude(funcsToExclude)
            self.statistics.setFuncsToInclude(funcsToInclude)
            self.statistics.addFunctionTraces(protoRunsOfInterest)
            ###############
            
            processingGraphs = self.A_WEAZEL(protoRunsOfInterest, fileIoAction, basePathTraceData, funcsToInclude=funcsToInclude, funcsToExclude=funcsToExclude)
            self._postProcessing(protoRunInvalid, protoRuns, processingGraphs)
            
            print self.statistics
            yield processingGraphs
                          
    def _collectTracesCmd(self, privLevel, protoStrings, recorder):
        
        traces = []
        for protoString in protoStrings:
            try:
                procCmd = self.comp.compileCmdFirst(privLevel, protoString)
            except protocols.protocol.ErrCompilingScript:
                print "Apparently there are no commands for priv-level %d and protocol-string %d. Skipping this pair..." % (privLevel, protoString)
                continue
            
            while procCmd is not None:
                run = recorder(procCmd, unrebaseTraces=True)
                procCmd.reset()
                traces.append(run)
                procCmd = self.comp.compileCmdNext()
                  
        procCmdInvalid = self.comp.compileCmdInvalid(privLevel, protoString)
        runInvalid = recorder(procCmdInvalid, unrebaseTraces=True)
        procCmdInvalid.reset()
           
        return (traces, runInvalid)
            
    def writeTracesCmd(self, outDir, traceData=None, pathTraceData=None):
        names = self.getNames()
      
        for ps in range(len(traceData)):
            psTraces = traceData[ps]
            psCmdTraces = psTraces[0] 
            for cmd in psCmdTraces: 
                tr = psCmdTraces[cmd]
                Wiesel._helpWriteTracesCmd(tr, ps, cmd, outDir, names)
                
            psWrongCmdTrace = psTraces[1]
            Wiesel._helpWriteTracesCmd(psWrongCmdTrace, ps, Wiesel.NAME_INVALID, outDir, names)
        
                    
    @staticmethod
    def _helpWriteTracesCmd(pr, ps, cmd, outDir, names):
        digr = pr.diGraph
        path = outDir + Wiesel.FILE_NAME_CMD_OUTPUT % (ps, cmd)
    
        writeNamedDotFile(digr, path + ".dot", names=names)
        pr.trace.translate(names)
    
        f = file(path + ".txt", "wb")
        f.write(str(pr.trace))
        f.close()
        
    def _getTracesCmd(self, recorder, privLevel=None, protoStrings=None):
        pl = privLevel or self.proto.getDefaultPrivLevelCmd()
        ps = protoStrings or self.proto.PROTOCOL_STRINGS
        return self._collectTracesCmd(pl, ps, recorder)
            
    ## Authentication ##
    
    def writeTracesAuth(self, outDir, traceData=None, pathTraceData=None):
        names = self.getNames()
            
        for privLevel in traceData:
            i = 0
            for trace in traceData[privLevel]: 
                tr = trace[0]
                digr = tr.getDigraph()
                path = outDir + Wiesel.FILE_NAME_AUTH_OUTPUT % (privLevel, i)
                i += 1 
            
                writeNamedDotFile(digr, path + ".dot", names=names)
                tr.translate(names)
            
                f = file(path + ".txt", "wb")
                f.write(str(tr))
                f.close()
        
    def analyzeAuth(self, fileIoAction=None, basePathTraceData=None, privLevelsOfInterest=None):
        
        # get primary function traces
        privLevels = self._getTracesAuth(self._getFunctionRecorder(fileIoAction, basePathTraceData), privLevelsOfInterest)
        
        # get secondary control function traces
        privLevelsRef = self._getTracesAuth(self._getFunctionRecorder(fileIoAction, basePathTraceData, tag=Wiesel.TAG_SECONDARY), privLevelsOfInterest)
        
        results = {}
        for privLevel in privLevels:
            for protoRunsOfInterest, funcsToInclude, funcsToExclude in self._preProcessing(privLevels[privLevel], privLevelsRef[privLevel]):
            
                # do statistics
                self._resetStatistics()
                self.statistics.setFuncsToExclude(funcsToExclude)
                self.statistics.setFuncsToInclude(funcsToInclude)
                self.statistics.addFunctionTraces(protoRunsOfInterest)
                ###############
            
                # aggregate processing graphs using the A-WEAZEL algorithm
                processingGraphs = self.A_WEAZEL(protoRunsOfInterest, fileIoAction, basePathTraceData, funcsToInclude=funcsToInclude, funcsToExclude=funcsToExclude)
                self._postProcessing(protoRunsOfInterest[0], protoRunsOfInterest[1:], processingGraphs)
                if privLevel not in results:
                    results[privLevel] = []
                
                results[privLevel].append(processingGraphs)
                print self.statistics
            
        return results
        
    def _collectTracesAuth(self, privLevelsWithAuth, recorder):
        """
        Collects all possible auth-traces for the given priv-levels.
        """
        traces = {}
        for privLevel in privLevelsWithAuth:
            try:
                procAuth = self.comp.compileAuthValidFirst(privLevel)
            except protocols.protocol.ErrCompilingScript:
                print "Apparently there is no auth specified for priv-level %d. Skipping this one..." % privLevel
                continue
            traces[privLevel] = []
            
            while procAuth is not None:
                run = recorder(procAuth, unrebaseTraces=True)
                procAuth.reset()
                if run is not None:
                    traces[privLevel].append(run)
                else:
                    print "Error: Failed to collect authentication protocol-run %s." % procAuth.name
                procAuth = self.comp.compileAuthNext(privLevel)
        return traces
             
    def _getTracesAuth(self, recorder, privLevels=None):
        pl = privLevels or self.proto.PRIV_LEVELS_WITH_AUTH
        return self._collectTracesAuth(pl, recorder)
    
    def _preProcessing(self, rawProtoRuns, rawProtoRunsRef): 
        
        # first sort traces according to their first node
        # check if we need to normalize the virtual starting node
        startingNodes = {}
        startingNodesRef = {}
        for i in range(len(rawProtoRuns)):
            for j in range(len(rawProtoRuns[i].traces)):
                functionTrace = rawProtoRuns[i].traces[j]
                if functionTrace.startingNode not in startingNodes:
                    startingNodes[functionTrace.startingNode] = []
                startingNodes[functionTrace.startingNode].append(RunFunc(rawProtoRuns[i].protoProc, functionTrace))
                
                functionTraceRef = rawProtoRunsRef[i].traces[j]
                if functionTraceRef.startingNode not in startingNodesRef:
                    startingNodesRef[functionTraceRef.startingNode] = []
                startingNodesRef[functionTraceRef.startingNode].append(RunFunc(rawProtoRunsRef[i].protoProc, functionTraceRef))
                
        for startingNode in startingNodes:
            protoRuns = startingNodes[startingNode]
            protoRunsRef = startingNodesRef[startingNode]
            # check if primary and secondary traces are consistent for the given starting node
            if len(protoRuns) != len(protoRunsRef):
                # if not, just continue...
                continue
            
            funcsToInclude = PreFiltering.Ref.a1(protoRuns, protoRunsRef)
            funcsToExclude = PreFiltering.Ref.a0(protoRuns, protoRunsRef)
                    
            filteredProtoRuns = PreFiltering.a0(protoRuns)
            
            funcsToExclude += self.funcsExclude 
            funcsToExclude += [Wiesel._NORMALIZED_STARTING_NODE]
                
            yield filteredProtoRuns, funcsToInclude, funcsToExclude
            
    def _postProcessing(self, refProtoRun, protoRuns, processingGraphs):
        
        ALGOS = [DecisionNodeFinding.a2b, DecisionNodeFinding.a0, DecisionNodeFinding.a3b]
        ALGOS_BB = [DecisionNodeFinding.a0]
        ALGOS_FILTERING = [PostFiltering.a0]
        TRESHOLD_SCORE = 0.0
        
        # weigh the A-WEAZEL results using the older scoring algorithms
        # TODO: beautify and merge with A-WEAZEL results
        fixpointTrace = refProtoRun.trace
        traces = [protoRun.trace for protoRun in protoRuns]
        
        # create score generator for functions
        scores = Wiesel._evaluateTraces(traces, fixpointTrace, ALGOS, TRESHOLD_SCORE, ALGOS_FILTERING)            
        scorer = lambda addr : addr in scores and scores[addr] or 0.0
        
        # create attribute generator for functions
        names = self.pygdb.environment.getNames()
        namer = lambda addr : addr in names and names[addr] or None
        
        # apply generators and print out the processing graphs
        for pr in processingGraphs:
            pr.generateAttributeNodes("name", namer)
            pr.generateAttributeNodes("score", scorer)
            
            # now weigh the several bb traces
            for func in pr:
                if func.bbProtoRuns is not None:
                    fixpointTraceBb = func.bbProtoRuns[0].trace
                    otherTracesBb = [bbProtoRun.trace for bbProtoRun in func.bbProtoRuns[1:]] 
                    scoresBb = Wiesel._evaluateTraces(otherTracesBb, fixpointTraceBb, ALGOS_BB, TRESHOLD_SCORE, ALGOS_FILTERING)            
                    scorerBb = lambda addr : addr in scoresBb and scoresBb[addr] or 0.0
                    for bbGraph in func.bbGraphs:
                        bbGraph.generateAttributeNodes("score", scorerBb)
                        
    def analyzeAdvanced(self, processingGraphs):
        from analysis.evaluation import Live
        implFuncs = []
        for pr in processingGraphs:
            for func in pr:
                if isinstance(func, ImplementationFunc):
                    implFuncs.append(func)
            funcPointers = [func.addr for func in implFuncs]
            fptCandidates = Live.getFunctionPointerTableCandidates(self.pygdb, funcPointers)
            
            # DEBUG
            #for fptCandidate in fptCandidates:
            #    print fptCandidate
            #######
            
if __name__ == "__main__":
    import sys
    import pygdb
    import testbench
    import os
    
    MIN_AMOUNT_ARGUMENTS = 3
    TOKEN_TRUE = "True"
    TOKEN_FALSE = "False"
    
    if len(sys.argv) < MIN_AMOUNT_ARGUMENTS:
        print "Usage: %s <path to config file> <action to perform> [action specific arguments]" % sys.argv[0]
        print "\t Supported actions:"
        print "\t\t0: Analyze command processing."
        print "\t\tOptionally protocol-strings of interest can be supplied in numerical form. If no protocol-strings are supplied, all available are evaluated."
        
        print "\t\t1: Analyze authentication process."
        print "\t\tOptionally privilege levels of interest can be supplied in numerical form. If no privilege levels are supplied, all available are evaluated."
        print "Example %s proftpd_config.xml 0 1 3" % sys.argv[0]
        sys.exit()
        
    # parse config file
    PATH_CONFIG_FILE = sys.argv[1]
    BASE_PATH = os.path.dirname(PATH_CONFIG_FILE) 
    from xml.etree import ElementTree
    root = ElementTree.parse(PATH_CONFIG_FILE).getroot()
    cfgTarget = root.find("target")
    cfgGdb = root.find("gdb")
    cfgLocal = root.find("local")
    
    HOST_APP = cfgTarget.attrib["host"]
    PORT_APP = int(cfgTarget.attrib["port"])
    PORT_GDB = int(cfgGdb.attrib["port"])
    HOST_GDB = cfgGdb.attrib["host"]
    
    if "maxFunctionHits" in cfgGdb.attrib:
        MAX_HITS_FUNCTION = int(cfgGdb.attrib["maxFunctionHits"])
    else:
        MAX_HITS_FUNCTION = 5
    
    if "addrFork" in cfgTarget.attrib:
        tmpAddrFork = cfgTarget.attrib["addrFork"]
        ADDR_FORK = tmpAddrFork[:2] == "0x" and int(tmpAddrFork, 16) or int(tmpAddrFork, 10)
    else:
        ADDR_FORK =  None
        
    if "addrForkPtr" in cfgTarget.attrib:
        tmpAddrForkPtr = cfgTarget.attrib["addrForkPtr"]
        ADDR_FORK_PTR = tmpAddrForkPtr[:2] == "0x" and int(tmpAddrForkPtr, 16) or int(tmpAddrForkPtr, 10)
    else:
        ADDR_FORK_PTR = None
        
    PROTOCOL = cfgTarget.attrib["protocol"]
    PATH_EXECUTABLE = cfgTarget.attrib["path"]
    PATH_FUNCTIONS_LIST = "pathFunctionsList" in cfgTarget.attrib and cfgTarget.attrib["pathFunctionsList"] or None
    if PATH_FUNCTIONS_LIST is not None: 
        if not os.path.isabs(PATH_FUNCTIONS_LIST):
            PATH_FUNCTIONS_LIST = os.path.join(BASE_PATH, PATH_FUNCTIONS_LIST)
            
    CPU = cfgTarget.attrib["cpu"]
    ENVIRONMENT = cfgTarget.attrib["environment"]
    pygdb.globals.DEBUG = int(cfgLocal.attrib["levelDebugOutput"])
    OUT_DIR = cfgLocal.attrib["outputDir"]
    if not os.path.isabs(OUT_DIR):
        OUT_DIR = os.path.join(BASE_PATH, OUT_DIR)
        
    PRINT_PROTOCOL_INTERACTION = cfgLocal.attrib["printProtocolInteraction"] == TOKEN_TRUE
    SAVE_TRACING_DATA_LOCALLY = cfgLocal.attrib["saveTracingDataLocally"] 
    if SAVE_TRACING_DATA_LOCALLY != TOKEN_FALSE:
        FILE_IO_MODE = ServerTraceRecorder.FILE_IO.LOAD_TRACE_DATA
    else:
        FILE_IO_MODE = ServerTraceRecorder.FILE_IO.STORE_TRACE_DATA
    
    AUTH_DATA = {}
    for login in cfgTarget.iterfind("login"):
        data = ()
        for item in login.iterfind("item"):
            data += (item.attrib["value"],)
        AUTH_DATA[int(login.attrib["privLevel"])] = data 
        
    FUNCS_EXCLUDE = []
    for exclude in cfgTarget.iterfind("exclude"):
        FUNCS_EXCLUDE.append(int(exclude.attrib["function"],16))
        
    protocol = testbench.protocols.protocols[PROTOCOL.upper()]
    cpu = pygdb.cpus[CPU.upper()]()
    environment = pygdb.environments[ENVIRONMENT.upper()](PATH_EXECUTABLE, PATH_FUNCTIONS_LIST)
    protocolCompiler = protocol.getCompiler(AUTH_DATA)
    
    gdbSession = pygdb.PyGdb(HOST_GDB, PORT_GDB, cpu, environment, addrForkFunc=ADDR_FORK, addrForkPointer=ADDR_FORK_PTR, disableASLR=False)
    w = Wiesel(gdbSession, HOST_APP, PORT_APP, protocol, protocolCompiler, verbose=PRINT_PROTOCOL_INTERACTION, maxHitsFunction=MAX_HITS_FUNCTION, funcsExclude=FUNCS_EXCLUDE)
    
    # get optional numerical arguments
    OPTIONAL_ARGS = [int(arg) for arg in sys.argv[MIN_AMOUNT_ARGUMENTS:]]
    FUNCTION = int(sys.argv[MIN_AMOUNT_ARGUMENTS - 1])
    if FUNCTION == 0:
        RESULT_ENTITY = "Proto-string"
        protoStrings = len(OPTIONAL_ARGS) != 0 and OPTIONAL_ARGS or protocol.PROTOCOL_STRINGS
        # get the basic processing graphs for each protocol string
        i = 0 
        for processingGraphs in w.analyzeCmd(FILE_IO_MODE, OUT_DIR, protoStrings):
            print "Thread #%d" % i
            w.analyzeAdvanced(processingGraphs)
        
            for processingGraph in processingGraphs:
                print processingGraph
                
            i += 1
    
    elif FUNCTION == 1:
        RESULT_ENTITY = "Privilege level"
        privLevels = len(OPTIONAL_ARGS) != 0 and OPTIONAL_ARGS or protocol.PRIV_LEVELS
        # TODO: results should get their own data structure
        results = w.analyzeAuth(FILE_IO_MODE, OUT_DIR, privLevels)
        for privLevel in results:
            print "Priv-Level %d" % privLevel
            i = 0
            for processingGraphs in results[privLevel]:
                print "Thread #%d" % i
                w.analyzeAdvanced(processingGraphs)
                for processingGraph in processingGraphs:
                    print processingGraph
                i += 1
    else:
        print "Error: Unknown function."
        
        
    
          
     
    