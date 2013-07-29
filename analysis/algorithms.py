'''
Created on 10.08.2012

@author: Felix

Collection of trace-analysis algorithms
'''

import sets
try:
    from pygraph.classes.digraph import digraph
except ImportError:
    raise ImportError("Please intall pygraph.")

class _Helper:
    
    @staticmethod
    def normalizeScores(scores):
        overall = 0.0
        for val in scores.values():
            overall += val
        if overall == 0.0:
            return scores
        
        normalizedScores = {}
        for key in scores:
            value = scores[key]
            if value == 0:
                continue
            normalizedScores[key] = value / overall
        return normalizedScores
    
    @staticmethod
    def getNodeSet(traces):
        nodes = sets.Set()
        # first get nodes present in all graphs
        for trace in traces:
            dgCmd = trace.getDigraph()
            nodes = nodes.union(dgCmd.nodes())
        return nodes
    
class PreFiltering:
    
    @staticmethod
    def a0(traces):
        """
        Filters out too short traces. 
        """
        LENGTH_TRESHOLD = 0.1
        n = len(traces)
        if n <= 1:
            return traces
        
        lsum = 0.0
        for trace in traces:
            lsum += len(trace)
            
        # only keep traces that are at least 10% of the average size
        newTraces = []
        for trace in traces:
            v = float(len(trace))/((lsum - len(trace))/float((n-1))) 
            if v >= LENGTH_TRESHOLD:
                newTraces.append(trace)
                
        return newTraces
    
    class Ref:
        @staticmethod
        def a0(traces, tracesRef):
            """
            Generates a list of nodes only present in either a primary or secondary (ref) trace.
            The list should be excluded from furhter analysis.
            @param traces: Primary traces
            @param tracesRef: Secondary traces
            @type traces: list of RunFunc
            @type tracesRef: list of RunFunc
            @return: List of addresses 
            """
            
            assert len(traces) == len(tracesRef)
            uncommonNodes = sets.Set()
            for i in range(len(traces)):
                nodes = sets.Set(traces[i].diGraph.nodes())
                nodesRef = sets.Set(tracesRef[i].diGraph.nodes())
                
                uncommonNodes |= ((nodes | nodesRef) - (nodes & nodesRef))
                
            return list(uncommonNodes)
        
        @staticmethod
        def a1(traces, tracesRef):
            """
            Compares the return values of the given primary traces and their corresponding secondary (reference) traces. 
            Returns a list of functions that have different return values between traces of different protocol runs but not between primary and secondary trace of each protocol run.
            @param traces: Primary traces
            @param tracesRef: Secondary traces
            @type traces: list of RunFunc
            @type tracesRef: list of RunFunc
            @return: List of addresses
            """
            assert len(traces) == len(tracesRef)
            stableFuncs = {}
            unstableFuncs = sets.Set()
            for i in range(len(traces)):
                
                retValues = traces[i].trace.getFunctionReturnValues()
                retValuesRef = tracesRef[i].trace.getFunctionReturnValues()
                for func in retValues:
                    
                    if func in unstableFuncs:
                        continue
                    
                    unstableFuncs.add(func)
                    
                    if func not in retValuesRef:
                        continue
                    
                    rv = retValues[func]
                    rvRef = retValuesRef[func]
                        
                    if len(rv) != 1 or len(rvRef) != 1:
                        continue 
                    
                    if rv != rvRef:
                        continue
                    
                    unstableFuncs.remove(func)
                    
                    if func not in stableFuncs:
                        stableFuncs[func] = []
                            
                    stableFuncs[func].append(rv)
            
            funcsOfInterest = []        
            for stableFunc in stableFuncs:
                
                if stableFunc in unstableFuncs:
                    continue
                
                funcOfInterest = False
                for returnValues in stableFuncs[stableFunc][1:]:
                    if returnValues != stableFuncs[stableFunc][0]:
                        funcOfInterest = True
                        break
                    
                if funcOfInterest:
                    funcsOfInterest.append(stableFunc)
                    
            return funcsOfInterest
        
class PostFiltering:
        
    @staticmethod
    def a0(traces):
        """
        Simply filters out 'None' traces.
        """
        return [t for t in traces if t is not None]

class DecisionNodeFinding:
    
    @staticmethod
    def a0(traces, referenceTrace):
        """
        Assumes the trace for the invalid command as fixed-point. Consists of the following steps:
            
            1) Normalizes all traces and removes repetitions.
            2) Determines the largest common sub-sequence of the trace of the invalid command and each valid command.
            3) Determines the largest common sub-sequence of all previously determined invalid command/command sub-sequences
            4) Outputs the sequence determined in step 3) in reverse order. The first function in this output is likely to be the command-dispatcher. If not, it could likely be the functions at the subsequent positions.
            
        Functions should get a score depending on their position in the sequence (lower == better) and the overall lenght of the sequence (longer == better).
        If the returned list is empty, it is likely that the server-application in question does not possess a central command-dispatcher (maybe multiple for different commands or chained command-handlers with each having its own dispatcher).
        
        Possible further improvements:
            
            1) If the length of the lcss drops significantly for a certain subseq, then this subseq should be left out, at the cost of a lower scoring for the result.
            
        @param traces: A list of function traces belonging to a certain protocol string
        @type traces: pygdb.trace.FunctionTrace
        @param referenceTrace: A trace 
        """
        from tools import sequence, algorithms
        
        seqRef = sequence.Sequence(algorithms.removeRepetitions(referenceTrace.getNormalizedSequence()))
        seqRef.removeAll(referenceTrace.getVirtualStartingNode())
    
        subSeqsInvalid = []
        for trace in traces:
            if trace is None:
                continue
            seq = sequence.Sequence(algorithms.removeRepetitions(trace.getNormalizedSequence()))
            seq.removeAll(trace.getVirtualStartingNode())
            lcss = seqRef.findLargestCommonSubSequence(seq)
            if lcss is not None:
                subSeqsInvalid.append(lcss)
            
        if len(subSeqsInvalid) == 0:
            return []
        
        lcss = subSeqsInvalid[0]
        for subSeqInvalid in subSeqsInvalid[1:]:
            if lcss is None:
                return []
            lcss = lcss.findLargestCommonSubSequence(subSeqInvalid)
            
        if lcss is None:
                return []
        
        return _Helper.normalizeScores({lcss.rawSeq[i] : i for i in range(len(lcss.rawSeq))})
    
    @staticmethod
    def a1(stringTraces, traceInvalid):
        try:
            from pygraph.algorithms.accessibility import cut_nodes
        except ImportError:
            raise ImportError("Please intall pygraph.")
        
        dgInvalid = traceInvalid.getDigraph()
        cutNodes = [cut_nodes(dgInvalid)]
        
        for trace in stringTraces:
            dgCmd = trace[0].getDigraph()
            cutNodes.append(cut_nodes(dgInvalid))
        return cutNodes
    
    @staticmethod
    def a2(traces, referenceTrace):
        """
        Assumes the trace for the invalid command as fixed-point. Consists of the following steps:
            1) Identify all nodes that are present in all graphs.
            2) For each of those nodes identify all neighbors that are present in all traces.
            3) Calculate a score for each node in the following way:
                For each neighbor in each trace that is not present in all traces a common function gets one point.
            4) The score reflects the likelihood of each function to contain the command-dispatcher
        """
        dgReference = referenceTrace.getDigraph()
        nodesReference = dgReference.nodes()
        nodesCommon = sets.Set(nodesReference)
        nodesCommon.discard(referenceTrace.getVirtualStartingNode())
        # first get nodes present in all graphs
        graphs = []
        for trace in traces:
            dgCmd = trace.getDigraph()
            nodesCommon = nodesCommon.intersection(dgCmd.nodes())
            graphs.append(dgCmd)
            
        # now get the common neighbors for all common nodes
        neighborsCommon = {}
        for node in nodesCommon:
            neighborsCommon[node] = sets.Set(dgReference.neighbors(node))
            
        for dgCmd in graphs:
            for node in neighborsCommon:
                neighborsCommon[node] = neighborsCommon[node].intersection(dgCmd.neighbors(node))
                
        # finally calculate the 'variance of neighbors' for each node
        variances = {node:0 for node in neighborsCommon}
        for dgCmd in graphs:
            for node in neighborsCommon:
                neighborsCmd = sets.Set(dgCmd.neighbors(node))
                neighborsDiff = neighborsCmd.difference(neighborsCommon[node]) 
                variances[node] += len(neighborsDiff)
                
        from tools.algorithms import findItemInList
        values = []
        keys = []
        for node in variances:
            value = variances[node]
            i = findItemInList(values, value)[0]
            values = values[:i+1] + [value] + values[i+1:]
            keys = keys[:i+1] + [node] + keys[i+1:]
            
        return keys[::-1]
    
    @staticmethod
    def a2b(traces, referenceTrace):
        """
        Like A2 but with modified scoring:
            For each neighbor out of all traces a function gets a point for each trace that does not contain the neighbor.
        
        Apparently delivers better results than A2.
        """
        import sets
        try:
            from pygraph.classes.digraph import digraph
        except ImportError:
            raise ImportError("Please intall pygraph.")
        dgReference = referenceTrace.getDigraph()
        nodesReference = dgReference.nodes()
        nodesCommon = sets.Set(nodesReference)
        nodesCommon.discard(referenceTrace.getVirtualStartingNode())
        # first get nodes present in all graphs
        graphs = []
        for trace in traces:
            dgCmd = trace.getDigraph()
            nodesTmp = dgCmd.nodes()
            nodesCommon = nodesCommon.intersection(nodesTmp)
            graphs.append(dgCmd)
            
        graphs.append(dgReference)
            
        # get the neighbors for all common nodes in all traces
        neighbors = {node:{} for node in nodesCommon}
        for graph in graphs:
            for node in nodesCommon:
                for neighbor in graph.neighbors(node):
                    if neighbor not in neighbors[node]:
                        neighbors[node][neighbor] = len(graphs) 
                    neighbors[node][neighbor] -= 1
        
        scores = {node : 0 for node in nodesCommon}
        for node in nodesCommon:
            for v in neighbors[node].values():
                scores[node] += v
            
        return _Helper.normalizeScores(scores)
    
    @staticmethod
    def a3(traces, referenceTrace, depth=-1):
        from tools import sequence, algorithms
        
        seqRef = sequence.Sequence(algorithms.removeRepetitions(referenceTrace.getNormalizedSequence(depth)))
        seqRef.removeAll(referenceTrace.getVirtualStartingNode())
        seqs = []
        for trace in traces:
            seq = sequence.Sequence(algorithms.removeRepetitions(trace.getNormalizedSequence(depth)))
            seq.removeAll(trace.getVirtualStartingNode())
            seqs.append(seq)
            
        return DecisionNodeFinding._a3core(seqs, seqRef)
    
    @staticmethod
    def a3b(traces, referenceTrace):
        """
        Same as A3 but does only take immediate sub-nodes of the root-node into account.
        """ 
        return DecisionNodeFinding.a3(traces, referenceTrace, 1)
    
    @staticmethod
    def _a3core(seqs, seqRef):
        from tools import sortDictionary
        
        scoresIndexes = {}
        for seq in seqs:
            rangesCommon = seqRef.getCommonRanges(seq)[0]
            # add sentinel range
            rangesCommon.append([seqRef.len])
            for i in range(len(rangesCommon)-1):
                r = rangesCommon[i]
                baseScore = rangesCommon[i+1][0] - r[-1]
                for i in range(len(r)):
                    index = r[i]
                    if index not in scoresIndexes:
                        scoresIndexes[index] = 0
                    scoresIndexes[index] += baseScore + i 
                                    
        scores = {seqRef.rawSeq[index] : scoresIndexes[index] for index in scoresIndexes}
        normalizedScores = _Helper.normalizeScores(scores)
        keys, values = sortDictionary(normalizedScores)
        # print keys[::-1]
        # print values[::-1]
        return normalizedScores
        
    class Evaluation:
        
        @staticmethod
        def a2b(results, stringTraces, traceInvalid):
            """
            Supposed to identify candidate functions that are linked by a direct edge.
            Yet to be implemented.
            """
            from tools import sortDictionary
            funcs, scores = sortDictionary(results)
            funcs = funcs[::-1]
            scores = scores[::-1]
            # find connection between identified functions
            i = 0
            while scores[i] != 0.0:
                i += 1
                
            funcs = funcs[:i]
            scores = scores[:i]
            
            chains = []
            chainsDict = {}
            
            # TODO: Finish me!
            i = 0
            while i < len(funcs):
                neighbors = traceInvalid.neighbors()
                func = funcs[i]
                while len(neighbors) != 0:
                    pass
                    
                i += 1
                
class ImplementationNodeFinding:
    """
    Algorithms for finding exclusive functionality in a trace given a set of reference traces.
    """
    @staticmethod
    def a0(trace, referenceTraces):
        """
        Just returns a list of events exclusive to the given trace.
        @param trace: The trace to examine.
        @param referenceTraces: A list of traces to use for reference.
        @return: A set of nodes exclusively contained in the trace
        """
        from tools.sequence import Sequence
            
        refNodes = _Helper.getNodeSet(referenceTraces)
        graph = trace.getDigraph()
        nodes = sets.Set(graph.nodes())
        exNodes = nodes.difference(refNodes)
        
        # get the sub-traces of all exclusive nodes 
        exTraces = {}
        for node in exNodes:
            exTraces[node] = [Sequence(t.getNormalizedSequence()) for t in trace.getTracesBetween(node, node)]
            
        # check if any of the exclusive nodes is contained
        topExNodes = [] 
        for node in exTraces:
            isTopEx = True
            for otherNode in exTraces:
                if otherNode == node:
                    continue
                
                if not isTopEx:
                    break
                
                for otherTrace in exTraces[otherNode]:
                    isTopEx = not otherTrace.containsItem(node)
            
            if isTopEx:
                topExNodes.append(node)
                
        return topExNodes
        
class ThreadSelection:
    
    @staticmethod
    def a0(traces):
        """
        Just selects the longest thread-trace for each trace. 
        """
        threadTraces = []
        for trace in traces:
            threadTraces.append(ThreadSelection.a0Single(trace))
            
        return threadTraces
    
    @staticmethod
    def a0Single(trace):
        """
        Selects the longest thread-trace.
        """
        l = 0
        longestTt = None
        for tt in trace:
            if len(tt) > l:
                l = len(tt)
                longestTt = tt
                
        return longestTt
        
        
                    
                    
                        
                        
            
    
            
        
            
            
        
        
        
        
        
        