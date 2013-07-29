'''
Created on 21.11.2012

@author: Felix

Data-structures for passing analysis results.
Ugly, ugly code...
'''

class ProcessingGraph:
    
    def __str__(self):
        s = ""
        for node in self.nodes.values():
            for descriptor in self.edges[node.addr]:
                s += "\t%s," % descriptor
            
            tmp = "\r\n" + str(node)
            s += tmp.replace("\r\n", "\r\n\t")
            s += "\r\n"
        return s
    
    def __iter__(self):
        yield self
        for node in self.nodes.values():
            if isinstance(node, ProcessingGraph):
                for subNode in node:
                    yield subNode
            else:
                yield node    
                
    def __init__(self):
        self.nodes = {}
        self.edges = {}
        
    def addEdge(self, descriptor, node):
        
        if node.addr not in self.edges:
            self.edges[node.addr] = []
            self.nodes[node.addr] = node
            
        if isinstance(descriptor, list):
            descriptors = descriptor
        else:
            descriptors = [descriptor]
            
        for desc in descriptors:
            if descriptor not in self.edges[node.addr]:
                self.edges[node.addr].append(desc)
            
    def addEdges(self, descriptors, nodes):
        for node in nodes:
            self.addEdge(descriptors, node)
            
    def generateAttributeNodes(self, attribute, generator):
        for node in self:
            node.generateAttribute(attribute, generator)
            
class ProcessingGraphNode:
    
    TYPE = "Unknown"
    
    class ATTRIBUTES:
        NAME = "name"
        SCORE = "score"
        
    def __str__(self):
        name = self.ATTRIBUTES.NAME in self.attributes and self.attributes[self.ATTRIBUTES.NAME] or "%x" % self.addr
        scoreVal = self.ATTRIBUTES.SCORE in self.attributes and self.attributes[self.ATTRIBUTES.SCORE] or 0.0
        if scoreVal == 0.0:
            score = ""
        else:
            score = "(%f)" % scoreVal
        
        s = "%s %s %s\r\n" % (self.TYPE, name, score)
        
        # add optional attributes
        for attribute in self.attributes:
            if attribute != self.ATTRIBUTES.NAME and attribute != self.ATTRIBUTES.SCORE:
                s += "%s:%s" % (attribute, self.attributes[attribute])
        return s
    
    def __init__(self, addr):
        self.attributes = {}
        self.addr = addr
    
    def generateAttribute(self, attribute, generator):
        self.setAttribute(attribute, generator(self.addr))
        
    def setAttribute(self, attribute, value):
        self.attributes[attribute] = value
    
class _Func(ProcessingGraphNode):
    
    def __str__(self):    
        s = "%s" % (ProcessingGraphNode.__str__(self))
        if self.bbGraphs is not None:
            tmp = ""
            for i in range(len(self.bbGraphs)):
                tmp += "\r\n" + str(self.bbGraphs[i])
                
            s += tmp.replace("\r\n", "\r\n\t") + "\r\n"
            
        return s
    
    def __init__(self, addr):
        ProcessingGraphNode.__init__(self, addr)
        self.bbGraphs = None
        self.bbProtoRuns = None
            
    def addBbGraphs(self, bbGraphs, bbProtoRuns):
        if bbGraphs is not None and len(bbGraphs) > 0:
            self.bbGraphs = bbGraphs
            self.bbProtoRuns = bbProtoRuns
    
class DecisionFunc(ProcessingGraph, _Func):
    
    TYPE = "Decision func"
    class SPECIFIC_ATTRIBUTES:
        IMPORTANT = "important"
    
    def __str__(self):
        return _Func.__str__(self) +  ProcessingGraph.__str__(self)
    
    def __init__(self, addr):
        ProcessingGraph.__init__(self)
        _Func.__init__(self, addr)
        self.groups = []
        
    def addGroup(self, group):
        self.groups.append(group)
    
class ImplementationFunc(_Func):
    
    TYPE = "Implementation func"
    
class DecisionBb(ProcessingGraph, ProcessingGraphNode):
    
    TYPE = "Decision bb"
    
    class SPECIFIC_ATTRIBUTES:
        SUSPICIOUS_EDGES = "suspicious edges"
    
    def __str__(self):
        return ProcessingGraphNode.__str__(self) + ProcessingGraph.__str__(self)
    
    def __init__(self, addr):
        ProcessingGraph.__init__(self)
        ProcessingGraphNode.__init__(self, addr)

    def generateAttributeNodes(self, attribute, generator):
        self.generateAttribute(attribute, generator)
        ProcessingGraph.generateAttributeNodes(self, attribute, generator)
    
class ImplementationBb(ProcessingGraphNode):
    
    TYPE = "Implementation bb"
    
    def __init__(self, addr):
        ProcessingGraphNode.__init__(self, addr)
        self.exclusiveFuncs = {}
        
    def addExclusiveFunc(self, func):
        self.exclusiveFuncs[func.addr] = func
        
##
class FunctionPointerTableCandidate:

        def __init__(self, start, end, entrySize, unknownFunctionPointers):
            self.start = start
            self.end = end
            self.entrySize = entrySize
            self.unknownFunctionPointers = unknownFunctionPointers

        # output object (for debugging purposes)
        def __str__(self):
            res = "[{0:08x}:{1:08x}, {2:02d}]:".format(self.start, self.end,
                                              self.entrySize)
            for fp in self.unknownFunctionPointers:
                res += "\n[>] " + hex(fp)
            return res

        # we'll need to distinguish objects in a set, thus we need to implement
        # both __eq__ and __hash__
        def __eq__(self, other):
            if not isinstance(other, FunctionPointerTableCandidate):
                return False

            # unknownFunctionPointers is implicit, not part of identity
            return self.start == other.start and self.end == other.end and \
                self.entrySize == other.entrySize

        def __hash__(self):
            return hash(self.start) ^ hash(self.end) ^ hash(self.entrySize)