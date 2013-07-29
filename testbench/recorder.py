'''
Created on 23.04.2012

@author: Felix
'''
from pygdb import tracer
from testbench.protocols.protocol import RunFunc, RunBb
from player import ServerInvoker
import zlib
import pickle
import os

def _defaultTraceSelector(traces):
    longestTrace = None
    for trace in traces:
        if longestTrace is None or (len(trace.items) > len(longestTrace.items)):
            longestTrace = trace
    return trace

class ServerTraceRecorder:
    """
    Records traces of remote network services.
    """
    _RECORD_PROTOCOL_CHUNK_DELAY = 0
    _PAUSE_CONNECT = 0.1
    _MAX_TRIES_CONNECT = 10
    
    class FILE_IO:
        LOAD_TRACE_DATA = 0
        STORE_TRACE_DATA = 1
    
    def __init__(self, pygdb, transport):
        """
        @param pygdb: The PyGdb instance to use.        
        """
        self.gdbSession = pygdb
        self.transport = transport
    
    def _record(self, tracer, protoProcessor, verbose):
        
        si = ServerInvoker(protoProcessor, self.transport)
        
        self.gdbSession.enableCacheForBreakpoints(True)
        # before we connect, we start pygdb again in another thread (so things like forks get handled automatically)
        tt = self.gdbSession.start(True)
        if not si.playFirst(verbose):
            print "[e] Something went wrong while playing the protocol prologue!"
            return None
        
        # DEBUG
        print "[i] Stopping the debugger 1."
        #######
        
        self.gdbSession.stop()
        tt.join()
        # setup tracer and start in a separate thread
        
        if verbose:
            print "[i] Starting tracer. Playing rest of protocol."
        # make the tracer set its breakpoints    
        tracer.setup()
        tracer.start()
        if not si.playSecond(verbose):
            print "[e] Something went wrong while playing the protocol part of interest!"
            return None
        
        # DEBUG
        print "[i] Stopping the debugger 2."
        #######
        
        tracer.stop()
        if len(tracer.traces) == 0:
            print "[!] Successfully played the protocol, but no events were recorded. Please make sure, that the remote gdbserver is attached to the correct process."
            
        self.gdbSession.enableCacheForBreakpoints(False)
        return tracer
            
    def recordCallgraph(self, protoProcessor, reset=True, verbose=False, addrFuncs=None, unrebaseTraces=False, maxHits=5, traceSelector=_defaultTraceSelector, basePathTraceData=None, fileIoAction=None, tag=""):
        """
        Records a trace on function level (global callgraph).
        @param addrFuncs: [OPTIONAL] List of functions to take into account (not rebased!). If not specified, all function are taken into account. 
        @param protoProcessor: The processor of the protocol to evaluate.
        @type protoProcessor: protocol.Processor
        @type reset: bool
        @param verbose: A flag indicating the verbose level.
        @type verbose: bool 
        @param unrebaseTraces: [OPTIONAL] Undo the rebasing of all addresses in all traces before returning them.
        @param maxHits: [OPTIONAL] The maximum times a function can be hit before being ignored.
        @param traceSelector: [OPTIONAL] Function for selecting threads.
        @param basePathTraceData: [OPTIONAL] Path where traces are stored.
        @param fileIoAction: [OPTIONAL] Store/load traces to/from the specified path.
        @param tag: [OPTIONAL] Tag to prepend to the string-identifier used to load/store traces
        @return: A list of all recorded traces.
        """
        
        run = None
        if fileIoAction == self.FILE_IO.LOAD_TRACE_DATA:
            pathTraceData = self._generateTracePath(basePathTraceData, protoProcessor, tag, maxHits)
            run = ServerTraceRecorder._loadTrace(pathTraceData)
        
        if run is None:
            if reset:
                self.gdbSession.reset(hard=False)        
            ft = self._createFunctionTracer(maxHits, addrFuncs)
            tr = self._record(ft, protoProcessor, verbose)
            
            traces = tr.getTraces(unrebaseTraces)
            if traces is not None:
                run = RunFunc(protoProcessor, traces, traceSelector=traceSelector)
            
            if fileIoAction == self.FILE_IO.STORE_TRACE_DATA or fileIoAction == self.FILE_IO.LOAD_TRACE_DATA:
                pathTraceData = self._generateTracePath(basePathTraceData, protoProcessor, tag, maxHits)
                ServerTraceRecorder._storeTrace(pathTraceData, run)
        
        return run
    
    def _createFunctionTracer(self, maxHits, addrFuncs=None):
        if addrFuncs is None:
            funcs = self.gdbSession.environment.getFunctionsRebased(self.gdbSession)
        else:
            funcs = []
            for func in addrFuncs:
                funcs.append(self.gdbSession.environment.rebaseCodeAddr(self.gdbSession, func))
        ft = tracer.FunctionTracer(self.gdbSession, funcs, maxHits)
        return ft
    
    def recordFlowgraph(self, addrFunc, protoProcessor, reset=True, verbose=False, unrebaseTraces=False, requiredCallStack=None, addrFuncs=None, maxHitsCallStack=5, traceSelector=_defaultTraceSelector, basePathTraceData=None, fileIoAction=None, tag=""):
        """
        Records a trace on function level (global callgraph).
        @param addrFunc: The address of the function to trace.
        @param protoProcessor: The processor of the protocol to evaluate.
        @type protoProcessor: protocol.Processor
        @param reset: A flag indicating whether to the remote server should be initially reset.
        @type reset: bool
        @param verbose: A flag indicating the verbosity level.
        @type verbose: bool
        @param unrebaseTraces: [OPTIONAL] Undo the rebasing of all addresses in all traces before returning them.
        @param requiredCallStack: [OPTIONAL] If given, the given function will only be traced in case the certain call-stack is encountered.
        @param addrFuncs: [OPTIONAL] List of functions to take into account (not rebased!) when checking a call-stack. If not specified, all function are taken into account.
        @param maxHitsCallStack: [OPTIONAL] Maximum number of function hits while tracking the call-stack.
        @param traceSelector: [OPTIONAL] Function for selecting threads.
        @param basePathTraceData: [OPTIONAL] Path where traces are stored.
        @param fileIoAction: [OPTIONAL] Store/load traces to/from the specified path.
        @param tag: [OPTIONAL] Tag to prepend to the string-identifier used to load/store traces
        @return: A list of all recorded traces. 
        """
        # first check if we can just load the trace from disk
        run = None
        if fileIoAction == self.FILE_IO.LOAD_TRACE_DATA:
            pathTraceData = self._generateBBTracePath(basePathTraceData, protoProcessor, addrFunc, requiredCallStack, tag, maxHitsCallStack)
            run = ServerTraceRecorder._loadTrace(pathTraceData)
        
        if run is None: 
            if reset:
                self.gdbSession.reset(hard=False)
            addrFuncRebased = self.gdbSession.environment.rebaseCodeAddr(self.gdbSession, addrFunc)
            
            if requiredCallStack is not None and not len(requiredCallStack) == 0:
                ft = self._createFunctionTracer(maxHitsCallStack, addrFuncs)
            else:
                ft = None
                
            bbt = tracer.BasicBlockTracer(self.gdbSession, addrFuncRebased, requiredCallStack=requiredCallStack, functionTracer=ft)
            tr =  self._record(bbt, protoProcessor, verbose)
            
            traces =  tr.getTraces(unrebaseTraces)
            if traces is not None:
                run = RunBb(protoProcessor, traces, traceSelector=traceSelector)
                
            # should we back up the trace?
            if fileIoAction == self.FILE_IO.STORE_TRACE_DATA or fileIoAction == self.FILE_IO.LOAD_TRACE_DATA:
                pathTraceData = self._generateBBTracePath(basePathTraceData, protoProcessor, addrFunc, requiredCallStack, tag, maxHitsCallStack)
                ServerTraceRecorder._storeTrace(pathTraceData, run)
        
        
        return run
    
    ## helper methods
    
    def _generateBBTracePath(self, basePath, protoProc, addrFunc, callStack, tag, maxHits):
        data = tag
        data += self.gdbSession.environment.pathExecutable or ""
        data += protoProc.name
        data += str(maxHits)
            
        data += "%x" % addrFunc
        if callStack is not None:
            for csItem in callStack:
                data += "%x" % csItem
               
        fileName = "bb_trace_%x" % zlib.adler32(data)  
        return os.path.join(basePath or "", fileName)
    
    def _generateTracePath(self, basePath, protoProc, tag, maxHits):
        data = tag
        data += self.gdbSession.environment.pathExecutable or ""
        data += protoProc.name
        data += str(maxHits)
        
        fileName = "ft_trace_%x" % zlib.adler32(data)
        return os.path.join(basePath or "", fileName)
    
    @staticmethod
    def _loadTrace(path):
        try:
            f = file(path, "rb")
        except IOError:
            return None
        else:
            traceData = pickle.load(f)
            f.close()
            return traceData
        
    @staticmethod
    def _storeTrace(path, trace):
        if path is not None:
            f = file(path, "wb")
            pickle.dump(trace, f)
            f.close()
    
    
    
    
        
        
        
