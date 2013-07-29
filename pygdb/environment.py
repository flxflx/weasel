'''
Created on 18.07.2012

@author: Felix
'''
import tools
from tools.algorithms import findItemInList

class _environment:
    
    def __init__(self, pathExecutable=None, pathFunctionsList=None):
        """
        @param pathExecutable: [OPTIONAL] Path to the executable of the debugee. If this is not supplied, no rebasing is possible.
        @param pathFunctionsList: File containing a list of functions within the target executable. Format is: virtual-address[:name][:size]    \r\n.
        """
        self.pathExecutable = pathExecutable
        self.pathFunctionsList = pathFunctionsList
        self.baseAddrCode = 0
        self.funcs = None
        self.names = None
        self.funcsRebased = {}
        if self.pathFunctionsList is not None:
            self.funcs = {}
            self.names = {}
            f = file(pathFunctionsList, "rb")
            x = f.read()
            f.close()
            for line in x.split():
                addr, name, size = line.split(":")
                if len(size) == 0:
                    size = "-1"
                func = tools.Function(int(addr,16), int(size,10), name)
                self.funcs[func.addr] = func
                self.names[func.addr] = func.name
        
    def getForkProcessId(self, gdbSession, tid):
        """
        Call this right after the invocation of fork(), CreateProcess or similar to get the process id of the newly created process.
        @param gdbSession: The gdbSession instance to use.
        @param tid: The thread to evaluate.
        """
        raise NotImplemented("Needed for follow-fork.")
    
    def packThreadId(self, pid, tid):
        """
        Returns a unique identifier for the given tid/pid pair.
        """
        return (pid << self.BITS_THREAD_ID) | tid
    
    def unpackThreadId(self, packedTid):
        """
        Returns seperate tid/pid of the given packed tid.
        """
        if packedTid == -1:
            return (-1, -1)
        
        if packedTid == 0:
            return (0,0)
        
        tid = packedTid & ~(~0 << self.BITS_THREAD_ID)
        pid = packedTid >> self.BITS_THREAD_ID
        return (pid, tid)
    
    def rebaseCodeAddr(self, gdbSession, addr, pid=None):
        """
        Rebases the given address (code-segment) for the actual running instance of the target application.
        @param gdbSession: The gdbSession instance to use.
        @param addr: The address (code-segment) to rebase.
        @param pid: The process id
        @return: The rebased address
        """
        raise NotImplemented("Needed for processes using ASLR and the like.")
    
    def unrebaseCodeAddr(self, gdbSession, addr, pid=None):
        """
        inverse function to rebaseCodeAddr
        @param gdbSession: The gdbSession instance to use.
        @param addr: The address (code-segment) to rebase.
        @param pid: The process id
        @return: The rebased address
        """
        raise NotImplemented("Needed for processes using ASLR and the like.")
    
    def getFunctionsRebased(self, gdbSession, pid=None):
        """
        Returns a list of all rebased function addresses.
        @param gdbSession: The gdbSession instance to use
        @param pid: The process id
        """
        raise NotImplemented("Needed for processes using ASLR and the like.")
    
    def getFunctionsUnrebased(self, gdbSession, pid=None):
        """
        Returns a list of all rebased function addresses.
        @param gdbSession: The gdbSession instance to use
        @param pid: The process id
        """
        raise NotImplemented("Needed for processes using ASLR and the like.")
    
    def rebaseFunctions(self, gdbSession, funcs, pid=None):
        """
        Rebases a list of functions.
        @param gdbSession: The gdbSession instance to use
        @param funcs: The list of functions to rebase
        @param pid: The process id
        @return: A list of rebased addresses
        """
        raise NotImplemented("Convenience function")
    
    def unrebaseFunctions(self, gdbSession, rebasedFuncs, pid=None):
        """
        Inverse of rebaseFunctions
        @param gdbSession: The gdbSession instance to use
        @param funcs: The list of functions for which to undo rebasing
        @param pid: The process id
        @return: A list of not rebased addresses
        """
        raise NotImplemented("Convenience function")
    
    def forkInheritsBreakpoints(self):
        return self._FORK_INHERITS_BREAKPOINTS
    
    def getNearestFunction(self, gdbSession, codeAddr, pid=None):
        """
        Gets the address of the function that most likely contains the given code address.
        @param pid: The process id
        """
        raise NotImplemented("Needed for callgraph-recording.")
    
    def reset(self):
        """
        Resets the environment instance.
        """
        raise NotImplemented()
    
    def getNames(self, gdbSession):
        """
        Gets a dictionary mapping unrebased addresses to names.
        @param gdbSession: The gdbSession instance to use
        """
        raise NotImplemented()
    
    def getSizeOfFunction(self, addrFunc):
        """
        Gets the size of the given function (unrebased).
        """
        raise NotImplemented()

    def hookFunction(self, gdbSession, pid, callback, addrImportPointer, addrFunc=None, internal=False):
        """
        Hooks a certain function. When addrImportPointer is given, it is checked after each invocation if the pointer has changed. This is useful for hooking lazy-binding imports on POSIX.
        At least one of addrFunc and addrImportPointer must be given.
        @param gdbSession: The gdbSession instance to use
        @param pid: The pid od the process to install the hook in
        @param addrImportPointer: The rebased address of a pointer to the function to hook (e.g. in the IAT on Windows or the GOT on POSIX).
        @param addrFunc: [OPTIONAL] The rebased address of the function to hook.
        @param callback: The callback to invoke on the invocation of the respective function.
        @param internal: [OPTIONAL] Boolean flag indicating if the function should be hooked using internal breakpoints.
        @return: Boolean value indicating success.
        """
        raise NotImplemented()
    
    def addrBelongsToImage(self, pygdb, addr, pid=None):
        """
        Checks if the given address is inside the current image.
        @param addr: The rebased address to check.
        @param pygdb: The pygdb instance to use.
        @param pid: The process of interest.
        """
        return addr >= self.getStartAddrImage(pygdb, pid) and addr <= self.getEndAddrImage(pygdb, pid)
    
    def getStartAddrImage(self, pygdb, pid):
        """
        Get the rebased start address of the image in the given process.
        @param pygdb: The pygdb instance to use.
        @param pid: The process of interest.
        """
        raise NotImplemented()
    
    def getEndAddrImage(self, pygdb, pid):
        """
        Get the rebased end address of the image in the given process.
        @param pygdb: The pygdb instance to use.
        @param pid: The process of interest.
        """
        raise NotImplemented()
    
class Windows(_environment):
    NAME = "Windows"
    BITS_THREAD_ID = 16
    _FORK_INHERITS_BREAKPOINTS = False 
    
class Posix(_environment):
    NAME = "Posix"
    BITS_THREAD_ID = 16
    _FORK_INHERITS_BREAKPOINTS = True 
    
    # TODO: the following blacklist should not be hardcoded
    BLACKLIST_FUNCTIONS = ["boost", "std", "gnu"]
    
    class _AUXILIARY_VECTOR:
        AT_PHDR = 3 # Program headers for program, can be used to get base-address (?!)
        
    class ELF:
        class HEADER:
            class TYPE:
                REL = 1
                EXEC = 2
                
    class _FunctionsRebased:
        
        def __init__(self, baseAddr, funcsRebased):
            self.baseAddr = baseAddr
            self.funcsRebased = funcsRebased
    
    def __init__(self, pathExecutable=None, pathFunctionsList=None):
        _environment.__init__(self, pathExecutable, pathFunctionsList)
        
        # now check if the app needs code rebasing (aka if it contains relocations)
        self.functionHooks = {}
        if self.pathExecutable is not None:
            self.elf = tools.getELFFromPathOrObject(self.pathExecutable)
            e_type = self.elf.header.get('e_type')
            self.needsCodeRebasing = e_type == 'ET_REL' or e_type == 'ET_DYN'
        else:
            self.needsCodeRebasing = False
            
        self.reset()
        
    def getEndAddrImage(self, gdbSession, pid=None):
        # TODO: dirty!
        _pid = pid or gdbSession.pid
        if _pid not in self.endAddrImage:
            endAddr = self.rebaseCodeAddr(gdbSession, tools.getLoadedImageEndELF(self.elf))
            self.endAddrImage[_pid] = endAddr
           
        return self.endAddrImage[_pid]
    
    def getStartAddrImage(self, gdbSession, pid=None):
        _pid = pid or gdbSession.pid
        if _pid not in self.startAddrImage:
            startAddr = self.rebaseCodeAddr(gdbSession, tools.getLoadedImageStartELF(self.elf), _pid) 
            self.startAddrImage[_pid] = startAddr
           
        return self.startAddrImage[_pid]
            
    def getForkProcessId(self, gdbSession, tid):
        # The return value of fork() is the process id.
        return gdbSession.cpu.getFunctionReturnValues(gdbSession, tid)[0]
    
    def getBaseAddrCode(self, gdbSession, pid=None):
        _pid = pid or gdbSession.pid
        if pid not in self.baseAddrCode:
            auxv = self.getAuxiliaryVector(gdbSession)
            self.baseAddrCode[pid] = auxv[self._AUXILIARY_VECTOR.AT_PHDR] & (~0xFF)
            
        return self.baseAddrCode[pid]
    
    def getAuxiliaryVector(self, gdbSession):
        
        rawAuxv = gdbSession.getRawAuxiliaryVector()
        entrySize = gdbSession.cpu.getNativeRegisterWidth()/8
        if gdbSession.cpu.islittleEndian():
            endianess = tools.ENDIANESS.LITTLE
        else:
            endianess = tools.ENDIANESS.BIG
        auxv = {}
        isIndex = True
        for i in range(len(rawAuxv))[::entrySize]:
            chunk = rawAuxv[i:i+entrySize]
            tmp = tools.byteStrToInt(chunk, endianess)
            if isIndex:
                index = tmp
            else:
                auxv[index] = tmp
            isIndex = not isIndex
        return auxv
    
            
    def rebaseCodeAddr(self, gdbSession, addr, pid=None):
        if self.needsCodeRebasing:
            return addr + self.getBaseAddrCode(gdbSession, pid)
        
        return addr
    
    def unrebaseCodeAddr(self, gdbSession, addr, pid=None):
        if not self.needsCodeRebasing:
            return addr
        
        baseAddr = self.getBaseAddrCode(gdbSession, pid)
        if addr < baseAddr:
            return addr
        return addr - baseAddr
    
    def getFunctionsRebased(self, gdbSession, pid=None):
        
        _pid = pid or gdbSession.pid
        if not self.needsCodeRebasing:
            funcs = self.getFunctionsUnrebased(gdbSession, _pid)
            return funcs
        
        if _pid not in self.funcsRebased:
            baseAddr = self.getBaseAddrCode(gdbSession, _pid)
            funcsRebased = None
            for fb in self.funcsRebased.values():
                if fb.baseAddr == baseAddr:
                    self.funcsRebased[_pid] = fb
                    funcsRebased = fb.funcsRebased
                    break
                    
            if funcsRebased is None:
                funcs = self.getFunctionsUnrebased(gdbSession, _pid)
                funcsRebased = [self.rebaseCodeAddr(gdbSession, func, _pid) for func in funcs]
                self.funcsRebased[_pid] = Posix._FunctionsRebased(baseAddr, funcsRebased)
        else:
            funcsRebased = self.funcsRebased[_pid].funcsRebased
                
        return funcsRebased
    
    def getFunctionsUnrebased(self, gdbSession, pid=None):
        if self.elf is None:
            raise Exception("No ELF set.")
            
        funcs = self.getFunctionDescriptors()
        return funcs.keys()
        
        
    def unrebaseFunctions(self, gdbSession, rebasedFuncs, pid=None):
        return [self.unrebaseCodeAddr(gdbSession, func, pid) for func in rebasedFuncs]
    
    def getNearestFunction(self, gdbSession, codeAddr, pid=None):
        if not self.addrBelongsToImage(gdbSession, codeAddr, pid):
            return None
        
        funcs = self.getFunctionsRebased(gdbSession, pid)
        funcs.sort()
        i = findItemInList(funcs, codeAddr)[0]
        return funcs[i]
    
    def reset(self):
        self.baseAddrCode = {}
        self.endAddrImage = {}
        self.startAddrImage = {} 
        
    def getFunctionDescriptors(self):
        if self.funcs is None:
            self.funcs = tools.extractFunctionsFromELF(self.elf, self.BLACKLIST_FUNCTIONS)
        return self.funcs
            
    def getNames(self):
        if self.names is None:
            funcs = self.getFunctionDescriptors()
            self.names = {func.addr:func.name for func in funcs.values()}
        return self.names
    
    def getSizeOfFunction(self, addrFunc):
        funcs = self.getFunctionDescriptors()
        func = funcs[addrFunc]
        return func.size
            
    class FunctionHook:
        
        def __init__(self, pid, callback, addrImportPointer, internal, addrFunc=None):
            self.pid = pid
            self.callback = callback
            self.addrFunc = addrFunc
            self.addrImportPointer = addrImportPointer
            self.internal = internal
            
        def install(self, pygdb):
            if self.addrFunc is None:
                if not self.update(pygdb):
                    return False
            if self.internal:
                return pygdb._setBreakpointInternal(self.addrFunc, self._HANDLER, self0=self, pid=self.pid)
            else:
                return pygdb.setBreakpoint(self.addrFunc, self._HANDLER, self0=self, pid=self.pid)
            
        def uninstall(self, pygdb):
            if self.internal:
                return pygdb._removeBreakpointInternal(self.addrFunc, self.pid)
            return pygdb.removeBreakpoint(self.addrFunc, self.pid, bpCallback=self._HANDLER)
            
        def update(self, pygdb):
            tmp = pygdb.cpu.getPointerAt(pygdb, self.addrImportPointer, self.pid)
            if tmp is None:
                return False
            
            self.addrFunc = tmp
            return True
            
        @staticmethod
        def _HANDLER(self, pygdb, event):
            
            # DEBUG
            print "Accessed function hook handler at %x" % event.addr
            #######
            
            # get the return-address of the hooked function
            retAddr = pygdb.cpu.getFunctionReturnAddress(pygdb, event.tid)
            # set a bp on the return address
            pygdb.setBreakpoint(retAddr, self._HANDLER_RET, self0=self, pid=event.pid)
            # remove the current breakpoint, TODO: only do this in case we are hooking a function via a function pointer
            self.uninstall(pygdb)
            # invoke callback
            return self.callback(pygdb, event)
        
        @staticmethod
        def _HANDLER_RET(self, pygdb, event):
            self.update(pygdb)
            self.install(pygdb)
            if self.internal:
                pygdb._removeBreakpointInternal(event.addr, event.pid)
            else:
                pygdb.removeBreakpoint(event.addr, event.pid, bpCallback=self._HANDLER_RET)
        
    def hookFunction(self, pygdb, pid, callback, addrImportPointer, addrFunc=None, internal=False):
                
        fh = Posix.FunctionHook(pid, callback, addrImportPointer, internal, addrFunc)
        if not fh.install(pygdb):
            return False
        
        if pid not in self.functionHooks:
            self.functionHooks[pid] = {}
        self.functionHooks[pid][addrImportPointer] = fh
        
        return True
        
    def unhookFunction(self, pygdb, pid, addrImportPointer):
        return self.functionHooks[pid][addrImportPointer].uninstall()
        