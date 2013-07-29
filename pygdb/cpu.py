'''
Created on 11.05.2012

@author: Felix

'''
import tools
from instruction import Instruction, ConditionalInstruction, ConditionalInstructionSimple, CHARACTERISTIC

class InstructionNotSupported(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class InvalidCPUMode(Exception):
    def __str__(self):
        return "The supplied cpu mode is not supported."

class FeatureNotAvailableOnArchitecture(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class InvalidRequest(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


## _CPU types
class _CPU:
    """
    Abstract base class for all _CPU types.
    """
    def __init__(self):
        self.endianess = self.IS_LITTLE_ENDIAN and tools.ENDIANESS.LITTLE or tools.ENDIANESS.BIG  
    
    def getBreakpointKind(self): #virtual
        """
        Gets the GDB breakpoint kind of the platform.
        """
        return self.SIZE_BREAKPOINT

    def __str__(self):
        return self.NAME

    def islittleEndian(self): #default is little endian
        """
        Checks if the platform is little endian.
        """
        return self.IS_LITTLE_ENDIAN

    def getNativeRegisterWidth(self): #default is 32 bits
        """
        Gets the platforms native register width (e.g. 32 on x86).
        """
        return self.NATIVE_REGISTER_WIDTH

    def getBasicRegisterName(self, index):
        """
        Gets the name of the register with the given index.
        @param index: The index of the register to get the name for.
        @return: The name of the register.
        """
        if not self.BASIC_REGISTERS:
            raise NotImplemented("Your processor arch lacks a list of registers.")

        return self.BASIC_REGISTERS[index]

    def getBasicRegisterIndex(self, name):
        """
        Gets the index of the register with the given name.
        @param name: The name of the register to get the index for.
        @return: The index of the register.
        """
        if not self.BASIC_REGISTERS:
            raise NotImplemented("Your processor arch lacks a list of registers.")

        return self.BASIC_REGISTERS.index(name)

    def getPcIndex(self):
        """
        Gets the index of the platform's program counter.
        """
        if self.PC_INDEX is None:
            raise NotImplemented("Your processor arch has no PC index set.")
        return self.PC_INDEX

    def toRegisterHexString(self, value):
        """
        Generates a GDB register string from a given integer value.
        @param value: The integer value.
        @return: The converted regsiter string.
        """
        raise NotImplemented()

    def registerHexStringToValue(self, s):
        """
        Converts a GDB register string to an actual integer.
        @param s: The string to convert.
        @return: The integer value of the register string.
        """
        raise NotImplemented()

    def patchFunctionReturnAddress(self, pygdb, ptid, addr):
        """
        Patches the return address of the function just called by the given thread. The thread must be halted on the first instruction of the corresponding function.
        @param pygdb: The pygdb object to use.
        @param ptid: The (packed) tid of thread to evaluate.
        @param addr: The address to set as new return address.
        """
        # should return the actual return address after patching
        raise NotImplemented()

    def getIllegalAddressRange(self, os):
        """
        Gets the address range that is illegal in user-mode for the given OS.
        @param os: The OS to get the illegal address range for.
        @return: The illegal address range.
        """
        return self.ILLEGAL_ADDRESS_RANGES[os]

    def getFunctionReturnAddress(self, pygdb, ptid, pid=None):
        """
        Gets the return address of the function just called by the given thread. The thread must be halted on the first instruction of the corresponding function.
        @param pygdb: The pygdb object to use.
        @param tid: The thread to evaluate.
        @param pid: [OPTIONAL] The pid of the process of the thread. Not really needed since ptid already contains the pid, you can specify it nonetheless to save some cycles :-)
        """
        raise NotImplemented("Needed for function tracing.")

    def getInstrCharacteristics(self, pygdb, tid, addrInstr=None):
        """
        Gets the characteristics of the next instruction of a given thread.
        @param pygdb: The pygdb object to use.
        @param tid: The thread to evaluate.
        @param addrInstr: Optional address of instruction to evaluate (if different from pc).
        @return: The characteristics of the next instruction.
        """
        raise NotImplemented("Needed for basic-block tracing.")

    def evaluateCondInstr(self, pygdb, tid, addrInstr=None):
        """
        Determines if the condition for the next (conditional) instruction in the given thread is met.
        @param pygdb: The pygdb object to use.
        @param tid: The thread to evaluate.
        @param addrInstr: Optional address of instruction to evaluate (if different from pc).
        @return: A boolean flag indicating the state of the condition.
        """
        raise NotImplemented("Needed for implicit basic-block tracing.")

    def getPageSize(self):
        return self.PAGE_SIZE

    def getAddressDelaySlot(self, addr):
        """
        Returns the address of the instruction of the delay slot of the instruction at the given address. Throws if the architecture does not know delay slots.
        """
        raise FeatureNotAvailableOnArchitecture("The architecture does not have delay slots.")

    def getFunctionReturnValues(self, pygdb, tid):
        """
        Gets the return values of a function just executed. PC stand at the first instruction after the function in question.
        @param pygdb: The pygdb object to use.
        @param tid: The thread to evaluate.
        @return: An array containing the return values of the function.
        """
        raise NotImplemented("Needed for fork-following.")

    def getOpcodeJmpPC(self):
        """
        Gets the opcode for the endless loop instruction "jmp pc".
        """
        return self.OPCODE_JMP_PC

    def getOpcodeBreakpoint(self):
        """
        Gets the opcode for a breakpoint.
        """
        return self.OPCODE_BREAKPOINT

    def getAddressBreakpoint(self, pc):
        """
        Gets the address of the actual breakpoint instruction for the current pc.
        """
        raise NotImplemented()

    def supportsNativeSingleStep(self):

        return self.SUPPORTS_NATIVE_SINGLE_STEP

    def getNextPC(self, pygdb, tid, cond=None):
        """
        Calculates the next to be expected pc for the givne thread.
        @param pygdb: The PyGdb instance to use
        @param tid: The id of the thread to step
        @param cond: [OPTIONAL] Overwrites the actual condition of the current conditional instruction.
        """
        raise NotImplemented()
    
    def getPointerAt(self, pygdb, addr, pid):
        """
        Gets the pointer at the given address.
        @param pygdb: The PyGdb instance to use
        @param addr: THe address of interest
        @param pid: The pid of interest
        """
        mem = pygdb.readMemory(addr, self.NATIVE_REGISTER_WIDTH >> 3, False, pid=pid)
        if mem is None:
            return None
        return tools.byteStrToInt(mem, self.endianess)
    
    def getRegisterString(self, pygdb, tid):
        """
        Gets the register values of the given thread in printable format.
        """
        registers = pygdb.getRegisters(tid)
        s = ""
        for i in range(len(self.BASIC_REGISTERS)):
            s += "%s:%x, " % (self.BASIC_REGISTERS[i],registers[i])
            
        return s
    
    def isEndOfFunction(self, pygdb, tid, instructionCharacteristics=None):
        """
        Checks if the current instruction is the end of the function.
        @return: True/False or None if not sure.
        """
        return None
        
class X86_64_CONSTS(_CPU):
    
    OPCODE_BREAKPOINT = "\xcc"
    SIZE_BREAKPOINT = len(OPCODE_BREAKPOINT)
    SIZE_JMP_SHORT = 2
    SIZE_JMP_NEAR = 6
    OPCODE_JMP_PC = "\xeb\xfe"
    IS_LITTLE_ENDIAN = True
    SUPPORTS_NATIVE_SINGLE_STEP = True
    PAGE_SIZE = 1024 * 4
    
    INDEX_ACCUMULATOR = 0
    
    
class X86_CONSTS(X86_64_CONSTS):
    
    NAME = "x86"
    NATIVE_REGISTER_WIDTH = 32
    WORD_SIZE = NATIVE_REGISTER_WIDTH/8
    
    # register table taken from gdb/i386-tdep.c, i386_register_names array
    BASIC_REGISTERS = ["eax", "ecx", "edx", "ebx",
                      "esp", "ebp", "esi", "edi",
                      "eip", "eflags", "cs", "ss",
                      "ds", "es", "fs", "gs",
                      "st0", "st1", "st2", "st3",
                      "st4", "st5", "st6", "st7",
                      "fctrl", "fstat", "ftag", "fiseg",
                      "fioff", "foseg", "fooff", "fop",
                      "xmm0", "xmm1", "xmm2", "xmm3",
                      "xmm4", "xmm5", "xmm6", "xmm7",
                      "mxcsr"]

    ILLEGAL_ADDRESS_RANGES = [[0x80000000, 0xFFFFFFFF], # Windows
                              [0xC0000000, 0xFFFFFFFF]] # Linux]

    REGISTER_STRING_TEMPLATE = "%08x"

    INDEX_EFLAGS = 9
    INDEX_COUNTER = 1
    PC_INDEX = 8
    INDEX_SP = 4
    
    LEN_CHARACTERISTIC_BYTES = 2
    
class X64_CONSTS(X86_64_CONSTS):
    
    NAME = "x64"
    REGISTER_STRING_TEMPLATE = "%016x"
    NATIVE_REGISTER_WIDTH = 64
    WORD_SIZE = NATIVE_REGISTER_WIDTH/8 
    
    BASIC_REGISTERS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                       "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                       "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs",
                       "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
                       "fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop",
                       "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
                       "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
                       "mxcsr"]
    
    INDEX_EFLAGS = 17
    INDEX_COUNTER = 2
    INDEX_SP = 7
    PC_INDEX = 16
    
    LEN_CHARACTERISTIC_BYTES = 3
    
    REX_RANGE = range(0x40,0x50)

class X86_64:
    """
    Description of the X86_64 architecture.
    TODO: Examine prefixes like REX.W more carefully. For example it is possible to overwrite the addressing mode of an instruction by supplying the prefix 67h.
    """
    
    class NEXT_PC:
        @staticmethod
        def JMP_SHORT(pc, cond, opnd):
            return X86_64.NEXT_PC.JMP_COND(pc, cond, opnd, X86_64_CONSTS.SIZE_JMP_SHORT)
        
        @staticmethod
        def JMP_NEAR(pc, cond, opnd):
            return X86_64.NEXT_PC.JMP_COND(pc, cond, opnd, X86_64_CONSTS.SIZE_JMP_NEAR)
            
        @staticmethod
        def JMP_COND(pc, cond, opnd, sizeInstr):
            nextPc = pc + sizeInstr
            if cond:
                nextPc += X86_64.NEXT_PC._GET_JMP_OFFSET(opnd)
                
            return nextPc
            
        @staticmethod
        def _GET_JMP_OFFSET(opnd):
            opndSize = len(opnd)
            v = tools.byteStrToInt(opnd, tools.ENDIANESS.LITTLE)
            mask = 1 << ((opndSize*8)-1) 
            offset = (v^mask) - mask
            return offset
            
        @staticmethod
        def JMP_FAR(pc, cond, opnd):
            pass
        
    
    class InstrContext:
        
        def __init__(self, registers, indexCounter, indexEflags):
            self.registers = registers
            self.indexCounter = indexCounter
            self.indexEflags = indexEflags
    
    class CInstrEFSimp(ConditionalInstructionSimple):
        
        def COND_FUNC(self, *args):
            context = args[1]
            registers = context.registers
            eflags = registers[context.indexEflags]
            condition = eflags & self.regMask != 0
            if self.negative != 0:
                condition = not condition
            return condition
            
        def __init__(self, regMask, negative=0, characteristics=0, label=""):
            self.regMask = regMask
            self.negative = negative
            ConditionalInstruction.__init__(self, self.COND_FUNC, characteristics, label)    

    class CInstrEF(ConditionalInstruction):
        def __init__(self, condFunc, characteristics=0, label=""):
            ConditionalInstruction.__init__(self, condFunc, characteristics, label)

        def checkCondition(self, args):
            context = args[1]
            registers = context.registers
            eflags = registers[context.indexEflags]
            c = eflags & 1
            p = (eflags >> 2) & 1
            z = (eflags >> 6) & 1
            s = (eflags >> 7) & 1
            o = (eflags >> 11) & 1
            return self.condFunc(c=c, p=p, z=z, s=s, o=o, counter=registers[context.indexCounter])

    
    INSTRUCTIONS_ONE_BYTE = {# conditional branches
                             0x70 : CInstrEFSimp(1 << 11, 0, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JO_S"),
                             0x71 : CInstrEFSimp(1 << 11, 1, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JNO_S"),
                             0x72 : CInstrEFSimp(1 << 0, 0, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JB_S"),
                             0x73 : CInstrEFSimp(1 << 0, 1, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JNB_S"),
                             0x74 : CInstrEFSimp(1 << 6, 0, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JZ_S"),
                             0x75 : CInstrEFSimp(1 << 6, 1, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JNZ_S"),
                             0x76 : CInstrEF(lambda c, p, z, s, o, counter: (c or z) == 1, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JB_S"),
                             0x77 : CInstrEF(lambda c, p, z, s, o, counter: (c or z) == 0, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JNB_S"),
                             0x78 : CInstrEFSimp(1 << 7, 0, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JS_S"),
                             0x79 : CInstrEFSimp(1 << 7, 1, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JNS_S"),
                             0x7A : CInstrEFSimp(1 << 2, 0, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JP_S"),
                             0x7B : CInstrEFSimp(1 << 2, 1, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JNP_S"),
                             0x7C : CInstrEF(lambda c, p, z, s, o, counter:  s != o, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JL_S"),
                             0x7D : CInstrEF(lambda c, p, z, s, o, counter: s == o, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JNL_S"),
                             0x7E : CInstrEF(lambda c, p, z, s, o, counter:  z == 1 or s != o, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JG_S"),
                             0x7F : CInstrEF(lambda c, p, z, s, o, counter: z == 0 and s == o, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JNG_S"),
                             # count dependent branches
                             0xE0 : CInstrEF(lambda c, p, z, s, o, counter: counter != 0 and z == 0, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "LOOPNZ"),
                             0xE1 : CInstrEF(lambda c, p, z, s, o, counter: counter != 0 and z == 1, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "LOOPZ"),
                             0xE1 : CInstrEF(lambda c, p, z, s, o, counter: counter != 0, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "LOOP"),
                             0xE3 : CInstrEF(lambda c, p, z, s, o, counter: counter == 0, CHARACTERISTIC.JMP | CHARACTERISTIC.SHORT_BRANCH, "JCXZ"),
                             # branches
                             0x9A : Instruction(CHARACTERISTIC.CALL | CHARACTERISTIC.FAR_BRANCH, "CALL_F"),
                             0xE8 : Instruction(CHARACTERISTIC.CALL, "CALL"),
                             0xE9 : Instruction(CHARACTERISTIC.JMP, "JMP"),
                             0xEA : Instruction(CHARACTERISTIC.JMP | CHARACTERISTIC.FAR_BRANCH, "JMP_F"),
                             0xEB : Instruction(CHARACTERISTIC.JMP, "JMP_N"),
                             0xC2 : Instruction(CHARACTERISTIC.RET, "RETN"),
                             0xC3 : Instruction(CHARACTERISTIC.RET, "RETN"),
                             0xCA : Instruction(CHARACTERISTIC.RET, "RETN"),
                             0xCB : Instruction(CHARACTERISTIC.RET, "RETN"),
                             # other
                             0xD6 : CInstrEFSimp(1, 0, CHARACTERISTIC.NONE, "SALC"),
                             }

    INSTRUCTIONS_TWO_BYTES = {0x0F : { # regular two-byte instructions
                             # jumps
                             0x80 : CInstrEFSimp(1 << 11, 0, CHARACTERISTIC.JMP, "JO_N"),
                             0x81 : CInstrEFSimp(1 << 11, 1, CHARACTERISTIC.JMP, "JNO_N"),
                             0x82 : CInstrEFSimp(1 << 0, 0, CHARACTERISTIC.JMP, "JB_N"),
                             0x83 : CInstrEFSimp(1 << 0, 1, CHARACTERISTIC.JMP, "JNB_N"),
                             0x84 : CInstrEFSimp(1 << 6, 0, CHARACTERISTIC.JMP, "JZ_N"),
                             0x85 : CInstrEFSimp(1 << 6, 1, CHARACTERISTIC.JMP, "JNZ_N"),
                             0x86 : CInstrEF(lambda c, p, z, s, o, counter: (c or z) == 1, CHARACTERISTIC.JMP, "JB_N"),
                             0x87 : CInstrEF(lambda c, p, z, s, o, counter: (c or z) == 0, CHARACTERISTIC.JMP, "JNB_N"),
                             0x88 : CInstrEFSimp(1 << 7, 0, CHARACTERISTIC.JMP, "JS_N"),
                             0x89 : CInstrEFSimp(1 << 7, 1, CHARACTERISTIC.JMP, "JNS_N"),
                             0x8A : CInstrEFSimp(1 << 2, 0, CHARACTERISTIC.JMP, "JP_N"),
                             0x8B : CInstrEFSimp(1 << 2, 1, CHARACTERISTIC.JMP, "JNP_N"),
                             0x8C : CInstrEF(lambda c, p, z, s, o, counter:  s != o, CHARACTERISTIC.JMP, "JL_N"),
                             0x8D : CInstrEF(lambda c, p, z, s, o, counter: s == o, CHARACTERISTIC.JMP, "JNL_N"),
                             0x8E : CInstrEF(lambda c, p, z, s, o, counter:  z == 1 or s != o, CHARACTERISTIC.JMP, "JG_N"),
                             0x8F : CInstrEF(lambda c, p, z, s, o, counter: z == 0 and s == o, CHARACTERISTIC.JMP, "JNG_N"),
                             # conditional move
                             0x40 : CInstrEF(lambda c, p, z, s, o, counter: o == 1, CHARACTERISTIC.IMPLICIT_BRANCH, "CMOVO"),
                             0x41 : CInstrEF(lambda c, p, z, s, o, counter: o == 0, CHARACTERISTIC.IMPLICIT_BRANCH, "CMOVNO"),
                             0x42 : CInstrEF(lambda c, p, z, s, o, counter: c == 1, CHARACTERISTIC.IMPLICIT_BRANCH, "CMOVB"),
                             0x43 : CInstrEF(lambda c, p, z, s, o, counter: c == 0, CHARACTERISTIC.IMPLICIT_BRANCH, "CMOVNB"),
                             0x44 : CInstrEF(lambda c, p, z, s, o, counter: z == 1, CHARACTERISTIC.IMPLICIT_BRANCH, "CMOVZ"),
                             0x45 : CInstrEF(lambda c, p, z, s, o, counter: z == 0, CHARACTERISTIC.IMPLICIT_BRANCH, "CMOVNZ"),
                             0x46 : CInstrEF(lambda c, p, z, s, o, counter: c == 1 and z == 1, CHARACTERISTIC.IMPLICIT_BRANCH, "CMOVBE"),
                             0x47 : CInstrEF(lambda c, p, z, s, o, counter: c == 0 and z == 0, CHARACTERISTIC.IMPLICIT_BRANCH, "CMOVNBE"),
                             0x48 : CInstrEF(lambda c, p, z, s, o, counter: s == 1, CHARACTERISTIC.IMPLICIT_BRANCH, "CMOVS"),
                             0x49 : CInstrEF(lambda c, p, z, s, o, counter: s == 0, CHARACTERISTIC.IMPLICIT_BRANCH, "CMOVNS"),
                             0x4A : CInstrEF(lambda c, p, z, s, o, counter: p == 1, CHARACTERISTIC.IMPLICIT_BRANCH, "CMOVP"),
                             0x4B : CInstrEF(lambda c, p, z, s, o, counter: p == 0, CHARACTERISTIC.IMPLICIT_BRANCH, "CMOVNP"),
                             0x4C : CInstrEF(lambda c, p, z, s, o, counter: s != o, CHARACTERISTIC.IMPLICIT_BRANCH, "CMOVL"),
                             0x4D : CInstrEF(lambda c, p, z, s, o, counter: s == o, CHARACTERISTIC.IMPLICIT_BRANCH, "CMOVNL"),
                             0x4E : CInstrEF(lambda c, p, z, s, o, counter: z == 1 or s != o, CHARACTERISTIC.IMPLICIT_BRANCH, "CMOVLE"),
                             0x4F : CInstrEF(lambda c, p, z, s, o, counter: z == 0 and s == o, CHARACTERISTIC.IMPLICIT_BRANCH, "CMOVNLE"),
                             # conditional set
                             0x90 : CInstrEF(lambda c, p, z, s, o, counter: o == 1, CHARACTERISTIC.IMPLICIT_BRANCH, "SETO"),
                             0x91 : CInstrEF(lambda c, p, z, s, o, counter: o == 0, CHARACTERISTIC.IMPLICIT_BRANCH, "SETNO"),
                             0x92 : CInstrEF(lambda c, p, z, s, o, counter: c == 1, CHARACTERISTIC.IMPLICIT_BRANCH, "SETB"),
                             0x93 : CInstrEF(lambda c, p, z, s, o, counter: c == 0, CHARACTERISTIC.IMPLICIT_BRANCH, "SETNB"),
                             0x94 : CInstrEF(lambda c, p, z, s, o, counter: z == 1, CHARACTERISTIC.IMPLICIT_BRANCH, "SETZ"),
                             0x95 : CInstrEF(lambda c, p, z, s, o, counter: z == 0, CHARACTERISTIC.IMPLICIT_BRANCH, "SETNZ"),
                             0x96 : CInstrEF(lambda c, p, z, s, o, counter: c == 1 and z == 1, CHARACTERISTIC.IMPLICIT_BRANCH, "SETBE"),
                             0x97 : CInstrEF(lambda c, p, z, s, o, counter: c == 0 and z == 0, CHARACTERISTIC.IMPLICIT_BRANCH, "SETNBE"),
                             0x98 : CInstrEF(lambda c, p, z, s, o, counter: s == 1, CHARACTERISTIC.IMPLICIT_BRANCH, "SETS"),
                             0x99 : CInstrEF(lambda c, p, z, s, o, counter: s == 0, CHARACTERISTIC.IMPLICIT_BRANCH, "SETNS"),
                             0x9A : CInstrEF(lambda c, p, z, s, o, counter: p == 1, CHARACTERISTIC.IMPLICIT_BRANCH, "SETP"),
                             0x9B : CInstrEF(lambda c, p, z, s, o, counter: p == 0, CHARACTERISTIC.IMPLICIT_BRANCH, "SETNP"),
                             0x9C : CInstrEF(lambda c, p, z, s, o, counter: s != o, CHARACTERISTIC.IMPLICIT_BRANCH, "SETL"),
                             0x9D : CInstrEF(lambda c, p, z, s, o, counter: s == o, CHARACTERISTIC.IMPLICIT_BRANCH, "SETNL"),
                             0x9E : CInstrEF(lambda c, p, z, s, o, counter: z == 1 or s != o, CHARACTERISTIC.IMPLICIT_BRANCH, "SETLE"),
                             0x9F : CInstrEF(lambda c, p, z, s, o, counter: z == 0 and s == o, CHARACTERISTIC.IMPLICIT_BRANCH, "SETNLE")
                             },

                             0xDA : { # fake two-byte opcodes, floating-point 0
                             0xC0 : CInstrEF(lambda c, p, z, s, o, counter: c == 1, CHARACTERISTIC.IMPLICIT_BRANCH, "FCMOVB"),
                             0xC8 : CInstrEF(lambda c, p, z, s, o, counter: z == 1, CHARACTERISTIC.IMPLICIT_BRANCH, "FCMOVE"),
                             0xD0 : CInstrEF(lambda c, p, z, s, o, counter: z == 1 or c == 1, CHARACTERISTIC.IMPLICIT_BRANCH, "FCMOVBE"),
                             0xD8 : CInstrEF(lambda c, p, z, s, o, counter: p == 1, CHARACTERISTIC.IMPLICIT_BRANCH, "FCMOVU")
                             },

                             0xDB : { # fake two-byte opcodes, floating-point 1
                             0xC0 : CInstrEF(lambda c, p, z, s, o, counter: c == 0, CHARACTERISTIC.IMPLICIT_BRANCH, "FCMOVNB"),
                             0xC8 : CInstrEF(lambda c, p, z, s, o, counter: z == 0, CHARACTERISTIC.IMPLICIT_BRANCH, "FCMOVNE"),
                             0xD0 : CInstrEF(lambda c, p, z, s, o, counter: z == 0 and c == 0, CHARACTERISTIC.IMPLICIT_BRANCH, "FCMOVNBE"),
                             0xD8 : CInstrEF(lambda c, p, z, s, o, counter: p == 0, CHARACTERISTIC.IMPLICIT_BRANCH, "FCMOVNU")
                             }, }

    INSTRUCTIONS_MODRM = {0xFF:{
                             0x02 : Instruction(CHARACTERISTIC.CALL | CHARACTERISTIC.DYNAMIC_BRANCH, "CALL"),
                             0x03 : Instruction(CHARACTERISTIC.CALL | CHARACTERISTIC.FAR_BRANCH | CHARACTERISTIC.DYNAMIC_BRANCH, "CALL_F"),
                             0x04 : Instruction(CHARACTERISTIC.JMP | CHARACTERISTIC.DYNAMIC_BRANCH, "JMP"),
                             0x05 : Instruction(CHARACTERISTIC.JMP | CHARACTERISTIC.FAR_BRANCH | CHARACTERISTIC.DYNAMIC_BRANCH, "JMP_F"),
                            }, }

    def getFunctionReturnAddress(self, pygdb, ptid, pid=None):
        if pid is None:
            _pid = pygdb.getPidFromTid(ptid)
        else:
            _pid = pid
        sp = pygdb.getRegisterIndex(self.INDEX_SP, ptid)
        tmp = pygdb.readMemory(sp, self.WORD_SIZE, pid=_pid)
        return tools.byteStrToInt(tmp, tools.ENDIANESS.LITTLE)

    def patchFunctionReturnAddress(self, pygdb, ptid, addr):
        pid = _pid = pygdb.getPidFromTid(ptid)
        sp = pygdb.getRegisterIndex(self.INDEX_SP, ptid)
        retAddr = self.getFunctionReturnAddress(pygdb, ptid, pid)
        pygdb.writeMemory(sp, tools.intToByteStr(addr, self.WORD_SIZE * 8, tools.ENDIANESS.LITTLE), pid=pid)
        return retAddr

    def __str__(self):
        return self.NAME

    def toRegisterHexString(self, value):
        return self.REGISTER_STRING_TEMPLATE % tools.reverseEndianess(value, self.getNativeRegisterWidth())

    def registerHexStringToValue(self, s):
        tmp = int(s, 16)
        return tools.reverseEndianess(tmp, self.getNativeRegisterWidth())

    def _getInstruction(self, mem):
        raise NotImplemented()
    
    def _getInstructionRaw(self, op0, op1):
        if op0 in self.INSTRUCTIONS_ONE_BYTE:
            return self.INSTRUCTIONS_ONE_BYTE[op0]

        if op0 in self.INSTRUCTIONS_TWO_BYTES:
            if op1 in self.INSTRUCTIONS_TWO_BYTES[op0]:
                return self.INSTRUCTIONS_TWO_BYTES[op0][op1]

        if op0 in self.INSTRUCTIONS_MODRM:
            op1 = (op1 >> 3) & 0b111 # extract 2nd opcode from ModR/M field
            if op1 in self.INSTRUCTIONS_MODRM[op0]:
                return self.INSTRUCTIONS_MODRM[op0][op1]

        return None
    
    def _getCharacteristicBytes(self, pygdb, addr):
        return self._readBytesSafe(pygdb, addr, self.LEN_CHARACTERISTIC_BYTES)

    def _readBytesSafe(self, pygdb, addr, size):
        if pygdb.hasBreakpoint(addr):
            mem = pygdb.getOriginalBytesBreakpoint(addr) + pygdb.readMemory(addr+self.SIZE_BREAKPOINT, size - self.SIZE_BREAKPOINT, cache=True)
        else:
            mem = pygdb.readMemory(addr, size, cache=True)
            
        return mem

    def getInstrCharacteristics(self, pygdb, tid, addrInstr=None):
        # read the first two bytes at eip
        if not addrInstr:
            addr = pygdb.getPC(tid)
        else:
            addr = addrInstr
        
        mem = self._getCharacteristicBytes(pygdb, addr)
        instr = self._getInstruction(mem)
        if instr:
            return instr.getCharacteristics()
        return CHARACTERISTIC.NONE

    def evaluateCondInstr(self, pygdb, tid, addrInstr=None):
        if addrInstr is None:
            addr = pygdb.getPC(tid)
        else:
            addr = addrInstr

        mem = self._getCharacteristicBytes(pygdb, addr)
        instr = self._getInstruction(mem)
        if not instr:
            raise InstructionNotSupported("The requested instruction is unknown: %02x %02x" % (ord(mem[0], ord(mem[1]))))

        if instr.getCharacteristics() & CHARACTERISTIC.CONDITIONAL == 0:
            raise InstructionNotSupported("The requested instruction is not conditional.")
        
        context = X86_64.InstrContext(registers=pygdb.getRegisters(tid), indexCounter=self.INDEX_COUNTER, indexEflags=self.INDEX_EFLAGS)
        return instr.checkCondition((instr, context))

    def getFunctionReturnValues(self, pygdb, tid):
        return [pygdb.getRegisters(tid)[self.INDEX_ACCUMULATOR]]

    def getAddressBreakpoint(self, pc):
        return pc - self.SIZE_BREAKPOINT
    
    def getNextPC(self, pygdb, tid, cond=None):
        """
        TODO: This is a rather quick hack.
        """
        if cond is None:
            return None
        
        pc = pygdb.getPC(tid)
        mem = self._readBytesSafe(pygdb, pc, self.SIZE_JMP_NEAR)
        instr = self._getInstruction(mem)
        if instr is None:
            return None
            
        characteristics = instr.getCharacteristics()
        if not ((characteristics & CHARACTERISTIC.CONDITIONAL != 0) and (characteristics & CHARACTERISTIC.JMP != 0)): 
            return None
        
        if (characteristics & CHARACTERISTIC.SHORT_BRANCH != 0):
            
            return self.NEXT_PC.JMP_SHORT(pc, cond, mem[1:2])
            
        return self.NEXT_PC.JMP_NEAR(pc, cond, mem[2:])
            
          
class X64(X86_64, X64_CONSTS):
    
    def _getInstruction(self, mem):
        # is this an explicit x64 instruction?
        prefix = ord(mem[0])
        if prefix in self.REX_RANGE:
            op0 = ord(mem[1])
            op1 = ord(mem[2])
        else:
            op0 = prefix
            op1 = ord(mem[1])
            
        return self._getInstructionRaw(op0, op1)

class X86(X86_64, X86_CONSTS):
    
    def _getInstruction(self, mem):
        
        op0 = ord(mem[0])
        op1 = ord(mem[1])
        return self._getInstructionRaw(op0, op1)
    
class ARM(_CPU):
    """
    Unfinished stub for the ARM platform.
    """
    MODES = {2:"THUMB16", 3:"THUMB32", 4:"ARM32"}

    def __init__(self, mode):
        if not mode in ARM.MODES:
            raise InvalidCPUMode()
            return
        self.mode = mode

    def getBreakpointKind(self):
        return self.mode

    def __str__(self):
        return ARM.MODES[self.mode]

    def getNativeRegisterWidth(self):
        if self.mode == 2:
            return 16

        return 32

class MIPS32_CONSTS(_CPU):
    """
    MIPS32 constants.
    """

    """
    Taken from mips-tdep.c from the gdb sources. Should be correct for most/all MIPS32 flavors but not IRIX (who cares?).
    sp is stack pointer, ra is return address register and pc is the program counter.
    """
    BASIC_REGISTERS = ["zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
                        "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
                        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
                        "t8", "t9", "k0", "k1", "gp", "sp", "s8", "ra",
                        "ps", "lo", "hi", "badvaddr", "cause", "pc", "fp0"]

    NATIVE_REGISTER_WIDTH = 32
    PC_INDEX = 37
    RA_INDEX = 31
    T7_INDEX = 15
    V0_INDEX = 2
    V1_INDEX = 3
    WORD_SIZE = 4
    PAGE_SIZE = 1024*4

    OPCODE_BREAKPOINT = "\x00\x00\x00" + chr(0b1101)
    OPCODE_NOP = "\x00\x00\x00\x00"
    ACTUAL_OPCODE_JMP_PC = 0b00010000000000001111111111111111 # Branch (B) PC
    OPCODE_JMP_PC = tools.intToByteStr(ACTUAL_OPCODE_JMP_PC, NATIVE_REGISTER_WIDTH, tools.ENDIANESS.BIG) + OPCODE_NOP # TODO: Is this valid as well for MIPSEL?

    SIZE_BREAKPOINT = len(OPCODE_BREAKPOINT)
    NAME = "MIPS32"

    SUPPORTS_NATIVE_SINGLE_STEP = False


class MIPS32(MIPS32_CONSTS):
    """
    Adapter class for the MIPS32 platform. Is not fp and "likely" instructions aware. TODO!
    """

    class Operands:

        def __init__(self, rs, rt, imm, rsI, rtI, instrIndex):
            """
            @param rs: The value of the register specified in the rs field.
            @param rt: The value of the register specified in the rt field.
            @param imm: The immediate value specified in the imm field.
            @param rsI: The index of the register specified in the rs field.
            @param rtI: The index of the register specified in the rt field.
            """
            self.rs = rs
            self.rt = rt
            self.imm = imm
            self.rsI = rsI
            self.rtI = rtI
            self.instrIndex = instrIndex
                
    class NEXT_PC:
        @staticmethod
        def JUMP_FAR(pc, cond, opnds):
            region = opnds.instrIndex << 2
            addrDelaySlot = pc + MIPS32.WORD_SIZE
            nextPC = region + (addrDelaySlot & ~((1 << (MIPS32.NATIVE_REGISTER_WIDTH - 4)) - 1)) 
            return nextPC
        
        @staticmethod
        def JUMP_REG(pc, cond, opnds):
            return opnds.rs
        
        @staticmethod
        def BRANCH(pc, cond, opnds):
            if cond:
                off = ((opnds.imm ^ 0x8000) - 0x8000) << 2  
                return pc + MIPS32.WORD_SIZE + off
            return pc + 2 * MIPS32.WORD_SIZE

    INSTRUCTIONS_OWN_OPCODE = {0b010 : Instruction(CHARACTERISTIC.JMP | CHARACTERISTIC.HAS_DELAY_SLOT | CHARACTERISTIC.FAR_BRANCH, "J", NEXT_PC.JUMP_FAR),
                               0b011 : Instruction(CHARACTERISTIC.CALL | CHARACTERISTIC.HAS_DELAY_SLOT | CHARACTERISTIC.FAR_BRANCH, "JAL", NEXT_PC.JUMP_FAR),
                               0b100 : ConditionalInstruction(lambda opnd: (opnd.rs == opnd.rt), CHARACTERISTIC.JMP | CHARACTERISTIC.HAS_DELAY_SLOT, "BEQ", NEXT_PC.BRANCH, charFunc=lambda self, opnd: self.characteristics ^ (opnd.rsI == opnd.rtI and CHARACTERISTIC.CONDITIONAL or CHARACTERISTIC.NONE)),
                               0b10100 : ConditionalInstruction(lambda opnd: (opnd.rs == opnd.rt), CHARACTERISTIC.JMP | CHARACTERISTIC.HAS_DELAY_SLOT_LIKELY , "BEQL", NEXT_PC.BRANCH, charFunc=lambda self, opnd: self.characteristics ^ (opnd.rsI == opnd.rtI and CHARACTERISTIC.CONDITIONAL or CHARACTERISTIC.NONE)),
                               0b101 : ConditionalInstruction(lambda opnd: (opnd.rs != opnd.rt), CHARACTERISTIC.JMP | CHARACTERISTIC.HAS_DELAY_SLOT, "BNE", NEXT_PC.BRANCH),
                               0b10101 : ConditionalInstruction(lambda opnd: (opnd.rs != opnd.rt), CHARACTERISTIC.JMP | CHARACTERISTIC.HAS_DELAY_SLOT_LIKELY, "BNEL", NEXT_PC.BRANCH),
                               0b110 : ConditionalInstruction(lambda opnd: (opnd.rs <= 0), CHARACTERISTIC.JMP | CHARACTERISTIC.HAS_DELAY_SLOT, "BLEZ", NEXT_PC.BRANCH),
                               0b10110 : ConditionalInstruction(lambda opnd: (opnd.rs <= 0), CHARACTERISTIC.JMP | CHARACTERISTIC.HAS_DELAY_SLOT_LIKELY, "BLEZL", NEXT_PC.BRANCH),
                               0b111 : ConditionalInstruction(lambda opnd: (opnd.rs > 0), CHARACTERISTIC.JMP | CHARACTERISTIC.HAS_DELAY_SLOT, "BGTZ", NEXT_PC.BRANCH),
                               0b10111 : ConditionalInstruction(lambda opnd: (opnd.rs > 0), CHARACTERISTIC.JMP | CHARACTERISTIC.HAS_DELAY_SLOT_LIKELY, "BGTZL", NEXT_PC.BRANCH),
                               }

    OP_SPECIAL = 0
    INSTRUCTIONS_SPECIAL = {# JR can be regarded as RET when $RA is used as argument register.
                            0b1000 : Instruction(CHARACTERISTIC.JMP | CHARACTERISTIC.DYNAMIC_BRANCH | CHARACTERISTIC.HAS_DELAY_SLOT | CHARACTERISTIC.FAR_BRANCH, "JR", NEXT_PC.JUMP_REG, charFunc=lambda self, opnd: self.characteristics | (opnd.rsI == MIPS32.RA_INDEX and CHARACTERISTIC.RET or CHARACTERISTIC.NONE)),
                            0b1001 : Instruction(CHARACTERISTIC.CALL | CHARACTERISTIC.DYNAMIC_BRANCH | CHARACTERISTIC.HAS_DELAY_SLOT | CHARACTERISTIC.FAR_BRANCH, "JALR", NEXT_PC.JUMP_REG),
                            0b1010 : ConditionalInstruction(lambda opnd: (opnd.rt == 0), CHARACTERISTIC.IMPLICIT_BRANCH, "MOVZ"),
                            0b1011 : ConditionalInstruction(lambda opnd: (opnd.rt != 0), CHARACTERISTIC.IMPLICIT_BRANCH, "MOVN"),
                            0b101010 : ConditionalInstruction(lambda opnd: (opnd.rs < opnd.rt), CHARACTERISTIC.IMPLICIT_BRANCH, "SLT"), # dunno if this really counts as a conditional function
                            0b101011 : ConditionalInstruction(lambda opnd: (abs(opnd.rs) < abs(opnd.rt)), CHARACTERISTIC.IMPLICIT_BRANCH, "SLTU"), # same here
                            0b110000 : ConditionalInstruction(lambda opnd: (opnd.rs > opnd.rt), CHARACTERISTIC.TRAP, "TGE"),
                            0b110001 : ConditionalInstruction(lambda opnd: (abs(opnd.rs) > abs(opnd.rt)), CHARACTERISTIC.TRAP, "TGEU"),
                            0b110010 : ConditionalInstruction(lambda opnd: (opnd.rs < opnd.rt), CHARACTERISTIC.TRAP, "TLT"),
                            0b110011 : ConditionalInstruction(lambda opnd: (abs(opnd.rs) < abs(opnd.rt)), CHARACTERISTIC.TRAP, "TLTU"),
                            0b110100 : ConditionalInstruction(lambda opnd: (opnd.rs == opnd.rt), CHARACTERISTIC.TRAP, "TEQ"),
                            0b110110 : ConditionalInstruction(lambda opnd: (opnd.rs != opnd.rt), CHARACTERISTIC.TRAP, "TNE")
                             }
    OP_REGIMM = 1
    INSTRUCTIONS_REGIMM = {0 : ConditionalInstruction(lambda opnd: (opnd.rs < 0), CHARACTERISTIC.JMP | CHARACTERISTIC.HAS_DELAY_SLOT, "BLTZ", NEXT_PC.BRANCH),
                           0b10 : ConditionalInstruction(lambda opnd: (opnd.rs < 0), CHARACTERISTIC.JMP | CHARACTERISTIC.HAS_DELAY_SLOT_LIKELY, "BLTZL", NEXT_PC.BRANCH),
                           1 : ConditionalInstruction(lambda opnd: (opnd.rs >= 0), CHARACTERISTIC.JMP | CHARACTERISTIC.HAS_DELAY_SLOT, "BGEZ", NEXT_PC.BRANCH),
                           0b11 : ConditionalInstruction(lambda opnd: (opnd.rs >= 0), CHARACTERISTIC.JMP | CHARACTERISTIC.HAS_DELAY_SLOT_LIKELY, "BGEZL", NEXT_PC.BRANCH),
                           0b01000 : ConditionalInstruction(lambda opnd: (opnd.rs >= opnd.imm), CHARACTERISTIC.TRAP | CHARACTERISTIC.HAS_DELAY_SLOT, "TGEI"),
                           0b01001 : ConditionalInstruction(lambda opnd: (abs(opnd.rs) >= abs(opnd.imm)), CHARACTERISTIC.TRAP | CHARACTERISTIC.HAS_DELAY_SLOT, "TGEIU"),
                           0b01010 : ConditionalInstruction(lambda opnd: (opnd.rs < opnd.imm), CHARACTERISTIC.TRAP | CHARACTERISTIC.HAS_DELAY_SLOT, "TLTI"),
                           0b01011 : ConditionalInstruction(lambda opnd: (abs(opnd.rs) < abs(opnd.imm)), CHARACTERISTIC.TRAP | CHARACTERISTIC.HAS_DELAY_SLOT, "TLTIU"),
                           0b01100 : ConditionalInstruction(lambda opnd: (opnd.rs == opnd.imm), CHARACTERISTIC.TRAP | CHARACTERISTIC.HAS_DELAY_SLOT, "TEQI"),
                           0b01100 : ConditionalInstruction(lambda opnd: (opnd.rs != opnd.imm), CHARACTERISTIC.TRAP | CHARACTERISTIC.HAS_DELAY_SLOT, "TNEI"),
                           0b10000 : ConditionalInstruction(lambda opnd: (opnd.rs < 0), CHARACTERISTIC.CALL | CHARACTERISTIC.HAS_DELAY_SLOT, "BLTZAL"),
                           0b10010 : ConditionalInstruction(lambda opnd: (opnd.rs < 0), CHARACTERISTIC.CALL | CHARACTERISTIC.HAS_DELAY_SLOT_LIKELY, "BLTZALL"),
                           0b10001 : ConditionalInstruction(lambda opnd: (opnd.rs >= 0), CHARACTERISTIC.CALL | CHARACTERISTIC.HAS_DELAY_SLOT, "BGEZAL"),
                           0b10011 : ConditionalInstruction(lambda opnd: (opnd.rs >= 0), CHARACTERISTIC.CALL | CHARACTERISTIC.HAS_DELAY_SLOT_LIKELY, "BGEZALL")
                           }

    def __init__(self, isLittleEndian=False):
        """
        @param isLittleEndian: Flag indicating the endianess of the processor (default is big).
        """
        self.isLE = isLittleEndian
        self.IS_LITTLE_ENDIAN = isLittleEndian
        if isLittleEndian:
            # TODO: remove when little endian is supported!
            raise NotImplemented("Currently the only supported endianess is BIG.")
        
        _CPU.__init__(self)
        
    @staticmethod
    def parseInstruction(ins):
        """
        Interprets a given byte-string (4 bytes) as an instruction.
        @param ins: The byte-string.
        @return: A tupel of the for values describing the instruction.
        """
        i = tools.byteStrToInt(ins, tools.ENDIANESS.BIG)
        a = i >> (MIPS32.NATIVE_REGISTER_WIDTH - 6)
        b = i >> (MIPS32.NATIVE_REGISTER_WIDTH - 6 - 5) & 0x1F
        c = i >> (MIPS32.NATIVE_REGISTER_WIDTH - 6 - 5 - 5) & 0x1F
        d = i & 0xFFFF
        e = i & ((1 << (MIPS32.NATIVE_REGISTER_WIDTH - 6)) - 1) # lower 26 bits

        return (a, b, c, d, e)

    @staticmethod
    def getInstructionDescriptor(op, rs, rt, imm):
        if op == MIPS32.OP_SPECIAL:
            # for SPECIAL instructions the last 6 bits select the instruction
            specSel = imm & 0b111111
            return specSel in MIPS32.INSTRUCTIONS_SPECIAL and MIPS32.INSTRUCTIONS_SPECIAL[specSel] or None

        if op == MIPS32.OP_REGIMM:
            # for REGIMM instruction the rt value selects the instruction.
            return rt in MIPS32.INSTRUCTIONS_REGIMM and MIPS32.INSTRUCTIONS_REGIMM[rt] or None

        if op in MIPS32.INSTRUCTIONS_OWN_OPCODE:
            return MIPS32.INSTRUCTIONS_OWN_OPCODE[op]

        return None

    def toRegisterHexString(self, value):
        if self.isLE:
            v = tools.reverseEndianess(value, self.getNativeRegisterWidth())
        else:
            v = value
        return "%08x" % v

    def registerHexStringToValue(self, s):
        if s == ('x'*(self.NATIVE_REGISTER_WIDTH/8*2)):
            return 0
        
        tmp = int(s, 16)
        if self.isLE:
            return tools.reverseEndianess(tmp, self.getNativeRegisterWidth())
        return tmp

    def getFunctionReturnAddress(self, pygdb, ptid, pid=None):
        ra = pygdb.getRegisters(ptid)[self.RA_INDEX]
        return ra

    @staticmethod
    def _getInstructionContext(pygdb, tid, addrInstr):

        if addrInstr is None:
            addr = pygdb.getPC(tid)
        else:
            addr = addrInstr

        if pygdb.hasBreakpoint(addr):
            mem = pygdb.getOriginalBytesBreakpoint(addr) # implicit WORD_SIZE bytes
        else:
            mem = pygdb.readMemory(addr, MIPS32.WORD_SIZE, cache=True)

        regs = pygdb.getRegisters(tid)
        instr = MIPS32.parseInstruction(mem)
        op = instr[0]
        rsI = instr[1]
        rs = tools.unsignedToSignedInt(regs[rsI], MIPS32.NATIVE_REGISTER_WIDTH)
        rtI = instr[2]
        rt = tools.unsignedToSignedInt(regs[rtI], MIPS32.NATIVE_REGISTER_WIDTH)
        imm = instr[3]
        instrIndex = instr[4]

        opnds = MIPS32.Operands(rs, rt, imm, rsI, rtI, instrIndex)
        descr = MIPS32.getInstructionDescriptor(op, rsI, rtI, imm)

        return (descr, opnds)

    def getInstrCharacteristics(self, pygdb, tid, addrInstr=None):
        descr, opnds = MIPS32._getInstructionContext(pygdb, tid, addrInstr)
        if descr is None:
            return CHARACTERISTIC.NONE
        else:
            return descr.getCharacteristics(opnds)

    def evaluateCondInstr(self, pygdb, tid, addrInstr=None):
        descr, opnds = MIPS32._getInstructionContext(pygdb, tid, addrInstr)
        if descr is None:
            raise InvalidRequest("The supplied instruction is not conditional.")
        return descr.checkCondition((opnds,))

    def getAddressDelaySlot(self, addr):
        return MIPS32.WORD_SIZE + addr

    def getAddressBreakpoint(self, pc):
        return pc

    def getNextPC(self, pygdb, tid, cond=None):
        # TODO:
        # - check everything for endianess
        # - what about branch likely? docs say it may nullify delay slot
        # - what about bc1(anyl)*(2/4)*(f/t), jalx (ISA mode switch),
        #   bposge(32/64), syscall?
        pc = pygdb.getPC(tid)
        descr, opnds = MIPS32._getInstructionContext(pygdb, tid, pc)
        if descr is None or descr.nextAddrFunc is None:
            # default
            nextPc = pc + 4
            
        else:
            if descr.characteristics & CHARACTERISTIC.CONDITIONAL != 0:
                if cond is not None:
                    _cond = cond
                else:
                    _cond = descr.checkCondition((opnds,))
            else:
                _cond = True
          
            nextPc = descr.nextAddrFunc(pc, _cond, opnds)
            
        return nextPc
    
    def getFunctionReturnValues(self, pygdb, tid):
        
        regs = pygdb.getRegisters(tid)
        return [regs[MIPS32_CONSTS.V0_INDEX], regs[MIPS32_CONSTS.V1_INDEX]]
    
    def isEndOfFunction(self, pygdb, tid, instructionCharacteristics=None):
        addr = pygdb.getPC(tid)
        chars = instructionCharacteristics or self.getInstrCharacteristics(pygdb, tid, addr)
        if chars & CHARACTERISTIC.CALL == 0:
            return None
        
        # TODO: this is probably only valid on POSIX
        regs = pygdb.getRegisters(tid)
        return regs[self.RA_INDEX] == regs[self.T7_INDEX] 
        
    