'''
Created on 11.05.2012

@author: Felix
'''

class CHARACTERISTIC:
    NONE = 0
    CALL = 1
    RET = 2
    JMP = 4
    CONDITIONAL = 8
    IMPLICIT_BRANCH = 16
    FAR_BRANCH = 32
    DYNAMIC_BRANCH = 64
    HAS_DELAY_SLOT = 128 # needed for mips
    DELAY_SLOT_LIKELY = 256
    HAS_DELAY_SLOT_LIKELY = HAS_DELAY_SLOT | DELAY_SLOT_LIKELY
    TRAP = 512
    SHORT_BRANCH = 1024
    
    
class Instruction:    
    @staticmethod
    def CHAR_FUNC(self, env):
        return self.characteristics 
    
    def __init__(self, characteristics = 0, label = "", nextAddrFunc=None, charFunc=None):
        self.characteristics = characteristics
        self.charFunc = charFunc is None and Instruction.CHAR_FUNC or charFunc 
        self.nextAddrFunc = nextAddrFunc
    
    def getCharacteristics(self, env=None):
        return self.charFunc(self, env)
        
class ConditionalInstruction(Instruction):
        
    def __init__(self, condFunc, characteristics = 0, label = "", nextAddrFunc=None, charFunc=None):
        Instruction.__init__(self, characteristics, label, nextAddrFunc=nextAddrFunc, charFunc=charFunc)
        self.characteristics |= CHARACTERISTIC.CONDITIONAL
        self.condFunc = condFunc
        
    def checkCondition(self, args):
        condFunc = self.condFunc
        return condFunc(*args)
    
class ConditionalInstructionSimple(ConditionalInstruction):
    
    @staticmethod
    def COND_FUNC(self, registers):
        condition = registers[self.regIndex] & self.regMask != 0
        if self.negative != 0:
            condition = not condition
        return condition
             
    def __init__(self, regIndex, regMask, negative, characteristics = 0, label = "", nextAddrFunc=None):
        ConditionalInstruction.__init__(self, ConditionalInstructionSimple.COND_FUNC, characteristics, label, nextAddrFunc=nextAddrFunc)
        self.characteristics |= CHARACTERISTIC.CONDITIONAL
        self.regIndex = regIndex
        self.regMask = regMask
        self.negative = negative
            
    
        
        
        
    