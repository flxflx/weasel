'''
Created on 29.07.2013

@author: Felix
'''

from pygdb import PyGdb, environment, cpu, tracer

GDB_HOST = "192.168.0.2"
GDB_PORT = "1234"
ADDR_FUNC = 0x004006b4 

mips = cpu.MIPS32()
posix = environment.Posix()
gdbSession = PyGdb(HOST, PORT_GDB, mips, posix)
gdbSession.reset()
bbTracer = tracer.BasicBlockTracer(gdbSession, ADDR_FUNC, breakOnEntireFunction=False)
bbTracer.setup()
tt = bbTracer.start()
tt.join()
print bbTracer.getTraces()[0]


    
    
    
    
    
