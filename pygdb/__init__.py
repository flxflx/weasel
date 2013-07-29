from core import PyGdb
import globals
import tracer
import trace
import environment
import cpu

environments = {"POSIX":environment.Posix, "WINDOWS":environment.Windows}
cpus = {"X86":cpu.X86, "X64":cpu.X64, "MIPS32":cpu.MIPS32, "ARM":cpu.ARM}