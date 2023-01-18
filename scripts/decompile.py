import sys
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()

decomp_interface = DecompInterface()
decomp_interface.openProgram(currentProgram)
functionManager = currentProgram.getFunctionManager()

offset = int(args[0], 16)
addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
function = functionManager.getFunctionContaining(addr)

decompiled_function = decomp_interface.decompileFunction(function, 0, ConsoleTaskMonitor())
c = decompiled_function.getDecompiledFunction().getC()

print("=====BIGCHEESE_START=====")
print(c)
print("=====BIGCHEESE_END=====")
