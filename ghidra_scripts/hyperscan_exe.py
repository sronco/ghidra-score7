# Load Hyperscan HYPER.EXE
#@category Hyperscan
#@author

from ghidra.program.model.lang import RegisterValue
from ghidra.app.util import PseudoDisassembler
from java.math import BigInteger


filename = askFile("HYPER.EXE", "File")
with open(filename.absolutePath, "rb") as fh:
	buf = fh.read()

if (getMemoryBlock("GAME")):
	removeMemoryBlock(getMemoryBlock("GAME"))

mblock = createMemoryBlock("GAME", toAddr(0xa00901fc), buf, True)
mblock.setExecute(True)
clearListing(mblock.getStart(), mblock.getEnd())
entry_addr = mblock.getStart().add(0xe04)   # 0xa0091000


# Most games sets the Base Pointer at start
#  a0091000     ldis             r28,0xHHHH
#  a0091004     ori              r28,0xLLLL

inst0 = PseudoDisassembler(currentProgram).disassemble(entry_addr)
if (inst0 and inst0.getMnemonicString() == "ldis" and inst0.getDefaultOperandRepresentation(0) == "r28"):
	inst4 = PseudoDisassembler(currentProgram).disassemble(entry_addr.add(4))
	if (inst4 and inst4.getMnemonicString() == "ori" and inst4.getDefaultOperandRepresentation(0) == "r28"):
		r28Val = (int(inst0.getDefaultOperandRepresentation(1), 0) << 16) | int(inst4.getDefaultOperandRepresentation(1), 0)
		regR28 = currentProgram.getLanguage().getRegister("r28")
		programContext = currentProgram.getProgramContext()
		print("R28: %08x" % (r28Val))
		programContext.setRegisterValue(mblock.getStart(), mblock.getEnd(), RegisterValue(regR28, BigInteger.valueOf(r28Val)))


# HyperScan game entry point
goTo(entry_addr)
createFunction(entry_addr, "game_entrypoint")
disassemble(entry_addr)
