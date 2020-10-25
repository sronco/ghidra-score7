/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.NotFoundException;

public class Score7_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_SCORE7 || elf.e_machine() == Score7_ElfRelocationConstants.EM_SCORE_OLD;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation, Address relocationAddress) throws MemoryAccessException, NotFoundException {

		var elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() != ElfConstants.EM_SCORE7 && elf.e_machine() != Score7_ElfRelocationConstants.EM_SCORE_OLD)
			return;

		var program = elfRelocationContext.getProgram();

		var memory = program.getMemory();

		int type = relocation.getType();
		if (type == Score7_ElfRelocationConstants.R_SCORE_NONE)
			return;

		int symbolIndex = relocation.getSymbolIndex();
		long addend = relocation.getAddend();

		var sym = elfRelocationContext.getSymbol(symbolIndex);
		String symbolName = sym.getNameAsString();

		//long offset = (int) relocationAddress.getOffset();
		long symbolValue = elfRelocationContext.getSymbolValue(sym);

		switch (type) {
			case Score7_ElfRelocationConstants.R_SCORE_HI16:
			case Score7_ElfRelocationConstants.R_SCORE_LO16: {
				int oldValue = memory.getInt(relocationAddress);

				int oldAddr = ((oldValue & 0x00007ffe) >> 1) | ((oldValue & 0x00030000) >> 2);
				int newValue = (int) (oldAddr + symbolValue + addend);
				if (type == Score7_ElfRelocationConstants.R_SCORE_HI16)
					newValue >>= 16;

				int sValue = (oldValue & 0xfffc8001) | ((newValue & 0x00003fff) << 1) | ((newValue & 0x0000c000) << 2);
				memory.setInt(relocationAddress, sValue);
				break;
			}
			case Score7_ElfRelocationConstants.R_SCORE_24: {
				int oldValue = memory.getInt(relocationAddress);
				int oldAddr = ((oldValue & 0x03ff0000) >> 1) | (oldValue & 0x00007ffe);
				int newValue = (int) (oldAddr + addend + symbolValue) >> 1;

				int sValue = (oldValue & 0xfc008001) | ((newValue & 0x00003fff) << 1) | ((newValue & 0x00ffc000) << 2);
				memory.setInt(relocationAddress, sValue);
				break;
			}
			case Score7_ElfRelocationConstants.R_SCORE_ABS32: {
				int oldValue = memory.getInt(relocationAddress);
				int sValue = (int) (oldValue + symbolValue - addend);
				memory.setInt(relocationAddress, sValue);
				break;
			}
			case Score7_ElfRelocationConstants.R_SCORE_GP15: {
				int oldValue = memory.getInt(relocationAddress);
				int oldAddr = oldValue & 0x00007fff;

				if ((oldAddr & 0x4000) != 0)    // sign extend
					oldAddr = -(oldAddr ^ 0x7fff) - 1;

				int newValue = (int) (oldAddr + symbolValue - addend);

				int sValue = (oldValue & 0xffff8000) | (newValue & 0x00007fff);
				memory.setInt(relocationAddress, sValue);
				break;
			}

			//case Score7_ElfRelocationConstants.R_SCORE_BCMP:
			//case Score7_ElfRelocationConstants.R_SCORE_PC19:
			//case Score7_ElfRelocationConstants.R_SCORE16_11:
			//case Score7_ElfRelocationConstants.R_SCORE16_PC8:
			//case Score7_ElfRelocationConstants.R_SCORE_ABS16:
			//case Score7_ElfRelocationConstants.R_SCORE_DUMMY2:
			//case Score7_ElfRelocationConstants.R_SCORE_GNU_VTINHERIT:
			//case Score7_ElfRelocationConstants.R_SCORE_GNU_VTENTRY:
			//case Score7_ElfRelocationConstants.R_SCORE_GOT15:
			//case Score7_ElfRelocationConstants.R_SCORE_GOT_LO16:
			//case Score7_ElfRelocationConstants.R_SCORE_CALL15:
			//case Score7_ElfRelocationConstants.R_SCORE_GPREL32:
			//case Score7_ElfRelocationConstants.R_SCORE_REL32:
			//case Score7_ElfRelocationConstants.R_SCORE_DUMMY_HI16:
			//case Score7_ElfRelocationConstants.R_SCORE_IMM30:
			//case Score7_ElfRelocationConstants.R_SCORE_IMM32:

			default: {
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				break;
			}
		}
	}
}
