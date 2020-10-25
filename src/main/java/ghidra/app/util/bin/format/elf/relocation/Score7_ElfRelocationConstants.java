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

public class Score7_ElfRelocationConstants {

	/* Old Sunplus S+core7 backend magic number. Written in the absence of an ABI.  */
	public static final int EM_SCORE_OLD = 95;

	/** No operation needed */
	public static final int R_SCORE_NONE = 0;
	public static final int R_SCORE_HI16 = 1;
	public static final int R_SCORE_LO16 = 2;
	public static final int R_SCORE_BCMP = 3;
	public static final int R_SCORE_24 = 4;
	public static final int R_SCORE_PC19 = 5;
	public static final int R_SCORE16_11 = 6;
	public static final int R_SCORE16_PC8 = 7;
	public static final int R_SCORE_ABS32 = 8;
	public static final int R_SCORE_ABS16 = 9;
	public static final int R_SCORE_DUMMY2 = 10;
	public static final int R_SCORE_GP15 = 11;
	public static final int R_SCORE_GNU_VTINHERIT = 12;
	public static final int R_SCORE_GNU_VTENTRY = 13;
	public static final int R_SCORE_GOT15 = 14;
	public static final int R_SCORE_GOT_LO16 = 15;
	public static final int R_SCORE_CALL15 = 16;
	public static final int R_SCORE_GPREL32 = 17;
	public static final int R_SCORE_REL32 = 18;
	public static final int R_SCORE_DUMMY_HI16 = 19;
	public static final int R_SCORE_IMM30 = 20;
	public static final int R_SCORE_IMM32 = 21;

	private Score7_ElfRelocationConstants() {
		// no construct
	}
}
