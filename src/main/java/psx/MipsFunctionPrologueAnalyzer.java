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
package psx;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer that detects MIPS function prologues following function returns.
 *
 * Problem: Ghidra's disassembler follows execution flow. When it hits "jr ra" (return),
 * it stops because there's no flow to the next address. The bytes after the return
 * belong to a separate function that's only reachable via calls (jal) to that address.
 * If nothing calls it yet (e.g., indirect calls via function pointers), it stays
 * as undefined bytes.
 *
 * Solution: When we see a "jr ra" instruction, check if the bytes immediately after
 * the delay slot look like a function prologue (addiu sp,sp,-N). If so, disassemble
 * them and create a function.
 *
 * This analyzer uses INSTRUCTION_ANALYZER to only process actual disassembled code,
 * not raw bytes (which could be data).
 */
public class MipsFunctionPrologueAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "MIPS Function Prologue Detector";
	private static final String DESCRIPTION =
		"Detects MIPS function prologues (addiu sp,sp,-N) following returns (jr ra) " +
		"and creates functions at those addresses. Essential for PSX binaries.";

	// addiu sp,sp,imm encoding (little-endian): imm_lo imm_hi 0xBD 0x27
	private static final byte ADDIU_SP_BYTE2 = (byte)0xBD;
	private static final byte ADDIU_SP_BYTE3 = (byte)0x27;

	public MipsFunctionPrologueAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Run after disassembly, before function analysis
		setPriority(AnalysisPriority.DISASSEMBLY.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		Processor processor = program.getLanguage().getProcessor();
		return processor.equals(Processor.findOrPossiblyCreateProcessor("PSX")) ||
		       processor.equals(Processor.findOrPossiblyCreateProcessor("MIPS"));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		Memory memory = program.getMemory();
		Listing listing = program.getListing();
		int functionsCreated = 0;

		// Iterate through newly added instructions looking for "jr ra"
		InstructionIterator iter = listing.getInstructions(set, true);
		while (iter.hasNext()) {
			monitor.checkCancelled();

			Instruction instr = iter.next();

			// Check if this is "jr ra" (function return)
			if (!isJrRa(instr)) {
				continue;
			}

			// Found jr ra - get the address after the delay slot
			Address afterDelaySlot = getAddressAfterDelaySlot(instr, listing);
			if (afterDelaySlot == null) {
				continue;
			}

			// Skip if already disassembled or has a function
			if (listing.getInstructionAt(afterDelaySlot) != null ||
			    listing.getFunctionAt(afterDelaySlot) != null) {
				continue;
			}

			// Check if memory exists and is initialized at this address
			if (!memory.contains(afterDelaySlot)) {
				continue;
			}

			// Check if bytes look like a function prologue (addiu sp,sp,-N)
			try {
				if (isFunctionPrologue(memory, afterDelaySlot)) {
					// Disassemble and create function
					if (disassembleAndCreateFunction(program, afterDelaySlot, monitor)) {
						functionsCreated++;
					}
				}
			} catch (MemoryAccessException e) {
				// Can't read memory here, skip
			}
		}

		if (functionsCreated > 0) {
			log.appendMsg(NAME, "Created " + functionsCreated + " functions after jr ra instructions");
		}

		return true;
	}

	/**
	 * Check if instruction is "jr ra" (return from function).
	 * Handles both "jr" and "_jr" (delay slot variant) mnemonics.
	 */
	private boolean isJrRa(Instruction instr) {
		String mnemonic = instr.getMnemonicString();
		if (!mnemonic.equals("jr") && !mnemonic.equals("_jr")) {
			return false;
		}

		// Check if operand is the ra register
		Object[] opObjects = instr.getOpObjects(0);
		if (opObjects.length > 0 && opObjects[0] instanceof Register) {
			Register reg = (Register) opObjects[0];
			return reg.getName().equals("ra");
		}
		return false;
	}

	/**
	 * Get the address immediately after the delay slot of a jr instruction.
	 * In MIPS, jr has a delay slot (the next instruction always executes).
	 */
	private Address getAddressAfterDelaySlot(Instruction jrInstr, Listing listing) {
		try {
			// The delay slot is at jr address + 4
			Address delaySlotAddr = jrInstr.getAddress().add(4);

			// Check if delay slot is disassembled
			Instruction delaySlot = listing.getInstructionAt(delaySlotAddr);
			if (delaySlot != null) {
				// Return address after delay slot instruction
				return delaySlot.getAddress().add(delaySlot.getLength());
			} else {
				// Delay slot not disassembled - return address after where it should be
				return delaySlotAddr.add(4);
			}
		} catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	/**
	 * Check if bytes at address form "addiu sp,sp,-N" (function prologue).
	 *
	 * Encoding (little-endian): imm_lo imm_hi 0xBD 0x27
	 * - 0x27BD = opcode for "addiu sp,sp,imm"
	 * - imm must be negative (stack grows down)
	 */
	private boolean isFunctionPrologue(Memory memory, Address addr) throws MemoryAccessException {
		byte[] bytes = new byte[4];
		memory.getBytes(addr, bytes);

		// Check for addiu sp,sp,imm pattern
		if (bytes[2] == ADDIU_SP_BYTE2 && bytes[3] == ADDIU_SP_BYTE3) {
			// Check if immediate is negative (allocating stack space)
			short immediate = (short)((bytes[1] << 8) | (bytes[0] & 0xFF));
			return immediate < 0;
		}
		return false;
	}

	/**
	 * Disassemble at address and create a function.
	 */
	private boolean disassembleAndCreateFunction(Program program, Address addr, TaskMonitor monitor) {
		// Disassemble
		DisassembleCommand disCmd = new DisassembleCommand(addr, null, true);
		if (!disCmd.applyTo(program, monitor)) {
			return false;
		}

		// Create function
		CreateFunctionCmd funcCmd = new CreateFunctionCmd(addr);
		return funcCmd.applyTo(program, monitor);
	}
}
