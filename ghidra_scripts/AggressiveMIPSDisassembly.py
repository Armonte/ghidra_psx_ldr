# -*- coding: utf-8 -*-
#@author Arika Games Research
#@category Analysis.PSX
#@keybinding
#@menupath Tools.Analysis.Aggressive MIPS Disassembly
#@toolbar
"""
Aggressive MIPS disassembly for PSX binaries.

This script fixes Ghidra's conservative analysis by:
1. Finding all jr $reg (computed jumps, not returns) and disassembling fallthrough code
2. Finding undefined bytes after j/jal instructions (delay slot issues)
3. Disassembling code referenced by branch targets that weren't followed
4. Creating functions at switch table inline targets

Run this AFTER initial auto-analysis to catch what Ghidra missed.
"""

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.program.model.mem import MemoryAccessException

api = FlatProgramAPI(currentProgram)
listing = currentProgram.getListing()
funcManager = currentProgram.getFunctionManager()
memory = currentProgram.getMemory()
addrFactory = api.getAddressFactory()
refManager = currentProgram.getReferenceManager()

# Statistics
stats = {
    "jr_computed": 0,
    "disassembled": 0,
    "functions_created": 0,
    "undefined_refs_fixed": 0,
}

def is_valid_code_address(addr):
    """Check if address is in valid PSX code range"""
    try:
        addr_val = addr.getOffset()
        # PSX RAM: 0x80000000 - 0x801FFFFF typically for code
        return 0x80000000 <= addr_val <= 0x803FFFFF
    except:
        return False

def is_undefined_at(addr):
    """Check if address has no instruction"""
    return listing.getInstructionAt(addr) is None

def is_valid_mips_instruction(addr):
    """Quick heuristic check if bytes at addr look like valid MIPS instruction"""
    try:
        if not memory.contains(addr):
            return False
        bytes_arr = bytearray(4)
        memory.getBytes(addr, bytes_arr)

        # Get opcode (bits 31-26)
        word = bytes_arr[0] | (bytes_arr[1] << 8) | (bytes_arr[2] << 16) | (bytes_arr[3] << 24)
        opcode = (word >> 26) & 0x3F

        # Common valid opcodes for MIPS
        # 0x00 = SPECIAL (most ALU ops), 0x01 = REGIMM (branches)
        # 0x02 = J, 0x03 = JAL, 0x04 = BEQ, 0x05 = BNE, etc.
        # 0x08-0x0F = immediate ops (ADDI, ADDIU, SLTI, etc.)
        # 0x20-0x2F = loads, 0x28-0x2F = stores
        valid_opcodes = set([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  # Special, branches, jumps
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,  # Immediate ops
            0x10, 0x11, 0x12, 0x13,  # Coprocessor ops
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,  # Loads
            0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,  # Stores
        ])

        return opcode in valid_opcodes
    except:
        return False

def disassemble_at(addr):
    """Disassemble at address if not already done"""
    if listing.getInstructionAt(addr) is not None:
        return True

    if not is_valid_code_address(addr):
        return False

    if not is_valid_mips_instruction(addr):
        return False

    try:
        cmd = DisassembleCommand(addr, None, True)
        if cmd.applyTo(currentProgram):
            stats["disassembled"] += 1
            return True
    except Exception as e:
        pass
    return False

def create_function_at(addr):
    """Create function at address if not exists"""
    if funcManager.getFunctionAt(addr) is not None:
        return True

    # Make sure it's disassembled
    if listing.getInstructionAt(addr) is None:
        if not disassemble_at(addr):
            return False

    try:
        cmd = CreateFunctionCmd(addr)
        if cmd.applyTo(currentProgram):
            stats["functions_created"] += 1
            return True
    except:
        pass
    return False

def analyze_jr_computed(instr):
    """
    Analyze a jr instruction that's a computed jump (not jr ra).
    Try to find and disassemble inline switch targets.
    """
    jr_addr = instr.getAddress()

    # Look backwards for sltiu (range check) to find table size
    range_max = None
    addr = jr_addr
    for i in range(20):
        addr = addr.subtract(4)
        prev_instr = listing.getInstructionAt(addr)
        if prev_instr is None:
            continue

        mnemonic = prev_instr.getMnemonicString()
        if mnemonic == "sltiu":
            # Get the immediate value (range)
            try:
                from ghidra.program.model.scalar import Scalar
                ops = prev_instr.getOpObjects(2)
                if ops and len(ops) > 0 and isinstance(ops[0], Scalar):
                    range_max = ops[0].getUnsignedValue()
                    break
            except:
                pass

    # Start disassembling after jr + delay slot
    next_addr = jr_addr.add(8)  # jr + delay slot = 8 bytes

    if range_max:
        # We know the range, disassemble that many entries
        # Each entry is typically 3 instructions (12 bytes) for lui+j+addiu pattern
        # But could also be 2 instructions (8 bytes) for simpler patterns

        # First, detect the pattern by looking at the first target
        disassemble_at(next_addr)
        first_instr = listing.getInstructionAt(next_addr)

        if first_instr:
            # Check if it's lui (start of lui+j+addiu pattern)
            if first_instr.getMnemonicString() == "lui":
                entry_size = 12  # lui + j + addiu
            else:
                entry_size = 8  # simpler 2-instruction pattern

            targets_found = 0
            for i in range(range_max):
                target_addr = next_addr.add(i * entry_size)
                if disassemble_at(target_addr):
                    targets_found += 1
                # Try to create function at each target
                create_function_at(target_addr)

            if targets_found > 0:
                print("  jr at {} - disassembled {} inline targets (range={})".format(
                    jr_addr, targets_found, range_max))
    else:
        # No range found, try to disassemble a reasonable amount
        # Look for patterns that indicate end of switch targets
        targets_found = 0
        for i in range(20):  # Max 20 potential targets
            target_addr = next_addr.add(i * 12)  # Assume 12-byte entries

            if not is_undefined_at(target_addr):
                # Already disassembled, check if it's part of another function
                instr = listing.getInstructionAt(target_addr)
                if instr:
                    func = funcManager.getFunctionContaining(target_addr)
                    if func and func.getEntryPoint() != target_addr:
                        # Inside another function, stop
                        break

            if disassemble_at(target_addr):
                targets_found += 1
                create_function_at(target_addr)
            else:
                break  # Hit invalid code, stop

        if targets_found > 0:
            print("  jr at {} - disassembled {} inline targets (no range)".format(
                jr_addr, targets_found))

def find_undefined_branch_targets():
    """Find branch/jump targets that point to undefined code and disassemble them"""

    fixed = 0
    instr_iter = listing.getInstructions(True)

    for instr in instr_iter:
        mnemonic = instr.getMnemonicString()

        # Check branches and jumps
        if mnemonic in ["beq", "bne", "bgtz", "blez", "bltz", "bgez",
                        "bltzal", "bgezal", "j", "jal"]:
            # Get the target address from references
            refs = refManager.getReferencesFrom(instr.getAddress())
            for ref in refs:
                target = ref.getToAddress()
                if is_undefined_at(target) and is_valid_code_address(target):
                    if disassemble_at(target):
                        fixed += 1

    return fixed

def find_all_computed_jumps():
    """Find all jr $reg instructions where reg != ra"""

    computed_jrs = []
    instr_iter = listing.getInstructions(True)

    for instr in instr_iter:
        mnemonic = instr.getMnemonicString()

        if mnemonic == "jr":
            ops = instr.getOpObjects(0)
            if ops and len(ops) > 0:
                reg = str(ops[0])
                if reg != "ra":
                    computed_jrs.append(instr)
                    stats["jr_computed"] += 1

    return computed_jrs

def find_fallthrough_after_jumps():
    """
    Find undefined code immediately after unconditional jumps.
    Sometimes code falls through from the delay slot.
    """

    fixed = 0
    instr_iter = listing.getInstructions(True)

    for instr in instr_iter:
        mnemonic = instr.getMnemonicString()

        # After j/jal instructions, check if there's a gap
        if mnemonic in ["j", "jal"]:
            # Skip delay slot (next instruction)
            next_addr = instr.getAddress().add(8)  # j + delay slot

            # Check if there's undefined code that looks valid
            if is_undefined_at(next_addr):
                if disassemble_at(next_addr):
                    fixed += 1
                    # Try to create a function here since it's after a jump
                    create_function_at(next_addr)

    return fixed

def find_data_that_is_code():
    """
    Find addresses labeled as DAT_ or PTR_ that contain valid MIPS instructions.
    These are often missed by analysis due to computed address references.
    """

    fixed = 0
    symbol_table = currentProgram.getSymbolTable()

    # Get all symbols starting with DAT_ or showing as undefined
    symbol_iter = symbol_table.getAllSymbols(True)

    dat_symbols = []
    for sym in symbol_iter:
        name = sym.getName()
        if name.startswith("DAT_") or name.startswith("PTR_"):
            addr = sym.getAddress()
            if is_valid_code_address(addr) and is_undefined_at(addr):
                dat_symbols.append((addr, name))

    print("  Found {} DAT_/PTR_ symbols that might be code".format(len(dat_symbols)))

    for addr, name in dat_symbols:
        if is_valid_mips_instruction(addr):
            if disassemble_at(addr):
                fixed += 1
                print("    Disassembled {} at {} (was labeled as data)".format(name, addr))
                # Try to create function
                create_function_at(addr)

    return fixed

def find_gaps_between_functions():
    """
    Find gaps between consecutive functions that contain valid code.
    """

    fixed = 0

    # Get all functions sorted by address
    func_iter = funcManager.getFunctions(True)
    functions = []
    for func in func_iter:
        functions.append(func)

    if len(functions) < 2:
        return fixed

    # Sort by entry point
    functions.sort(key=lambda f: f.getEntryPoint().getOffset())

    for i in range(len(functions) - 1):
        func = functions[i]
        next_func = functions[i + 1]

        # Get end of current function
        func_end = func.getBody().getMaxAddress()
        next_func_start = next_func.getEntryPoint()

        # Check if there's a gap
        gap_start = func_end.add(1)
        gap_size = next_func_start.getOffset() - gap_start.getOffset()

        if gap_size > 4 and gap_size < 0x1000:  # Reasonable gap size
            # Check if gap contains valid code
            addr = gap_start
            while addr.getOffset() < next_func_start.getOffset():
                if is_undefined_at(addr) and is_valid_mips_instruction(addr):
                    if disassemble_at(addr):
                        fixed += 1
                        # Try to create function at start of gap
                        if addr == gap_start:
                            create_function_at(addr)
                addr = addr.add(4)

    return fixed

def process_address_range(start_addr, end_addr):
    """Process a specific address range"""

    print("Processing range {} to {}".format(start_addr, end_addr))

    # First pass: find and fix undefined branch targets
    print("  Pass 1: Fixing undefined branch targets...")
    find_undefined_branch_targets()

    # Second pass: find computed jumps and disassemble targets
    print("  Pass 2: Finding computed jumps...")
    computed_jrs = find_all_computed_jumps()

    print("  Found {} computed jumps (jr non-ra)".format(len(computed_jrs)))

    for jr_instr in computed_jrs:
        analyze_jr_computed(jr_instr)

    # Third pass: check for fallthrough gaps after j/jal
    print("  Pass 3: Checking for fallthrough gaps...")
    find_fallthrough_after_jumps()

    # Fourth pass: find DAT_/PTR_ symbols that are actually code
    print("  Pass 4: Checking DAT_/PTR_ symbols for code...")
    find_data_that_is_code()

    # Fifth pass: find gaps between functions
    print("  Pass 5: Checking gaps between functions...")
    find_gaps_between_functions()

def main():
    print("=" * 70)
    print("AGGRESSIVE MIPS DISASSEMBLY FOR PSX")
    print("=" * 70)
    print("")

    # Check for selection
    current_addr = currentLocation.getAddress() if currentLocation else None
    selection = currentSelection

    if selection and not selection.isEmpty():
        # Process selected range
        start = selection.getMinAddress()
        end = selection.getMaxAddress()
        print("Processing selected range: {} to {}".format(start, end))
        process_address_range(start, end)
    elif current_addr:
        # Process around current address (function or nearby)
        func = funcManager.getFunctionContaining(current_addr)
        if func:
            print("Processing function: {} ({})".format(func.getName(), func.getEntryPoint()))
            start = func.getEntryPoint()
            end = func.getBody().getMaxAddress().add(0x200)  # Include some extra
            process_address_range(start, end)
        else:
            # Process a range around current address
            start = current_addr.subtract(0x100)
            end = current_addr.add(0x400)
            print("Processing range around {}: {} to {}".format(current_addr, start, end))
            process_address_range(start, end)
    else:
        # Process entire program
        print("Processing entire program...")

        # Define common PSX code regions
        regions = [
            (0x80010000, 0x80200000),  # Main code
            (0x80200000, 0x80300000),  # Extended code
        ]

        for start_val, end_val in regions:
            try:
                start = addrFactory.getAddress("0x{:08x}".format(start_val))
                end = addrFactory.getAddress("0x{:08x}".format(end_val))
                if start and end and memory.contains(start):
                    process_address_range(start, end)
            except:
                pass

    print("")
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("Computed jumps found:   {}".format(stats["jr_computed"]))
    print("Addresses disassembled: {}".format(stats["disassembled"]))
    print("Functions created:      {}".format(stats["functions_created"]))
    print("")
    print("Done! If you still have issues:")
    print("  1. Re-run Ghidra's auto-analysis (Analysis > Auto Analyze)")
    print("  2. Run this script again (it may find more on second pass)")
    print("  3. Check for remaining DAT_/PTR_ symbols in code regions")

if __name__ == "__main__":
    main()
