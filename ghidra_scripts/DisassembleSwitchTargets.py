# -*- coding: utf-8 -*-
#@author Arika Games Research
#@category Analysis.PSX
#@keybinding
#@menupath Tools.Analysis.Disassemble Switch Targets
#@toolbar
"""
Script to find computed jumps (switch statements) and disassemble/create functions
at their inline targets.

MIPS switch pattern this script handles:
    sltiu   v0, v1, N          ; Range check
    beq     v0, zero, default  ; Branch if out of range
    sll     v0, v1, 0x2        ; v0 = index * 4
    addu    v0, v0, base       ; v0 = base + offset
    lw      v0, offset(v0)     ; Load jump target (for pointer tables)
    jr      v0                 ; Jump to target

Or for inline targets (embedded jump table):
    jr      v0                 ; Jump computed from inline addresses

This script:
1. Finds all jr $reg (where reg != ra) instructions
2. Analyzes the preceding code to find the jump table pattern
3. For inline targets: disassembles and creates functions at each target
4. For pointer tables: reads the table and creates functions at targets
"""

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.listing import Instruction
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.cmd.disassemble import DisassembleCommand

api = FlatProgramAPI(currentProgram)
listing = currentProgram.getListing()
funcManager = currentProgram.getFunctionManager()
memory = currentProgram.getMemory()
addrFactory = api.getAddressFactory()

def get_instruction_at(addr):
    """Get instruction at address"""
    return listing.getInstructionAt(addr)

def is_undefined_at(addr):
    """Check if address has undefined/unanalyzed bytes"""
    instr = listing.getInstructionAt(addr)
    if instr is not None:
        return False
    data = listing.getDataAt(addr)
    if data is not None and not data.isPointer():
        # Has data but not a pointer - could be undefined bytes
        return data.isDefined() == False or data.getDataType().getName() == "undefined"
    return data is None or not data.isDefined()

def disassemble_at(addr, context_addr=None):
    """Disassemble code at address"""
    try:
        # Check if already disassembled
        if listing.getInstructionAt(addr) is not None:
            return True

        # Disassemble
        cmd = DisassembleCommand(addr, None, True)
        success = cmd.applyTo(currentProgram)
        if success:
            print("    Disassembled at {}".format(addr))
        return success
    except Exception as e:
        print("    Error disassembling at {}: {}".format(addr, e))
        return False

def create_function_at(addr, name=None):
    """Create function at address if not already a function"""
    try:
        # Check if already a function
        existing = funcManager.getFunctionAt(addr)
        if existing is not None:
            return existing

        # Make sure it's disassembled first
        if listing.getInstructionAt(addr) is None:
            disassemble_at(addr)

        # Create function
        cmd = CreateFunctionCmd(addr)
        success = cmd.applyTo(currentProgram)

        if success:
            func = funcManager.getFunctionAt(addr)
            if func and name:
                func.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
            print("    Created function at {}".format(addr))
            return func
        return None
    except Exception as e:
        print("    Error creating function at {}: {}".format(addr, e))
        return None

def read_dword_at(addr):
    """Read 32-bit little-endian value from memory"""
    try:
        if not memory.contains(addr):
            return None
        bytes_array = bytearray(4)
        memory.getBytes(addr, bytes_array)
        # MIPS is big-endian in Ghidra's representation but let's check
        # Actually for PSX it's little-endian
        value = bytes_array[0] | (bytes_array[1] << 8) | (bytes_array[2] << 16) | (bytes_array[3] << 24)
        return value
    except:
        return None

def analyze_switch_pattern(jr_addr):
    """
    Analyze the instructions before a jr to understand the switch pattern.
    Returns info about the switch: range, base, targets.
    """
    result = {
        "type": None,
        "jr_addr": jr_addr,
        "range_max": None,
        "inline_targets": [],
        "table_base": None
    }

    # Look backwards from jr to find the pattern
    # We need to find: sltiu (range check), sll (multiply by 4), addu (add base), lw (load target)

    prev_instrs = []
    addr = jr_addr.subtract(4)
    for i in range(15):  # Look back up to 15 instructions
        instr = listing.getInstructionAt(addr)
        if instr is None:
            addr = addr.subtract(4)
            continue
        prev_instrs.insert(0, {"addr": addr, "instr": instr})
        addr = addr.subtract(4)

    # Find sltiu for range check
    range_max = None
    for item in prev_instrs:
        instr = item["instr"]
        mnemonic = instr.getMnemonicString()
        if mnemonic == "sltiu":
            # sltiu rd, rs, imm - rd = (rs < imm) ? 1 : 0
            try:
                ops = instr.getOpObjects(2)  # immediate is operand 2
                if ops and len(ops) > 0:
                    from ghidra.program.model.scalar import Scalar
                    if isinstance(ops[0], Scalar):
                        range_max = ops[0].getUnsignedValue()
                        result["range_max"] = range_max
                        break
            except:
                pass

    if range_max is None:
        # Try to detect inline jump table by looking at code after jr
        # If there are consecutive 3-instruction blocks that all jump to same location
        result["type"] = "unknown_inline"
        return result

    # Now check if this is inline targets or a pointer table
    # Look at the instruction right after jr (in the delay slot position)
    next_addr = jr_addr.add(8)  # After jr + delay slot

    # Check if there's a lw before the jr (indicates pointer table)
    has_lw = False
    for item in prev_instrs:
        if item["instr"].getMnemonicString() == "lw":
            has_lw = True
            break

    if has_lw:
        # This is a pointer table switch - targets loaded from memory
        result["type"] = "pointer_table"
        # Would need more analysis to find the table base
    else:
        # Inline targets - code blocks embedded after the switch
        result["type"] = "inline"
        result["inline_targets"] = []

        # Each inline target is typically:
        # - lui  + j + addiu (3 instructions, 12 bytes)
        # Calculate target addresses based on range
        for i in range(range_max):
            target_addr = next_addr.add(i * 12)  # 3 instructions * 4 bytes each
            result["inline_targets"].append(target_addr)

    return result

def find_and_process_computed_jumps(start_addr=None, end_addr=None):
    """Find all jr instructions (computed jumps) and analyze them"""

    results = []

    if start_addr is None:
        # Use program's min/max addresses
        start_addr = currentProgram.getMinAddress()
    if end_addr is None:
        end_addr = currentProgram.getMaxAddress()

    print("Scanning {} to {} for computed jumps...".format(start_addr, end_addr))

    # Iterate through all instructions
    instr = listing.getInstructionAfter(start_addr)
    count = 0
    jr_count = 0

    while instr is not None and instr.getAddress().compareTo(end_addr) <= 0:
        count += 1
        mnemonic = instr.getMnemonicString()

        if mnemonic == "jr":
            # Check if it's jr $ra (function return) - skip those
            ops = instr.getOpObjects(0)
            if ops and len(ops) > 0:
                reg = str(ops[0])
                if reg != "ra":
                    jr_count += 1
                    # This is a computed jump (not a return)
                    jr_addr = instr.getAddress()

                    # Analyze the switch pattern
                    switch_info = analyze_switch_pattern(jr_addr)

                    if switch_info["type"] == "inline" and switch_info["range_max"]:
                        print("\nFound inline switch at {} (range: 0-{})".format(
                            jr_addr, switch_info["range_max"] - 1))

                        results.append(switch_info)

                        # Check and disassemble each target
                        for target in switch_info["inline_targets"]:
                            if is_undefined_at(target):
                                print("  Target {} needs disassembly".format(target))
                            else:
                                print("  Target {} already disassembled".format(target))

        instr = instr.getNext()

        if count % 10000 == 0:
            print("  Processed {} instructions...".format(count))

    print("\nFound {} computed jumps (non-ra jr instructions)".format(jr_count))
    return results

def process_specific_address(addr):
    """Process a specific jr instruction address"""
    instr = listing.getInstructionAt(addr)
    if instr is None:
        print("No instruction at {}".format(addr))
        return None

    if instr.getMnemonicString() != "jr":
        print("Instruction at {} is not jr: {}".format(addr, instr.getMnemonicString()))
        return None

    switch_info = analyze_switch_pattern(addr)

    print("\nSwitch analysis at {}:".format(addr))
    print("  Type: {}".format(switch_info["type"]))
    print("  Range max: {}".format(switch_info["range_max"]))

    if switch_info["type"] == "inline":
        print("  Inline targets ({} total):".format(len(switch_info["inline_targets"])))
        for i, target in enumerate(switch_info["inline_targets"]):
            exists = listing.getInstructionAt(target) is not None
            func_exists = funcManager.getFunctionAt(target) is not None
            status = "OK" if exists else "UNDEFINED"
            func_status = "(func)" if func_exists else "(no func)"
            print("    [{}] {} - {} {}".format(i, target, status, func_status))

    return switch_info

def disassemble_switch_targets(switch_info, create_funcs=True):
    """Disassemble all targets for a switch and optionally create functions"""
    if switch_info["type"] != "inline":
        print("Not an inline switch, skipping")
        return

    jr_addr = switch_info["jr_addr"]
    print("\nProcessing switch at {}...".format(jr_addr))

    disassembled = 0
    functions_created = 0

    for i, target in enumerate(switch_info["inline_targets"]):
        # Disassemble if needed
        if listing.getInstructionAt(target) is None:
            if disassemble_at(target, jr_addr):
                disassembled += 1

        # Create function if needed
        if create_funcs:
            if funcManager.getFunctionAt(target) is None:
                func = create_function_at(target)
                if func:
                    functions_created += 1

    print("  Disassembled {} targets, created {} functions".format(
        disassembled, functions_created))

def main():
    print("=" * 70)
    print("DISASSEMBLE SWITCH TARGETS")
    print("=" * 70)
    print("")

    # Check if user selected an address
    current_addr = currentLocation.getAddress() if currentLocation else None

    if current_addr:
        # Check if current address is a jr instruction or nearby
        instr = listing.getInstructionAt(current_addr)

        if instr and instr.getMnemonicString() == "jr":
            # Process just this one
            print("Processing selected jr instruction at {}".format(current_addr))
            switch_info = process_specific_address(current_addr)
            if switch_info and switch_info["type"] == "inline":
                print("\nDisassembling and creating functions...")
                disassemble_switch_targets(switch_info, create_funcs=True)
            return
        else:
            # Look for nearby jr
            print("Selected address {} is not a jr instruction".format(current_addr))
            print("Searching nearby...")

            # Search forward
            addr = current_addr
            for i in range(20):
                instr = listing.getInstructionAt(addr)
                if instr and instr.getMnemonicString() == "jr":
                    ops = instr.getOpObjects(0)
                    if ops and str(ops[0]) != "ra":
                        print("Found computed jr at {}".format(addr))
                        switch_info = process_specific_address(addr)
                        if switch_info and switch_info["type"] == "inline":
                            print("\nDisassembling and creating functions...")
                            disassemble_switch_targets(switch_info, create_funcs=True)
                        return
                addr = addr.add(4)

    # No specific address - scan a range
    print("No jr instruction selected. Scanning for all computed jumps...")
    print("")

    # Scan common code regions
    regions = [
        ("0x80010000", "0x80100000"),  # Main code area
        ("0x80200000", "0x80300000"),  # Extended code area
    ]

    all_switches = []
    for start_str, end_str in regions:
        try:
            start = addrFactory.getAddress(start_str)
            end = addrFactory.getAddress(end_str)
            if start and end:
                switches = find_and_process_computed_jumps(start, end)
                all_switches.extend(switches)
        except:
            pass

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("Found {} inline switches".format(len(all_switches)))

    if all_switches:
        print("\nDo you want to disassemble all targets and create functions?")
        print("(Run script again with cursor on a specific jr instruction for single processing)")

if __name__ == "__main__":
    main()
