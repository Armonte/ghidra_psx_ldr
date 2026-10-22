# -*- coding: utf-8 -*-
#@author Arika Games Research
#@category Analysis.PSX
#@keybinding
#@menupath Tools.Analysis.Fix Shared Epilogues
#@toolbar
"""
Fix shared epilogue issues in PSX/MIPS binaries.

MIPS compilers often optimize by having multiple functions share the same
epilogue (stack cleanup + return) code. This causes Ghidra to:
1. Create weird function boundaries
2. Show jumps to labels inside other functions
3. Miss proper function flow

This script:
1. Finds epilogue patterns (lw ra,X(sp); jr ra; addiu sp,sp,Y)
2. Identifies which functions jump to shared epilogues
3. Either extends functions to include their epilogue OR
4. Marks shared epilogues as thunks/shared code
"""

from ghidra.program.flatapi import FlatProgramAPI

api = FlatProgramAPI(currentProgram)
listing = currentProgram.getListing()
funcManager = currentProgram.getFunctionManager()
refManager = currentProgram.getReferenceManager()
addrFactory = api.getAddressFactory()

def is_epilogue_start(addr):
    """Check if address is the start of an epilogue sequence (lw ra,X(sp))"""
    instr = listing.getInstructionAt(addr)
    if instr is None:
        return False

    mnemonic = instr.getMnemonicString()
    if mnemonic != "lw":
        return False

    # Check if it's loading ra from stack
    instr_str = str(instr)
    return "ra," in instr_str and "(sp)" in instr_str

def find_epilogue_sequence(start_addr):
    """
    Find the full epilogue sequence starting at addr.
    Returns: (end_addr, jr_ra_addr) or None if not an epilogue
    """
    addr = start_addr
    found_jr_ra = None

    # Epilogue pattern:
    # lw ra, X(sp)      <- start
    # lw s8, Y(sp)      <- optional saved registers
    # lw s7, Z(sp)      <- optional
    # ...
    # jr ra             <- end before this
    # addiu sp, sp, N   <- delay slot (actual end)

    for i in range(20):  # Max 20 instructions in epilogue
        instr = listing.getInstructionAt(addr)
        if instr is None:
            break

        mnemonic = instr.getMnemonicString()

        if mnemonic == "jr":
            # Check if jr ra
            ops = instr.getOpObjects(0)
            if ops and str(ops[0]) == "ra":
                found_jr_ra = addr
                # Include delay slot
                return (addr.add(4), found_jr_ra)

        addr = addr.add(4)

    return None

def find_shared_epilogues():
    """Find epilogues that are jumped to from multiple functions"""

    shared_epilogues = {}

    # Iterate through all instructions looking for epilogue starts
    instr_iter = listing.getInstructions(True)

    for instr in instr_iter:
        addr = instr.getAddress()

        if is_epilogue_start(addr):
            # Check if this epilogue has xrefs from other functions
            refs = refManager.getReferencesTo(addr)
            calling_functions = set()

            for ref in refs:
                from_addr = ref.getFromAddress()
                from_func = funcManager.getFunctionContaining(from_addr)

                if from_func:
                    calling_functions.add(from_func.getEntryPoint())

            # Also check the function this epilogue is in
            containing_func = funcManager.getFunctionContaining(addr)

            if len(calling_functions) > 1 or (containing_func and len(calling_functions) >= 1):
                # This epilogue is shared!
                epilogue_info = find_epilogue_sequence(addr)
                if epilogue_info:
                    end_addr, jr_ra_addr = epilogue_info
                    shared_epilogues[addr] = {
                        "start": addr,
                        "end": end_addr,
                        "jr_ra": jr_ra_addr,
                        "containing_func": containing_func.getEntryPoint() if containing_func else None,
                        "callers": list(calling_functions)
                    }

    return shared_epilogues

def analyze_function_epilogue_issues(func):
    """Analyze a specific function for epilogue issues"""

    entry = func.getEntryPoint()
    body = func.getBody()

    issues = []

    # Check if function has jumps to addresses outside its body
    instr_iter = listing.getInstructions(body, True)

    for instr in instr_iter:
        mnemonic = instr.getMnemonicString()

        # Check conditional branches and jumps
        if mnemonic in ["beq", "bne", "bgtz", "blez", "bltz", "bgez", "j"]:
            refs = refManager.getReferencesFrom(instr.getAddress())
            for ref in refs:
                target = ref.getToAddress()

                # Is target outside this function's body?
                if not body.contains(target):
                    target_func = funcManager.getFunctionContaining(target)
                    if target_func and target_func != func:
                        # Jumping into another function!
                        issues.append({
                            "type": "jump_into_other_func",
                            "from": instr.getAddress(),
                            "to": target,
                            "target_func": target_func.getName(),
                            "instruction": str(instr)
                        })

    return issues

def main():
    print("=" * 70)
    print("SHARED EPILOGUE ANALYSIS")
    print("=" * 70)
    print("")

    # Check for current function
    current_addr = currentLocation.getAddress() if currentLocation else None

    if current_addr:
        func = funcManager.getFunctionContaining(current_addr)
        if func:
            print("Analyzing function: {} ({})".format(func.getName(), func.getEntryPoint()))
            print("")

            issues = analyze_function_epilogue_issues(func)

            if issues:
                print("Found {} potential epilogue issues:".format(len(issues)))
                for issue in issues:
                    print("")
                    print("  {} at {}".format(issue["type"], issue["from"]))
                    print("    Instruction: {}".format(issue["instruction"]))
                    print("    Target: {} (in {})".format(issue["to"], issue["target_func"]))
            else:
                print("No epilogue issues found in this function.")

            print("")
            print("-" * 70)
            print("")

    # Find all shared epilogues in the program
    print("Scanning for shared epilogues...")
    shared = find_shared_epilogues()

    if shared:
        print("\nFound {} shared epilogue(s):".format(len(shared)))

        for addr, info in shared.items():
            print("")
            print("  Epilogue at {}:".format(addr))
            print("    Range: {} to {}".format(info["start"], info["end"]))
            if info["containing_func"]:
                print("    Inside function: {}".format(
                    funcManager.getFunctionAt(info["containing_func"]).getName() if funcManager.getFunctionAt(info["containing_func"]) else info["containing_func"]))
            print("    Called from {} function(s):".format(len(info["callers"])))
            for caller in info["callers"][:5]:  # Show first 5
                caller_func = funcManager.getFunctionAt(caller)
                caller_name = caller_func.getName() if caller_func else str(caller)
                print("      - {} ({})".format(caller_name, caller))
            if len(info["callers"]) > 5:
                print("      ... and {} more".format(len(info["callers"]) - 5))
    else:
        print("No shared epilogues found.")

    print("")
    print("=" * 70)
    print("RECOMMENDATIONS")
    print("=" * 70)
    print("")
    print("For shared epilogues, you can:")
    print("1. Leave them as-is (functions jump to shared cleanup code)")
    print("2. Manually extend function bodies to include the epilogue")
    print("3. Create a shared 'epilogue thunk' function")
    print("")
    print("This is a common MIPS optimization and not necessarily a problem.")

if __name__ == "__main__":
    main()
