PSX/MIPS Ghidra Scripts for Fighting Layer Analysis
===================================================

These scripts fix common issues with Ghidra's MIPS/PSX analysis.

ANALYSIS SCRIPTS (run these after initial auto-analysis)
-------------------------------------------------------

AggressiveMIPSDisassembly.py
  - MAIN SCRIPT - Run this first!
  - Finds computed jumps (jr $reg where reg != ra) and disassembles inline targets
  - Fixes undefined bytes after j/jal instructions
  - Disassembles code that branches/jumps reference but weren't followed
  - Creates functions at switch table targets

  Usage: Select a range, function, or run on entire program
  Menu: Tools > Analysis > Aggressive MIPS Disassembly

DisassembleSwitchTargets.py
  - Specifically targets switch statement inline jump tables
  - Analyzes jr patterns to find range (sltiu) and entry size
  - Disassembles and creates functions at each target

  Usage: Select a jr instruction or run to scan entire program
  Menu: Tools > Analysis > Disassemble Switch Targets

FixSharedEpilogues.py
  - Analyzes shared epilogue (tail-merge) optimization
  - Finds functions that jump to shared cleanup/return code
  - Reports which functions share epilogues

  Usage: Select a function or run to scan entire program
  Menu: Tools > Analysis > Fix Shared Epilogues

REFERENCE SCRIPTS
-----------------

FindFunctionPointerXrefs.py
  - Creates references for functions called via pointer tables
  - Fixes functions showing zero xrefs because they're called indirectly
  - Add known tables to FUNCTION_POINTER_TABLES list

  Menu: Tools > References > Find Function Pointer XRefs

DiscoverFunctionPointerTables.py
  - Scans memory regions for function pointer tables
  - Finds consecutive valid function addresses

  Menu: Tools > Analysis > Discover Function Pointer Tables

ReferenceMain.py
  - Redirects references to main memory addresses

  Menu: Tools > References > Reference Main

COMMON ISSUES THIS SOLVES
-------------------------

1. Undefined bytes (??) that should be code
   - Cause: Ghidra stops after computed jumps (jr v0, etc.)
   - Fix: Run AggressiveMIPSDisassembly.py

2. Switch statement targets showing as data
   - Cause: jr $reg doesn't tell Ghidra where execution goes
   - Fix: Run DisassembleSwitchTargets.py on the jr instruction

3. Functions showing 0 XREFs
   - Cause: Called via function pointer tables, not direct calls
   - Fix: Run FindFunctionPointerXrefs.py

4. Jumps to labels inside other functions
   - Cause: Shared epilogue optimization (tail merging)
   - Info: Run FixSharedEpilogues.py to analyze

5. DAT_XXXXXXXX that's actually code
   - Cause: Analysis stopped at conditional branches or jumps
   - Fix: Press 'D' to disassemble, or run AggressiveMIPSDisassembly.py

RECOMMENDED WORKFLOW
--------------------

1. Load PSX binary with ghidra_psx_ldr
2. Run Ghidra's auto-analysis
3. Run AggressiveMIPSDisassembly.py (entire program)
4. Run DiscoverFunctionPointerTables.py
5. Update FindFunctionPointerXrefs.py with discovered tables
6. Run FindFunctionPointerXrefs.py
7. Re-run Ghidra's auto-analysis
