# Find Function Pointer XRefs Script

## Purpose

This Ghidra script automatically finds and creates references for functions that are called via function pointer tables. This fixes the common issue where functions show **zero xrefs** even though they're being called indirectly.

## Problem

Many functions in the Arika codebase are called via function pointer tables:
- `g_CharacterStateInitTable` (0x801d8354) - 38 state initialization functions
- `g_CharacterStateUpdateTable` (0x801d82c0) - 38 state update functions
- Character callback tables
- Jump tables

When functions are called via pointers, Ghidra's standard xref analysis doesn't find them because there's no direct `CALL` instruction - only a data reference to the function address.

## Solution

This script:
1. **Searches known function pointer tables** for function addresses
2. **Creates DATA references** from table entries to functions
3. **Makes references visible** in Ghidra's xref view

## Usage

### Option 1: Search for Currently Selected Function

1. Navigate to a function in Ghidra (or select a function)
2. Run the script: `Tools > References > Find Function Pointer XRefs`
3. The script will:
   - Search all known function pointer tables for this function
   - Create DATA references if found
   - Print results to console

### Option 2: Scan All Tables

1. Run the script without selecting a function
2. The script will:
   - Scan all known function pointer tables
   - Find all functions referenced in those tables
   - Create DATA references for all of them
   - Print summary statistics

## Known Function Pointer Tables

The script currently searches these tables:

| Table Name | Address | Entries | Description |
|------------|---------|---------|-------------|
| `g_CharacterStateInitTable` | 0x801d8354 | 38 | State initialization functions |
| `g_CharacterStateUpdateTable` | 0x801d82c0 | 38 | State update functions (per-frame) |

## Adding New Tables

To add more function pointer tables, edit the `FUNCTION_POINTER_TABLES` list in the script:

```python
FUNCTION_POINTER_TABLES = [
    {
        "name": "g_CharacterStateInitTable",
        "address": "0x801d8354",
        "entry_size": 4,  # 32-bit pointers
        "entry_count": 38,
        "description": "Character state initialization functions"
    },
    # Add more tables here...
]
```

## Output

The script prints:
- Which table(s) contain the function
- Table index (e.g., `g_CharacterStateUpdateTable[5]`)
- Whether references were created or already existed

Example output:
```
=== Searching for function: FUN_800a2ad0 (800a2ad0) ===
Searching g_CharacterStateInitTable (38 entries at 0x801d8354)...
Searching g_CharacterStateUpdateTable (38 entries at 0x801d82c0)...
  ✓ Created reference: g_CharacterStateUpdateTable[12] -> FUN_800a2ad0

=== Summary ===
Found function in 1 table(s):
  - g_CharacterStateUpdateTable[12]
```

## After Running

After running the script:
1. **Check xrefs**: Right-click function → `References > Show References to Address`
2. You should now see **DATA** references from the table entries
3. These references show where the function is stored in function pointer tables

## Limitations

- Only searches **known** function pointer tables (add more as discovered)
- Creates **DATA** references, not **CALL** references (because calls are indirect)
- Doesn't identify which dispatcher function calls the table (that requires manual analysis)

## Related Documentation

- **[Finding Function Pointers and Missing XRefs](../../docs/guides/FINDING_FUNCTION_POINTERS_AND_XREFS.md)** - Detailed explanation of the problem
- **[Phase 2 Checklist](../../docs/checklists/PHASE2_LARGE_FUNCTIONS_CHECKLIST.md)** - Functions being analyzed

## Future Enhancements

- [ ] Auto-detect function pointer tables by pattern
- [ ] Create CALL references by analyzing dispatcher functions
- [ ] Support variable-length tables
- [ ] Export results to CSV/JSON
- [ ] Batch process multiple functions



