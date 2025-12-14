# Function Detection Fix: Code Marked as Data

## Problem

Addresses like `0x800af3f8` contain valid MIPS instructions but are marked as data (DAT_ labels). When you press 'd' (disassemble), they show valid code, but Function Start Search analyzer doesn't find them because it only searches in code regions, not data regions.

## Root Cause

1. **Function Start Search analyzer only searches code regions** - If an address is marked as data, it won't be analyzed
2. **PSX loader doesn't clear data in code regions** - When code is incorrectly marked as data, it stays that way
3. **No explicit Function Start Search configuration** - The loader doesn't ensure Function Start Search is enabled/configured properly

## Solution Options

### Option 1: Enable Function Start Search Explicitly (Quick Fix)

Add to `PsxLoader.java` after line 271:

```java
// Ensure Function Start Search analyzer is enabled
// This analyzer finds function entry points by looking for common patterns
try {
    aOpts.setBoolean("Function Start Search", true);
    log.appendMsg("Enabled Function Start Search analyzer");
} catch (IllegalArgumentException e) {
    // Try alternative name
    try {
        aOpts.setBoolean("Function Start Analyzer", true);
    } catch (IllegalArgumentException e2) {
        log.appendMsg("Warning: Could not enable Function Start Search - functions may be missed");
    }
}
```

### Option 2: Clear Data in Code Regions Before Analysis (Better Fix)

Add a method to clear data that looks like code before analysis runs:

```java
private void clearDataInCodeRegions(Program program, MessageLog log) {
    // This would need to be called before auto-analysis
    // It would scan memory and clear data that looks like valid MIPS instructions
    // This is complex and may have false positives
}
```

### Option 3: Post-Analysis Function Creation Script (Recommended)

Create a Ghidra script that:
1. Finds addresses referenced by `jal`/`jalr` instructions
2. Checks if they're marked as data
3. If they contain valid MIPS instructions, clears the data and creates functions

## Immediate Workaround

For now, manually create functions at these addresses:
- `0x800af3f8` ✅ (already created via MCP)
- `0x800af3fc` ✅ (already created via MCP)
- `0x800af408` ✅ (already created via MCP)
- `0x800af40c` ✅ (already created via MCP)
- `0x800af414` ✅ (already created via MCP)

Or use GhidraMCP to batch create:
```python
# Find all addresses referenced by jal/jalr that are marked as data
# Then create functions at those addresses
```

## Long-term Fix

The loader should:
1. **Explicitly enable Function Start Search** analyzer
2. **Clear data in regions that look like code** before analysis
3. **Post-process after analysis** to find missed functions (addresses referenced by calls but not marked as functions)

