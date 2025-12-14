# Quick Build Guide

## The Problem

Eclipse export isn't creating the ZIP file. This is common - Eclipse's GhidraDev export can be finicky.

## Solution: Use Gradle Directly

Since you have Gradle experience, build directly with Gradle instead of using Eclipse export.

### Windows (PowerShell)

```powershell
cd C:\dev\FL\ghidra_psx_ldr
$env:GHIDRA_INSTALL_DIR="C:\apps\ghidra"
gradle clean buildExtension
```

### Windows (CMD)

```cmd
cd C:\dev\FL\ghidra_psx_ldr
set GHIDRA_INSTALL_DIR=C:\apps\ghidra
gradle clean buildExtension
```

### Linux/WSL

```bash
cd /mnt/c/dev/FL/ghidra_psx_ldr
export GHIDRA_INSTALL_DIR=/mnt/c/apps/ghidra
gradle clean buildExtension
```

## After Build

Check for the ZIP file:
- `dist/Psx.zip` (or similar)
- Should be several MB in size

## Install in Ghidra

1. Open Ghidra
2. **File → Install Extensions...**
3. Click **+** button
4. Select the `.zip` from `dist/` directory
5. Restart Ghidra

## Why Eclipse Export Might Fail

1. Gradle not configured in Eclipse
2. GHIDRA_INSTALL_DIR not set in Eclipse environment
3. Export process silently failing
4. Build errors not shown in Eclipse

**Solution**: Use Gradle command line - it's more reliable and shows clear error messages.







