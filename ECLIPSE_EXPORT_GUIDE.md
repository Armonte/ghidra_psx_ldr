# Eclipse Export Guide for Ghidra Extension

## Why Eclipse Export Might Not Work

Eclipse's GhidraDev export relies on Gradle to build the extension. If the export isn't creating a ZIP file, it's usually because:

1. **Gradle not configured properly** - Eclipse needs access to Gradle
2. **GHIDRA_INSTALL_DIR not set** - Required for the build
3. **Build errors** - Check the Problems view for compilation errors
4. **Export process not completing** - Check Console for error messages

## Step-by-Step Export Process

### 1. Verify Project Builds Successfully

1. Right-click project → **Project → Clean...**
2. Select your project → **Clean**
3. Check **Problems** view - should have no errors (warnings are OK)

### 2. Set GHIDRA_INSTALL_DIR (if needed)

If Gradle build fails, you may need to set this in Eclipse:

1. **Window → Preferences → Java → Build Path → Classpath Variables**
2. Add variable: `GHIDRA_INSTALL_DIR` = `C:\apps\ghidra` (or your path)

Or set as environment variable before starting Eclipse.

### 3. Export Extension

1. Right-click project → **GhidraDev → Export → Ghidra Module Extension...**
2. Select your project
3. Click **Finish**

### 4. Check Output Location

The ZIP should be created in:
- `dist/` directory in your project root
- Or check the Console output for the actual path

### 5. If Export Still Fails

Try manual Gradle build instead (see `build_extension.sh` or `manual_gradle_build.md`)

## Alternative: Use Gradle Directly

If Eclipse export continues to fail, use Gradle directly:

### Windows (PowerShell)
```powershell
cd C:\dev\FL\ghidra_psx_ldr
$env:GHIDRA_INSTALL_DIR="C:\apps\ghidra"
gradle buildExtension
```

### Windows (CMD)
```cmd
cd C:\dev\FL\ghidra_psx_ldr
set GHIDRA_INSTALL_DIR=C:\apps\ghidra
gradle buildExtension
```

### Linux/WSL
```bash
cd /mnt/c/dev/FL/ghidra_psx_ldr
export GHIDRA_INSTALL_DIR=/mnt/c/apps/ghidra
gradle buildExtension
```

## What to Look For

After successful build:
- `dist/Psx.zip` (or similar name)
- File should be several MB in size
- Contains: `ExtensionModule.manifest`, compiled classes, resources

## Installing the Extension

1. Open Ghidra
2. **File → Install Extensions...**
3. Click **+** button
4. Select the `.zip` file from `dist/` directory
5. Restart Ghidra

## Troubleshooting

### "GHIDRA_INSTALL_DIR is not defined!"
- Set the environment variable before running Gradle
- Or pass as property: `gradle -PGHIDRA_INSTALL_DIR=C:\apps\ghidra buildExtension`

### "Gradle not found"
- Install Gradle: https://gradle.org/install/
- Or use the Gradle wrapper if available
- Or check if Ghidra includes Gradle in its installation

### Export completes but no ZIP file
- Check Console output for actual file location
- Check `dist/` and `build/distributions/` directories
- Look for any error messages in the build output







