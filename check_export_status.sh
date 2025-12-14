#!/bin/bash
# Check if extension was built and where the ZIP file is

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Checking for built extension..."
echo ""

# Check common locations
FOUND=0

if [ -d "dist" ]; then
    echo "✓ Found dist/ directory:"
    ls -lh dist/*.zip 2>/dev/null && FOUND=1 || echo "  (No ZIP files in dist/)"
    echo ""
fi

if [ -d "build/distributions" ]; then
    echo "✓ Found build/distributions/ directory:"
    ls -lh build/distributions/*.zip 2>/dev/null && FOUND=1 || echo "  (No ZIP files in build/distributions/)"
    echo ""
fi

# Search for any ZIP files
ZIP_FILES=$(find . -maxdepth 3 -name "*.zip" -type f 2>/dev/null)
if [ -n "$ZIP_FILES" ]; then
    echo "✓ Found ZIP files:"
    echo "$ZIP_FILES" | while read -r zip; do
        ls -lh "$zip"
    done
    FOUND=1
    echo ""
fi

if [ $FOUND -eq 0 ]; then
    echo "✗ No extension ZIP file found."
    echo ""
    echo "To build the extension, run:"
    echo "  ./build_extension.sh"
    echo ""
    echo "Or manually:"
    echo "  export GHIDRA_INSTALL_DIR=/path/to/ghidra"
    echo "  gradle buildExtension"
fi







