#!/bin/bash
# Quick build script for Ghidra PSX Loader
# Just run: ./build.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Auto-detect Ghidra if not set
if [ -z "$GHIDRA_INSTALL_DIR" ]; then
    # Try common locations
    for dir in /mnt/c/apps/ghidra /mnt/c/Program\ Files/ghidra* /opt/ghidra* ~/ghidra*; do
        if [ -d "$dir" ] && [ -f "$dir/support/buildExtension.gradle" ]; then
            export GHIDRA_INSTALL_DIR="$dir"
            echo "Auto-detected Ghidra: $GHIDRA_INSTALL_DIR"
            break
        fi
    done
fi

# Check for GHIDRA_INSTALL_DIR
if [ -z "$GHIDRA_INSTALL_DIR" ]; then
    echo "Error: GHIDRA_INSTALL_DIR not set and auto-detection failed"
    echo ""
    echo "Please set it:"
    echo "  export GHIDRA_INSTALL_DIR=/path/to/ghidra"
    echo ""
    echo "Or edit this script to add your Ghidra path"
    exit 1
fi

# Check if Ghidra directory exists
if [ ! -d "$GHIDRA_INSTALL_DIR" ]; then
    echo "Error: Ghidra directory not found: $GHIDRA_INSTALL_DIR"
    exit 1
fi

echo "=========================================="
echo "Building Ghidra PSX Loader Extension"
echo "=========================================="
echo "Ghidra: $GHIDRA_INSTALL_DIR"
echo ""

# Check for Gradle
if command -v gradle &> /dev/null; then
    GRADLE_CMD="gradle"
elif [ -f "gradlew" ]; then
    GRADLE_CMD="./gradlew"
    chmod +x gradlew 2>/dev/null || true
else
    echo "Error: Gradle not found. Please install Gradle."
    exit 1
fi

# Clean and build
echo "Running: $GRADLE_CMD clean buildExtension"
echo ""
$GRADLE_CMD clean buildExtension

# Check for output
echo ""
echo "=========================================="
if [ -d "dist" ] && ls dist/*.zip 1> /dev/null 2>&1; then
    echo "✓ Build successful!"
    echo ""
    echo "Extension ZIP:"
    ls -lh dist/*.zip
elif [ -d "build/distributions" ] && ls build/distributions/*.zip 1> /dev/null 2>&1; then
    echo "✓ Build successful!"
    echo ""
    echo "Extension ZIP:"
    ls -lh build/distributions/*.zip
else
    echo "⚠ Build completed, but no ZIP file found."
    echo "  Check the output above for errors."
fi
echo "=========================================="






