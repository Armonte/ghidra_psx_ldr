#!/bin/bash
# Build Ghidra Extension using Gradle
# This script builds the extension and creates the dist/zip file

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check for GHIDRA_INSTALL_DIR
if [ -z "$GHIDRA_INSTALL_DIR" ]; then
    echo "Error: GHIDRA_INSTALL_DIR environment variable not set"
    echo ""
    echo "Please set it to your Ghidra installation directory:"
    echo "  export GHIDRA_INSTALL_DIR=/path/to/ghidra"
    echo ""
    echo "Or on Windows (PowerShell):"
    echo "  \$env:GHIDRA_INSTALL_DIR=\"C:\\apps\\ghidra\""
    echo ""
    echo "Or on Windows (CMD):"
    echo "  set GHIDRA_INSTALL_DIR=C:\\apps\\ghidra"
    exit 1
fi

# Check if Ghidra directory exists
if [ ! -d "$GHIDRA_INSTALL_DIR" ]; then
    echo "Error: Ghidra directory not found: $GHIDRA_INSTALL_DIR"
    exit 1
fi

echo "Building Ghidra extension..."
echo "Ghidra Install Dir: $GHIDRA_INSTALL_DIR"
echo ""

# Check for Gradle
if command -v gradle &> /dev/null; then
    GRADLE_CMD="gradle"
elif [ -f "gradlew" ]; then
    GRADLE_CMD="./gradlew"
    chmod +x gradlew
else
    echo "Error: Gradle not found. Please install Gradle or use gradlew wrapper."
    exit 1
fi

# Build the extension
echo "Running: $GRADLE_CMD buildExtension"
$GRADLE_CMD buildExtension

# Check for output
if [ -d "dist" ]; then
    echo ""
    echo "✓ Build successful! Extension ZIP should be in: dist/"
    ls -lh dist/*.zip 2>/dev/null || echo "  (No ZIP files found in dist/)"
elif [ -d "build/distributions" ]; then
    echo ""
    echo "✓ Build successful! Extension ZIP should be in: build/distributions/"
    ls -lh build/distributions/*.zip 2>/dev/null || echo "  (No ZIP files found in build/distributions/)"
else
    echo ""
    echo "⚠ Build completed, but no dist/ or build/distributions/ directory found."
    echo "  Check the build output above for errors."
fi







