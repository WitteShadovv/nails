#!/usr/bin/env bash
# NAILS Build System - Creates portable distribution formats
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/dist"
VERSION=$(grep '^version.*=' pyproject.toml | head -n1 | sed 's/.*"\(.*\)".*/\1/')

echo "🔨 NAILS Build System v$VERSION"
echo "================================"
echo "Creating portable packages for hidden volume deployment..."

# Clean previous builds
rm -rf "$BUILD_DIR" build/ *.egg-info/
mkdir -p "$BUILD_DIR"

# 1. Create standalone executable with PyInstaller
echo ""
echo "🔧 Building standalone executable..."

# Check for required system dependencies
if ! command -v objdump >/dev/null 2>&1; then
    echo "❌ Missing system dependency: objdump (binutils)"
    echo "   On NixOS, install with:"
    echo "   nix-env -iA nixos.binutils"
    echo "   Or add 'binutils' to your system configuration"
    exit 1
fi

# Check if PyInstaller is available
if ! command -v pyinstaller >/dev/null 2>&1; then
    echo "❌ PyInstaller not found"
    echo "   Install build dependencies with:"
    echo "   pip install -e .[build]"
    exit 1
fi

pyinstaller --onefile \
    --name "nails" \
    --distpath "$BUILD_DIR/" \
    --workpath "build/pyinstaller/" \
    --specpath "build/" \
    --hidden-import "nails.manager" \
    --hidden-import "nails.overlay" \
    --hidden-import "nails.config" \
    --hidden-import "nails.nixos" \
    --hidden-import "nails.state" \
    --hidden-import "nails.exceptions" \
    --paths "." \
    --console \
    --clean \
    nails.py

if [[ $? -eq 0 ]]; then
    echo "✓ Standalone executable: $BUILD_DIR/nails"
else
    echo "❌ PyInstaller build failed"
    exit 1
fi

# 2. Create single-file Python script (for maximum portability)
echo ""
echo "🐍 Creating single-file Python script..."
SINGLE_FILE="$BUILD_DIR/nails-standalone.py"

# Create the standalone Python file by combining all modules
cat > "$SINGLE_FILE" << 'STANDALONE_EOF'
#!/usr/bin/env python3
"""
NAILS - NixOS Anti-forensics Isolation & Layering System
Single-file standalone version - no installation required

Copy this file to your VeraCrypt hidden volume and run directly.
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

# Embedded modules start here
STANDALONE_EOF

# Append all the module contents
for module in "exceptions.py" "state.py" "config.py" "overlay.py" "nixos.py" "manager.py"; do
    if [[ -f "nails/$module" ]]; then
        echo "" >> "$SINGLE_FILE"
        echo "# === $module ===" >> "$SINGLE_FILE"
        # Skip the imports and add the class/function definitions
        sed '/^import /d; /^from /d' "nails/$module" >> "$SINGLE_FILE"
    fi
done

# Add the main entry point
cat >> "$SINGLE_FILE" << 'MAIN_EOF'

# Main entry point
def main():
    parser = argparse.ArgumentParser(
        description="NAILS - NixOS Anti-forensics using Safe Overlay System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 nails-standalone.py init                 # Initialize hidden config
  sudo python3 nails-standalone.py activate        # Activate hidden environment
  sudo python3 nails-standalone.py deactivate      # Return to decoy system
  sudo python3 nails-standalone.py rebuild         # Rebuild with current hidden config
  python3 nails-standalone.py status               # Show current status
  sudo python3 nails-standalone.py emergency-clean # Emergency restore to decoy

Safe Overlay Mode:
✓ Completely untraceable using overlay filesystems
✓ All state stored in hidden volume (untraceable when unmounted)
✓ Emergency cleanup always available
✓ Maintains 100% plausible deniability
        """
    )

    parser.add_argument("command", choices=[
        "init", "activate", "deactivate", "rebuild", "status", "emergency-clean"
    ])
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--version", action="version", version="NAILS 1.0.0")

    args = parser.parse_args()

    # Initialize NAILS manager
    try:
        manager = NailsManager(verbose=args.verbose)

        # Execute the requested command
        if args.command == "init":
            manager.init()
        elif args.command == "activate":
            manager.activate()
        elif args.command == "deactivate":
            manager.deactivate()
        elif args.command == "rebuild":
            manager.rebuild()
        elif args.command == "status":
            manager.status()
        elif args.command == "emergency-clean":
            manager.emergency_clean()

    except KeyboardInterrupt:
        print("\nOperation cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"NAILS Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
MAIN_EOF

chmod +x "$SINGLE_FILE"
echo "✓ Single-file Python script: $BUILD_DIR/nails-standalone.py"

# 3. Create AppImage (if tools available)
echo ""
echo "📱 Creating AppImage..."
if command -v python3-appimage >/dev/null 2>&1; then
    # Use python3-appimage for a more reliable AppImage
    python3-appimage build app \
        --python-version 3.12 \
        --name "NAILS" \
        --entry-point "nails:main" \
        --icon "nails.png" \
        --output-dir "$BUILD_DIR/" \
        .
    echo "✓ AppImage: $BUILD_DIR/NAILS-$VERSION-x86_64.AppImage"
elif command -v appimagetool >/dev/null 2>&1; then
    # Manual AppImage creation
    APPDIR="$BUILD_DIR/NAILS.AppDir"
    mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/lib/python3/site-packages"

    # Create AppDir structure
    cp nails.py "$APPDIR/usr/bin/nails"
    cp -r nails/ "$APPDIR/usr/lib/python3/site-packages/"
    chmod +x "$APPDIR/usr/bin/nails"

    # Create desktop file
    cat > "$APPDIR/nails.desktop" << EOF
[Desktop Entry]
Type=Application
Name=NAILS
Comment=NixOS Anti-forensics Isolation & Layering System
Icon=nails
Exec=nails
Categories=System;Security;
Terminal=true
MimeType=application/x-nails;
EOF

    # Create simple icon (placeholder)
    cat > "$APPDIR/nails.png" << 'EOF'
iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==
EOF

    # Create AppRun
    cat > "$APPDIR/AppRun" << 'EOF'
#!/bin/bash
SELF=$(readlink -f "$0")
HERE=${SELF%/*}
export PATH="${HERE}/usr/bin:${PATH}"
export PYTHONPATH="${HERE}/usr/lib/python3/site-packages:${PYTHONPATH:-}"
cd "${HERE}"
exec python3 "${HERE}/usr/bin/nails" "$@"
EOF
    chmod +x "$APPDIR/AppRun"

    # Build AppImage
    appimagetool "$APPDIR" "$BUILD_DIR/NAILS-$VERSION-x86_64.AppImage"
    rm -rf "$APPDIR"
    echo "✓ AppImage: $BUILD_DIR/NAILS-$VERSION-x86_64.AppImage"
else
    echo "⚠️  AppImage tools not found - skipping AppImage build"
    echo "   Install with: pip install python3-appimage"
    echo "   Or: apt install appimagetool (manual method)"
fi

# 4. Create verification checksums
echo ""
echo "🔐 Creating checksums..."
cd "$BUILD_DIR"
find . -maxdepth 1 -type f \( -name "nails" -o -name "nails-standalone.py" -o -name "*.AppImage" \) -exec sha256sum {} \; > checksums.txt
cd "$SCRIPT_DIR"

echo "✓ Checksums: $BUILD_DIR/checksums.txt"

# 5. Create deployment instructions
cat > "$BUILD_DIR/README.txt" << EOF
NAILS - Portable Distribution
============================

This package contains portable versions of NAILS designed for use in VeraCrypt hidden volumes.

Files:
------
• nails                       - Standalone executable (no dependencies)
• nails-standalone.py         - Single-file Python script (requires Python 3.12+)
• NAILS-$VERSION-x86_64.AppImage - AppImage (if available)
• checksums.txt              - SHA256 verification checksums

Usage Options:
-------------

Option 1 - Standalone Executable (recommended):
1. Copy 'nails' to your VeraCrypt hidden volume
2. Make it executable: chmod +x nails
3. Run: ./nails init

Option 2 - Python Script (maximum compatibility):
1. Copy 'nails-standalone.py' to your VeraCrypt hidden volume
2. Make it executable: chmod +x nails-standalone.py
3. Run: python3 nails-standalone.py init
   Or: ./nails-standalone.py init

Commands:
--------
./nails init                    # Initialize hidden environment
sudo ./nails activate           # Activate hidden environment
sudo ./nails deactivate         # Return to decoy state
sudo ./nails rebuild            # Apply configuration changes
./nails status                  # Check current status
sudo ./nails emergency-clean    # Emergency cleanup

Security Notes:
--------------
• NEVER install NAILS system-wide - this defeats the purpose
• ONLY run from within a VeraCrypt hidden volume
• Always deactivate before unmounting the hidden volume
• Both files contain no installation traces

Verification:
------------
Verify file integrity with: sha256sum -c checksums.txt
EOF

# Summary
echo ""
echo "🎉 Build Complete!"
echo "=================="
echo "Portable packages created in $BUILD_DIR:"
echo ""
echo "🔧 Standalone Executable (recommended):"
echo "   $BUILD_DIR/nails"
echo "   • Copy to hidden volume and run directly"
echo "   • No dependencies, no installation needed"
echo "   • Zero system traces"
echo ""
echo "🐍 Single-file Python Script (maximum portability):"
echo "   $BUILD_DIR/nails-standalone.py"
echo "   • Requires only Python 3.12+"
echo "   • All modules embedded in one file"
echo "   • Run with: python3 nails-standalone.py <command>"
echo ""
if [[ -f "$BUILD_DIR/NAILS-$VERSION-x86_64.AppImage" ]]; then
    echo "📱 AppImage:"
    echo "   $BUILD_DIR/NAILS-$VERSION-x86_64.AppImage"
    echo "   • Portable Linux application"
    echo "   • Run anywhere with: chmod +x && ./NAILS-*.AppImage"
    echo ""
fi
echo "🔐 All checksums: $BUILD_DIR/checksums.txt"
echo "📋 Instructions: $BUILD_DIR/README.txt"
echo ""
echo "🛡️  Security Reminder:"
echo "   • Use only in VeraCrypt hidden volumes"
echo "   • Never install system-wide"
echo "   • Verify checksums before use"
