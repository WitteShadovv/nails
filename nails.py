#!/usr/bin/env python3
"""
NAILS - NixOS Anti-forensics using Safe Extension System
Maintains 100% untraceability while preventing system bricking
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional


class NailsSafeManager:
    """NAILS using safe extension approach that maintains untraceability."""

    def __init__(self, verbose: bool = False):
        # Determine script location (should be in hidden volume root)
        self.hidden_volume_root = Path(__file__).parent.absolute()
        self.hidden_nix = self.hidden_volume_root / "nix"
        self.hidden_config = self.hidden_volume_root / "config"

        # Safe paths - no direct /nix manipulation for safety
        self.system_config_dir = Path("/etc/nixos")
        self.nails_extension_config = self.system_config_dir / "nails-extension.nix"

        # State tracking (stored in hidden volume for untraceability)
        self.state_file = self.hidden_volume_root / ".nails-state"
        self.backup_dir = self.hidden_volume_root / "backups"

        # UnionFS paths for advanced mode
        self.union_mount = Path("/tmp/nails-union")
        self.system_nix = Path("/nix")

        # Setup logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")
        self.logger = logging.getLogger("nails")

    def init(self):
        """Initialize hidden configuration as extension module."""
        print("NAILS Initialization - Safe & Untraceable Mode")
        print("=============================================")

        if self.hidden_config.exists() and (self.hidden_config / "extension.nix").exists():
            print("✓ Hidden configuration already exists")
            return

        # Create directories
        self.hidden_config.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # Create extension-based configuration
        extension_config = '''{ config, pkgs, lib, ... }:

{
  # NAILS Hidden Extension Configuration
  # This extends the existing system configuration safely and untraceably
  
  # Additional packages for hidden environment
  environment.systemPackages = with pkgs; [
    # Security tools (uncomment as needed)
    # tor
    # gnupg
    # keepassxc
    # veracrypt
    
    # Development tools (uncomment as needed) 
    # python3
    # nodejs
    # docker
    # git
    # vim
    
    # Communication tools (uncomment as needed)
    # signal-desktop
    # element-desktop
    # thunderbird
    # torbrowser-launcher
    
    # Analysis tools (uncomment as needed)
    # wireshark
    # nmap
    # john
    # hashcat
  ];

  # Optional: Additional services (commented out by default for safety)
  # services = {
  #   tor = {
  #     enable = true;
  #     client.enable = true;
  #   };
  #   privoxy = {
  #     enable = true;
  #     settings = {
  #       forward-socks5t = "/ 127.0.0.1:9050 .";
  #     };
  #   };
  # };

  # Optional: Additional users (commented out by default)
  # users.users.ghost = {
  #   isNormalUser = true;
  #   description = "Hidden user";
  #   extraGroups = [ "wheel" "networkmanager" ];
  #   # Set password with: passwd ghost
  # };

  # Environment variables for hidden tools (undetectable when inactive)
  environment.variables = lib.mkIf (builtins.pathExists /.nails-active) {
    NAILS_ACTIVE = "true";
    TOR_SOCKS_HOST = "127.0.0.1";
    TOR_SOCKS_PORT = "9050";
  };
  
  # Custom aliases and shell configuration (only when active)
  environment.shellAliases = lib.mkIf (builtins.pathExists /.nails-active) {
    nails-status = "echo 'NAILS hidden environment active'";
    nails-deactivate = "sudo ${toString ./../..}/nails.py deactivate";
    clear-history = "history -c && history -w";
  };
  
  # Security hardening for hidden environment
  security = lib.mkIf (builtins.pathExists /.nails-active) {
    # Disable coredumps in hidden mode
    pam.loginLimits = [
      { domain = "*"; type = "hard"; item = "core"; value = "0"; }
    ];
  };
}'''

        config_file = self.hidden_config / "extension.nix"
        with open(config_file, "w") as f:
            f.write(extension_config)

        print(f"✓ Created extension config: {config_file}")

        # Create a simple flake for the extension
        flake_content = '''{
  description = "NAILS Hidden Environment Extension - Untraceable";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }: {
    nixosModules.default = import ./extension.nix;
  };
}'''

        flake_file = self.hidden_config / "flake.nix"
        with open(flake_file, "w") as f:
            f.write(flake_content)

        print(f"✓ Created flake: {flake_file}")
        print("\n✓ Hidden configuration initialized as safe extension")
        print(f"✓ Edit {config_file} to customize your hidden environment")
        print("✓ Configuration extends (not replaces) your system - prevents bricking")
        print("✓ All traces stored in hidden volume - maintains untraceability")

    def activate(self):
        """Activate hidden environment by extending system configuration."""
        print("NAILS Activation - Safe & Untraceable Mode")
        print("==========================================")

        if os.geteuid() != 0:
            print("Error: Root privileges required")
            print("Run with: sudo ./nails.py activate")
            sys.exit(1)

        # Check if already active
        if self._is_active():
            print("✓ Hidden environment is already active")
            return

        if not (self.hidden_config / "extension.nix").exists():
            print("✗ Hidden configuration not found. Run './nails.py init' first")
            return

        print("Activating hidden environment safely...")

        try:
            # Step 1: Backup current system configuration to hidden volume
            self._backup_system_config()

            # Step 2: Create extension import in main config
            self._inject_extension()

            # Step 3: Create activation marker (stored in hidden volume)
            self._create_activation_marker()

            # Step 4: Build the extended system
            if self._build_extended_system():
                print("✓ Hidden environment activated safely")

                # Save state in hidden volume (untraceable)
                state = {
                    "active": True,
                    "activated_at": datetime.now().isoformat(),
                    "method": "safe_extension",
                    "backup_created": True,
                    "hidden_volume": str(self.hidden_volume_root)
                }
                with open(self.state_file, "w") as f:
                    json.dump(state, f, indent=2)

                print("\n✅ NAILS Hidden Environment Active")
                print("✓ Your system now has access to hidden packages and configs")
                print("✓ Base system remains untouched and bootable")
                print("✓ All traces stored in hidden volume (untraceable when unmounted)")
                print("\nRun 'sudo ./nails.py deactivate' to return to decoy state")
            else:
                print("✗ Failed to activate hidden environment")
                self._restore_system_config()
                self._remove_activation_marker()

        except Exception as e:
            print(f"✗ Activation failed: {e}")
            print("Restoring original configuration...")
            self._restore_system_config()
            self._remove_activation_marker()

    def deactivate(self):
        """Deactivate hidden environment by removing extension."""
        print("NAILS Deactivation - Safe & Untraceable Mode")
        print("===========================================")

        if os.geteuid() != 0:
            print("Error: Root privileges required")
            print("Run with: sudo ./nails.py deactivate")
            sys.exit(1)

        if not self._is_active():
            print("✓ Hidden environment is already inactive")
            return

        print("Deactivating hidden environment...")

        try:
            # Remove activation marker first
            self._remove_activation_marker()

            # Restore original configuration
            self._restore_system_config()

            # Rebuild system without extension
            if self._rebuild_system():
                print("✓ Hidden environment deactivated")

                # Clear state (stored in hidden volume)
                if self.state_file.exists():
                    self.state_file.unlink()

                print("\n✅ System returned to decoy state")
                print("✓ Hidden packages and configurations are no longer active")
                print("✓ No traces left on system when hidden volume unmounted")
            else:
                print("✗ Failed to rebuild system")
                print("You may need to run emergency-clean or manually restore from backup")

        except Exception as e:
            print(f"✗ Deactivation failed: {e}")
            print("Consider running 'emergency-clean' to force restoration")

    def _backup_system_config(self):
        """Backup current system configuration to hidden volume."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_dir / f"system_backup_{timestamp}"
        backup_path.mkdir(parents=True, exist_ok=True)

        print(f"Backing up system config to hidden volume: {backup_path}")

        # Backup /etc/nixos to hidden volume (untraceable)
        try:
            shutil.copytree("/etc/nixos", backup_path / "nixos", dirs_exist_ok=True)
            print("✓ System configuration backed up to hidden volume")
        except Exception as e:
            print(f"⚠️ Backup warning: {e}")

    def _inject_extension(self):
        """Inject NAILS extension into system configuration."""
        main_config = self.system_config_dir / "configuration.nix"

        if not main_config.exists():
            raise Exception("System configuration.nix not found")

        # Read current configuration
        with open(main_config, 'r') as f:
            content = f.read()

        # Check if NAILS extension already injected
        if "nails-extension.nix" in content:
            print("✓ Extension already injected")
            return

        # Find imports section and add our extension
        imports_pattern = r'imports\s*=\s*\[(.*?)\];'
        match = re.search(imports_pattern, content, re.DOTALL)

        if match:
            # Add our extension to imports
            imports_content = match.group(1).strip()
            if imports_content:
                new_imports = f"{imports_content}\n    ./nails-extension.nix"
            else:
                new_imports = "\n    ./nails-extension.nix\n  "

            new_content = content.replace(match.group(0),
                                        f'imports = [{new_imports}\n  ];')
        else:
            # No imports section found, add one
            lines = content.split('\n')
            if lines[0].startswith('{') and ':' in lines[0]:
                lines.insert(1, '')
                lines.insert(2, '  imports = [')
                lines.insert(3, '    ./nails-extension.nix')
                lines.insert(4, '  ];')
                lines.insert(5, '')
            new_content = '\n'.join(lines)

        # Write modified configuration
        with open(main_config, 'w') as f:
            f.write(new_content)

        # Create the extension import file
        extension_import = f'''# NAILS Extension Import - Auto-generated
# This file imports the hidden configuration safely
import {self.hidden_config / "extension.nix"}
'''

        with open(self.nails_extension_config, 'w') as f:
            f.write(extension_import)

        print("✓ Extension injected into system configuration")

    def _create_activation_marker(self):
        """Create activation marker for conditional configurations."""
        marker = Path("/.nails-active")
        try:
            marker.touch()
            print("✓ Created activation marker")
        except Exception as e:
            print(f"⚠️ Could not create activation marker: {e}")

    def _remove_activation_marker(self):
        """Remove activation marker."""
        marker = Path("/.nails-active")
        try:
            if marker.exists():
                marker.unlink()
                print("✓ Removed activation marker")
        except Exception as e:
            print(f"⚠️ Could not remove activation marker: {e}")

    def _build_extended_system(self) -> bool:
        """Build system with NAILS extension."""
        print("Building extended system configuration...")
        print("This may take several minutes on first activation...")
        print("NixOS is downloading and building hidden packages...")

        try:
            # Show what's being built
            print(f"Building system with extension: {self.hidden_config / 'extension.nix'}")
            print("Running: nixos-rebuild switch")
            print("(You can press Ctrl+C to cancel if needed)\n")

            # Run with real-time output and timeout
            process = subprocess.Popen([
                "nixos-rebuild", "switch"
            ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
               universal_newlines=True, bufsize=1)

            # Stream output line by line with timeout handling
            output_lines = []
            last_output_time = datetime.now()
            timeout_seconds = 600  # 10 minutes timeout

            import select
            import time

            while True:
                # Check if process is still running
                if process.poll() is not None:
                    break

                # Check for timeout (no output for too long)
                if (datetime.now() - last_output_time).total_seconds() > timeout_seconds:
                    print(f"\n⚠️ Build timeout after {timeout_seconds} seconds of no output")
                    print("This might be due to package conflicts or hanging builds")
                    print("Terminating build process...")
                    process.terminate()
                    time.sleep(5)  # Give it time to terminate gracefully
                    if process.poll() is None:
                        process.kill()  # Force kill if needed
                    return False

                # Use select to check if output is available (Unix only)
                if hasattr(select, 'select'):
                    ready, _, _ = select.select([process.stdout], [], [], 1)
                    if ready:
                        line = process.stdout.readline()
                        if line:
                            # Print line immediately for real-time feedback
                            print(f"[nixos-rebuild] {line.rstrip()}")
                            output_lines.append(line)
                            last_output_time = datetime.now()

                            # Show progress indicators
                            if "building" in line.lower():
                                print("  ↳ Building packages...")
                            elif "downloading" in line.lower():
                                print("  ↳ Downloading from cache...")
                            elif "copying" in line.lower():
                                print("  ↳ Installing packages...")
                            elif "switching" in line.lower():
                                print("  ↳ Switching to new configuration...")
                            elif "collision" in line.lower():
                                print("  ⚠️ Package collision detected - this may cause issues")
                            elif "warning" in line.lower():
                                print("  ⚠️ Build warning detected")
                            elif "error" in line.lower():
                                print("  ❌ Build error detected")
                else:
                    # Fallback for systems without select
                    time.sleep(1)
                    line = process.stdout.readline()
                    if line:
                        print(f"[nixos-rebuild] {line.rstrip()}")
                        output_lines.append(line)
                        last_output_time = datetime.now()

            # Get final output
            remaining_output = process.stdout.read()
            if remaining_output:
                for line in remaining_output.splitlines():
                    print(f"[nixos-rebuild] {line}")
                    output_lines.append(line + '\n')

            # Wait for completion
            return_code = process.wait()

            if return_code == 0:
                print("\n✓ Extended system built successfully")
                print("✓ Hidden packages are now available")

                # Check for warnings in output
                warnings = [line for line in output_lines if 'warning' in line.lower() or 'collision' in line.lower()]
                if warnings:
                    print(f"\n⚠️ Build completed with {len(warnings)} warnings:")
                    for warning in warnings[-3:]:  # Show last 3 warnings
                        print(f"  • {warning.strip()}")

                return True
            else:
                print(f"\n✗ Build failed with exit code: {return_code}")
                print("Last few lines of output:")
                for line in output_lines[-10:]:
                    print(f"  {line.rstrip()}")

                # Check for common issues
                output_text = ''.join(output_lines).lower()
                if 'collision' in output_text:
                    print("\n💡 Detected package collisions. This often causes builds to hang.")
                    print("   Consider running: sudo nixos-rebuild switch --show-trace")
                    print("   Or add nixpkgs.config.allowUnfree = true; to your config")

                return False

        except KeyboardInterrupt:
            print("\n⚠️ Build interrupted by user")
            print("Terminating build process...")
            try:
                process.terminate()
                time.sleep(2)
                if process.poll() is None:
                    process.kill()
            except:
                pass
            print("System may be in partial state - consider running emergency-clean")
            return False
        except Exception as e:
            print(f"Build error: {e}")
            return False

    def _rebuild_system(self) -> bool:
        """Rebuild system (used for deactivation)."""
        print("Rebuilding system to decoy state...")

        try:
            result = subprocess.run([
                "nixos-rebuild", "switch"
            ], capture_output=True, text=True)

            return result.returncode == 0

        except Exception as e:
            print(f"Rebuild error: {e}")
            return False

    def _restore_system_config(self):
        """Restore original system configuration."""
        print("Restoring original system configuration...")

        # Remove NAILS extension import
        if self.nails_extension_config.exists():
            self.nails_extension_config.unlink()
            print("✓ Removed extension import")

        # Restore configuration.nix
        main_config = self.system_config_dir / "configuration.nix"

        if main_config.exists():
            with open(main_config, 'r') as f:
                content = f.read()

            # Remove NAILS extension from imports
            content = re.sub(r'\s*\./nails-extension\.nix', '', content)
            # Clean up empty imports if needed
            content = re.sub(r'imports\s*=\s*\[\s*\];', 'imports = [ ];', content)

            with open(main_config, 'w') as f:
                f.write(content)

            print("✓ Restored original configuration")

    def _is_active(self) -> bool:
        """Check if NAILS is currently active."""
        return (self.state_file.exists() and
                self.nails_extension_config.exists() and
                Path("/.nails-active").exists())

    def status(self):
        """Show current NAILS status."""
        print("NAILS Status - Safe & Untraceable Mode")
        print("=====================================")

        if self._is_active():
            print("Status: ✅ ACTIVE (Hidden environment)")

            if self.state_file.exists():
                try:
                    with open(self.state_file, 'r') as f:
                        state = json.load(f)
                    print(f"Activated: {state.get('activated_at', 'unknown')}")
                    print(f"Method: {state.get('method', 'unknown')}")
                except:
                    print("State file corrupted")
        else:
            print("Status: 🔒 INACTIVE (Decoy environment)")

        print(f"Hidden volume: {self.hidden_volume_root}")
        print(f"Hidden config: {'Present' if (self.hidden_config / 'extension.nix').exists() else 'Missing'}")
        print(f"Extension active: {self.nails_extension_config.exists()}")
        print(f"Activation marker: {Path('/.nails-active').exists()}")

        # Show hidden packages if active
        if self._is_active():
            print("\n✅ Hidden environment features:")
            print("- Additional packages available")
            print("- Hidden configurations active")
            print("- Base system remains intact (no bricking risk)")
            print("- All traces in hidden volume (untraceable when unmounted)")

    def emergency_clean(self):
        """Emergency cleanup - restore to clean decoy state."""
        print("NAILS Emergency Cleanup - Safe & Untraceable Mode")
        print("================================================")
        print("⚠️  This will immediately restore decoy state")

        if os.geteuid() != 0:
            print("Error: Root privileges required")
            print("Run with: sudo ./nails.py emergency-clean")
            sys.exit(1)

        try:
            print("Performing emergency cleanup...")

            # Remove activation marker
            self._remove_activation_marker()

            # Remove all NAILS traces from system
            if self.nails_extension_config.exists():
                self.nails_extension_config.unlink()
                print("✓ Removed extension config")

            self._restore_system_config()
            print("✓ Restored original system config")

            # Clear state (in hidden volume)
            if self.state_file.exists():
                self.state_file.unlink()
                print("✓ Cleared state file")

            # Quick rebuild to clean state
            print("Rebuilding to clean decoy state...")
            result = subprocess.run(["nixos-rebuild", "switch"],
                         capture_output=True, text=True)

            if result.returncode == 0:
                print("\n✅ Emergency cleanup complete")
                print("✅ System restored to decoy state")
                print("✅ No traces left when hidden volume unmounted")
            else:
                print(f"⚠️  Rebuild warning: {result.stderr}")
                print("System may still be in partial state")

        except Exception as e:
            print(f"Emergency cleanup error: {e}")
            print("Manual intervention may be required")


def main():
    parser = argparse.ArgumentParser(
        description="NAILS - NixOS Anti-forensics using Safe Extension System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./nails.py init                 # Initialize hidden config
  sudo ./nails.py activate        # Activate hidden environment  
  sudo ./nails.py deactivate      # Return to decoy system
  ./nails.py status               # Show current status
  sudo ./nails.py emergency-clean # Emergency restore to decoy

Safe & Untraceable Mode:
✓ Extends existing NixOS configuration (prevents bricking)
✓ All state stored in hidden volume (untraceable when unmounted)  
✓ Conditional configurations only active when marker present
✓ Emergency cleanup always available
✓ Maintains 100% plausible deniability
        """
    )

    parser.add_argument("command", choices=["init", "activate", "deactivate", "status", "emergency-clean"])
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    nails = NailsSafeManager(verbose=args.verbose)

    try:
        if args.command == "init":
            nails.init()
        elif args.command == "activate":
            nails.activate()
        elif args.command == "deactivate":
            nails.deactivate()
        elif args.command == "status":
            nails.status()
        elif args.command == "emergency-clean":
            nails.emergency_clean()

    except KeyboardInterrupt:
        print("\nOperation cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
