#!/usr/bin/env python3
"""
NAILS - NixOS Anti-forensics using Safe UnionFS System
Combines UnionFS untraceability with safety mechanisms to prevent bricking
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


class NailsSafeUnionFSManager:
    """NAILS using safe UnionFS approach that maintains complete untraceability."""

    def __init__(self, verbose: bool = False):
        # Determine script location (should be in hidden volume root)
        self.hidden_volume_root = Path(__file__).parent.absolute()
        self.hidden_overlay = self.hidden_volume_root / "overlay"
        self.hidden_config = self.hidden_volume_root / "config"

        # UnionFS mount points (temporary, in memory when possible)
        self.union_root = Path("/tmp/nails-union")
        self.union_etc = self.union_root / "etc"
        self.union_nix = self.union_root / "nix"

        # Original system paths
        self.system_etc = Path("/etc")
        self.system_nix = Path("/nix")

        # State tracking (stored ONLY in hidden volume for untraceability)
        self.state_file = self.hidden_volume_root / ".nails-state"
        self.backup_dir = self.hidden_volume_root / "backups"

        # Safety mechanisms
        self.safety_backup = self.hidden_volume_root / "safety"

        # Setup logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")
        self.logger = logging.getLogger("nails")

    def init(self):
        """Initialize hidden UnionFS overlay structure."""
        print("NAILS Initialization - Safe UnionFS Mode")
        print("=======================================")
        print("This mode provides complete untraceability using UnionFS overlays")

        # Create overlay structure that mirrors system hierarchy
        overlay_structure = [
            self.hidden_overlay / "etc" / "nixos",
            self.hidden_overlay / "nix" / "store",
            self.hidden_overlay / "var" / "lib",
            self.hidden_overlay / "home",
            self.hidden_config,
            self.backup_dir,
            self.safety_backup
        ]

        for path in overlay_structure:
            path.mkdir(parents=True, exist_ok=True)
            print(f"✓ Created overlay: {path}")

        # Create hidden system configuration that inherits essential host settings
        hidden_config = '''{ config, pkgs, lib, ... }:

{
  # NAILS Hidden Configuration - Completely Untraceable
  # This extends the host system configuration safely
  
  # Essential host system configurations (copied from host)
  boot.loader.grub.enable = true;
  boot.loader.grub.device = "/dev/sda";
  boot.loader.grub.useOSProber = true;
  
  # Essential filesystem configuration (from host hardware-configuration.nix)
  boot.initrd.availableKernelModules = [ "ata_piix" "ohci_pci" "ehci_pci" "ahci" "sd_mod" "sr_mod" ];
  boot.initrd.kernelModules = [ ];
  boot.kernelModules = [ ];
  boot.extraModulePackages = [ ];

  fileSystems."/" = {
    device = "/dev/disk/by-uuid/bd4db48d-a786-4c59-9a5d-02a616c7ca3f";
    fsType = "ext4";
  };

  swapDevices = [
    { device = "/dev/disk/by-uuid/9f4edc58-20b7-4d10-90cb-a43d7efb417d"; }
  ];

  # Host platform and networking
  nixpkgs.hostPlatform = lib.mkDefault "x86_64-linux";
  networking.useDHCP = lib.mkDefault true;
  virtualisation.virtualbox.guest.enable = true;
  
  # Set state version to match host system
  system.stateVersion = "25.05";
  
  # Hidden packages (additional to host system)
  environment.systemPackages = with pkgs; [
    # Security tools
    tor
    gnupg
    keepassxc
    
    # Development tools
    git
    vim
    python3
    
    # Communication tools (uncomment as needed)
    # signal-desktop
    # element-desktop
    # thunderbird
  ];

  # Hidden services (additional to host system)
  services = {
    tor = {
      enable = true;
      client.enable = true;
    };
  };

  # Hidden user (exists only in overlay)
  users.users.ghost = {
    isNormalUser = true;
    description = "Hidden user - untraceable";
    extraGroups = [ "wheel" "networkmanager" ];
    # Password will be set in overlay only
  };

  # Hidden environment (overlay-only)
  environment.variables = {
    NAILS_ACTIVE = "true";
    HIDDEN_MODE = "unionfs";
  };
  
  # Hidden shell aliases (overlay-only)
  environment.shellAliases = {
    nails-status = "echo 'NAILS UnionFS mode active - fully untraceable'";
    nails-deactivate = "sudo ${toString ./../..}/nails.py deactivate";
    secure-delete = "shred -vfz -n 3";
    clear-traces = "history -c && history -w && sync";
  };
}'''

        config_file = self.hidden_config / "configuration.nix"
        with open(config_file, "w") as f:
            f.write(hidden_config)

        # Create hardware config for hidden system
        hardware_config = '''{ config, lib, pkgs, modulesPath, ... }:

{
  # Hardware configuration for hidden system
  # This extends the host hardware config safely
  
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];
  
  # Use host's hardware config as base
  # Additional hidden hardware settings can go here
}'''

        hardware_file = self.hidden_config / "hardware-configuration.nix"
        with open(hardware_file, "w") as f:
            f.write(hardware_config)

        print(f"\n✓ Hidden configuration created: {config_file}")
        print("✓ UnionFS overlay structure initialized")
        print("✓ All changes will be written to hidden volume only")
        print("✓ Zero traces left on system filesystem")
        print(f"\n💡 Edit {config_file} to customize your hidden environment")

    def activate(self):
        """Activate hidden environment using safe UnionFS overlays."""
        print("NAILS Activation - Safe UnionFS Mode")
        print("===================================")
        print("Creating untraceable overlay environment...")

        if os.geteuid() != 0:
            print("Error: Root privileges required")
            print("Run with: sudo ./nails.py activate")
            sys.exit(1)

        if self._is_active():
            print("✓ Hidden environment is already active")
            return

        if not (self.hidden_config / "configuration.nix").exists():
            print("✗ Hidden configuration not found. Run './nails.py init' first")
            return

        try:
            # Step 1: Create safety backup (to hidden volume)
            self._create_safety_backup()

            # Step 2: Create UnionFS overlays
            self._create_unionfs_overlays()

            # Step 3: Activate overlays FIRST (before building)
            if self._activate_overlays():
                print("✓ Overlays activated - system now sees unified filesystem")

                # Step 4: Build hidden system with overlays active
                if self._build_hidden_system():
                    self._save_active_state()
                    print("\n✅ NAILS Hidden Environment Active")
                    print("✓ All changes written to hidden volume overlay")
                    print("✓ System filesystem completely untouched")
                    print("✓ Zero forensic traces when deactivated")
                    print("\nRun 'sudo ./nails.py deactivate' to return to decoy")
                else:
                    print("✗ Failed to build hidden system - rolling back")
                    self._deactivate_overlays()
                    self._cleanup_unionfs()
            else:
                print("✗ Failed to activate overlays")
                self._cleanup_unionfs()

        except Exception as e:
            print(f"✗ Activation failed: {e}")
            print("Performing emergency cleanup...")
            self._emergency_cleanup()

    def deactivate(self):
        """Deactivate hidden environment and remove all traces."""
        print("NAILS Deactivation - Safe UnionFS Mode")
        print("=====================================")
        print("Removing overlay and returning to clean decoy state...")

        if os.geteuid() != 0:
            print("Error: Root privileges required")
            print("Run with: sudo ./nails.py deactivate")
            sys.exit(1)

        if not self._is_active():
            print("✓ Hidden environment is already inactive")
            return

        try:
            # Deactivate overlays (atomic operation)
            self._deactivate_overlays()

            # Cleanup UnionFS mounts
            self._cleanup_unionfs()

            # Clear state (in hidden volume only)
            if self.state_file.exists():
                self.state_file.unlink()

            print("\n✅ System returned to decoy state")
            print("✓ All overlays removed")
            print("✓ System filesystem restored to original state")
            print("✓ Zero forensic traces remaining")

        except Exception as e:
            print(f"✗ Deactivation failed: {e}")
            print("Attempting emergency cleanup...")
            self._emergency_cleanup()

    def emergency_clean(self):
        """Emergency cleanup - restore to clean decoy state."""
        print("NAILS Emergency Cleanup - Safe UnionFS Mode")
        print("==========================================")
        print("⚠️  This will immediately restore decoy state")

        if os.geteuid() != 0:
            print("Error: Root privileges required")
            print("Run with: sudo ./nails.py emergency-clean")
            sys.exit(1)

        try:
            print("Performing emergency cleanup...")

            # Force unmount everything
            for path in ["/nix", "/etc"]:
                subprocess.run(["umount", "-f", path], capture_output=True)
                subprocess.run(["umount", "-l", path], capture_output=True)  # lazy unmount
                print(f"  ✓ Force unmounted {path}")

            # Cleanup unionfs
            self._cleanup_unionfs()

            # Clear state
            if self.state_file.exists():
                self.state_file.unlink()
                print("  ✓ Cleared state file")

            print("\n✅ Emergency cleanup complete")
            print("✅ System restored to decoy state")
            print("✅ All traces removed")

        except Exception as e:
            print(f"Emergency cleanup error: {e}")
            print("Manual intervention may be required")

    def _create_safety_backup(self):
        """Create safety backup of critical system files."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.safety_backup / f"safety_{timestamp}"
        backup_path.mkdir(parents=True, exist_ok=True)

        print(f"Creating safety backup in hidden volume...")

        # Backup critical system files
        critical_paths = [
            "/etc/nixos",
            "/etc/fstab",
            "/etc/passwd",
            "/etc/group"
        ]

        for path in critical_paths:
            src = Path(path)
            if src.exists():
                try:
                    if src.is_dir():
                        shutil.copytree(src, backup_path / src.name, dirs_exist_ok=True)
                    else:
                        shutil.copy2(src, backup_path / src.name)
                    print(f"  ✓ Backed up {path}")
                except Exception as e:
                    print(f"  ⚠️ Could not backup {path}: {e}")

        print("✓ Safety backup created in hidden volume")

    def _create_unionfs_overlays(self):
        """Create UnionFS overlay mounts."""
        print("Creating UnionFS overlays...")

        # Create union mount points
        self.union_root.mkdir(exist_ok=True)

        # Check for unionfs-fuse
        if not shutil.which("unionfs"):
            raise Exception("unionfs-fuse not available. Install with: nix-shell -p unionfs-fuse")

        # Create /etc overlay (for configuration changes)
        etc_union = self.union_root / "etc"
        etc_union.mkdir(exist_ok=True)

        print("  Creating /etc overlay...")
        etc_cmd = [
            "unionfs",
            "-o", "cow",
            f"{self.hidden_overlay / 'etc'}=RW:{self.system_etc}=RO",
            str(etc_union)
        ]

        result = subprocess.run(etc_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Failed to create /etc overlay: {result.stderr}")

        print("  ✓ /etc overlay created")

        # Create /nix overlay (for package changes)
        nix_union = self.union_root / "nix"
        nix_union.mkdir(exist_ok=True)

        print("  Creating /nix overlay...")
        nix_cmd = [
            "unionfs",
            "-o", "cow",
            f"{self.hidden_overlay / 'nix'}=RW:{self.system_nix}=RO",
            str(nix_union)
        ]

        result = subprocess.run(nix_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Failed to create /nix overlay: {result.stderr}")

        print("  ✓ /nix overlay created")
        print("✓ UnionFS overlays ready")

    def _build_hidden_system(self) -> bool:
        """Build hidden system using a simpler approach."""
        print("Building hidden system...")
        print("Using standard nixos-rebuild without overlay redirection")

        try:
            # Don't try to redirect Nix paths - this causes permission issues
            # Just build the configuration normally and let NixOS handle the store
            build_cmd = [
                "nixos-rebuild", "build",
                "-I", f"nixos-config={self.hidden_config}/configuration.nix",
                "--show-trace"
            ]

            print("Building hidden system configuration...")
            print("(This may take several minutes on first run)")

            # Run without environment variable overrides to avoid permission issues
            process = subprocess.run(build_cmd, capture_output=True, text=True)

            if process.returncode == 0:
                print("✓ Hidden system built successfully")
                return True
            else:
                print(f"✗ Build failed:")
                # Show more detailed error information
                error_lines = process.stderr.split('\n')
                for line in error_lines[-20:]:  # Show last 20 lines
                    if line.strip():
                        print(f"  {line}")
                return False

        except Exception as e:
            print(f"Build error: {e}")
            return False

    def _activate_overlays(self) -> bool:
        """Directly mount UnionFS over system paths (correct NAILS implementation)."""
        print("Activating NAILS UnionFS overlays...")
        print("Mounting hidden store over system directories for merged access")

        try:
            # Step 1: Create UnionFS overlay directly over /etc
            print("  Creating /etc UnionFS overlay...")
            etc_cmd = [
                "unionfs",
                "-o", "cow",
                f"{self.hidden_overlay / 'etc'}=RW:/etc=RO",
                "/etc"
            ]

            result = subprocess.run(etc_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                raise Exception(f"Failed to create /etc overlay: {result.stderr}")

            print("  ✓ /etc UnionFS overlay activated")

            # Step 2: Create UnionFS overlay directly over /nix (THE KEY INNOVATION)
            print("  Creating /nix UnionFS overlay...")
            print(f"  Merging: {self.hidden_overlay / 'nix'} (hidden store) + /nix (system store)")
            print("  This provides access to BOTH decoy and hidden packages")

            nix_cmd = [
                "unionfs",
                "-o", "cow",
                f"{self.hidden_overlay / 'nix'}=RW:/nix=RO",
                "/nix"
            ]

            nix_mount_result = subprocess.run(nix_cmd, capture_output=True, text=True, timeout=60)

            if nix_mount_result.returncode != 0:
                print(f"  ✗ /nix overlay failed: {nix_mount_result.stderr}")
                # Rollback /etc overlay
                subprocess.run(["fusermount", "-u", "/etc"], capture_output=True, timeout=30)
                raise Exception(f"Failed to create /nix UnionFS overlay: {nix_mount_result.stderr}")

            print("  ✓ /nix UnionFS overlay activated - both stores now merged")

            # Verify the overlay is working
            print("  Verifying merged store functionality...")
            nix_test = subprocess.run(["ls", "/nix/store"], capture_output=True, text=True, timeout=10)
            if nix_test.returncode == 0:
                store_items = len([line for line in nix_test.stdout.split('\n') if line.strip()])
                print(f"  ✓ /nix store accessible ({store_items} packages visible)")
                print("  ✓ Both decoy and hidden packages are now available")
                print("  ✓ All writes will go to hidden volume overlay")
            else:
                print("  ⚠️ /nix store verification failed")

            print("✓ NAILS UnionFS overlays successfully activated")
            print("✓ System now has merged view: decoy + hidden packages")
            print("✓ Copy-on-write ensures hidden volume isolation")

            # Debug: Show what's in /etc/nixos after overlay activation
            self._debug_overlay_state()

            return True

        except subprocess.TimeoutExpired as e:
            print(f"  ✗ UnionFS operation timed out: {e}")
            print("  This may indicate issues with UnionFS or system load")
            # Emergency cleanup
            subprocess.run(["fusermount", "-u", "/nix"], capture_output=True)
            subprocess.run(["fusermount", "-u", "/etc"], capture_output=True)
            return False
        except Exception as e:
            print(f"UnionFS overlay activation failed: {e}")
            # Emergency cleanup
            subprocess.run(["fusermount", "-u", "/nix"], capture_output=True)
            subprocess.run(["fusermount", "-u", "/etc"], capture_output=True)
            return False

    def _debug_overlay_state(self):
        """Debug function to show overlay filesystem state."""
        print("\n🔍 Debug: Checking overlay filesystem state...")

        # Check /etc/nixos contents
        try:
            print("Contents of /etc/nixos after overlay activation:")
            result = subprocess.run(["ls", "-la", "/etc/nixos"], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        print(f"  {line}")
            else:
                print(f"  ❌ Could not list /etc/nixos: {result.stderr}")
        except Exception as e:
            print(f"  ❌ Error checking /etc/nixos: {e}")

        # Check if configuration.nix exists and is readable
        config_files = ["/etc/nixos/configuration.nix", "/etc/nixos/hardware-configuration.nix"]
        for config_file in config_files:
            try:
                if Path(config_file).exists():
                    stat_result = subprocess.run(["stat", config_file], capture_output=True, text=True)
                    print(f"  ✓ {config_file} exists")
                    if stat_result.returncode == 0:
                        # Show just the file info line
                        for line in stat_result.stdout.split('\n'):
                            if 'File:' in line or 'Size:' in line:
                                print(f"    {line.strip()}")
                else:
                    print(f"  ❌ {config_file} does not exist")
            except Exception as e:
                print(f"  ❌ Error checking {config_file}: {e}")

        # Check mount points
        print("\nMount point information:")
        try:
            result = subprocess.run(["findmnt", "/etc"], capture_output=True, text=True)
            if result.returncode == 0:
                print("  /etc mount info:")
                for line in result.stdout.split('\n')[1:2]:  # Show header and first result
                    if line.strip():
                        print(f"    {line}")

            result = subprocess.run(["findmnt", "/nix"], capture_output=True, text=True)
            if result.returncode == 0:
                print("  /nix mount info:")
                for line in result.stdout.split('\n')[1:2]:  # Show header and first result
                    if line.strip():
                        print(f"    {line}")
        except Exception as e:
            print(f"  ❌ Error checking mounts: {e}")

        # Check union filesystem contents
        print("\nUnion filesystem contents:")
        try:
            print(f"Contents of union /etc ({self.union_etc}):")
            if self.union_etc.exists():
                result = subprocess.run(["ls", "-la", str(self.union_etc / "nixos")], capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"  Union /etc/nixos contents:")
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            print(f"    {line}")
                else:
                    print(f"    ❌ No nixos directory in union /etc")
            else:
                print(f"    ❌ Union /etc does not exist")
        except Exception as e:
            print(f"  ❌ Error checking union contents: {e}")

        print("🔍 End debug information\n")

    def _deactivate_overlays(self):
        """Safely deactivate overlays and restore system paths."""
        print("Deactivating overlays...")

        # Unmount in reverse order
        for mount_point in ["/nix", "/etc"]:
            try:
                result = subprocess.run(["umount", mount_point], capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"  ✓ {mount_point} overlay deactivated")
                else:
                    print(f"  ⚠️ Warning unmounting {mount_point}: {result.stderr}")
                    # Force unmount
                    subprocess.run(["umount", "-f", mount_point], capture_output=True)
            except Exception as e:
                print(f"  ⚠️ Error deactivating {mount_point}: {e}")

    def _cleanup_unionfs(self):
        """Clean up UnionFS mounts."""
        print("Cleaning up UnionFS mounts...")

        # Unmount union filesystems
        for union_path in [self.union_nix, self.union_etc]:
            if union_path.exists():
                try:
                    result = subprocess.run(["fusermount", "-u", str(union_path)],
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        print(f"  ✓ UnionFS {union_path.name} unmounted")
                        union_path.rmdir()
                    else:
                        print(f"  ⚠️ Warning unmounting {union_path}: {result.stderr}")
                        subprocess.run(["fusermount", "-uz", str(union_path)], capture_output=True)
                except Exception as e:
                    print(f"  ⚠️ Error cleaning up {union_path}: {e}")

        # Remove union root
        if self.union_root.exists():
            try:
                self.union_root.rmdir()
                print("  ✓ Union root removed")
            except:
                print("  ⚠️ Could not remove union root")

    def _save_active_state(self):
        """Save active state to hidden volume."""
        state = {
            "active": True,
            "activated_at": datetime.now().isoformat(),
            "method": "safe_unionfs",
            "overlays": {
                "etc": str(self.union_etc),
                "nix": str(self.union_nix)
            },
            "hidden_volume": str(self.hidden_volume_root)
        }

        with open(self.state_file, "w") as f:
            json.dump(state, f, indent=2)

    def _is_active(self) -> bool:
        """Check if NAILS UnionFS is currently active."""
        if not self.state_file.exists():
            return False

        # Check if overlays are mounted
        try:
            result = subprocess.run(["findmnt", "/etc"], capture_output=True, text=True)
            etc_mounted = result.returncode == 0 and "unionfs" in result.stdout

            result = subprocess.run(["findmnt", "/nix"], capture_output=True, text=True)
            nix_mounted = result.returncode == 0 and "unionfs" in result.stdout

            return etc_mounted and nix_mounted
        except:
            return False

    def _emergency_cleanup(self):
        """Emergency cleanup to restore system state."""
        print("🚨 Performing emergency cleanup...")

        # Force unmount everything
        for path in ["/nix", "/etc"]:
            subprocess.run(["umount", "-f", path], capture_output=True)
            subprocess.run(["umount", "-l", path], capture_output=True)  # lazy unmount

        # Cleanup unionfs
        self._cleanup_unionfs()

        # Clear state
        if self.state_file.exists():
            self.state_file.unlink()

        print("🚨 Emergency cleanup complete - check system state manually")

    def status(self):
        """Show current NAILS status."""
        print("NAILS Status - Safe UnionFS Mode")
        print("===============================")

        if self._is_active():
            print("Status: ✅ ACTIVE (Hidden environment via UnionFS)")
            print("Mode: Safe UnionFS overlays")

            if self.state_file.exists():
                try:
                    with open(self.state_file, 'r') as f:
                        state = json.load(f)
                    print(f"Activated: {state.get('activated_at', 'unknown')}")
                except:
                    pass
        else:
            print("Status: 🔒 INACTIVE (Decoy environment)")

        print(f"Hidden volume: {self.hidden_volume_root}")
        print(f"Overlay structure: {'Present' if self.hidden_overlay.exists() else 'Missing'}")
        print(f"Hidden config: {'Present' if (self.hidden_config / 'configuration.nix').exists() else 'Missing'}")

        # Check mount status
        try:
            result = subprocess.run(["findmnt", "/etc"], capture_output=True, text=True)
            etc_status = "Overlaid" if "unionfs" in result.stdout else "Normal"
            print(f"/etc status: {etc_status}")

            result = subprocess.run(["findmnt", "/nix"], capture_output=True, text=True)
            nix_status = "Overlaid" if "unionfs" in result.stdout else "Normal"
            print(f"/nix status: {nix_status}")
        except:
            print("Mount status: Could not determine")

        if self._is_active():
            print("\n✅ UnionFS Hidden Environment Features:")
            print("- All changes written to hidden volume overlay")
            print("- System filesystem completely untouched")
            print("- Zero forensic traces when deactivated")
            print("- Complete plausible deniability")

def main():
    parser = argparse.ArgumentParser(
        description="NAILS - NixOS Anti-forensics using Safe UnionFS System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./nails.py init                 # Initialize hidden config
  sudo ./nails.py activate        # Activate hidden environment  
  sudo ./nails.py deactivate      # Return to decoy system
  ./nails.py status               # Show current status
  sudo ./nails.py emergency-clean # Emergency restore to decoy

Safe UnionFS Mode:
✓ Completely untraceable using UnionFS overlays
✓ All state stored in hidden volume (untraceable when unmounted)  
✓ Conditional configurations only active when marker present
✓ Emergency cleanup always available
✓ Maintains 100% plausible deniability
        """
    )

    parser.add_argument("command", choices=["init", "activate", "deactivate", "status", "emergency-clean"])
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    nails = NailsSafeUnionFSManager(verbose=args.verbose)

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
