#!/usr/bin/env python3
"""
NAILS Overlay Manager
This script sits in the root of a VeraCrypt hidden volume and manages
overlaying the hidden nix/ directory over the system /nix directory.
"""

import json
import logging
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


class NailsOverlay:
    def __init__(self):
        # Determine script location (should be in hidden volume root)
        self.hidden_volume_root = Path(__file__).parent.absolute()
        self.hidden_nix_store = self.hidden_volume_root / "nix"
        self.hidden_config = self.hidden_volume_root / "config"
        self.system_nix = Path("/nix")
        self.system_config = Path("/etc/nixos")

        # State tracking
        self.state_file = self.hidden_volume_root / ".nails-state"
        self.backup_dir = self.hidden_volume_root / "backups"
        self.log_file = self.hidden_volume_root / "nails.log"

        # Overlay mount point
        self.overlay_work_dir = Path("/tmp/nails-overlay-work")
        self.overlay_upper_dir = self.hidden_nix_store
        self.overlay_lower_dir = self.system_nix

        # Emergency files to clean up
        self.emergency_cleanup_files = [
            "/tmp/nails-*",
            "/var/log/nails*",
            self.state_file,
            "/proc/mounts",  # Will be filtered for overlay entries
        ]

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler(self.log_file), logging.StreamHandler()],
        )
        self.logger = logging.getLogger("nails-overlay")

        # Ensure required directories exist
        self._ensure_directories()

    def _ensure_directories(self):
        """Ensure required directories exist in hidden volume"""
        dirs_to_create = [
            self.hidden_nix_store,
            self.hidden_nix_store / "store",
            self.hidden_config,
            self.backup_dir,
            self.overlay_work_dir,
        ]

        for directory in dirs_to_create:
            directory.mkdir(parents=True, exist_ok=True)

    def _run_command(
        self, cmd: list[str], check: bool = True, capture_output: bool = True
    ) -> subprocess.CompletedProcess:
        """Execute system command with error handling"""
        self.logger.debug(f"Executing: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd, capture_output=capture_output, text=True, check=check
            )

            if result.returncode != 0 and check:
                self.logger.error(f"Command failed: {' '.join(cmd)}")
                self.logger.error(f"Error: {result.stderr}")

            return result

        except subprocess.CalledProcessError as e:
            self.logger.error(
                f"Command failed with exit code {e.returncode}: {' '.join(cmd)}"
            )
            raise
        except Exception as e:
            self.logger.error(f"Failed to execute command: {e}")
            raise

    def _is_overlay_active(self) -> bool:
        """Check if the overlay is currently active"""
        try:
            with open("/proc/mounts") as f:
                mounts = f.read()
                return "overlay" in mounts and str(self.system_nix) in mounts
        except Exception:
            return False

    def _get_current_state(self) -> dict:
        """Get current overlay state"""
        if not self.state_file.exists():
            return {"active": False, "activated_at": None, "pid": None}

        try:
            with open(self.state_file) as f:
                return json.load(f)
        except Exception:
            return {"active": False, "activated_at": None, "pid": None}

    def _save_state(self, state: dict):
        """Save overlay state to file"""
        try:
            with open(self.state_file, "w") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save state: {e}")

    def _backup_system_config(self) -> str:
        """Backup current system configuration"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_dir / f"system_backup_{timestamp}"
        backup_path.mkdir(parents=True, exist_ok=True)

        try:
            # Backup /etc/nixos
            if self.system_config.exists():
                shutil.copytree(
                    self.system_config, backup_path / "nixos", dirs_exist_ok=True
                )

            # Backup current generation info
            result = self._run_command(
                ["nixos-version"], capture_output=True, check=False
            )
            if result.returncode == 0:
                with open(backup_path / "nixos-version.txt", "w") as f:
                    f.write(result.stdout)

            # Save current Nix profile info
            result = self._run_command(
                ["nix-env", "--list-generations"], capture_output=True, check=False
            )
            if result.returncode == 0:
                with open(backup_path / "nix-generations.txt", "w") as f:
                    f.write(result.stdout)

            self.logger.info(f"System backed up to: {backup_path}")
            return str(backup_path)

        except Exception as e:
            self.logger.error(f"Failed to backup system: {e}")
            return ""

    def _create_overlay(self) -> bool:
        """Create the overlay filesystem"""
        try:
            # Ensure overlay work directory is clean
            if self.overlay_work_dir.exists():
                shutil.rmtree(self.overlay_work_dir)
            self.overlay_work_dir.mkdir(parents=True, exist_ok=True)

            # Create overlay mount command
            overlay_options = (
                f"lowerdir={self.overlay_lower_dir},"
                f"upperdir={self.overlay_upper_dir},"
                f"workdir={self.overlay_work_dir}"
            )

            mount_cmd = [
                "mount",
                "-t",
                "overlay",
                "overlay",
                "-o",
                overlay_options,
                str(self.system_nix),
            ]

            self.logger.info(f"Creating overlay: {' '.join(mount_cmd)}")
            result = self._run_command(mount_cmd, check=False, capture_output=True)

            if result.returncode == 0:
                self.logger.info("Overlay created successfully")
                return True
            else:
                self.logger.error(f"Failed to create overlay: {result.stderr}")
                return False

        except Exception as e:
            self.logger.error(f"Error creating overlay: {e}")
            return False

    def _remove_overlay(self) -> bool:
        """Remove the overlay filesystem"""
        try:
            # Unmount the overlay
            umount_cmd = ["umount", str(self.system_nix)]
            self.logger.info(f"Removing overlay: {' '.join(umount_cmd)}")

            result = self._run_command(umount_cmd, check=False, capture_output=True)

            if result.returncode == 0:
                self.logger.info("Overlay removed successfully")

                # Clean up work directory
                if self.overlay_work_dir.exists():
                    shutil.rmtree(self.overlay_work_dir)

                return True
            else:
                self.logger.error(f"Failed to remove overlay: {result.stderr}")
                return False

        except Exception as e:
            self.logger.error(f"Error removing overlay: {e}")
            return False

    def _apply_hidden_config(self):
        """Apply hidden system configuration"""
        if not (self.hidden_config / "configuration.nix").exists():
            self.logger.warning(
                "No hidden configuration found, skipping config application"
            )
            return

        try:
            # Backup current config
            self._backup_system_config()

            # Copy hidden config to system location
            shutil.copytree(self.hidden_config, self.system_config, dirs_exist_ok=True)

            self.logger.info("Hidden configuration applied")

        except Exception as e:
            self.logger.error(f"Failed to apply hidden config: {e}")

    def _restore_system_config(self, backup_path: str | None = None):
        """Restore system configuration from backup"""
        if not backup_path:
            # Find most recent backup
            if not self.backup_dir.exists():
                self.logger.warning("No backups found")
                return

            backups = sorted(self.backup_dir.glob("system_backup_*"))
            if not backups:
                self.logger.warning("No system backups found")
                return

            backup_path = backups[-1]

        try:
            nixos_backup = Path(backup_path) / "nixos"
            if nixos_backup.exists():
                # Remove current config
                if self.system_config.exists():
                    shutil.rmtree(self.system_config)

                # Restore from backup
                shutil.copytree(nixos_backup, self.system_config)
                self.logger.info(f"System configuration restored from {backup_path}")
            else:
                self.logger.error(f"No nixos config found in backup: {backup_path}")

        except Exception as e:
            self.logger.error(f"Failed to restore system config: {e}")

    def init(self):
        """Initialize the hidden volume for NAILS"""
        self.logger.info("Initializing NAILS in hidden volume...")

        # Create directory structure
        self._ensure_directories()

        # Create default configuration if none exists
        if not (self.hidden_config / "configuration.nix").exists():
            default_config = """{ config, pkgs, ... }:

{
  # Hidden environment configuration
  imports = [ ./hardware-configuration.nix ];

  # Example hidden packages
  environment.systemPackages = with pkgs; [
    vim
    git
    curl
    tor
    gnupg
    # Add your hidden packages here
  ];

  # Minimal services for stealth
  services = {
    openssh.enable = false;  # Disable SSH by default
    tor.enable = true;
  };

  # Hidden user
  users.users.ghost = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
  };

  system.stateVersion = "23.11";
}"""

            with open(self.hidden_config / "configuration.nix", "w") as f:
                f.write(default_config)

        # Copy hardware config from system
        system_hardware_config = self.system_config / "hardware-configuration.nix"
        hidden_hardware_config = self.hidden_config / "hardware-configuration.nix"

        if system_hardware_config.exists() and not hidden_hardware_config.exists():
            shutil.copy2(system_hardware_config, hidden_hardware_config)

        self.logger.info("NAILS initialization complete!")
        self.logger.info(f"Hidden volume root: {self.hidden_volume_root}")
        self.logger.info(
            f"Edit {self.hidden_config}/configuration.nix to customize your hidden environment"
        )

    def activate(self):
        """Activate the hidden environment"""
        current_state = self._get_current_state()

        if current_state["active"]:
            self.logger.warning("Hidden environment already active")
            return

        self.logger.info("Activating hidden environment...")

        # Check if we have required privileges
        if os.geteuid() != 0:
            self.logger.error("Root privileges required for overlay operations")
            sys.exit(1)

        # Backup current system state
        backup_path = self._backup_system_config()

        # Create the overlay
        if not self._create_overlay():
            self.logger.error("Failed to create overlay - aborting activation")
            return

        # Apply hidden configuration
        self._apply_hidden_config()

        # Update state
        new_state = {
            "active": True,
            "activated_at": datetime.now().isoformat(),
            "pid": os.getpid(),
            "backup_path": backup_path,
        }
        self._save_state(new_state)

        self.logger.info("Hidden environment activated successfully!")
        self.logger.info("Run 'nixos-rebuild switch' to apply hidden configuration")

    def deactivate(self):
        """Deactivate the hidden environment"""
        current_state = self._get_current_state()

        if not current_state["active"]:
            self.logger.warning("Hidden environment not active")
            return

        self.logger.info("Deactivating hidden environment...")

        # Check privileges
        if os.geteuid() != 0:
            self.logger.error("Root privileges required for overlay operations")
            sys.exit(1)

        # Remove the overlay
        if not self._remove_overlay():
            self.logger.error(
                "Failed to remove overlay - manual cleanup may be required"
            )

        # Restore system configuration
        backup_path = current_state.get("backup_path")
        if backup_path:
            self._restore_system_config(backup_path)

        # Clear state
        self._save_state({"active": False, "activated_at": None, "pid": None})

        self.logger.info("Hidden environment deactivated")
        self.logger.info("Run 'nixos-rebuild switch' to restore decoy configuration")

    def status(self):
        """Show current status"""
        current_state = self._get_current_state()
        overlay_active = self._is_overlay_active()

        print("NAILS Overlay Status")
        print("==================")
        print(f"Hidden Volume: {self.hidden_volume_root}")
        print(f"State File: {'Active' if current_state['active'] else 'Inactive'}")
        print(f"Overlay Mount: {'Active' if overlay_active else 'Inactive'}")

        if current_state["active"]:
            print(f"Activated: {current_state['activated_at']}")
            print(f"PID: {current_state.get('pid', 'Unknown')}")

        print(f"\nHidden Nix Store: {self.hidden_nix_store}")
        print(f"Hidden Config: {self.hidden_config}")

        # Check consistency
        if current_state["active"] != overlay_active:
            print("\n⚠️  WARNING: State inconsistency detected!")
            print(
                f"   State file shows: {'active' if current_state['active'] else 'inactive'}"
            )
            print(f"   Actual overlay: {'active' if overlay_active else 'inactive'}")

    def emergency_clean(self):
        """Emergency cleanup - remove all traces"""
        self.logger.warning("EMERGENCY CLEANUP INITIATED")

        # Force remove overlay if active
        if self._is_overlay_active():
            try:
                self._run_command(["umount", "-f", str(self.system_nix)], check=False)
            except:
                pass

        # Clean up temporary files
        for pattern in self.emergency_cleanup_files:
            try:
                if "*" in pattern:
                    import glob

                    for path in glob.glob(pattern):
                        if os.path.exists(path):
                            os.remove(path)
                else:
                    if os.path.exists(pattern):
                        os.remove(pattern)
            except Exception as e:
                self.logger.debug(f"Could not clean {pattern}: {e}")

        # Clear work directory
        if self.overlay_work_dir.exists():
            shutil.rmtree(self.overlay_work_dir)

        # Clear state
        if self.state_file.exists():
            self.state_file.unlink()

        self.logger.warning("Emergency cleanup completed")


def main():
    if len(sys.argv) < 2:
        print("Usage: nails-overlay.py <command>")
        print("Commands:")
        print("  init              Initialize hidden volume")
        print("  activate          Activate hidden environment")
        print("  deactivate        Deactivate hidden environment")
        print("  status            Show current status")
        print("  emergency-clean   Emergency cleanup")
        sys.exit(1)

    command = sys.argv[1]
    overlay = NailsOverlay()

    try:
        if command == "init":
            overlay.init()
        elif command == "activate":
            overlay.activate()
        elif command == "deactivate":
            overlay.deactivate()
        elif command == "status":
            overlay.status()
        elif command == "emergency-clean":
            overlay.emergency_clean()
        else:
            print(f"Unknown command: {command}")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
