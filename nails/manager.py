"""
Main NAILS manager class that orchestrates all operations
"""

import logging
import os
from pathlib import Path

from .config import ConfigManager
from .exceptions import NailsPermissionError, NailsStateError
from .nixos import NixOSManager
from .overlay import OverlayManager
from .state import StateManager


class NailsManager:
    """Main NAILS manager that coordinates all subsystems"""

    def __init__(self, verbose: bool = False):
        # Determine script location (should be in hidden volume root)
        self.hidden_volume_root = Path(__file__).parent.parent.absolute()

        # Setup logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")
        self.logger = logging.getLogger("nails")

        # Initialize subsystem managers
        self.overlay_manager = OverlayManager(self.hidden_volume_root)
        self.config_manager = ConfigManager(self.hidden_volume_root)
        self.nixos_manager = NixOSManager(self.hidden_volume_root)
        self.state_manager = StateManager(self.hidden_volume_root)

    def _require_root(self) -> None:
        """Check that we have root privileges"""
        if os.geteuid() != 0:
            raise NailsPermissionError("Root privileges required")

    def init(self) -> None:
        """Initialize hidden overlay structure and configurations"""
        print("NAILS Initialization - Safe Overlay Mode")
        print("=======================================")
        print("This mode provides complete untraceability using overlay filesystems")

        # Initialize overlay structure
        self.overlay_manager.init_structure()

        # Create initial configurations
        self.config_manager.create_initial_configs()

        print("\n✓ NAILS initialization complete")
        print("✓ All changes will be written to hidden volume only")
        print("✓ Zero traces left on system filesystem")
        print(
            f"\n💡 Edit {self.config_manager.config_dir}/configuration.nix to customize your hidden environment"
        )

    def activate(self) -> None:
        """Activate hidden environment using safe overlay filesystems"""
        print("NAILS Activation - Safe Overlay Mode")
        print("===================================")
        print("Creating untraceable overlay environment...")

        self._require_root()

        if self.state_manager.is_active():
            print("✓ Hidden environment is already active")
            return

        if not self.config_manager.config_exists():
            raise NailsStateError(
                "Hidden configuration not found. Run './nails.py init' first"
            )

        try:
            # Create safety backup
            self.overlay_manager.create_safety_backup()

            # Create and activate overlays
            self.overlay_manager.create_mounts()
            self.overlay_manager.activate()

            # Build and switch to hidden system
            self.nixos_manager.build_and_switch()

            # Save active state
            self.state_manager.save_active_state()

            print("\n✅ NAILS Hidden Environment Active")
            print("✓ System switched to hidden configuration")
            print("✓ All changes written to hidden volume overlay")
            print("✓ System filesystem completely untouched")
            print("✓ Zero forensic traces when deactivated")
            print("\nHidden environment features now available:")
            print("  - Hidden packages: tor, gnupg, keepassxc, etc.")
            print("  - Hidden user: ghost (set password with 'sudo passwd ghost')")
            print("  - Hidden services: Tor daemon")
            print("  - User data isolation: /home overlay active")
            print("\nRun 'sudo ./nails.py deactivate' to return to decoy system")

        except Exception as e:
            print(f"✗ Activation failed: {e}")
            print("Performing emergency cleanup...")
            self.overlay_manager.emergency_cleanup()
            raise

    def deactivate(self) -> None:
        """Deactivate hidden environment and remove all traces"""
        print("NAILS Deactivation - Safe Overlay Mode")
        print("=====================================")
        print("Removing overlay and returning to clean decoy state...")

        self._require_root()

        if not self.state_manager.is_active():
            print("✓ Hidden environment is already inactive")
            return

        try:
            # Switch back to previous generation
            self.nixos_manager.switch_to_previous_generation()

            # Deactivate overlays
            self.overlay_manager.deactivate()

            # Clear state
            self.state_manager.clear_state()

            print("\n✅ System returned to decoy state")
            print("✓ All overlays removed")
            print("✓ System filesystem restored to original state")
            print("✓ Zero forensic traces remaining")

        except Exception as e:
            print(f"✗ Deactivation failed: {e}")
            print("Attempting emergency cleanup...")
            self.overlay_manager.emergency_cleanup()
            raise

    def rebuild(self) -> None:
        """Rebuild the hidden system with changes from config/configuration.nix"""
        print("NAILS Rebuild - Safe Overlay Mode")
        print("=================================")
        print("Rebuilding hidden system with updated configuration...")

        self._require_root()

        if not self.state_manager.is_active():
            raise NailsStateError(
                "Hidden environment is not active. Run './nails.py activate' first"
            )

        if not self.config_manager.config_exists():
            raise NailsStateError(
                "Hidden configuration not found at config/configuration.nix"
            )

        try:
            success = self.nixos_manager.rebuild()

            if success:
                print("\n✅ NAILS Hidden System Rebuilt Successfully")
                print("✓ Configuration changes applied")
                print("✓ System updated while maintaining overlay filesystem")
                print("✓ Hidden environment remains active and untraceable")
                print("\n💡 Your changes from config/configuration.nix are now active")
                print("   To see what packages are available: nix-env -qa")
                print("   To deactivate: sudo ./nails.py deactivate")
            else:
                print("✗ Rebuild failed - system remains in previous state")

        except Exception as e:
            print(f"✗ Rebuild error: {e}")
            print("System remains in previous state")
            raise

    def emergency_clean(self) -> None:
        """Emergency cleanup - restore to clean decoy state"""
        print("NAILS Emergency Cleanup - Safe Overlay Mode")
        print("==========================================")
        print("⚠️  This will immediately restore decoy state")

        self._require_root()

        self.overlay_manager.emergency_cleanup()
        self.state_manager.clear_state()

        print("\n✅ Emergency cleanup complete")
        print("✅ System restored to decoy state")
        print("✅ All traces removed")

    def status(self) -> None:
        """Show current NAILS status"""
        print("NAILS Status - Safe Overlay Mode")
        print("===============================")

        is_active = self.state_manager.is_active()

        if is_active:
            print("Status: ✅ ACTIVE (Hidden environment via overlay)")
            print("Mode: Safe overlay filesystems")

            activation_time = self.state_manager.get_activation_time()
            if activation_time:
                print(f"Activated: {activation_time}")
        else:
            print("Status: 🔒 INACTIVE (Decoy environment)")

        print(f"Hidden volume: {self.hidden_volume_root}")
        print(
            f"Overlay structure: {'Present' if self.overlay_manager.structure_exists() else 'Missing'}"
        )
        print(
            f"Hidden config: {'Present' if self.config_manager.config_exists() else 'Missing'}"
        )

        # Show mount status
        mount_status = self.overlay_manager.get_mount_status()
        for mount_point, status in mount_status.items():
            print(f"{mount_point} status: {status}")

        if is_active:
            print("\n✅ Overlay Hidden Environment Features:")
            print("- All changes written to hidden volume overlay")
            print("- System filesystem completely untouched")
            print("- User data completely isolated (/home overlay)")
            print("- Zero forensic traces when deactivated")
            print("- Complete plausible deniability")
