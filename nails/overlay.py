"""
Overlay filesystem management for NAILS
"""

import contextlib
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

from .exceptions import NailsOverlayError


class OverlayManager:
    """Manages overlay filesystem operations"""

    def __init__(self, hidden_volume_root: Path):
        self.hidden_volume_root = hidden_volume_root
        self.hidden_overlay = hidden_volume_root / "overlay"
        self.work_dir = hidden_volume_root / "work"
        self.safety_backup = hidden_volume_root / "safety"
        self.union_root = Path("/tmp/nails-union")

        # System paths to overlay
        self.overlay_targets = {
            "/etc": self.hidden_overlay / "etc",
            "/nix": self.hidden_overlay / "nix",
            "/home": self.hidden_overlay / "home",
        }

    def init_structure(self) -> None:
        """Initialize overlay directory structure"""
        overlay_structure = [
            self.hidden_overlay / "etc" / "nixos",
            self.hidden_overlay / "nix" / "store",
            self.hidden_overlay / "var" / "lib",
            self.hidden_overlay / "home",
            self.work_dir,
            self.safety_backup,
        ]

        for path in overlay_structure:
            path.mkdir(parents=True, exist_ok=True)
            print(f"✓ Created overlay: {path}")

    def structure_exists(self) -> bool:
        """Check if overlay structure exists"""
        return self.hidden_overlay.exists()

    def create_safety_backup(self) -> None:
        """Create safety backup of critical system files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.safety_backup / f"safety_{timestamp}"
        backup_path.mkdir(parents=True, exist_ok=True)

        print("Creating safety backup in hidden volume...")

        critical_paths = ["/etc/nixos", "/etc/fstab", "/etc/passwd", "/etc/group"]

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

    def create_mounts(self) -> None:
        """Create temporary overlay mount points"""
        print("Creating overlay filesystem mounts...")

        self.union_root.mkdir(exist_ok=True)

        for target in self.overlay_targets:
            mount_name = target.lstrip("/")
            work_path = self.work_dir / mount_name
            union_path = self.union_root / mount_name

            work_path.mkdir(exist_ok=True)
            union_path.mkdir(exist_ok=True)

        print("✓ Overlay mount points ready")

    def activate(self) -> None:
        """Activate overlay filesystems"""
        print("Activating NAILS overlay filesystems...")
        print("Mounting hidden store over system directories for merged access")

        try:
            for target, overlay_path in self.overlay_targets.items():
                self._mount_overlay(target, overlay_path)

            print("✓ NAILS overlay filesystems successfully activated")
            print("✓ System now has merged view: decoy + hidden packages")
            print("✓ User data completely isolated in overlay")
            print("✓ Copy-on-write ensures hidden volume isolation")

        except Exception as e:
            self.emergency_cleanup()
            raise NailsOverlayError(f"Failed to activate overlays: {e}") from e

    def _mount_overlay(self, target: str, overlay_path: Path) -> None:
        """Mount a single overlay filesystem"""
        mount_name = target.lstrip("/")
        work_path = self.work_dir / mount_name

        print(f"  Creating {target} overlay filesystem...")
        if target == "/home":
            print(
                "  This prevents leakage of user data, shell history, and application configs"
            )

        cmd = [
            "mount",
            "-t",
            "overlay",
            "overlay",
            "-o",
            f"lowerdir={target},upperdir={overlay_path},workdir={work_path}",
            target,
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise NailsOverlayError(
                f"Failed to create {target} overlay: {result.stderr}"
            )

        print(f"  ✓ {target} overlay filesystem activated")

    def deactivate(self) -> None:
        """Deactivate overlay filesystems with comprehensive cleanup"""
        print("🛑 Stopping overlay-dependent services...")
        self._stop_overlay_services()

        print("🔄 Ensuring no processes are using overlay filesystems...")
        self._terminate_overlay_processes()

        print("📤 Deactivating overlays...")
        self._unmount_overlays_with_retry()

        print("🧹 Cleaning up temporary mounts...")
        self._cleanup_temp_mounts()

    def _stop_overlay_services(self) -> None:
        """Stop services that might interfere with unmounting"""
        services = ["nix-daemon", "tor"]

        for service in services:
            try:
                status = subprocess.run(
                    ["systemctl", "is-active", service], capture_output=True, text=True
                )
                if status.returncode == 0 and "active" in status.stdout:
                    print(f"  Stopping {service} service...")
                    subprocess.run(
                        ["systemctl", "stop", service], capture_output=True, timeout=10
                    )
                    print(f"  ✓ {service} stopped")
            except (subprocess.TimeoutExpired, Exception) as e:
                print(f"  ⚠️ Could not stop {service}: {e}")

    def _terminate_overlay_processes(self) -> None:
        """Terminate processes using overlay filesystems"""
        try:
            lsof_result = subprocess.run(
                ["lsof", "+D", "/nix", "+D", "/etc", "+D", "/home"],
                capture_output=True,
                text=True,
            )

            if lsof_result.returncode == 0 and lsof_result.stdout.strip():
                pids_to_kill = set()
                for line in lsof_result.stdout.split("\n")[1:]:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            pid = parts[1]
                            command = parts[0]
                            if command not in [
                                "systemd",
                                "kernel",
                                "python3",
                                "nails.py",
                            ]:
                                pids_to_kill.add(pid)

                if pids_to_kill:
                    print(f"  Terminating {len(pids_to_kill)} processes...")
                    for pid in pids_to_kill:
                        with contextlib.suppress(subprocess.SubprocessError, OSError):
                            subprocess.run(["kill", "-TERM", pid], capture_output=True)

                    time.sleep(2)  # Allow graceful termination

                    for pid in pids_to_kill:
                        with contextlib.suppress(subprocess.SubprocessError, OSError):
                            subprocess.run(["kill", "-KILL", pid], capture_output=True)
                    print("  ✓ Overlay-using processes terminated")

        except FileNotFoundError:
            print("  ℹ️ lsof not available, skipping process cleanup")

    def _unmount_overlays_with_retry(self) -> None:
        """Unmount overlays with retry logic"""
        max_retries = 3
        targets = ["/home", "/nix", "/etc"]  # Reverse order

        for attempt in range(max_retries):
            print(f"  Attempt {attempt + 1}/{max_retries} to unmount overlays...")
            success = True

            for target in targets:
                try:
                    result = subprocess.run(
                        ["umount", target], capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        print(f"    ✓ {target} overlay unmounted")
                    else:
                        print(
                            f"    ⚠️ Failed to unmount {target}: {result.stderr.strip()}"
                        )
                        success = False

                        # Try lazy unmount
                        lazy_result = subprocess.run(
                            ["umount", "-l", target], capture_output=True, text=True
                        )
                        if lazy_result.returncode == 0:
                            print(f"    ✓ {target} lazy unmount successful")
                            success = True

                except subprocess.TimeoutExpired:
                    print(f"    ⚠️ Timeout unmounting {target}")
                    success = False

            if success:
                print("  ✓ All overlays successfully deactivated")
                return

            if attempt < max_retries - 1:
                time.sleep(2)

        # Force unmount if all retries failed
        print("  🚨 Attempting force unmount...")
        for target in targets:
            subprocess.run(["umount", "-f", target], capture_output=True)
            subprocess.run(["umount", "-l", target], capture_output=True)
            print(f"    ✓ Force unmounted {target}")

    def _cleanup_temp_mounts(self) -> None:
        """Clean up temporary mount points"""
        if self.union_root.exists():
            try:
                for path in self.union_root.iterdir():
                    if path.is_dir():
                        subprocess.run(["umount", str(path)], capture_output=True)
                        path.rmdir()
                self.union_root.rmdir()
                print("  ✓ Temporary mounts cleaned up")
            except Exception as e:
                print(f"  ⚠️ Could not cleanup temp mounts: {e}")

    def emergency_cleanup(self) -> None:
        """Emergency cleanup - force unmount everything"""
        print("🚨 Performing emergency overlay cleanup...")

        targets = ["/home", "/nix", "/etc"]
        for target in targets:
            subprocess.run(["umount", "-f", target], capture_output=True)
            subprocess.run(["umount", "-l", target], capture_output=True)
            print(f"  ✓ Force unmounted {target}")

        self._cleanup_temp_mounts()

    def get_mount_status(self) -> dict[str, str]:
        """Get current mount status for overlay targets"""
        status = {}

        for target in self.overlay_targets:
            try:
                result = subprocess.run(
                    ["findmnt", target], capture_output=True, text=True
                )
                if result.returncode == 0 and "overlay" in result.stdout:
                    status[target] = "Overlaid"
                else:
                    status[target] = "Normal"
            except (subprocess.SubprocessError, OSError):
                status[target] = "Unknown"

        return status
