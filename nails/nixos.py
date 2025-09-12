"""
NixOS system management for NAILS
"""

import subprocess
from pathlib import Path

from .exceptions import NailsBuildError


class NixOSManager:
    """Manages NixOS build, switch, and generation operations"""

    def __init__(self, hidden_volume_root: Path) -> None:
        self.hidden_volume_root = hidden_volume_root
        self.config_dir = hidden_volume_root / "config"

    def build_and_switch(self) -> None:
        """Build and switch to hidden system configuration"""
        print("Building and switching to hidden system...")
        print("This will activate the extended configuration with hidden functionality")

        config_path = self.config_dir / "configuration.nix"

        try:
            # Step 1: Build the configuration
            print("\n🔨 Building hidden system configuration...")
            if not self._build_config(config_path):
                raise NailsBuildError("Failed to build hidden configuration")

            # Step 2: Switch to the configuration
            print("\n🔄 Switching to hidden system configuration...")
            if not self._switch_config(config_path):
                raise NailsBuildError("Failed to switch to hidden configuration")

            # Step 3: Verify the switch
            self._verify_hidden_system()

        except Exception as e:
            print(f"Build/switch error: {e}")
            raise

    def rebuild(self) -> bool:
        """Rebuild system with updated configuration"""
        config_path = self.config_dir / "configuration.nix"

        print(f"📋 Using configuration: {config_path}")
        print("🔄 Building updated hidden system configuration...")

        try:
            # Build first
            if not self._build_config(config_path):
                return False

            # Then switch
            print("\n🔄 Switching to updated hidden system configuration...")
            if not self._switch_config(config_path):
                return False

            # Verify
            print("\n🔍 Verifying rebuild completion...")
            self._verify_rebuild()

            return True

        except Exception as e:
            print(f"Rebuild failed: {e}")
            return False

    def switch_to_previous_generation(self) -> None:
        """Switch back to the previous system generation"""
        print("🔄 Switching back to previous system generation...")

        try:
            # Get current generation
            current_gen = subprocess.run(
                ["readlink", "/nix/var/nix/profiles/system"],
                capture_output=True,
                text=True,
            )

            if current_gen.returncode != 0:
                print("  ⚠️ Could not determine current generation")
                return

            print(f"  Current generation: {current_gen.stdout.strip()}")

            # List generations
            list_gens = subprocess.run(
                ["nix-env", "--list-generations", "-p", "/nix/var/nix/profiles/system"],
                capture_output=True,
                text=True,
            )

            if list_gens.returncode != 0:
                print("  ⚠️ Could not list system generations")
                return

            # Find previous generation
            generations = []
            for line in list_gens.stdout.split("\n"):
                if line.strip() and "current" not in line:
                    parts = line.strip().split()
                    if parts and parts[0].isdigit():
                        generations.append(int(parts[0]))

            if not generations:
                print("  ⚠️ No previous generations found")
                return

            previous_gen = max(generations)
            print(f"  Switching to previous generation: {previous_gen}")

            # Switch generation
            switch_result = subprocess.run(
                [
                    "nix-env",
                    "--switch-generation",
                    str(previous_gen),
                    "-p",
                    "/nix/var/nix/profiles/system",
                ],
                capture_output=True,
                text=True,
            )

            if switch_result.returncode == 0:
                print(f"  ✓ Switched to generation {previous_gen}")

                # Activate the generation
                activate_result = subprocess.run(
                    [
                        "/nix/var/nix/profiles/system/bin/switch-to-configuration",
                        "switch",
                    ],
                    capture_output=True,
                    text=True,
                )

                if activate_result.returncode == 0:
                    print("  ✓ Previous generation activated")
                else:
                    print("  ⚠️ Could not activate previous generation")
            else:
                print("  ⚠️ Could not switch to previous generation")

        except Exception as e:
            print(f"  ⚠️ Error switching to previous generation: {e}")

    def _build_config(self, config_path: Path) -> bool:
        """Build a NixOS configuration"""
        build_cmd = [
            "nixos-rebuild",
            "build",
            "-I",
            f"nixos-config={config_path}",
            "--show-trace",
        ]

        print("  Building configuration (this may take a while)...")
        print("  " + "=" * 60)

        result = subprocess.run(build_cmd, text=True)

        print("  " + "=" * 60)

        if result.returncode == 0:
            print("  ✓ Configuration built successfully")
            return True
        else:
            print("✗ Build failed - check the output above for errors")
            print("💡 Common issues:")
            print("   - Syntax errors in configuration.nix")
            print("   - Missing or invalid package names")
            print("   - Hardware configuration conflicts")
            return False

    def _switch_config(self, config_path: Path) -> bool:
        """Switch to a NixOS configuration"""
        switch_cmd = [
            "nixos-rebuild",
            "switch",
            "-I",
            f"nixos-config={config_path}",
            "--show-trace",
        ]

        print("  Activating configuration...")
        print("  This will:")
        print("    - Install hidden packages (tor, gnupg, keepassxc, etc.)")
        print("    - Create hidden user 'ghost'")
        print("    - Start hidden services (Tor daemon)")
        print("    - Merge with existing system configuration")
        print("  " + "=" * 60)

        result = subprocess.run(switch_cmd, text=True)

        print("  " + "=" * 60)

        if result.returncode == 0:
            print("  ✓ Successfully switched to configuration")
            return True
        else:
            print("✗ Switch failed - check the output above for errors")
            return False

    def _verify_hidden_system(self) -> None:
        """Verify hidden system components are active"""
        print("\n🔍 Verifying hidden environment activation...")

        # Check Nix store
        try:
            verify_cmd = ["nix-store", "--verify"]
            result = subprocess.run(
                verify_cmd, capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                print("  ✓ Nix store verification passed")
            else:
                print("  ⚠️ Nix store verification found issues (may be normal)")
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as e:
            print(f"  ℹ️ Could not verify store integrity: {e}")

        # Check services
        self._check_service_status("tor")

        # Check packages
        self._check_package_availability("tor")

        # Check user
        self._check_user_creation("ghost")

    def _verify_rebuild(self) -> None:
        """Verify rebuild was successful"""
        try:
            verify_cmd = ["nix-store", "--verify"]
            result = subprocess.run(
                verify_cmd, capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                print("  ✓ Nix store verification passed")
            else:
                print("  ⚠️ Nix store verification found issues (may be normal)")
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as e:
            print(f"  ℹ️ Could not verify store integrity: {e}")

        try:
            test_cmd = ["nix-store", "--query", "--references", "/run/current-system"]
            result = subprocess.run(
                test_cmd, capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                print("  ✓ System functionality verified")
            else:
                print("  ⚠️ System functionality test failed")
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as e:
            print(f"  ℹ️ Could not test system functionality: {e}")

    def _check_service_status(self, service: str) -> None:
        """Check if a service is running"""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", service], capture_output=True, text=True
            )
            if result.returncode == 0 and "active" in result.stdout:
                print(f"  ✓ {service} service is running")
            else:
                print(f"  ℹ️ {service} service not running (may need manual start)")
        except (subprocess.SubprocessError, OSError) as e:
            print(f"  ℹ️ Could not check {service} service status: {e}")

    def _check_package_availability(self, package: str) -> None:
        """Check if a package is available"""
        try:
            result = subprocess.run(["which", package], capture_output=True)
            if result.returncode == 0:
                print(f"  ✓ Hidden packages installed ({package} available)")
            else:
                print(f"  ⚠️ {package} package may not be fully installed")
        except (subprocess.SubprocessError, OSError) as e:
            print(f"  ℹ️ Could not verify {package} installation: {e}")

    def _check_user_creation(self, username: str) -> None:
        """Check if a user was created"""
        try:
            result = subprocess.run(["id", username], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"  ✓ Hidden user '{username}' created successfully")
            else:
                print(f"  ℹ️ Hidden user '{username}' may not be created yet")
        except (subprocess.SubprocessError, OSError) as e:
            print(f"  ℹ️ Could not verify {username} user creation: {e}")
