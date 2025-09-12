"""
State management for NAILS operations
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path


class StateManager:
    """Manages NAILS operational state tracking"""

    def __init__(self, hidden_volume_root: Path):
        self.hidden_volume_root = hidden_volume_root
        self.state_file = hidden_volume_root / ".nails-state"

    def is_active(self) -> bool:
        """Check if NAILS overlay filesystems are currently active"""
        if not self.state_file.exists():
            return False

        # Verify overlays are actually mounted
        try:
            etc_result = subprocess.run(
                ["findmnt", "/etc"], capture_output=True, text=True
            )
            etc_mounted = etc_result.returncode == 0 and "overlay" in etc_result.stdout

            nix_result = subprocess.run(
                ["findmnt", "/nix"], capture_output=True, text=True
            )
            nix_mounted = nix_result.returncode == 0 and "overlay" in nix_result.stdout

            home_result = subprocess.run(
                ["findmnt", "/home"], capture_output=True, text=True
            )
            home_mounted = (
                home_result.returncode == 0 and "overlay" in home_result.stdout
            )

            return etc_mounted and nix_mounted and home_mounted
        except (subprocess.SubprocessError, OSError):
            return False

    def save_active_state(self) -> None:
        """Save active state to hidden volume"""
        state = {
            "active": True,
            "activated_at": datetime.now().isoformat(),
            "method": "safe_overlay",
            "overlays": {"etc": "/etc", "nix": "/nix", "home": "/home"},
            "hidden_volume": str(self.hidden_volume_root),
            "version": "1.0.0",
        }

        with open(self.state_file, "w") as f:
            json.dump(state, f, indent=2)

    def get_activation_time(self) -> str | None:
        """Get activation timestamp if available"""
        if self.state_file.exists():
            try:
                with open(self.state_file) as f:
                    state = json.load(f)
                activation_time = state.get("activated_at", "unknown")
                return str(activation_time) if activation_time is not None else None
            except (json.JSONDecodeError, OSError) as e:
                print(f"Warning: Could not read state file: {e}")
        return None

    def clear_state(self) -> None:
        """Clear state file"""
        if self.state_file.exists():
            self.state_file.unlink()

    def get_state_info(self) -> dict[str, str]:
        """Get complete state information"""
        if self.state_file.exists():
            try:
                with open(self.state_file) as f:
                    data = json.load(f)
                # Convert all values to strings to match the return type
                return {str(k): str(v) for k, v in data.items()}
            except (json.JSONDecodeError, OSError) as e:
                print(f"Warning: Could not read state file: {e}")
        return {}
