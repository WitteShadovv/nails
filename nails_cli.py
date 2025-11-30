#!/usr/bin/env python3
"""
NAILS - NixOS Anti-forensics Isolation & Layering System
Main entry point and command-line interface
"""

import argparse
import sys
from pathlib import Path

# Handle both installed package and development modes
try:
    from nails.exceptions import NailsError
    from nails.manager import NailsManager
except ImportError:
    # Development mode - add current directory to path
    sys.path.insert(0, str(Path(__file__).parent))
    from nails.exceptions import NailsError
    from nails.manager import NailsManager


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NAILS - NixOS Anti-forensics using Safe Overlay System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nails init                 # Initialize hidden config
  sudo nails activate        # Activate hidden environment
  sudo nails deactivate      # Return to decoy system
  sudo nails rebuild         # Rebuild with current hidden config
  nails status               # Show current status
  sudo nails emergency-clean # Emergency restore to decoy

Safe Overlay Mode:
✓ Completely untraceable using overlay filesystems
✓ All state stored in hidden volume (untraceable when unmounted)
✓ Conditional configurations only active when marker present
✓ Emergency cleanup always available
✓ Maintains 100% plausible deniability
        """,
    )

    parser.add_argument(
        "command",
        choices=[
            "init",
            "activate",
            "deactivate",
            "rebuild",
            "status",
            "emergency-clean",
        ],
    )
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
    except NailsError as e:
        print(f"NAILS Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
