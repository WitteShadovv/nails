#!/bin/bash
# NAILS Installation Script for VeraCrypt Hidden Volume Setup

set -e

echo "NAILS - VeraCrypt Hidden Volume Setup"
echo "====================================="

# Check if running on NixOS
if [[ ! -f /etc/nixos/configuration.nix ]]; then
    echo "Error: This system does not appear to be running NixOS"
    exit 1
fi

# Check if we're in a directory that looks like a hidden volume
if [[ ! -w "." ]]; then
    echo "Error: Current directory is not writable"
    exit 1
fi

echo "Setting up NAILS in: $(pwd)"

# Make the main script executable
chmod +x nails-overlay.py

# Create the hidden nix store structure
echo "Creating hidden Nix store structure..."
mkdir -p nix/store
mkdir -p nix/var/nix/{profiles,gcroots}
mkdir -p config
mkdir -p data
mkdir -p backups

# Initialize empty Nix database in hidden store
if command -v nix-store >/dev/null 2>&1; then
    echo "Initializing hidden Nix database..."
    # This creates the basic database structure
    NIX_STATE_DIR="$(pwd)/nix/var/nix" nix-store --init || true
fi

# Create a basic hidden configuration if none exists
if [[ ! -f config/configuration.nix ]]; then
    echo "Creating default hidden configuration..."
    cat > config/configuration.nix << 'EOF'
{ config, pkgs, ... }:

{
  imports = [ ./hardware-configuration.nix ];

  # Hidden environment packages
  environment.systemPackages = with pkgs; [
    # Core utilities
    vim
    git
    curl
    wget
    tmux

    # Security tools (uncomment as needed)
    # tor
    # gnupg
    # nmap
    # wireshark

    # Development tools (uncomment as needed)
    # python3
    # nodejs
    # docker
  ];

  # Minimal services for stealth
  services = {
    openssh.enable = false;  # Disabled by default for stealth
  };

  # Hidden user configuration
  users.users.ghost = {
    isNormalUser = true;
    description = "Hidden user";
    extraGroups = [ "wheel" "networkmanager" ];
    # Set password with: passwd ghost
  };

  # System settings
  time.timeZone = "UTC";  # Avoid timezone fingerprinting

  # Disable unnecessary services for minimal footprint
  services.avahi.enable = false;
  services.printing.enable = false;

  system.stateVersion = "23.11"; # Update to match your NixOS version
}
EOF
fi

# Copy hardware configuration from system
if [[ -f /etc/nixos/hardware-configuration.nix ]] && [[ ! -f config/hardware-configuration.nix ]]; then
    echo "Copying hardware configuration..."
    cp /etc/nixos/hardware-configuration.nix config/
fi

# Create a helper script for common operations
cat > nails-helper.sh << 'EOF'
#!/bin/bash
# NAILS Helper Script - Common operations for hidden volume

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$1" in
    "build-hidden")
        echo "Building hidden environment..."
        cd "$SCRIPT_DIR/config"
        nixos-rebuild build -I nixos-config=./configuration.nix
        ;;
    "test-hidden")
        echo "Testing hidden configuration..."
        cd "$SCRIPT_DIR/config"
        nixos-rebuild dry-build -I nixos-config=./configuration.nix
        ;;
    "populate-store")
        echo "Populating hidden store with packages..."
        cd "$SCRIPT_DIR/config"
        # Build the system and copy to hidden store
        result=$(nixos-rebuild build -I nixos-config=./configuration.nix --no-out-link)
        if [[ -n "$result" ]]; then
            echo "Copying packages to hidden store..."
            nix-store --export $(nix-store -qR "$result") | \
                NIX_STATE_DIR="$SCRIPT_DIR/nix/var/nix" nix-store --import
        fi
        ;;
    "status")
        "$SCRIPT_DIR/nails-overlay.py" status
        ;;
    "activate")
        echo "Activating hidden environment (requires root)..."
        sudo "$SCRIPT_DIR/nails-overlay.py" activate
        ;;
    "deactivate")
        echo "Deactivating hidden environment (requires root)..."
        sudo "$SCRIPT_DIR/nails-overlay.py" deactivate
        ;;
    *)
        echo "Usage: $0 {build-hidden|test-hidden|populate-store|status|activate|deactivate}"
        echo ""
        echo "  build-hidden    Build hidden configuration"
        echo "  test-hidden     Test hidden configuration (dry-run)"
        echo "  populate-store  Build and populate hidden nix store"
        echo "  status          Show overlay status"
        echo "  activate        Activate hidden environment"
        echo "  deactivate      Deactivate hidden environment"
        ;;
esac
EOF

chmod +x nails-helper.sh

# Create systemd service file for emergency cleanup
cat > nails-emergency.service << 'EOF'
[Unit]
Description=NAILS Emergency Cleanup
DefaultDependencies=false
Before=shutdown.target reboot.target halt.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'if mountpoint -q /nix && grep -q overlay /proc/mounts; then umount -f /nix; fi'
ExecStart=/bin/bash -c 'rm -rf /tmp/nails-*'
TimeoutSec=10
RemainAfterExit=true

[Install]
WantedBy=shutdown.target reboot.target halt.target
EOF

echo ""
echo "NAILS setup complete!"
echo "===================="
echo ""
echo "Next steps:"
echo "1. Edit config/configuration.nix to customize your hidden environment"
echo "2. Run: ./nails-helper.sh test-hidden    # Test configuration"
echo "3. Run: ./nails-helper.sh populate-store # Build and populate hidden store"
echo "4. Run: ./nails-helper.sh activate       # Activate hidden environment"
echo ""
echo "Files created:"
echo "  nails-overlay.py      - Main overlay management script"
echo "  nails-helper.sh       - Helper script for common operations"
echo "  config/               - Hidden system configuration"
echo "  nix/                  - Hidden Nix store"
echo "  data/                 - User data directory"
echo "  backups/              - System configuration backups"
echo ""
echo "Security Notes:"
echo "- This directory should be in a VeraCrypt hidden volume"
echo "- The hidden volume provides cryptographic plausible deniability"
echo "- Always use 'deactivate' before unmounting the hidden volume"
echo "- Consider installing the emergency cleanup service in your system"
