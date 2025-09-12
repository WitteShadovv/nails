"""
Configuration management for NAILS hidden system
"""

from pathlib import Path


class ConfigManager:
    """Manages NAILS configuration files and templates"""

    def __init__(self, hidden_volume_root: Path):
        self.hidden_volume_root = hidden_volume_root
        self.config_dir = hidden_volume_root / "config"

    def config_exists(self) -> bool:
        """Check if hidden configuration exists"""
        return (self.config_dir / "configuration.nix").exists()

    def create_initial_configs(self) -> None:
        """Create initial configuration files"""
        self.config_dir.mkdir(exist_ok=True)

        # Create main configuration
        config_content = """{ config, pkgs, lib, ... }:

{
  # NAILS Hidden Configuration - Extends Existing System Config
  # This imports the existing system config and adds hidden functionality

  # Import the existing system configuration as base
  imports = [ /etc/nixos/configuration.nix ];

  # Hidden packages (additional to existing system packages)
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

    # Forensics/Security tools
    # wireshark
    nmap
    tor-browser
    # hashcat
  ];

  # Hidden services (additional to existing services)
  services.tor = {
    enable = true;
    client.enable = true;
  };

  # Uncomment additional services if needed
  # services.openssh.enable = lib.mkForce true;  # Force enable SSH even if disabled in decoy

  # Hidden user (exists only when overlay is active)
  users.users.ghost = {
    isNormalUser = true;
    description = "Hidden user - untraceable";
    extraGroups = [ "wheel" "networkmanager" ];
    # Set password with: sudo passwd ghost (after activation)
  };

  # Hidden environment variables
  environment.variables = {
    NAILS_ACTIVE = "true";
    HIDDEN_MODE = "overlay";
  };

  # Hidden shell aliases
  environment.shellAliases = {
    nails-status = "echo 'NAILS overlay mode active - fully untraceable'";
    nails-deactivate = "sudo ${toString ./../..}/nails.py deactivate";
    secure-delete = "shred -vfz -n 3";
    clear-traces = "history -c && history -w && sync";
    hidden-rebuild = "sudo nixos-rebuild switch -I nixos-config=${toString ./.}/configuration.nix";
  };

  # Optional: Override specific settings from base config if needed
  # networking.firewall.enable = lib.mkForce false;  # Disable firewall in hidden mode

  # Ensure system state version matches base system
  # system.stateVersion will be inherited from base config
}"""

        config_file = self.config_dir / "configuration.nix"
        with open(config_file, "w") as f:
            f.write(config_content)

        # Create hardware config template
        hardware_content = """{ config, lib, pkgs, modulesPath, ... }:

{
  # Hardware configuration for hidden system
  # This extends the host hardware config safely

  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];

  # Use host's hardware config as base
  # Additional hidden hardware settings can go here
}"""

        hardware_file = self.config_dir / "hardware-configuration.nix"
        with open(hardware_file, "w") as f:
            f.write(hardware_content)

        print(f"✓ Hidden configuration created: {config_file}")
        print(f"✓ Hardware configuration created: {hardware_file}")

    def get_config_path(self) -> Path:
        """Get path to main configuration file"""
        return self.config_dir / "configuration.nix"
