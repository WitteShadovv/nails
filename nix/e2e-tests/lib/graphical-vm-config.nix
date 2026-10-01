{ lib, pkgs, ... }:
{
  imports = [ ./vm-config.nix ];

  swapDevices = lib.mkForce [ ];

  virtualisation.emptyDiskImages = lib.mkForce [ 2048 ];
  # The X server and the desktop session need more than the 2 GB base size.
  virtualisation.memorySize = lib.mkForce 4096;

  services = {
    xserver = {
      enable = true;
      displayManager.lightdm.enable = true;
      desktopManager.xterm.enable = true;
    };
    displayManager.autoLogin = {
      enable = true;
      user = "testuser";
    };
  };

  programs.zsh.enable = true;
  programs.fish.enable = true;

  environment.systemPackages = with pkgs; [
    zsh
    fish
    libnotify
    xterm
  ];
}
