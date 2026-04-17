{ lib, pkgs, ... }: {
  imports = [ ./vm-config.nix ];

  swapDevices = lib.mkForce [ ];

  virtualisation.emptyDiskImages = lib.mkForce [ 2048 ];

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

  environment.systemPackages = with pkgs; [ zsh fish libnotify xterm ];
}
