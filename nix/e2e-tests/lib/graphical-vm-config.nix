{ lib, pkgs, ... }:
{
  imports = [ ./vm-config.nix ];

  swapDevices = lib.mkForce [ ];

  # The X server and the desktop session need more than the 2 GB base size.
  virtualisation.memorySize = lib.mkForce 4096;

  services = {
    xserver = {
      enable = true;
      displayManager.lightdm.enable = true;
      # A real window manager is the session's main process, and a terminal
      # emulator runs *inside* it. This mirrors an ordinary desktop: the shell
      # in a terminal window is an ordinary child, so closing (or killing) it
      # tears down only that window, while the window manager keeps the logind
      # session alive. The earlier bare-xterm "desktop" made the terminal's own
      # shell the session's main client, so killing that shell ended the whole
      # session — an artifact of the test VM, not of how a desktop behaves.
      windowManager.icewm.enable = true;
      # Launch a terminal with an interactive login shell in the background
      # before the window manager (the session's main process) starts.
      displayManager.sessionCommands = ''
        ${pkgs.xterm}/bin/xterm &
      '';
    };
    displayManager = {
      autoLogin = {
        enable = true;
        user = "testuser";
      };
      defaultSession = "none+icewm";
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
