# Optional hidden-session network identity for a NixOS host.
#
# The overlay shares the host's network identity (machine-id, hostname, MAC
# addresses, NetworkManager/VPN profiles) between the decoy and the hidden
# session; correlation through these identifiers is out of scope for the overlay
# alone. Import this module into the *hidden* NixOS generation to give the hidden
# session a different network identity. It takes effect only once the hidden
# switch runs before the session restarts, so it is a hidden-generation setting,
# not an activation-time one.
#
# This is a template: set `networking.hostName` to a plausible, decoy-unrelated
# value. The file cannot be evaluated in the development sandbox (the Nix daemon
# is unavailable); evaluate it with the rest of the hidden configuration on a Nix
# host.

{ lib, ... }:
{
  # A distinct hostname for the hidden session. Choose something unremarkable and
  # unrelated to the decoy; the default below is a placeholder.
  networking.hostName = lib.mkDefault "localhost";

  networking.networkmanager = {
    # Randomise the Wi-Fi and Ethernet MAC addresses so the hidden session does
    # not reuse the decoy's hardware addresses on the network.
    wifi.macAddress = lib.mkDefault "random";
    ethernet.macAddress = lib.mkDefault "random";

    # Do not auto-connect saved VPNs in the hidden session: a VPN that dials out
    # under the decoy's profile is a correlation and leak hazard.
    settings.connection."vpn.autoconnect" = lib.mkDefault false;
  };
}
