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
# The hidden configuration imports the decoy configuration, which normally sets
# these options itself, so they are forced here: a default-priority value would
# silently lose to the decoy's definition.
#
# This is a template: set `networking.hostName` to a plausible, decoy-unrelated
# value. The file cannot be evaluated in the development sandbox (the Nix daemon
# is unavailable); evaluate it with the rest of the hidden configuration on a Nix
# host.
#
# NetworkManager has no global switch for VPN autoconnect, so it is not set
# here. Disable it per profile from the hidden session instead (see the user
# security guide); with /etc overlaid the change lands only in the hidden upper.
#
# The way back to the decoy does not undo what this changes on the running
# system: the random MAC address can stay on the decoy's own device (a decoy
# profile that sets no MAC address keeps the current one), and on a decoy
# without /etc/hostname the hostname stays too. End a session that used this
# module with `nails deactivate --poweroff`.

{ lib, ... }:
{
  # A distinct hostname for the hidden session. Choose something unremarkable and
  # unrelated to the decoy; the value below is a placeholder.
  networking.hostName = lib.mkForce "localhost";

  # Randomise the Wi-Fi and Ethernet MAC addresses so the hidden session does
  # not reuse the decoy's hardware addresses on the network.
  networking.networkmanager = {
    wifi.macAddress = lib.mkForce "random";
    ethernet.macAddress = lib.mkForce "random";
  };
}
