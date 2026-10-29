# Optional hidden-session network identity for a NixOS host.
#
# The overlay shares the host's network identity (machine-id, hostname, MAC
# addresses, NetworkManager/VPN profiles) between the decoy and the hidden
# session; correlation through these identifiers is out of scope for the overlay
# alone. Import this module into the hidden NixOS configuration to give the
# hidden session a different network identity. It takes effect when activation
# builds the hidden system (or `nixos-rebuild test` applies it in a hidden
# session, with `--flake <hidden-root>/nixos#<host> --impure` for a hidden
# flake), so it is a setting of the hidden system, never of the decoy. `<host>`
# is the decoy's hostname, the configuration activation builds: in a session
# that uses this module, `hostname` prints the hidden name instead.
#
# The hidden configuration imports the decoy configuration, which normally sets
# these options itself, so they are forced here: a default-priority value would
# silently lose to the decoy's definition.
#
# This is a template: set `networking.hostName` to a plausible, decoy-unrelated
# value. The `session-nixos-hidden-system` VM test builds a hidden system with it
# as it stands.
#
# NetworkManager has no global switch for VPN autoconnect, so it is not set
# here. Disable it per profile from the hidden session instead (see "Shared
# network identifiers" in docs/operator-guide.md); in the hidden session the
# change lands only in the hidden upper.
#
# The way back to the decoy undoes what this changes on the running system: it
# sets each device's MAC address back to the decoy's, taking the device down for
# the change when its driver refuses it while the device is up, and sets the
# hostname back. When a device's address still cannot be set back, the way back
# powers off instead of returning (a device keeps its current MAC address when
# the decoy's profile sets none), with one line on the console that says so;
# a device plugged in during the session is a new link and keeps the random
# address, and nothing tells you so. When the random address
# must never reach the decoy, end a session that used this module with
# `nails deactivate --poweroff` (or `nails emergency --poweroff`).

{ config, lib, ... }:
{
  networking = {
    # A distinct hostname for the hidden session. Choose something unremarkable
    # and unrelated to the decoy; the value below is a placeholder.
    hostName = lib.mkForce "localhost";

    # NixOS maps the hostname to 127.0.0.2 in /etc/hosts and refuses a system
    # that maps `localhost` anywhere but 127.0.0.1 and ::1, where it resolves
    # already: while the hostname is `localhost`, leave that mapping out.
    hosts."127.0.0.2" = lib.mkIf (config.networking.hostName == "localhost") (lib.mkForce [ ]);

    # Randomise the Wi-Fi and Ethernet MAC addresses so the hidden session does
    # not reuse the decoy's hardware addresses on the network.
    networkmanager = {
      wifi.macAddress = lib.mkForce "random";
      ethernet.macAddress = lib.mkForce "random";
    };
  };
}
