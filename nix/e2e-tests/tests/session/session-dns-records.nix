# The hidden session's DNS settings and network state never reach the decoy.
#
# A hidden session never goes back to the decoy: it ends in a power-off, so
# neither the records NetworkManager leaves below /run/resolvconf nor the
# kernel's network state reach the decoy's next start, a cold boot. On a decoy
# that keeps its name servers with openresolv (the NixOS default without
# systemd-resolved), resolvconf.service rebuilds /etc/resolv.conf on the decoy
# disk at every start, before NetworkManager runs, from those records.
#
#   1. In the hidden session, NetworkManager brings up a connection with a name
#      server and a search domain that only the hidden session uses, on a dummy
#      link of its own, from a profile it keeps only in memory (below
#      /run/NetworkManager). The session also adds a WireGuard full tunnel's
#      policy-routing rules and an nftables table, turns forwarding on, sets
#      arp_ignore as a VPN app does, and sets a hostname of its own.
#   2. `nails deactivate` powers the machine off for real. After the cold boot
#      none of the hidden DNS settings is in the records below
#      /run/resolvconf, in /etc/resolv.conf as the decoy's resolvconf.service
#      wrote it at the decoy's start (a probe copies it before NetworkManager
#      starts), in /etc/resolv.conf now, in NetworkManager's device state and
#      in-memory profiles below /run/NetworkManager, or in the decoy journal.
#   3. The decoy's network state is that of its first boot: the dummy link,
#      the rules and the table are gone, the settings and the hostname are the
#      decoy's, and the decoy's NetworkManager does not list the hidden
#      profile.
{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "session-dns-records";
  meta.tags = [
    "security"
    "session"
  ];
  globalTimeout = 1200;

  nodes.machine =
    { lib, pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      # nft: the test makes and lists firewall tables with it. NAILS itself
      # asks the kernel over netlink and runs no nft.
      environment.systemPackages = [
        self.packages.${pkgs.stdenv.hostPlatform.system}.nails
        pkgs.nftables
      ];
      # NetworkManager runs the user-mode network in place of dhcpcd, and
      # leaves the test network's static address alone. The hostname is the
      # test's to set: NetworkManager never takes one from DHCP or a lookup.
      networking.useDHCP = lib.mkForce false;
      networking.networkmanager = {
        enable = true;
        unmanaged = [ "eth1" ];
        settings.main.hostname-mode = "none";
      };
      # An /etc/hostname that names no host.
      environment.etc.hostname.text = lib.mkForce "";
      # What the decoy's resolvconf.service wrote into /etc/resolv.conf at its
      # start, before NetworkManager replaced it. It runs at every boot.
      systemd.services.resolv-conf-at-start = {
        after = [ "resolvconf.service" ];
        before = [ "NetworkManager.service" ];
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = "${pkgs.coreutils}/bin/cp /etc/resolv.conf /run/resolv-conf-at-start";
      };
    };

  testScript = _: ''
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    # Used by the hidden session only.
    SERVER = "10.213.77.53"
    DOMAIN = "dnsprobe-hidden.example"
    SETTINGS = ["net.ipv4.ip_forward", "net.ipv4.conf.all.arp_ignore"]


    def records():
        return machine.succeed(
            "find /run/resolvconf -type f -print -exec cat {} \\; 2>/dev/null || true"
        )


    def network_state():
        return {
            "rules": machine.succeed("ip -4 rule show; ip -6 rule show"),
            "tables": machine.succeed("nft list tables"),
            "settings": machine.succeed("sysctl " + " ".join(SETTINGS)),
            "hostname": machine.succeed("hostname").strip(),
        }


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("NetworkManager.service")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "EOF"
    )
    machine.log(f"the decoy's records before the session:\n{records()}")
    decoy = network_state()
    machine.log(f"the decoy's network state at its first boot: {decoy}")

    with subtest("the hidden session's NetworkManager registers its own name server"):
        canonical_activate(CONFIG, "--overlay-only", "activate")
        machine.wait_for_unit("NetworkManager.service")
        machine.succeed(
            "nmcli connection add save no type dummy ifname dns0 con-name probe "
            "ipv4.method manual ipv4.addresses 10.213.77.2/24 "
            f"ipv4.dns {SERVER} ipv4.dns-search {DOMAIN} ipv6.method disabled"
        )
        machine.succeed("nmcli connection up probe")
        machine.wait_until_succeeds(f"grep -q {DOMAIN} /etc/resolv.conf", timeout=60)
        hidden = records()
        machine.log(f"the records in the hidden session:\n{hidden}")
        assert DOMAIN in hidden, hidden
        machine.succeed(
            f"grep -rlF --devices=skip {DOMAIN} /run/NetworkManager/system-connections"
        )

    with subtest("the hidden session changes the kernel's network state"):
        for family in ["-4", "-6"]:
            machine.succeed(f"ip {family} rule add not fwmark 51820 table 51820")
            machine.succeed(f"ip {family} rule add table main suppress_prefixlength 0")
        machine.succeed("nft add table inet hiddenprobe")
        machine.succeed("sysctl -w net.ipv4.ip_forward=1 net.ipv4.conf.all.arp_ignore=2")
        machine.succeed("hostname hidden-probe")
        changed = network_state()
        machine.log(f"the network state in the hidden session: {changed}")
        for part in decoy:
            assert changed[part] != decoy[part], f"the session did not change {part}"

    with subtest("no hidden DNS setting reaches the decoy after the power-off"):
        canonical_deactivate(CONFIG, "deactivate")
        machine.wait_for_unit("resolv-conf-at-start.service")
        machine.wait_for_unit("NetworkManager.service")
        at_start = machine.succeed("cat /run/resolv-conf-at-start")
        now = machine.succeed("cat /etc/resolv.conf")
        after = records()
        _, nm_runtime = machine.execute(
            f"grep -rhF --devices=skip -e {DOMAIN} -e {SERVER} "
            "/run/NetworkManager/devices /run/NetworkManager/system-connections"
        )
        # Every boot the decoy journal kept, not only this one.
        _, journal = machine.execute(f"journalctl --no-pager | grep -F {DOMAIN}")
        machine.log(
            "after the cold boot:\n"
            f"/etc/resolv.conf at the decoy's start:\n{at_start}\n"
            f"/etc/resolv.conf now:\n{now}\n"
            f"the records:\n{after}\n"
            f"NetworkManager's runtime state naming them:\n{nm_runtime}\n"
            f"journal lines naming the hidden domain:\n{journal}"
        )
        for where, text in [
            ("/etc/resolv.conf at the decoy's start", at_start),
            ("/etc/resolv.conf", now),
            ("the records below /run/resolvconf", after),
            ("NetworkManager's device state and in-memory profiles", nm_runtime),
            ("the decoy journal", journal),
        ]:
            assert DOMAIN not in text and SERVER not in text, f"{where}:\n{text}"

    with subtest("the decoy's network state after the cold boot is its first boot's"):
        machine.fail("ip link show dns0")
        profiles = machine.succeed("nmcli -g NAME connection show")
        assert "probe" not in profiles.split("\n"), profiles
        restored = network_state()
        machine.log(f"the network state after the cold boot: {restored}")
        assert restored == decoy, f"before: {decoy}\nafter: {restored}"
  '';
}
