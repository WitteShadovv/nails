# The hidden session's DNS settings never reach the decoy, and the way back
# puts back the network state this test's session sets up.
#
# On a decoy that keeps its name servers with openresolv (the NixOS default
# without systemd-resolved), NetworkManager hands every DNS update to
# resolvconf, which keeps it as a record below /run/resolvconf, and
# NetworkManager leaves that record in place when it stops. A soft-reboot
# carries /run, and the decoy's resolvconf.service rebuilds /etc/resolv.conf on
# the decoy disk from those records at every start, before NetworkManager runs:
# a record the hidden session left would put the hidden name servers and search
# domains there. A soft-reboot also keeps the kernel's network state, which the
# way back puts back before the switch.
#
#   1. In the hidden session, NetworkManager brings up a connection with a name
#      server and a search domain that only the hidden session uses, on a dummy
#      link of its own, from a profile it keeps only in memory (below
#      /run/NetworkManager, which it loads again at its next start). The
#      session also adds a WireGuard full tunnel's policy-routing rules and an
#      nftables table, turns forwarding on, sets arp_ignore as a VPN app does,
#      and sets a hostname of its own.
#   2. After deactivate, none of the hidden DNS settings is in the records below
#      /run/resolvconf, in /etc/resolv.conf as the decoy's resolvconf.service
#      wrote it at the decoy's start (a probe copies it before NetworkManager
#      starts), in /etc/resolv.conf now, in NetworkManager's device state and
#      in-memory profiles below /run/NetworkManager, or in the decoy journal.
#   3. The way back put the decoy's network state back: the dummy link, the
#      rules and the table are gone, the settings are the decoy's again, the
#      decoy's NetworkManager does not list the hidden profile, and the
#      hostname is the decoy's. The decoy's /etc/hostname names no host, so
#      PID 1 keeps whatever hostname it finds at every start, the return
#      included: only the way back sets the decoy's own name again.
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
      # nft: the way back reads the firewall tables with it.
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
      # start, before NetworkManager replaced it. It runs at every start of the
      # service manager, the decoy's return included.
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
    from nails_e2e import session

    ${testHelpers.canonicalActivateFn}

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
    machine.succeed("hostname decoy-probe")
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
    machine.log(f"the decoy's network state before the session: {decoy}")

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

    with subtest("no hidden DNS setting reaches the decoy after the way back"):
        session.follow_soft_reboot(
            machine, f"nails --config {CONFIG} deactivate -y", "deactivate"
        )
        session.assert_decoy_root(machine)
        machine.wait_for_unit("resolv-conf-at-start.service")
        machine.wait_for_unit("NetworkManager.service")
        at_start = machine.succeed("cat /run/resolv-conf-at-start")
        now = machine.succeed("cat /etc/resolv.conf")
        after = records()
        _, nm_runtime = machine.execute(
            f"grep -rhF --devices=skip -e {DOMAIN} -e {SERVER} "
            "/run/NetworkManager/devices /run/NetworkManager/system-connections"
        )
        _, journal = machine.execute(f"journalctl -b --no-pager | grep -F {DOMAIN}")
        machine.log(
            "after the way back:\n"
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

    with subtest("the way back puts the decoy's network state back"):
        machine.fail("ip link show dns0")
        profiles = machine.succeed("nmcli -g NAME connection show")
        assert "probe" not in profiles.split("\n"), profiles
        restored = network_state()
        machine.log(f"the network state after the way back: {restored}")
        assert restored == decoy, f"before: {decoy}\nafter: {restored}"
  '';
}
