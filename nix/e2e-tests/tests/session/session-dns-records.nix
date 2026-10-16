# The hidden session's DNS settings never reach the decoy.
#
# On a decoy that keeps its name servers with openresolv (the NixOS default
# without systemd-resolved), NetworkManager hands every DNS update to
# resolvconf, which keeps it as a record below /run/resolvconf, and
# NetworkManager leaves that record in place when it stops. A soft-reboot
# carries /run, and the decoy's resolvconf.service rebuilds /etc/resolv.conf on
# the decoy disk from those records at every start, before NetworkManager runs:
# a record the hidden session left would put the hidden name servers and search
# domains there.
#
#   1. In the hidden session, NetworkManager brings up a connection with a name
#      server and a search domain that only the hidden session uses.
#   2. After deactivate, none of them is in the records below /run/resolvconf,
#      in /etc/resolv.conf as the decoy's resolvconf.service wrote it at the
#      decoy's start (a probe copies it before NetworkManager starts), in
#      /etc/resolv.conf now, or in the decoy journal.
#
# The dummy link the hidden connection runs on is logged, not asserted: a
# soft-reboot keeps the kernel's network state, so the link stays up in the
# decoy with its address and route until power-off, and the decoy's
# NetworkManager adopts it. That is a documented residual channel (the
# residue catalog's network-state row), not something the way back undoes.
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
      environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.nails ];
      # NetworkManager runs the user-mode network in place of dhcpcd, and
      # leaves the test network's static address alone.
      networking.useDHCP = lib.mkForce false;
      networking.networkmanager = {
        enable = true;
        unmanaged = [ "eth1" ];
      };
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


    def records():
        return machine.succeed(
            "find /run/resolvconf -type f -print -exec cat {} \\; 2>/dev/null || true"
        )


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

    with subtest("the hidden session's NetworkManager registers its own name server"):
        canonical_activate(CONFIG, "--overlay-only", "activate")
        machine.wait_for_unit("NetworkManager.service")
        machine.succeed(
            "nmcli connection add type dummy ifname dns0 con-name probe "
            "ipv4.method manual ipv4.addresses 10.213.77.2/24 "
            f"ipv4.dns {SERVER} ipv4.dns-search {DOMAIN} ipv6.method disabled"
        )
        machine.succeed("nmcli connection up probe")
        machine.wait_until_succeeds(f"grep -q {DOMAIN} /etc/resolv.conf", timeout=60)
        hidden = records()
        machine.log(f"the records in the hidden session:\n{hidden}")
        assert DOMAIN in hidden, hidden

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
        _, journal = machine.execute(f"journalctl -b --no-pager | grep -F {DOMAIN}")
        _, link = machine.execute("ip -brief address show dns0 2>&1")
        machine.log(
            "after the way back:\n"
            f"/etc/resolv.conf at the decoy's start:\n{at_start}\n"
            f"/etc/resolv.conf now:\n{now}\n"
            f"the records:\n{after}\n"
            f"journal lines naming the hidden domain:\n{journal}\n"
            f"the hidden session's dummy link: {link}"
        )
        for where, text in [
            ("/etc/resolv.conf at the decoy's start", at_start),
            ("/etc/resolv.conf", now),
            ("the records below /run/resolvconf", after),
            ("the decoy journal", journal),
        ]:
            assert DOMAIN not in text and SERVER not in text, f"{where}:\n{text}"
  '';
}
