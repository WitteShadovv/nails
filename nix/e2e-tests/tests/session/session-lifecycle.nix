# The whole-root session end to end, through the real `nails` commands.
#
# Replaces the live-overlay basic workflow, re-activation, status/verify,
# emergency and backend-close tests:
#
#   1. `nails init` and `nails check` on the decoy;
#   2. `nails activate`: a soft-reboot into the root overlay. In the hidden
#      root `/` is the overlay with its upper on the hidden volume, a write
#      lands in the upper and never on the decoy filesystem, status reports
#      the session, and `verify --deep` finds nothing critical in the session
#      `nails init` seeded;
#   3. `nails deactivate`: the machine powers off for real (a hidden session
#      never goes back to the decoy), and the next cold boot is the plain
#      decoy with the hidden mapping closed, no NAILS runtime state and none of
#      the hidden files or lines: the decoy never saw the hidden file, and its
#      volatile journal holds neither the hidden session's line nor its own
#      from before the session;
#   4. a second activation finds the hidden file again (the upper persists);
#   5. `nails emergency` in the hidden session kills a hidden service and the
#      login session at once and powers off, with its phases timed in the log
#      on the hidden volume;
#   6. `nails recover` and `nails emergency` on the plain decoy are no-ops.
#
# Throughout, eth1 keeps the static addresses the test framework gives it on
# the test network (`networking.interfaces.eth1`): in both hidden sessions,
# and on the decoy after each cold boot. NixOS applies them with
# network-addresses-eth1.service, whose stop deletes them, and the session
# clears that stop at the entry (STOP_GUARDED_UNITS in nails-teardown). Each
# place where eth1 lacks an address or is down is recorded, and the test fails
# at the end naming them all.
_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;

  # The static addresses `node` has on eth1, as address/prefix, as NixOS's
  # scripted networking adds them: the IPv6 ones only where IPv6 is enabled.
  staticAddresses =
    node:
    let
      inherit (node.networking.interfaces) eth1;
    in
    map (a: "${a.address}/${toString a.prefixLength}") (
      eth1.ipv4.addresses ++ (if node.networking.enableIPv6 then eth1.ipv6.addresses else [ ])
    );
in
{
  name = "session-lifecycle";
  meta.tags = [
    "smoke"
    "lifecycle"
    "session"
  ];
  # Two sessions (a soft-reboot in, a power-off and a cold boot out) at about
  # 30 s each, plus setup.
  globalTimeout = 1500;

  testScript = { nodes, ... }: ''
    import ipaddress
    import json
    import secrets

    from nails_e2e import session

    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.canonicalEmergencyFn}

    CONFIG = "/mnt/data/config/nails.toml"
    UPPER = "/mnt/data/root/upper"
    PEEK = "/run/decoy-peek"
    #: The static addresses the test framework gives eth1.
    STATIC_ADDRESSES = [
        ipaddress.ip_interface(a) for a in ${builtins.toJSON (staticAddresses nodes.machine)}
    ]
    #: Each place where eth1 lacked one of them, or was down.
    address_gaps = []


    def eth1_gaps(where):
        """What eth1 lacks of its static addresses at `where`, and whether it
        is down, one line each. Logs what it holds and the state of the unit
        that added them."""
        [link] = json.loads(machine.succeed("ip -j addr show dev eth1"))
        held = {
            ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}")
            for a in link.get("addr_info", [])
            if a.get("scope") == "global"
        }
        up = "UP" in link.get("flags", [])
        _, unit = machine.execute("systemctl is-active network-addresses-eth1.service")
        machine.log(
            f"{where}: eth1 holds {sorted(map(str, held))}, up: {up}; "
            f"network-addresses-eth1.service: {unit.strip()}"
        )
        gaps = [f"{where}: eth1 lacks {a}" for a in STATIC_ADDRESSES if a not in held]
        if not up:
            gaps.append(f"{where}: eth1 is down")
        return gaps




    machine.start()
    machine.wait_for_unit("multi-user.target")
    decoy_dev = machine.succeed("findmnt -no SOURCE /").strip()
    machine.log(f"decoy root: {decoy_dev}")

    with subtest("the decoy's eth1 holds its static addresses"):
        # Their unit starts when eth1 appears, which multi-user.target does
        # not wait for, and has the stop command that deletes them.
        machine.wait_for_unit("network-addresses-eth1.service")
        stop = machine.succeed(
            "systemctl show -p ExecStop --value network-addresses-eth1.service"
        ).strip()
        assert stop, "network-addresses-eth1.service has no stop command"
        gaps = eth1_gaps("the decoy at boot")
        assert STATIC_ADDRESSES and not gaps, f"{STATIC_ADDRESSES}: {gaps}"

    with subtest("init and check on the decoy"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("nails init /mnt/data")
        machine.succeed(f"test -s {CONFIG}")
        # The binary runs from the Nix store, so the root cannot be derived
        # from its location: name it, and lower the space floor for the 2 GiB
        # test disk.
        machine.succeed(
            f"cat > {CONFIG} <<'EOF'\n"
            "hidden_volume_root = \"/mnt/data\"\n"
            "minimum_space_mb = 100\n"
            "EOF"
        )
        rc, out = machine.execute(f"nails --config {CONFIG} check --overlay-only")
        machine.log(out)
        assert rc == 0, f"check refused a ready host (rc={rc})"
        status = read_status_json(config_path=CONFIG)
        assert status["place"] == "decoy", status

    # One line the decoy logs before activation and one the hidden session
    # logs. Neither names the tool or the hidden volume, so verify's journal
    # search below does not count them.
    decoy_line = "decoy-line-" + secrets.token_hex(8)
    hidden_line = "hidden-line-" + secrets.token_hex(8)

    with subtest("the decoy journal shows its own line"):
        # The control for the check after the power-off.
        machine.succeed("grep -qi '^Storage=volatile' /etc/systemd/journald.conf")
        machine.succeed(f"logger -t decoy {decoy_line}")
        machine.succeed("journalctl --sync")
        assert decoy_line in machine.succeed(
            f"journalctl --grep {decoy_line} --no-pager -o cat"
        ), "the decoy journal does not show its own line"

    with subtest("activate soft-reboots into the hidden root"):
        timings = canonical_activate(CONFIG, "--overlay-only", "activate-1")
        session.assert_hidden_root(machine, UPPER)
        status = read_status_json(config_path=CONFIG)
        machine.log(json.dumps(status, indent=1))
        assert status["place"] == "hidden", status
        count = machine.succeed("systemctl show -p SoftRebootsCount --value").strip()
        assert count == "1", f"SoftRebootsCount={count}"
        # Recorded, not asserted here: the later places are judged too.
        address_gaps.extend(eth1_gaps("the hidden session"))

    with subtest("verify --deep in the session reports nothing critical"):
        # The quick start's check before the session ends, through sudo as an
        # operator runs it. `nails init` staged the link to the hidden module
        # in the upper, so the live root shows it at /etc/nixos/nails: it is
        # the session's own, a note like the session's runtime files, its
        # state and sudo's records in the session's journal (in RAM here).
        machine.succeed(f"test -L {UPPER}/etc/nixos/nails/configuration.nix")
        rc, out = machine.execute(
            f"sudo nails --config {CONFIG} verify --deep --json 2>/run/verify-session.stderr"
        )
        machine.log(out)
        assert rc in (0, 10), f"in-session verify exited {rc}: {out}"
        findings = json.loads(out)["data"]["findings"]
        critical = [f for f in findings if f["severity"] == "critical"]
        assert not critical, f"in-session verify reported critical findings: {critical}"
        staged = [
            f["severity"]
            for f in findings
            if f["message"] == "Artifact file found: /etc/nixos/nails/configuration.nix"
        ]
        assert staged == ["info"], f"the staged link must be one note: {findings}"
        for own in (
            "/run/overlay-runtime",
            "records an active session",
            "Hidden volume path is accessible",
            "State file exists",
        ):
            assert not any(own in f["message"] for f in findings), f"{own}: {findings}"
        journal = [f for f in findings if f["category"] == "journal"]
        assert all(f["severity"] == "info" for f in journal), journal

    canary = "hidden-" + secrets.token_hex(8)
    with subtest("a hidden write lands in the upper, never on the decoy"):
        machine.succeed(f"echo {canary} > /root/hidden-canary && sync")
        assert machine.succeed(f"cat {UPPER}/root/hidden-canary").strip() == canary
        # The write fence keeps the decoy's filesystem read-only for the whole
        # session: a read-write mount of it is refused (a read-only one reuses
        # the live superblock), and the next boot shows the decoy without the
        # session's files.
        machine.fail(f"mkdir -p {PEEK} && mount -w -t ext4 -o rw {decoy_dev} {PEEK}")
        machine.succeed("mountpoint -q /mnt/data")

    with subtest("the hidden session logs into the runtime journal the decoy wrote"):
        machine.succeed(f"logger -t session {hidden_line}")
        machine.succeed("journalctl --sync")
        for line in (decoy_line, hidden_line):
            assert line in machine.succeed(
                f"journalctl --grep {line} --no-pager -o cat"
            ), f"{line} is not in the hidden session's journal"

    with subtest("deactivate powers off and the decoy boots cold and clean"):
        machine.succeed("systemd-run --unit hidden-probe --property=Type=exec sleep infinity")
        # canonical_deactivate follows the real power-off and the cold boot:
        # the plain decoy root, the mapping closed, no runtime directory.
        canonical_deactivate(CONFIG, "deactivate-1")
        machine.fail("test -e /root/hidden-canary")
        machine.fail("systemctl is-active hidden-probe.service")
        count = machine.succeed("systemctl show -p SoftRebootsCount --value").strip()
        assert count == "0", f"the decoy's boot is a soft-reboot: SoftRebootsCount={count}"
        machine.wait_for_unit("network-addresses-eth1.service")
        address_gaps.extend(eth1_gaps("the decoy after deactivate"))

    with subtest("the decoy's journal after the power-off holds no line of before"):
        # The journal is volatile: the cold boot starts it afresh, without the
        # hidden session's line and without the decoy's own from before it.
        machine.succeed("journalctl --sync")
        for line in (decoy_line, hidden_line):
            count = machine.succeed(
                f"journalctl --no-pager -o cat | grep -c -F {line} || true"
            ).strip()
            assert count == "0", f"{line} is in the decoy journal ({count} lines)"

    with subtest("the upper persists into the next session"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        status = read_status_json(config_path=CONFIG)
        assert status["place"] == "decoy", status
        canonical_activate(CONFIG, "--overlay-only", "activate-2")
        assert machine.succeed("cat /root/hidden-canary").strip() == canary
        address_gaps.extend(eth1_gaps("the second hidden session"))

    with subtest("emergency in the hidden session kills it and powers off at once"):
        # A unit gets systemd's default PATH, without coreutils on NixOS.
        machine.succeed(
            "systemd-run --unit hidden-writer --property=Type=exec --setenv=PATH=$PATH "
            "sh -c 'while sleep 1; do date >> /root/w; done'"
        )
        machine.succeed("systemctl is-active hidden-writer.service")
        # Followed to the real power-off and the cold boot of the plain decoy.
        canonical_emergency(CONFIG, "emergency", "--json")
        machine.fail("systemctl is-active hidden-writer.service")
        machine.wait_for_unit("network-addresses-eth1.service")
        address_gaps.extend(eth1_gaps("the decoy after the emergency"))

    with subtest("the emergency logged its timed phases on the hidden volume"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        hidden_log = machine.succeed("cat /mnt/data/logs/*.log 2>/dev/null || true")
        assert "emergency hot path finished" in hidden_log, hidden_log[-3000:]
        # The log is JSON: the phases are one field, "name=ms" each.
        for phase in ("kill-shells=", "enqueue=", "kill="):
            assert phase in hidden_log, hidden_log[-3000:]

    with subtest("recover and emergency on the plain decoy change nothing"):
        out = machine.succeed(f"nails --config {CONFIG} recover")
        assert "Nothing to recover" in out, out
        out = machine.succeed(f"nails --config {CONFIG} emergency")
        assert "nothing to tear down" in out, out
        session.assert_decoy_root(machine)

    with subtest("eth1 kept its static addresses through every switch"):
        assert not address_gaps, "; ".join(address_gaps)
  '';
}
