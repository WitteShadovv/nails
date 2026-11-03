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
#   3. `nails deactivate`: a soft-reboot back to the plain decoy. Nothing of the
#      hidden /run survives, the hidden volume's mapping closed itself, the
#      decoy never saw the hidden file. The decoy journal is volatile (the
#      suite's default) and shared with the hidden session, so the way back
#      deletes it whole: a line the decoy logged before activation is gone with
#      the hidden session's, and the journal starts at the deactivation,
#      without the kernel's boot records;
#   4. a second activation finds the hidden file again (the upper persists);
#   5. `nails emergency` in the hidden session kills a hidden service and the
#      login session at once and soft-reboots back, with its phases timed in
#      the log on the hidden volume;
#   6. `nails recover` and `nails emergency` on the plain decoy are no-ops.
#
# Throughout, eth1 keeps the static addresses the test framework gives it on
# the test network (`networking.interfaces.eth1`): in both hidden sessions,
# and on the decoy after the deactivation and after the emergency. NixOS
# applies them with network-addresses-eth1.service, whose stop deletes them,
# and the session clears that stop until the way back (STOP_GUARDED_UNITS in
# nails-teardown). The unit starts when eth1 appears, which a soft-reboot does
# not replay, so nothing starts it again after the first activation. The test
# starts it before each later switch: every switch then has a stop that would
# delete the addresses, and the start puts back what an earlier switch
# deleted, so each place judges the switch right before it. Each place where
# eth1 lacks an address or is down is recorded, and the test fails at the end
# naming them all.
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
  # Three soft-reboot round trips at about 15 s each, plus setup.
  globalTimeout = 1500;

  testScript = { nodes, ... }: ''
    import ipaddress
    import json
    import secrets

    from nails_e2e import session

    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

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


    def start_address_unit(where):
        """Start network-addresses-eth1.service at `where`, before a switch.

        Nothing starts it again after the first soft-reboot, so without this
        the switch would have no stop for the session to clear. The start also
        adds back the addresses an earlier switch deleted, so the place after
        the switch judges that switch alone."""
        machine.succeed("systemctl start network-addresses-eth1.service")
        machine.succeed("systemctl is-active network-addresses-eth1.service")
        stop = machine.succeed(
            "systemctl show -p ExecStop --value network-addresses-eth1.service"
        ).strip()
        machine.log(f"{where}: the unit's stop command: {stop or 'none'}")
        gaps = eth1_gaps(where)
        assert STATIC_ADDRESSES and not gaps, f"{STATIC_ADDRESSES}: {gaps}"


    def peek_decoy(decoy_dev, command):
        """Run `command` against a read-only mount of the decoy root at PEEK.

        The decoy superblock is still mounted read-write (it is the overlay's
        lower), so a plain read-only mount would fail with EBUSY: mount it,
        then make this mount read-only."""
        machine.succeed(
            f"mkdir -p {PEEK} && mount {decoy_dev} {PEEK} && mount -o remount,bind,ro {PEEK}"
        )
        try:
            return machine.execute(command)
        finally:
            machine.succeed(f"umount {PEEK} && rmdir {PEEK}")


    def kernel_records():
        """The journal's kernel records, as (us since boot, message).

        journald stamps a kernel record with the time it read it, so a record
        read in again later looks new. The time the kernel logged it is in
        _SOURCE_MONOTONIC_TIMESTAMP."""
        out = machine.succeed(
            "journalctl -q _TRANSPORT=kernel -o json "
            "--output-fields=_SOURCE_MONOTONIC_TIMESTAMP,MESSAGE --no-pager"
        )
        records = [json.loads(line) for line in out.splitlines() if line.strip()]
        for record in records:
            assert "_SOURCE_MONOTONIC_TIMESTAMP" in record, f"no kernel time: {record}"
        logged = [
            (int(record["_SOURCE_MONOTONIC_TIMESTAMP"]), record.get("MESSAGE"))
            for record in records
        ]
        return sorted(logged, key=lambda record: record[0])


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

    with subtest("the decoy journal shows its own line and the kernel's boot records"):
        machine.succeed("grep -qi '^Storage=volatile' /etc/systemd/journald.conf")
        machine.succeed(f"logger -t decoy {decoy_line}")
        machine.succeed("journalctl --sync")
        assert decoy_line in machine.succeed(
            f"journalctl --grep {decoy_line} --no-pager -o cat"
        ), "the decoy journal does not show its own line"
        # The control for the check after the way back: by the kernel's own
        # time, records from before userspace started are in the journal.
        userspace_us = int(
            machine.succeed("systemctl show -p UserspaceTimestampMonotonic --value").strip()
        )
        boot_records = [record for record in kernel_records() if record[0] < userspace_us]
        machine.log(
            f"{len(boot_records)} kernel records from before userspace started at "
            f"{userspace_us} us, the first: {boot_records[:1]}"
        )
        assert boot_records, "the decoy journal holds none of the kernel's boot records"

    run_before = session.run_entries(machine)

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
        # The quick start's check before the way back, through sudo as an
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
        rc, _ = peek_decoy(decoy_dev, f"test ! -e {PEEK}/root/hidden-canary")
        assert rc == 0, "the hidden file is on the decoy filesystem"
        machine.succeed("mountpoint -q /mnt/data")

    with subtest("the hidden session logs into the runtime journal the decoy wrote"):
        machine.succeed(f"logger -t session {hidden_line}")
        machine.succeed("journalctl --sync")
        for line in (decoy_line, hidden_line):
            assert line in machine.succeed(
                f"journalctl --grep {line} --no-pager -o cat"
            ), f"{line} is not in the hidden session's journal"

    with subtest("deactivate soft-reboots back and leaves no hidden /run"):
        start_address_unit("the hidden session before deactivate")
        machine.succeed("echo probe > /run/hidden-run-probe")
        machine.succeed("systemd-run --unit hidden-probe --property=Type=exec sleep infinity")
        wall = session.wall_clock(machine)
        deactivate_start_us = int(machine.succeed("date +%s%6N").strip())
        deactivate_uptime_us = int(session.guest_uptime(machine) * 1_000_000)
        canonical_deactivate(CONFIG, "deactivate-1")
        machine.fail("test -e /root/hidden-canary")
        machine.fail("test -e /run/hidden-run-probe")
        machine.fail("test -e /run/overlay-runtime")
        machine.fail("test -e /run/systemd/system/systemd-soft-reboot.service.d")
        machine.fail("systemctl is-active hidden-probe.service")
        residue = session.carried_run_residue(machine, run_before, wall)
        assert not residue, f"hidden /run residue on the decoy: {residue}"
        address_gaps.extend(eth1_gaps("the decoy after deactivate"))

    with subtest("the way back resets the decoy's runtime journal"):
        # The decoy's journald and the hidden one wrote the same runtime
        # journal, and the way back deletes it whole: the decoy's own line from
        # before activation goes with the hidden one, and the journal starts at
        # the return, without the kernel's boot records.
        machine.succeed("journalctl --sync")
        for line in (decoy_line, hidden_line):
            count = machine.succeed(
                f"journalctl --no-pager -o cat | grep -c -F {line} || true"
            ).strip()
            assert count == "0", f"{line} is in the decoy journal ({count} lines)"
        records = [
            json.loads(entry)
            for entry in machine.succeed(
                "journalctl -o json --output-fields=MESSAGE --no-pager"
            ).splitlines()
            if entry.strip()
        ]
        assert records, "the decoy journal is empty after the way back"
        oldest = min(records, key=lambda record: int(record["__REALTIME_TIMESTAMP"]))
        oldest_us = int(oldest["__REALTIME_TIMESTAMP"])
        machine.log(
            f"oldest decoy journal record: {oldest_us} us, {oldest.get('MESSAGE')!r}; "
            f"deactivation started at {deactivate_start_us} us"
        )
        assert oldest_us >= deactivate_start_us, (
            f"the decoy journal starts {deactivate_start_us - oldest_us} us before "
            f"the deactivation: {oldest.get('MESSAGE')!r}"
        )
        # That time is when journald read a record, so the kernel's boot
        # records, read in again after the return, would pass. By the time the
        # kernel logged them, no kernel record in the decoy journal is from
        # before the deactivation: the kmsg cursor keeps the boot's out too.
        kernel = kernel_records()
        early = [record for record in kernel if record[0] < deactivate_uptime_us]
        machine.log(
            f"{len(kernel)} kernel records in the decoy journal, the first: {kernel[:1]}; "
            f"deactivation started {deactivate_uptime_us} us after the boot"
        )
        assert not early, (
            f"the decoy journal holds {len(early)} kernel records from before the "
            f"deactivation, the first: {early[0]}"
        )

    with subtest("the upper persists into the next session"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        status = read_status_json(config_path=CONFIG)
        assert status["place"] == "decoy", status
        start_address_unit("the decoy before the second activation")
        canonical_activate(CONFIG, "--overlay-only", "activate-2")
        assert machine.succeed("cat /root/hidden-canary").strip() == canary
        address_gaps.extend(eth1_gaps("the second hidden session"))

    with subtest("emergency in the hidden session kills it and returns at once"):
        start_address_unit("the second hidden session before the emergency")
        # A unit gets systemd's default PATH, without coreutils on NixOS.
        machine.succeed(
            "systemd-run --unit hidden-writer --property=Type=exec --setenv=PATH=$PATH "
            "sh -c 'while sleep 1; do date >> /root/w; done'"
        )
        machine.succeed("systemctl is-active hidden-writer.service")
        timings = session.follow_soft_reboot(
            machine, f"nails --config {CONFIG} emergency --json > /dev/null", "emergency"
        )
        machine.log(f"emergency soft-reboot timings: {timings}")
        session.assert_decoy_root(machine)
        machine.fail("systemctl is-active hidden-writer.service")
        machine.wait_until_succeeds("test ! -e /dev/mapper/data", timeout=60)
        address_gaps.extend(eth1_gaps("the decoy after the emergency"))

    with subtest("the emergency logged its timed phases on the hidden volume"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        hidden_log = machine.succeed("cat /mnt/data/logs/*.log 2>/dev/null || true")
        assert "emergency hot path finished" in hidden_log, hidden_log[-3000:]
        # The log is JSON: the phases are one field, "name=ms" each.
        for phase in ("prepare-return=", "kill-shells=", "enqueue=", "kill="):
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
