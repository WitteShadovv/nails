# Test 83: The hidden session leaves no journal trace on a persistent decoy
#
# T-094. The decoy here keeps a persistent journal (forensic-vm-config sets
# Storage=persistent) and the operator accepts it with
# --accept-persistent-decoy, so a leak would be durable. Two channels are
# probed:
#   - a `logger` line inside the hidden session: the hidden journald writes it
#     into the root overlay, so it lands in the upper on the hidden volume and
#     never in the decoy's /var/log/journal;
#   - a late kernel record: a hidden unit that stops after journald during the
#     soft-reboot back writes a token to /dev/kmsg. No hidden journald sees it,
#     and the decoy journald must not import it from the ring buffer (the
#     transition seeks its kmsg cursor, ADR 0008 section 5).
# After the way back neither token is in the live decoy journal, and a carve of
# the decoy disk image finds neither in its journal or anywhere on the image.
# A line logged on the decoy before activation must still be carved from the
# image (positive control: the scan can see the journal).
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  diskForensics = import ./../../lib/disk-forensics.nix { inherit pkgs; };
in
{
  name = "decoy-journal-leak";
  meta.tags = [ "security" ];

  # Disk imaging plus two soft-reboots; generous margin.
  globalTimeout = 1800;

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/forensic-vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      };
  };

  testScript = _: ''

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${diskForensics.pythonSetup}

    # A line logged to the decoy journal before activation (positive control),
    # the line logged inside the hidden session, and the late kernel record
    # written while the hidden session shuts down.
    precontrol_token = "NAILS_JCTL_PRECONTROL_2026a"
    hidden_jrnl_token = "NAILS_JCTL_HIDDEN_2026a"
    late_kmsg_token = "NAILS_JCTL_LATEKMSG_2026a"
    hidden_tokens = [hidden_jrnl_token, late_kmsg_token]
    UPPER = "/mnt/data/root/upper"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("confirm the decoy keeps a persistent journal"):
        machine.succeed("grep -qi '^Storage=persistent' /etc/systemd/journald.conf")
        machine.succeed("test -d /var/log/journal")

    with subtest("plant a pre-activation journal control on the decoy"):
        machine.succeed(f"logger -t decoy {precontrol_token}")
        machine.succeed("journalctl --sync")

    with subtest("log inside the hidden session; the journal lands in the upper"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        # The config lives on the hidden volume, never on the imaged decoy disk.
        config = "/mnt/data/config/nails.toml"
        write_headless_config(config)
        canonical_activate(config, "--overlay-only --accept-persistent-decoy", "activate")
        machine.succeed(f"logger -t session {hidden_jrnl_token}")
        machine.succeed("journalctl --sync")
        assert hidden_jrnl_token in machine.succeed(
            f"journalctl --grep {hidden_jrnl_token} --no-pager -o cat"
        ), "the line must be visible in the live hidden journal"
        machine.succeed(f"grep -rqaF {hidden_jrnl_token} {UPPER}/var/log/journal")

    with subtest("capture the kernel and systemd fixtures of a live session"):
        # T-139: the parser tests read these (nails-base/tests/fixtures/kernel/
        # README.md). Read-only, written under /run, never on the decoy disk.
        # In the hidden root the host share is an overlay with its upper on
        # the hidden volume, so copy_from_host/copy_from_vm cannot reach the
        # host: the script goes in and the capture comes out through the
        # backdoor shell.
        import base64
        import io
        import tarfile

        with open("${../../../../scripts/capture-kernel-fixtures.sh}") as script:
            machine.succeed(
                "cat > /run/capture-kernel-fixtures.sh <<'NAILS_CAPTURE_EOF'\n"
                + script.read()
                + "NAILS_CAPTURE_EOF"
            )
        machine.succeed("bash /run/capture-kernel-fixtures.sh vm /run/kernel-fixtures")
        archive = machine.succeed("tar -C /run/kernel-fixtures -cz . | base64 -w0")
        machine.succeed("rm -rf /run/kernel-fixtures /run/capture-kernel-fixtures.sh")
        with tarfile.open(fileobj=io.BytesIO(base64.b64decode(archive)), mode="r:gz") as tar:
            tar.extractall(machine.out_dir / "kernel-fixtures", filter="data")

    with subtest("plant a unit that writes to /dev/kmsg after journald stopped"):
        machine.succeed(
            "systemd-run --unit late-kmsg-probe -p Type=oneshot -p RemainAfterExit=yes "
            "-p DefaultDependencies=no -p Before=systemd-journald.service "
            "-p Conflicts=soft-reboot.target "
            f"-p ExecStop='/bin/sh -c \"echo {late_kmsg_token} > /dev/kmsg\"' "
            "/run/current-system/sw/bin/true"
        )
        machine.succeed("systemctl is-active late-kmsg-probe.service")

    with subtest("deactivate: neither token is in the live decoy journal"):
        canonical_deactivate(config, "deactivate")
        # The probe really ran: its record is in the kernel ring buffer (RAM).
        # grep without -q reads all of dmesg: -q stops at the match, and
        # dmesg's write error then fails the pipeline.
        machine.succeed(f"dmesg | grep -F {late_kmsg_token} > /dev/null")
        machine.succeed("journalctl --sync")
        for token in hidden_tokens:
            count = machine.succeed(
                f"journalctl --no-pager -o cat | grep -c -F {token} || true"
            ).strip()
            assert count == "0", f"{token} reached the decoy journal ({count} lines)"
        assert precontrol_token in machine.succeed(
            f"journalctl --grep {precontrol_token} --no-pager -o cat"
        ), "the decoy journal lost its own pre-activation line"

    with subtest("the decoy image keeps the control but no hidden token"):
        post = disk_forensics.snapshot(machine, "post-journal-leak", restart=False)
        offset = disk_forensics.partition_offset(post)

        # Positive control: the pre-activation line is still carvable, so an
        # empty result below means "searched and clean", not "no journal".
        control_hits = disk_forensics.run_journal_scan(
            post, [precontrol_token], offset=offset
        )
        assert precontrol_token in control_hits, (
            f"positive control missing, the decoy journal was not read: {control_hits}"
        )

        leak_hits = disk_forensics.run_journal_scan(post, hidden_tokens, offset=offset)
        assert not leak_hits, (
            f"the hidden session reached the decoy journal: {sorted(leak_hits)}"
        )

        string_hits = disk_forensics.run_strings_scan(post, hidden_tokens)
        assert not string_hits, (
            f"strings found a hidden token on the decoy image: {sorted(string_hits)}"
        )
        print("✓ decoy journal clean of the hidden session, control intact")
  '';
}
