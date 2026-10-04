# Test 78: A stale decoy writer leaks onto the decoy disk, and NAILS reports it
#
# With `--session keep` the decoy session is not killed, so a decoy process that
# held an open file descriptor into /home before activation keeps writing through
# that descriptor afterwards. The descriptor points at the pre-overlay (decoy)
# inode, so those writes bypass the overlay and land on the decoy block device —
# a leak the overlay cannot contain. NAILS must detect and report such surviving
# writers (activation headline and `nails status`), and the disk image must show
# where the write actually landed.
#
# Disk imaging: it must run on the Nix VM driver.

{ pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  diskForensics = import ./../../lib/disk-forensics.nix { inherit pkgs; };
  baseOs = import ./../../lib/base-os-overlays.nix;
in
{
  name = "persona-stale-writer";
  meta.tags = [ "session" ];

  globalTimeout = 1500;

  baseNode = {
    python3 = true;
  };

  testScript = _: ''
    import shlex

    ${testHelpers.readStatusJsonFn}
    ${assertions.assertOverlayMountedFn}
    ${diskForensics.pythonSetup}

    WRITER_LOG = "/home/testuser/decoy-open.log"
    WRITER_TOKEN = "NAILS_STALE_WRITER_LEAK_2026a"
    # decoy_writers_headline: "1 writer still on the decoy" or "N writers ...".
    HEADLINE = "still on the decoy"


    def write_home_overlay_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "skip"

    ${baseOs.toml}
    [[overlays]]
    name = "home"
    lower = "/home"
    upper = "/mnt/data/home"
    work = "/mnt/data/.work/home"
    target = "/home"
    EOF""" % path
        )


    def start_stale_writer():
        # A non-interactive background writer (stdio to /dev/null, so activation
        # does not refuse it as interactive) that holds fd 9 open on a /home file
        # and keeps appending the token through it. setsid detaches it from the
        # backdoor shell so it survives this command and into activation.
        machine.succeed(f"touch {WRITER_LOG}")
        machine.succeed(f"chown testuser:users {WRITER_LOG}")
        loop = (
            f"exec 9>>{WRITER_LOG}; "
            f"while true; do echo {WRITER_TOKEN} >&9; sync; sleep 1; done"
        )
        command = (
            "setsid bash -c " + shlex.quote(loop) + " </dev/null >/dev/null 2>&1 & disown; "
            "sleep 1; true"
        )
        machine.succeed("bash -lc " + shlex.quote(command))
        pid = machine.wait_until_succeeds(
            "pgrep -f 'exec 9'"
        ).strip().splitlines()[0]
        # Confirm the descriptor really points at the decoy /home inode.
        fd9 = machine.succeed(f"readlink /proc/{pid}/fd/9").strip()
        assert fd9 == WRITER_LOG, f"writer fd is {fd9!r}, expected {WRITER_LOG!r}"
        return pid


    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-stale-writer.toml"
    write_home_overlay_config(config_path)

    with subtest("capture the decoy baseline image (token absent)"):
        # Image the decoy root while it is still pristine: before the hidden
        # volume exists and before the stale writer has appended anything. The
        # snapshot shuts the machine down (which would also close the LUKS
        # backend) and brings it back up, so the volume setup and the writer
        # both belong after this, exactly as the other forensic specs order it.
        baseline = disk_forensics.snapshot(machine, "baseline")
        assert disk_forensics.run_strings_scan(baseline, [WRITER_TOKEN]) == set(), (
            "writer token already present on the baseline image"
        )

    with subtest("prepare the hidden volume and a stale /home writer"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        writer_pid = start_stale_writer()

    with subtest("activation keeps the session and reports the surviving writer"):
        output = machine.succeed(
            f"nails --config {config_path} activate --overlay-only --session keep -y 2>&1"
        )
        assert_overlay_mounted("/home")
        assert HEADLINE in output, (
            f"activation did not report the surviving decoy writer:\n{output}"
        )
        machine.succeed(f"kill -0 {writer_pid}")

    with subtest("nails status also records the decoy writer"):
        status = read_status_json(config_path=config_path)
        writers = status.get("decoy_writers", [])
        assert writers, f"status reported no decoy writers: {status}"
        assert any("/home" in w.get("targets", []) for w in writers), (
            f"no decoy writer on /home in status: {writers}"
        )

    with subtest("the stale descriptor bypasses the overlay"):
        # Let the writer append through its pre-overlay descriptor.
        machine.succeed("sleep 3")
        # The write does not copy up into the overlay upper on the hidden volume.
        machine.fail("test -e /mnt/data/home/testuser/decoy-open.log")

    with subtest("the leaked token is on the decoy disk image, not the hidden volume"):
        active = disk_forensics.snapshot(machine, "active", restart=False)
        hits = disk_forensics.run_strings_scan(active, [WRITER_TOKEN])
        assert WRITER_TOKEN in hits, (
            "the stale writer's output should have landed on the decoy image; "
            "this is the leak the surviving-writer report warns about"
        )
  '';
}
