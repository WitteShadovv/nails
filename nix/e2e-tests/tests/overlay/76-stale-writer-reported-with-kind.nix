# Test 76: A writer surviving activation is reported with a classified kind
#
# A non-interactive, non-service process that holds a writable descriptor and its
# cwd inside /home before activation is left running under `--session keep` (a
# process with cwd in /home and no backing service is NoRestart). Its descriptor
# still resolves to the pre-overlay decoy inode, so it keeps writing to the decoy
# after the overlay goes up. NAILS must report it both in the activation output
# and in `nails status`, and the status JSON entry must now carry a `kind`
# classifying the writer (surviving / stale_lower / unverifiable) — the field the
# post-mount rescan surfaces. A lighter companion to persona/78, which also images
# the decoy disk; this one pins the reporting-and-kind contract.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  baseOs = import ./../../lib/base-os-overlays.nix;
in
{
  name = "overlay-stale-writer-kind";
  meta.tags = [ "overlay" ];

  baseNode = {
    python3 = true;
  };

  testScript = _: ''
    import shlex

    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    WRITER_LOG = "/home/testuser/decoy-open.log"
    WRITER_TOKEN = "NAILS_SURVIVING_WRITER_KIND_2026a"
    # decoy_writers_headline: "1 writer still on the decoy" or "N writers ...".
    HEADLINE = "still on the decoy"
    KINDS = {"surviving", "stale_lower", "unverifiable"}


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


    def start_surviving_writer():
        # A non-interactive background writer (stdio to /dev/null, so activation
        # does not refuse it as interactive). It cd's into /home/testuser so its
        # cwd references the decoy /home, and holds fd 9 open on a /home file it
        # keeps appending to. setsid detaches it from the backdoor shell so it
        # survives this command and into activation.
        machine.succeed(f"touch {WRITER_LOG}")
        machine.succeed(f"chown testuser:users {WRITER_LOG}")
        loop = (
            "cd /home/testuser; "
            f"exec 9>>{WRITER_LOG}; "
            f"while true; do echo {WRITER_TOKEN} >&9; sync; sleep 1; done"
        )
        command = (
            "setsid bash -c " + shlex.quote(loop) + " </dev/null >/dev/null 2>&1 & disown; "
            "sleep 1; true"
        )
        machine.succeed("bash -lc " + shlex.quote(command))
        pid = machine.wait_until_succeeds("pgrep -f 'exec 9'").strip().splitlines()[0]
        fd9 = machine.succeed(f"readlink /proc/{pid}/fd/9").strip()
        assert fd9 == WRITER_LOG, f"writer fd is {fd9!r}, expected {WRITER_LOG!r}"
        cwd = machine.succeed(f"readlink /proc/{pid}/cwd").strip()
        assert cwd == "/home/testuser", f"writer cwd is {cwd!r}, expected /home/testuser"
        return pid


    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-surviving-writer.toml"
    write_home_overlay_config(config_path)

    with subtest("prepare the hidden volume and a surviving /home writer"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        assert_no_overlays(["/home", "/usr", "/bin", "/lib64"])
        writer_pid = start_surviving_writer()

    with subtest("activation keeps the session and reports the surviving writer"):
        output = machine.succeed(
            f"nails --config {config_path} activate --overlay-only --session keep -y 2>&1"
        )
        assert_overlay_mounted("/home")
        assert HEADLINE in output, (
            f"activation did not report the surviving decoy writer:\n{output}"
        )
        machine.succeed(f"kill -0 {writer_pid}")
        assert_status_state("active", config_path=config_path)

    with subtest("nails status records the writer with a classified kind"):
        status = read_status_json(config_path=config_path)
        writers = status.get("decoy_writers", [])
        assert writers, f"status reported no decoy writers: {status}"
        on_home = [w for w in writers if "/home" in w.get("targets", [])]
        assert on_home, f"no decoy writer on /home in status: {writers}"
        for w in writers:
            assert w.get("kind") in KINDS, f"writer has no valid kind: {w}"

    with subtest("deactivate returns the machine to the decoy state"):
        machine.succeed(f"kill {writer_pid}")
        machine.wait_until_fails(f"kill -0 {writer_pid}")
        canonical_deactivate(
            config_path,
            unit_name="nails-deactivate-overlay-stale-writer-kind",
        )
        assert_no_overlays(["/home", "/usr", "/bin", "/lib64"])
        assert_status_state("inactive", config_path=config_path)
  '';
}
