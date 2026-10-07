# Test 37: Refuse to signal a non-service writer before mounting
#
# A process with no systemd unit can only be stopped by signal, so activation
# never signals one without --terminate-processes: an interactive writer (a
# `tail -f` on a pty) and a detached, non-interactive one are both refused
# before anything is mounted, and the detached one is ended only once the
# operator opts in.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  baseOs = import ./../../lib/base-os-overlays.nix;
in
{
  name = "activate-refuse-interactive-writer";
  meta.tags = [ "session" ];

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        # `script` allocates a real pty so the decoy writer's stdio is terminal
        # attached, which is what makes activation treat it as interactive.
        pkgs.util-linux
      ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    import shlex

    REFUSAL = "Refusing to signal non-service process(es)"


    def write_var_overlay_config(path):
        # A minimal explicit config that overlays /var (plus the base-OS trees
        # the writable-trees check requires), so the decoy writer below lands
        # on an overlay target. risky_services is set so a
        # non-interactive keep-session run has an explicit policy and fails only
        # on the interactive-writer refusal, not on a missing risky-service
        # choice.
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "skip"

    ${baseOs.toml}
    [[overlays]]
    name = "var"
    lower = "/var"
    upper = "/mnt/data/var"
    work = "/mnt/data/.work/var"
    target = "/var"
    EOF""" % path
        )


    def start_interactive_var_writer(log_path):
        # An interactive writer on /var: `script` runs it under a fresh pty, so
        # /proc/<pid>/fd/{0,1,2} point at /dev/pts/N, and it holds the log open
        # for writing on fd 3 (a read-only `tail -f` is a read-only consumer,
        # which activation rightly leaves alone, so it would not exercise the
        # refusal). systemd-run --scope moves it out of the test driver's service
        # cgroup into a transient scope, so it is a non-service process; setsid
        # detaches it from the driver shell so it survives this command.
        machine.succeed(f"touch {shlex.quote(log_path)}")
        quoted_log = shlex.quote(log_path)
        writer = f"exec 3>>{quoted_log}; exec tail -f {quoted_log}"
        command = (
            "systemd-run --scope --quiet setsid script -qfc "
            + shlex.quote("sh -c " + shlex.quote(writer))
            + " /dev/null </dev/null >/dev/null 2>&1 & disown; sleep 1; true"
        )
        machine.succeed("bash -lc " + shlex.quote(command))
        pid = machine.wait_until_succeeds("pgrep -x tail").strip().splitlines()[0]
        fd0 = machine.succeed(f"readlink /proc/{pid}/fd/0").strip()
        assert fd0.startswith("/dev/pts/"), f"writer stdin is not a pty: {fd0!r}"
        fds = machine.succeed(f"ls -l /proc/{pid}/fd")
        assert "nails-decoy-writer.log" in fds, fds
        flags_line = machine.succeed(f"grep '^flags:' /proc/{pid}/fdinfo/3").split()[1]
        assert int(flags_line, 8) & 0o3, f"writer fd 3 is not open for writing: {flags_line}"
        cgroup = machine.succeed(f"cat /proc/{pid}/cgroup")
        assert ".service" not in cgroup, f"writer is still in a service cgroup: {cgroup!r}"
        return pid


    def start_detached_var_writer(log_path):
        # A detached, non-interactive writer on /var: stdio on /dev/null (no
        # pty), fd 3 open for writing on the log, moved into a transient scope
        # so it has no service unit. It classifies Safe on /var, so it can only
        # be stopped by signal, which activation must not send without the
        # opt-in.
        machine.succeed(f"touch {shlex.quote(log_path)}")
        quoted_log = shlex.quote(log_path)
        writer = f"exec 3>>{quoted_log}; exec sleep 3600"
        command = (
            "systemd-run --scope --quiet setsid sh -c "
            + shlex.quote(writer)
            + " </dev/null >/dev/null 2>&1 & disown; sleep 1; true"
        )
        machine.succeed("bash -lc " + shlex.quote(command))
        pid = machine.wait_until_succeeds("pgrep -x -f 'sleep 3600'").strip().splitlines()[0]
        fd0 = machine.succeed(f"readlink /proc/{pid}/fd/0").strip()
        assert fd0 == "/dev/null", f"detached writer stdin is not /dev/null: {fd0!r}"
        flags_line = machine.succeed(f"grep '^flags:' /proc/{pid}/fdinfo/3").split()[1]
        assert int(flags_line, 8) & 0o3, f"writer fd 3 is not open for writing: {flags_line}"
        cgroup = machine.succeed(f"cat /proc/{pid}/cgroup")
        assert ".service" not in cgroup, f"writer is still in a service cgroup: {cgroup!r}"
        return pid


    machine.start()
    machine.wait_for_unit("multi-user.target")

    refuse_config = "/tmp/nails-var-refuse.toml"
    headless_config = "/tmp/nails-headless.toml"
    writer_log = "/var/log/nails-decoy-writer.log"
    detached_log = "/var/log/decoy-detached-writer.log"

    with subtest("prepare the hidden volume and an interactive /var writer"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        write_var_overlay_config(refuse_config)
        assert_no_overlays(["/var", "/home", "/etc", "/root", "/srv", "/tmp"])
        writer_pid = start_interactive_var_writer(writer_log)

    with subtest("non-interactive activation refuses before mounting"):
        output = machine.fail(
            f"nails --config {refuse_config} activate --overlay-only --session keep -y 2>&1"
        )
        assert REFUSAL in output, output
        assert f"tail (PID {writer_pid}, interactive)" in output, output
        # The writer is untouched and nothing was mounted: the refusal aborts
        # ahead of the first mount or signal.
        machine.succeed(f"kill -0 {writer_pid}")
        assert_no_overlays(["/var", "/home", "/etc", "/root", "/srv", "/tmp"])
        assert_status_state("inactive", config_path=refuse_config)

    with subtest("a detached non-service writer is refused as well"):
        machine.succeed(f"kill {writer_pid}")
        machine.wait_until_fails(f"kill -0 {writer_pid}")
        detached_pid = start_detached_var_writer(detached_log)
        output = machine.fail(
            f"nails --config {refuse_config} activate --overlay-only --session keep -y 2>&1"
        )
        assert REFUSAL in output, output
        assert f"sleep (PID {detached_pid}) on /var" in output, output
        assert "--terminate-processes" in output, output
        machine.succeed(f"kill -0 {detached_pid}")
        assert_no_overlays(["/var", "/home", "/etc", "/root", "/srv", "/tmp"])
        assert_status_state("inactive", config_path=refuse_config)

    with subtest("--terminate-processes ends the detached writer and mounts"):
        machine.succeed(
            f"nails --config {refuse_config} activate --overlay-only --session keep -y "
            "--terminate-processes"
        )
        machine.wait_until_fails(f"kill -0 {detached_pid}")
        assert_overlay_mounted("/var")
        assert_status_state("active", config_path=refuse_config)
        canonical_deactivate(
            refuse_config,
            unit_name="nails-deactivate-activate-refuse-detached-writer",
        )
        assert_no_overlays(["/var", "/home", "/etc", "/root", "/srv", "/tmp"])
        assert_status_state("inactive", config_path=refuse_config)

    with subtest("activation proceeds once no non-service writer remains"):
        # The deactivation above rebooted, which closed the hidden backend.
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        write_headless_config(headless_config)
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep -y"
        )
        assert_overlay_mounted("/home")
        assert_status_state("active", config_path=headless_config)

    with subtest("deactivate returns the machine to the decoy state"):
        canonical_deactivate(
            headless_config,
            unit_name="nails-deactivate-activate-refuse-interactive-writer",
        )
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        assert_status_state("inactive", config_path=headless_config)
  '';
}
