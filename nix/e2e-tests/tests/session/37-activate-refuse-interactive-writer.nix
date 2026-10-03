# Test 37: Refuse to force-terminate an interactive writer before mounting

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
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

    REFUSAL = "Refusing to force-terminate interactive process(es)"


    def write_var_overlay_config(path):
        # A minimal explicit config whose only overlay is /var, so the decoy
        # writer below lands on an overlay target. risky_services is set so a
        # non-interactive keep-session run has an explicit policy and fails only
        # on the interactive-writer refusal, not on a missing risky-service
        # choice.
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "skip"

    [[overlays]]
    name = "var"
    lower = "/var"
    upper = "/mnt/data/var"
    work = "/mnt/data/.work/var"
    target = "/var"
    EOF""" % path
        )


    def start_interactive_var_writer(log_path):
        # Give `tail -f` a controlling terminal: `script` runs it under a fresh
        # pty, so /proc/<pid>/fd/{0,1,2} point at /dev/pts/N and activation sees
        # an interactive, non-service process holding /var. setsid detaches it
        # from the backdoor shell so it survives this command.
        machine.succeed(f"touch {shlex.quote(log_path)}")
        command = (
            "setsid script -qfc "
            + shlex.quote(f"tail -f {shlex.quote(log_path)}")
            + " /dev/null </dev/null >/dev/null 2>&1 & disown; sleep 1; true"
        )
        machine.succeed("bash -lc " + shlex.quote(command))
        pid = machine.wait_until_succeeds("pgrep -x tail").strip().splitlines()[0]
        fd0 = machine.succeed(f"readlink /proc/{pid}/fd/0").strip()
        assert fd0.startswith("/dev/pts/"), f"writer stdin is not a pty: {fd0!r}"
        fds = machine.succeed(f"ls -l /proc/{pid}/fd")
        assert "nails-decoy-writer.log" in fds, fds
        return pid


    machine.start()
    machine.wait_for_unit("multi-user.target")

    refuse_config = "/tmp/nails-var-refuse.toml"
    headless_config = "/tmp/nails-headless.toml"
    writer_log = "/var/log/nails-decoy-writer.log"

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
        # The writer is untouched and nothing was mounted: the refusal aborts
        # ahead of the first mount or signal.
        machine.succeed(f"kill -0 {writer_pid}")
        assert_no_overlays(["/var", "/home", "/etc", "/root", "/srv", "/tmp"])
        assert_status_state("inactive", config_path=refuse_config)

    with subtest("activation proceeds once the interactive writer is gone"):
        machine.succeed(f"kill {writer_pid}")
        machine.wait_until_fails(f"kill -0 {writer_pid}")
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
