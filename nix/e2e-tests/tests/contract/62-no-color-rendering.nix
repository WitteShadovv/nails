# Test 62: No-Color Rendering
# Self-check: uses subtests, hard assertions, shared lib helpers, tags contract, no sleep.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  contractHelpers = import ./../../lib/contract-helpers.nix;
in {
  name = "no-color-rendering";
  meta.tags = [ "contract" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages =
      [ self.packages.x86_64-linux.nails pkgs.python3 ];
  };

  testScript = _: ''
    import shlex

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.canonicalDeactivateFn}
    ${contractHelpers.runPtyCommandCaptureFn}
    ${contractHelpers.assertNoAnsiFn}

    def activate_via_tty(name, command_prefix=""):
        prefix = (command_prefix + " ").strip()
        command = " ".join(part for part in [
            prefix,
            "nails --no-logs --config",
            shlex.quote(headless_config),
            "activate --overlay-only --no-kill-session -y",
        ] if part)
        return run_pty_command_capture(name, command)

    with subtest("boot and prepare hidden volume"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        headless_config = "/tmp/nails-headless.yaml"
        write_headless_config(headless_config)
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("baseline TTY activation emits ANSI escapes"):
        baseline = activate_via_tty("no-color-baseline")
        assert baseline["rc"] == 0, baseline
        assert_has_ansi(baseline["combined"], "baseline activation output")
        canonical_deactivate(headless_config, unit_name="nails-deactivate-no-color-baseline")

    with subtest("--no-color suppresses ANSI escapes"):
        disabled = run_pty_command_capture(
            "no-color-flag",
            " ".join([
                "nails --no-logs --config",
                shlex.quote(headless_config),
                "activate --overlay-only --no-kill-session -y --no-color",
            ]),
        )
        assert disabled["rc"] == 0, disabled
        assert_no_ansi(disabled["combined"], "--no-color activation output")
        canonical_deactivate(headless_config, unit_name="nails-deactivate-no-color-flag")

    with subtest("NO_COLOR environment variable suppresses ANSI escapes"):
        env_disabled = activate_via_tty("no-color-env", command_prefix="NO_COLOR=1")
        assert env_disabled["rc"] == 0, env_disabled
        assert_no_ansi(env_disabled["combined"], "NO_COLOR activation output")
        canonical_deactivate(headless_config, unit_name="nails-deactivate-no-color-env")
  '';
}
