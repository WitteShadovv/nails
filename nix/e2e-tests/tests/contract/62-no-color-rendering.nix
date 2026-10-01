# Test 62: No-Color Rendering
# Self-check: uses subtests, hard assertions, shared lib helpers, tags contract, no sleep.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  contractHelpers = import ./../../lib/contract-helpers.nix;
in
{
  name = "no-color-rendering";
  meta.tags = [ "contract" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.python3
      ];
    };

  testScript = _: ''
    import shlex

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.canonicalDeactivateFn}
    ${contractHelpers.runPtyCommandCaptureFn}
    ${contractHelpers.runCommandCaptureFn}
    ${contractHelpers.assertNoAnsiFn}

    def remount_hidden_volume_and_rewrite_config():
        write_headless_config(headless_config)
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")

    def activate_via_tty(name, command_prefix=""):
        prefix = (command_prefix + " ").strip()
        command = " ".join(part for part in [
            prefix,
            "nails --no-log-file --config",
            shlex.quote(headless_config),
            "activate --overlay-only --session keep -y",
        ] if part)
        return run_pty_command_capture(name, command)

    with subtest("boot and prepare hidden volume"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        headless_config = "/run/nails-tests/no-color-headless.toml"
        write_headless_config(headless_config)
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    def verify_via_tty(name, command_prefix=""):
        # verify paints its header whenever colour is on; its exit code
        # reflects findings and is irrelevant here.
        prefix = (command_prefix + " ").strip()
        command = " ".join(part for part in [
            prefix,
            "nails --no-log-file --config",
            shlex.quote(headless_config),
            "verify",
        ] if part)
        return run_pty_command_capture(name, command)

    with subtest("empty NO_COLOR keeps colour on a TTY"):
        empty = verify_via_tty("no-color-empty", command_prefix="NO_COLOR=")
        assert_has_ansi(empty["combined"], "verify output with empty NO_COLOR")
        set_env = verify_via_tty("no-color-set", command_prefix="NO_COLOR=1")
        assert_no_ansi(set_env["combined"], "verify output with NO_COLOR=1")

    with subtest("piped output is never coloured"):
        piped = run_command_capture(
            "no-color-piped",
            f"nails --no-log-file --config {shlex.quote(headless_config)} verify",
        )
        assert_no_ansi(piped["combined"], "piped verify output")

    with subtest("baseline TTY activation emits ANSI escapes"):
        baseline = activate_via_tty("no-color-baseline")
        assert baseline["rc"] == 0, baseline
        assert_has_ansi(baseline["combined"], "baseline activation output")
        canonical_deactivate(headless_config, unit_name="nails-deactivate-no-color-baseline")
        remount_hidden_volume_and_rewrite_config()

    with subtest("--color never suppresses ANSI escapes"):
        disabled = run_pty_command_capture(
            "no-color-flag",
            " ".join([
                "nails --no-log-file --config",
                shlex.quote(headless_config),
                "activate --overlay-only --session keep -y --color never",
            ]),
        )
        assert disabled["rc"] == 0, disabled
        assert_no_ansi(disabled["combined"], "--color never activation output")
        canonical_deactivate(headless_config, unit_name="nails-deactivate-no-color-flag")
        remount_hidden_volume_and_rewrite_config()

    with subtest("NO_COLOR environment variable suppresses ANSI escapes"):
        env_disabled = activate_via_tty("no-color-env", command_prefix="NO_COLOR=1")
        assert env_disabled["rc"] == 0, env_disabled
        assert_no_ansi(env_disabled["combined"], "NO_COLOR activation output")
        canonical_deactivate(headless_config, unit_name="nails-deactivate-no-color-env")
  '';
}
