# Test 61: Global Verbosity Flags
# Self-check: uses subtests, hard assertions, shared lib helpers, tags contract, no sleep.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  contractHelpers = import ./../../lib/contract-helpers.nix;
in
{
  name = "verbosity-flags";
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
    ${contractHelpers.runCommandCaptureFn}
    ${contractHelpers.countNonEmptyLinesFn}

    with subtest("boot and prepare harness state"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        headless_config = "/tmp/nails-headless.yaml"
        write_headless_config(headless_config)

    counts = {}
    invocations = [
        ("quiet", "-q"),
        ("verbose", "-v"),
        ("very-verbose", "-vv"),
        ("trace", "-vvv"),
    ]

    for index, (label, flag) in enumerate(invocations):
        with subtest(f"capture activation output for {label}"):
            if index == 0:
                machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
            else:
                machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
            result = run_command_capture(
                f"verbosity-{label}",
                " ".join([
                    "nails",
                    "--no-logs",
                    flag,
                    "--config",
                    shlex.quote(headless_config),
                    "activate",
                    "--overlay-only",
                    "--no-kill-session",
                    "-y",
                    "--plain",
                ]),
            )
            assert result["rc"] == 0, result
            counts[label] = count_nonempty_lines(result["combined"])
            assert counts[label] > 0, (label, result)
            canonical_deactivate(headless_config, unit_name=f"nails-deactivate-verbosity-{label}")

    with subtest("verbosity increases output monotonically"):
        assert counts["quiet"] < counts["verbose"], counts
        assert counts["verbose"] <= counts["very-verbose"], counts
        # The implementation maps 2+ flags to TRACE, so -vv and -vvv may legitimately tie.
        assert counts["very-verbose"] <= counts["trace"], counts
  '';
}
