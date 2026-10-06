# Test 82: Decoy-persistence preflight refuses a persistent-journal decoy
#
# T-094. A decoy that keeps a persistent systemd journal records a hidden
# session's pre-overlay metadata (sudo command lines, transient unit names) on
# its own disk, so activation must fail closed unless the operator explicitly
# accepts the risk. This node forces journald back to persistent storage (the
# standard decoy models an amnesic one), so the decoy-persistence check has
# something to refuse.
#
# Subtests: a plain activation is refused with remediation text that names the
# override, and the same activation with --accept-persistent-decoy proceeds.

{ self, pkgs, ... }:
let
  inherit (pkgs) lib;
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "decoy-persistence-preflight";
  meta.tags = [
    "security"
    "preflight"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      # vm-config models an amnesic decoy (volatile journald). Force a persistent
      # journal so this decoy keeps records of the hidden session on disk and the
      # decoy-persistence check must fail closed.
      services.journald.storage = lib.mkForce "persistent";
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/preflight-decoy-persistence.toml"
    write_headless_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    # Confirm the decoy really presents a persistent journal, so a pass below
    # would be a genuine override rather than an amnesic decoy slipping through.
    machine.succeed("grep -qi '^Storage=persistent' /etc/systemd/journald.conf")

    with subtest("a persistent-journal decoy is refused with remediation guidance"):
        result = run_command_capture(
            "preflight-decoy-persistence-fail",
            f"nails --config {config_path} activate --overlay-only --session keep -y",
        )
        assert_command_failed(result)
        assert_result_contains(
            result,
            ["persistent", "Storage=volatile", "--accept-persistent-decoy"],
            stream="stderr",
        )
        assert_status_state("inactive", config_path=config_path)
        assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])

    with subtest("--accept-persistent-decoy overrides the refusal"):
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --session keep --accept-persistent-decoy -y"
        )
        assert_status_state("active", config_path=config_path)
        assert_overlay_mounted("/home")
        canonical_deactivate(
            config_path, unit_name="nails-deactivate-decoy-persistence"
        )
        assert_status_state("inactive", config_path=config_path)
        assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])
  '';
}
