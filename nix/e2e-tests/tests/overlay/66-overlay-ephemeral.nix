# Test 66: Overlay Ephemeral Semantics (unsupported layout)
# Uses subtests, deterministic waits, hard assertions, and overlay tags only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "overlay-ephemeral";
  meta.tags = [ "overlay" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${testHelpers.writeEphemeralConfigFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-ephemeral.yaml"
    write_ephemeral_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("phase 1: unsupported ephemeral overlay layout is rejected before mount"):
        activation = run_command_capture(
            "overlay-ephemeral-activate",
            f"nails --config {config_path} activate --overlay-only --no-kill-session -y"
        )
        assert_command_failed(activation)
        assert_text_contains(
            activation["stderr"],
            [
                "Pre-flight checks failed:",
                "overlay-compatibility",
                "Extended ephemeral overlays are currently unsupported",
                "upperdir and workdir to reside on the same mount",
            ],
        )

    with subtest("phase 2: activation rejection leaves no ephemeral mounts behind"):
        assert_no_overlays(["/var", "/tmp", "/srv", "/opt"])
        for path in [
            "/run/nails/var-ephemeral",
            "/run/nails/tmp-ephemeral",
            "/run/nails/srv-ephemeral",
            "/run/nails/opt-ephemeral",
        ]:
            machine.fail(f"mountpoint -q {path}")

    with subtest("phase 3: hidden storage remains untouched"):
        machine.fail("test -e /mnt/hidden-volume/srv/ephemeral-marker")
  '';
}
