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
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    configured_targets = ["/etc", "/home", "/root", "/var", "/tmp", "/srv", "/opt"]
    tmpfs_roots = [
        "/run/nails/var-ephemeral",
        "/run/nails/tmp-ephemeral",
        "/run/nails/srv-ephemeral",
        "/run/nails/opt-ephemeral",
    ]

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-ephemeral.yaml"
    write_ephemeral_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("mkdir -p /opt")

    with subtest("ephemeral overlay activation is rejected by overlay-compatibility preflight"):
        result = run_command_capture(
            "overlay-ephemeral",
            f"nails --config {config_path} activate --overlay-only --no-kill-session -y",
        )
        assert_command_failed(result)
        combined = result["stdout"] + "\n" + result["stderr"]
        assert_text_contains(
            combined,
            [
                "overlay-compatibility",
                "Extended ephemeral overlays are currently unsupported",
                "/var, /tmp, /srv, /opt",
                "upperdir and workdir",
                "same mount",
                "Disable extended_overlays.enabled",
            ],
        )
        assert_status_state("inactive", config_path=config_path)
        assert_no_overlays(configured_targets)
        for path in tmpfs_roots:
            machine.fail(f"mountpoint -q {path}")
            machine.fail(f"test -e {path}")

    with subtest("preflight rejection leaves hidden and runtime storage untouched"):
        machine.fail("test -e /mnt/hidden-volume/srv/ephemeral-marker")
        machine.fail("test -d /mnt/hidden-volume/srv")
        machine.fail("test -d /mnt/hidden-volume/.work/srv")
  '';
}
