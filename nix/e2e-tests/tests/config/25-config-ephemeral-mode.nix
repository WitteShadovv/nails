# Test 25: Config Ephemeral Mode

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
  ephemeralFixture = ./../../fixtures/configs/ephemeral.yaml;
in
{
  name = "config-ephemeral-mode";
  meta.tags = [ "config" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    configured_targets = ["/etc", "/home", "/root", "/var", "/tmp", "/srv", "/opt"]
    ephemeral_targets = ["/var", "/tmp", "/srv", "/opt"]
    tmpfs_roots = [
        "/run/nails/var-ephemeral",
        "/run/nails/tmp-ephemeral",
        "/run/nails/srv-ephemeral",
        "/run/nails/opt-ephemeral",
    ]

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mkdir -p /srv /opt /var/lib")
    machine.succeed("cp ${ephemeralFixture} /tmp/ephemeral.yaml")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("ephemeral overlay config is cleanly rejected during preflight"):
        result = run_command_capture(
            "config-ephemeral-mode",
            "nails --config /tmp/ephemeral.yaml activate --overlay-only --no-kill-session -y",
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
        assert_status_state("inactive", config_path="/tmp/ephemeral.yaml")
        assert_no_overlays(configured_targets)
        for tmpfs_root in tmpfs_roots:
            machine.fail(f"mountpoint -q {tmpfs_root}")
            machine.fail(f"test -e {tmpfs_root}")

    with subtest("preflight rejection leaves hidden storage untouched"):
        machine.fail("test -e /mnt/hidden-volume/var/lib/ephemeral-proof")
        machine.fail("test -e /mnt/hidden-volume/tmp/ephemeral-proof")
        machine.fail("test -e /mnt/hidden-volume/srv/ephemeral/proof")
        machine.fail("test -e /mnt/hidden-volume/opt/ephemeral/proof")
        machine.fail("test -d /mnt/hidden-volume/tmp")
        machine.fail("test -d /mnt/hidden-volume/srv")
        machine.fail("test -d /mnt/hidden-volume/opt")
  '';
}
