# Test 25: Config Ephemeral Mode

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
  ephemeralFixture = ./../../fixtures/configs/ephemeral.yaml;
in {
  name = "config-ephemeral-mode";
  meta.tags = [ "config" ];

  nodes.machine = { ... }: {
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

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mkdir -p /srv /opt /var/lib")
    machine.succeed("cp ${ephemeralFixture} /tmp/ephemeral.yaml")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("ephemeral overlay config currently fails with overlayfs same-mount constraint"):
        console_start = len(machine.get_console_log())
        activation = run_command_capture(
            "config-ephemeral-mode-activate",
            "nails --config /tmp/ephemeral.yaml activate --overlay-only --no-kill-session -y",
        )
        assert_command_failed(activation)
        combined_output = activation["stdout"] + activation["stderr"]
        assert_text_contains(
            combined_output,
            [
                "Ephemeral overlay mount failed",
                "Failed to mount /mnt/nails-pivot/var: EINVAL: Invalid argument",
                "Automatic rollback completed.",
                "Current state: Inactive",
            ],
        )
        assert_text_contains(
            machine.get_console_log()[console_start:],
            ["overlayfs: workdir and upperdir must reside under the same mount"],
        )

    with subtest("failed ephemeral activation rolls back all overlays and tmpfs uppers"):
        assert_status_state("inactive", config_path="/tmp/ephemeral.yaml")
        assert_no_overlays(["/etc", "/home", "/root", "/var", "/tmp", "/srv", "/opt"])
        for tmpfs_path in [
            "/run/nails/var-upper",
            "/run/nails/var-work",
            "/run/nails/tmp-upper",
            "/run/nails/tmp-work",
            "/run/nails/srv-upper",
            "/run/nails/srv-work",
            "/run/nails/opt-upper",
            "/run/nails/opt-work",
        ]:
            machine.fail(f"mountpoint -q {tmpfs_path}")

    with subtest("failed ephemeral activation leaves hidden storage untouched"):
        machine.fail("test -e /mnt/hidden-volume/var/lib/ephemeral-proof")
        machine.fail("test -e /mnt/hidden-volume/tmp/ephemeral-proof")
        machine.fail("test -e /mnt/hidden-volume/srv/ephemeral/proof")
        machine.fail("test -e /mnt/hidden-volume/opt/ephemeral/proof")
  '';
}
