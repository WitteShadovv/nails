# Test 26: Config Overlay Exclusions

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in {
  name = "config-exclusions";
  meta.tags = [ "config" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    ${preflightHelpers.writeTextFileFn}
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    def write_exclusions_config(path):
        write_text_file(path, """
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: auto
    overlay_exclusions:
      - /opt
      - /nix
      - /var
      - /tmp
    """.strip() + "\n")

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mkdir -p /opt /srv")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    write_exclusions_config("/tmp/exclusions.yaml")

    with subtest("custom exclusions are honored while defaults still stay excluded"):
        machine.succeed("nails --config /tmp/exclusions.yaml activate --overlay-only --no-kill-session -y")
        assert_status_state("active")
        assert_overlay_mounted("/etc")
        assert_overlay_mounted("/home")
        assert_overlay_mounted("/srv")
        assert_no_overlays(["/opt", "/run", "/mnt", "/proc", "/var", "/tmp", "/nix"])

    with subtest("deactivation returns the system to decoy mounts"):
        canonical_deactivate("/tmp/exclusions.yaml", unit_name="nails-deactivate-config-exclusions")
        assert_status_state("inactive")
        assert_no_overlays(["/etc", "/home", "/srv", "/opt", "/run", "/mnt"])
  '';
}
