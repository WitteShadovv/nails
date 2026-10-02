# Test 26: Config Overlay Exclusions

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "config-exclusions";
  meta.tags = [ "config" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${preflightHelpers.writeTextFileFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    def write_exclusions_config(path, allow_leaky=True):
        allow = 'allow_leaky_exclusions = ["/opt", "/nix", "/var", "/tmp"]' if allow_leaky else ""
        write_text_file(path, f"""
    hidden_volume_root = "/mnt/hidden-volume"
    overlay_mode = "auto"
    risky_services = "skip"
    overlay_exclusions = ["/opt", "/nix", "/var", "/tmp"]
    {allow}
    """.strip() + "\n")

    def write_media_config(path):
        write_text_file(path, """
    hidden_volume_root = "/media/veracrypt1"
    overlay_mode = "auto"
    risky_services = "skip"
    """.strip() + "\n")

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mkdir -p /opt /srv")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    write_exclusions_config("/tmp/exclusions.toml")

    with subtest("excluding load-bearing directories is refused unless accepted"):
        write_exclusions_config("/tmp/leaky.toml", allow_leaky=False)
        result = run_command_capture(
            "leaky-exclusions",
            "nails --config /tmp/leaky.toml activate --overlay-only --session keep -y",
        )
        assert_command_failed(result)
        assert_result_contains(result, ["overlay_exclusions[0]", "allow_leaky_exclusions"])
        assert_no_overlays(["/etc", "/home", "/srv"])

    with subtest("a hidden volume under /media is refused before any mount or session kill"):
        machine.succeed("mkdir -p /media/veracrypt1 && mount --bind /mnt/hidden-volume /media/veracrypt1")
        write_media_config("/tmp/media.toml")
        result = run_command_capture(
            "media-hidden-root",
            "nails --config /tmp/media.toml activate --overlay-only --session kill -y",
        )
        assert_command_failed(result)
        assert_result_contains(result, [
            "overlay-targets",
            "hidden root /media/veracrypt1 is under overlay target /media",
            "add /media to overlay_exclusions",
        ])
        assert_no_overlays(["/media", "/etc", "/home", "/srv"])
        transient_units = machine.succeed(
            "systemctl list-units --all --plain --no-legend 'nails-activate-*' || true"
        )
        assert "nails-activate-" not in transient_units, transient_units
        # Leave the top level as the later auto-mode subtests expect it.
        machine.succeed("umount /media/veracrypt1 && rmdir /media/veracrypt1 && rmdir --ignore-fail-on-non-empty /media")

    with subtest("custom exclusions are honored while defaults still stay excluded"):
        machine.succeed("nails --config /tmp/exclusions.toml activate --overlay-only --session keep -y")
        assert_status_state("active")
        assert_overlay_mounted("/etc")
        assert_overlay_mounted("/home")
        assert_overlay_mounted("/srv")
        assert_no_overlays(["/opt", "/run", "/mnt", "/proc", "/var", "/tmp", "/nix"])

    with subtest("deactivation returns the system to decoy mounts"):
        canonical_deactivate("/tmp/exclusions.toml", unit_name="nails-deactivate-config-exclusions")
        assert_status_state("inactive")
        assert_no_overlays(["/etc", "/home", "/srv", "/opt", "/run", "/mnt"])
  '';
}
