# Test 21: Preflight NixOS Build Target Validation

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-nixos-build-target";
  meta.tags = [
    "preflight"
    "smoke"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}
    ${preflightHelpers.writeTextFileFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    def write_build_target_config(path):
        write_text_file(path, """
    hidden_volume_root = "/mnt/hidden-volume"
    nixos_flake = "relative/flake#test-host"
    overlay_mode = "explicit"

    [[overlays]]
    name = "home"
    lower = "/home"
    upper = "/mnt/hidden-volume/home"
    work = "/mnt/hidden-volume/.work/home"
    target = "/home"
    """.strip() + "\n")

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    write_build_target_config("/tmp/preflight-build-target.toml")

    with subtest("relative nixos flake references are rejected during preflight"):
        result = run_command_capture(
            "preflight-nixos-build-target",
            "nails --config /tmp/preflight-build-target.toml activate --session keep -y",
        )
        assert_command_failed(result)
        assert_result_contains(
            result,
          ["nixos-build-target", "relative/flake", "absolute"],
            stream="stderr",
        )
        assert_status_state("Inactive", config_path="/tmp/preflight-build-target.toml")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        machine.fail("test -e /mnt/hidden-volume/home/testuser/.config/autostart/nails-notify.desktop")
        machine.fail("test -e /mnt/hidden-volume/state.json")
        machine.fail("test -e /mnt/hidden-volume/state")

    with subtest("a local flake without a committed flake.lock is rejected before any activation side effects"):
        # T-067: the pre-overlay flake preflight is static only and never invokes
        # nix (a nix call would copy the hidden flake onto the decoy store before
        # the overlays hide it). A local flake that carries no committed
        # flake.lock is therefore rejected here, before any detach, overlay mount
        # or state write. The real attribute/eval validation is deferred to the
        # post-overlay phase, so it can no longer run before side effects.
        machine.succeed("mkdir -p /tmp/flake-target")
        machine.succeed("cat > /tmp/flake-target/flake.nix <<'EOF'\n{\n  outputs = _: {\n    nixosConfigurations.other-host = { };\n  };\n}\nEOF")
        write_text_file("/tmp/preflight-build-target.toml", "\n".join([
            'hidden_volume_root = "/mnt/hidden-volume"',
            'nixos_flake = "/tmp/flake-target#test-host"',
            'overlay_mode = "explicit"',
            "[[overlays]]",
            'name = "home"',
            'lower = "/home"',
            'upper = "/mnt/hidden-volume/home"',
            'work = "/mnt/hidden-volume/.work/home"',
            'target = "/home"',
        ]) + "\n")
        result = run_command_capture(
            "preflight-build-target-missing-flake-lock",
            "nails --config /tmp/preflight-build-target.toml activate --session keep -y",
        )
        assert_command_failed(result)
        stderr = result["stderr"]
        assert "nixos-build-target" in stderr, f"Expected 'nixos-build-target' in stderr, got: {stderr!r}"
        assert "flake.lock not found" in stderr, \
            f"Expected a committed-flake.lock rejection in stderr, got: {stderr!r}"
        assert_status_state("Inactive", config_path="/tmp/preflight-build-target.toml")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        machine.fail("test -e /mnt/hidden-volume/state")

    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
