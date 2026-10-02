# Test 10: Permission and Path Security
# Tests that unsafe config paths are refused and that the activity log is
# never group- or world-accessible.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  symlinkFixture = ./../../fixtures/configs/symlink-target.toml;
  traversalFixture = ./../../fixtures/configs/path-traversal.toml;
in
{
  name = "permissions-security";
  meta.tags = [ "security" ];

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      };
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.toml"
    overlay_targets = ["/home", "/etc", "/root", "/srv", "/tmp"]
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    def assert_config_refused(config_fixture, config_path, description):
        machine.succeed(f"cp {config_fixture} {config_path}")
        # Activation must exit non-zero: the config loader rejects the unsafe
        # path before anything is mounted. A zero exit would mean the guard is
        # gone, so this is the whole point of the test.
        machine.fail(
            f"nails --config {config_path} activate --overlay-only --session keep -y"
        )
        # A refusal must leave no trace: no overlay mounted and the tracked
        # state still inactive.
        assert_no_overlays(overlay_targets)
        assert_status_state("inactive", config_path=headless_config)
        print(f"✓ {description} is refused with no overlay left behind")

    with subtest("symlinked hidden-volume root is refused"):
        machine.succeed("ln -sfn /mnt/data /tmp/symlink-to-hidden")
        assert_config_refused(
            "${symlinkFixture}",
            "/tmp/symlink-config.toml",
            "Symlinked hidden-volume root",
        )
        machine.succeed("rm -f /tmp/symlink-to-hidden /tmp/symlink-config.toml")

    with subtest("relative path-traversal root is refused"):
        assert_config_refused(
            "${traversalFixture}",
            "/tmp/traversal-config.toml",
            "Path traversal in config",
        )
        machine.succeed("rm -f /tmp/traversal-config.toml")

    with subtest("activity log is owner-only"):
        # Default logging writes to the hidden-volume log. It records operator
        # activity, so it must exist after a real activation and must not be
        # readable or writable by group or other.
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep -y"
        )
        assert_status_state("active", config_path=headless_config)

        log_file = "/mnt/data/logs/nails.log"
        machine.succeed(f"test -f {log_file}")
        perms = machine.succeed(f"stat -c %a {log_file}").strip()
        mode = int(perms, 8)
        assert (mode & 0o077) == 0, \
            f"Log file {log_file} is accessible by group/other (perms={perms})"
        print(f"✓ Log file {log_file} is owner-only ({perms})")
  '';
}
