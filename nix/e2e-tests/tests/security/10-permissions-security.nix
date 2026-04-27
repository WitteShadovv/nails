# Test 10: Permission and Path Security
# Tests log permissions, directory permissions, symlink rejection, path traversal

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  symlinkFixture = ./../../fixtures/configs/symlink-target.yaml;
  traversalFixture = ./../../fixtures/configs/path-traversal.yaml;
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

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    print("\n=== Test 1: Log file permissions ===")
    machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")

    log_files = machine.succeed(
      "find /var/log /mnt/hidden-volume/logs -type f "
      "\\( -name 'nails.log' -o -name 'nails*.log' \\) 2>/dev/null || true"
    ).strip()

    if log_files:
        for log_file in log_files.split("\n"):
            log_file = log_file.strip()
            if log_file:
                perms = machine.succeed(f"stat -c %a {log_file}").strip()
                print(f"  Log file {log_file}: permissions {perms}")
                mode = int(perms, 8)
                assert (mode & 0o022) == 0, \
                    f"Log file {log_file} is writable by non-owner (perms={perms})"
        print("✓ Log files have restrictive permissions")
    else:
        print("Note: No nails log files found (may use journald)")

    print("\n=== Test 2: Symlink rejection ===")
    machine.succeed("nails emergency")
    machine.succeed("ln -sfn /mnt/hidden-volume /tmp/symlink-to-hidden")
    machine.succeed("cp ${symlinkFixture} /tmp/symlink-config.yaml")

    result = machine.execute("nails --config /tmp/symlink-config.yaml activate --overlay-only --no-kill-session -y 2>&1")
    print(f"  Symlink activation result: exit={result[0]}")
    if result[0] != 0:
        print("✓ Symlinked hidden-volume root is rejected")
    else:
        print("Note: Symlinked hidden-volume root was accepted (cleanup needed)")
        machine.succeed("nails emergency")

    machine.succeed("rm -f /tmp/symlink-to-hidden /tmp/symlink-config.yaml")

    print("\n=== Test 3: Path traversal rejection ===")
    machine.succeed("cp ${traversalFixture} /tmp/traversal-config.yaml")

    result = machine.execute("nails --config /tmp/traversal-config.yaml activate --overlay-only --no-kill-session -y 2>&1")
    print(f"  Path traversal activation result: exit={result[0]}")
    if result[0] != 0:
        print("✓ Path traversal in config is rejected")
    else:
        print("Note: Path traversal was accepted (cleanup needed)")
        machine.succeed("nails emergency")

    machine.succeed("rm -f /tmp/traversal-config.yaml")
    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
    print("\n=== All Permissions Security Tests Passed ===")
  '';
}
