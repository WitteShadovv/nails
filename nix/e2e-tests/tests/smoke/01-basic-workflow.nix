# Test 01: Basic Workflow
# Tests the happy path: activate -> user activities -> deactivate

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in {
  name = "basic-workflow";
  meta.tags = [ "smoke" "lifecycle" "overlay" ];

  nodes = {
    machine = { ... }: {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };
  };

  testScript = _: ''
    import time

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    print("\n=== Testing Pre-Conditions ===")
    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)

    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    machine.succeed("test -d /mnt/hidden-volume")
    machine.succeed("test -d /mnt/hidden-volume/home")
    machine.succeed("test -d /mnt/hidden-volume/.work/home")
    print("✓ Hidden volume is mounted at /mnt/hidden-volume")

    machine.fail("mount | grep 'overlay on /home'")
    machine.fail("mount | grep 'overlay on /etc'")
    machine.fail("mount | grep 'overlay on /var'")
    print("✓ No overlays mounted on /home, /etc, or /var")

    inactive_status = read_status_json()
    assert inactive_status["state"] == "Inactive", f"Expected Inactive status, got: {inactive_status}"
    print("✓ NAILS status reports Inactive before activation")

    print("\n=== Testing Activation ===")
    start_time = time.time()
    machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")
    activation_time = time.time() - start_time
    print(f"Activation completed in {activation_time:.2f}s")

    assert activation_time < 60, f"Activation too slow: {activation_time:.2f}s (limit: 60s)"
    print(f"✓ Activation completed in <60s ({activation_time:.2f}s)")

    home_mount = machine.succeed("mount | grep 'overlay on /home' || true")
    etc_mount = machine.succeed("mount | grep 'overlay on /etc' || true")
    assert "overlay" in home_mount, "Overlay not mounted on /home"
    assert "overlay" in etc_mount, "Overlay not mounted on /etc"
    assert "/mnt/hidden-volume/home" in home_mount, "Overlay upperdir not pointing to hidden volume"
    assert "/mnt/hidden-volume/etc" in etc_mount, "Overlay upperdir not pointing to hidden volume"
    print("✓ Overlays mounted on /home and /etc with correct upperdir")

    machine.succeed("su - testuser -c 'id -un | grep -qx testuser'")
    print("✓ Fresh testuser login shell is available after activation")

    machine.fail("touch ${builtins.storeDir}/test-write-should-fail")
    print("✓ store path is read-only (EROFS)")

    machine.succeed("nix-instantiate --eval -E '1+1'")
    print("✓ Nix operations work during active session")

    active_status = read_status_json()
    assert active_status["state"].startswith("Active"), f"Expected Active status, got: {active_status}"
    active_paths = {overlay["path"] for overlay in active_status["overlays"]}
    assert "/home" in active_paths and "/etc" in active_paths, \
        f"Expected core overlays in status output, got: {active_status}"
    print("✓ NAILS status reports Active after activation")

    print("\n=== Testing User Activities ===")
    machine.succeed("su - testuser -c 'echo \"This is a secret document\" > ~/secret-document.txt'")
    print("✓ Created secret-document.txt in home directory")

    machine.succeed("su - testuser -c 'mkdir -p ~/hidden-project/src'")
    machine.succeed("su - testuser -c 'echo \"print(\\\"Hello World\\\")\" > ~/hidden-project/src/main.py'")
    print("✓ Created hidden-project/ directory with files")

    machine.succeed("su - testuser -c 'test -f ~/secret-document.txt'")
    machine.succeed("su - testuser -c 'test -d ~/hidden-project/src'")
    machine.succeed("su - testuser -c 'test -f ~/hidden-project/src/main.py'")
    content = machine.succeed("su - testuser -c 'cat ~/secret-document.txt'")
    assert "secret document" in content, "File content doesn't match"
    print("✓ Files persist during active session")

    machine.succeed("test -f /mnt/hidden-volume/home/testuser/secret-document.txt")
    machine.succeed("test -d /mnt/hidden-volume/home/testuser/hidden-project")
    print("✓ Files stored in hidden volume overlay")

    print("\n=== Testing Deactivation ===")
    start_time = time.time()
    canonical_deactivate(headless_config, unit_name="nails-deactivate-basic-workflow")
    deactivation_time = time.time() - start_time
    print(f"Deactivation reboot completed in {deactivation_time:.2f}s")

    machine.fail("mount | grep 'overlay on /home'")
    machine.fail("mount | grep 'overlay on /etc'")
    print("✓ Overlays are absent after reboot into decoy state")

    machine.succeed("nix-instantiate --eval -E '1+1'")
    print("✓ Nix tooling works after reboot")

    post_status = read_status_json()
    assert post_status["state"] == "Inactive", f"Expected Inactive after reboot, got: {post_status}"
    print("✓ NAILS status reports Inactive after reboot")

    print("\n=== Testing Forensic Cleanliness ===")
    machine.fail("su - testuser -c 'test -f ~/secret-document.txt'")
    machine.fail("su - testuser -c 'test -d ~/hidden-project'")
    print("✓ User files are no longer visible in home directory")

    machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
    machine.succeed("test -f /mnt/hidden-volume/home/testuser/secret-document.txt")
    machine.succeed("test -d /mnt/hidden-volume/home/testuser/hidden-project")
    print("✓ Data preserved in hidden volume")

    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
    print("\n=== All Tests Passed ===")
  '';
}
