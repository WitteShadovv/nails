# Test 02: Verify Command Contract
# Tests clean, dirty, active, and post-emergency verification states

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "verify";
  meta.tags = [
    "smoke"
    "contract"
  ];

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      };
  };

  testScript = _: ''
    ${testHelpers.runVerifyFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    baseline_status, baseline_payload = run_verify()
    assert baseline_status in (0, 1), f"Unexpected baseline verify exit {baseline_status}: {baseline_payload}"
    baseline_messages = [finding["message"] for finding in baseline_payload["findings"]]
    assert not any("Artifact file found" in message for message in baseline_messages), \
        f"Baseline verify should not report artifact files, got: {baseline_payload}"
    assert not any("Overlay mount found" in message for message in baseline_messages), \
        f"Baseline verify should not report mounted overlays, got: {baseline_payload}"

    print("\n=== Verifying clean decoy baseline ===")
    print(f"✓ Baseline verify status: {baseline_payload['status']}")

    print("\n=== Verifying artifact detection ===")
    machine.succeed("touch /tmp/nails.log")
    status, payload = run_verify()
    assert status == 1, f"Expected artifact verify exit 1, got {status}"
    assert payload["status"] in ("Warning", "Critical"), \
        f"Expected Warning or Critical verify result, got: {payload}"
    assert any("/tmp/nails.log" in finding["message"] for finding in payload["findings"]), \
        f"Expected /tmp/nails.log finding, got: {payload}"
    machine.succeed("rm -f /tmp/nails.log")
    print("✓ Verify reports decoy artifacts")

    print("\n=== Verifying active overlay detection ===")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("mkdir -p /mnt/hidden-volume/home /mnt/hidden-volume/.work/home")
    machine.succeed(
        "mount -t overlay overlay -o lowerdir=/home,upperdir=/mnt/hidden-volume/home,workdir=/mnt/hidden-volume/.work/home /home"
    )

    status, payload = run_verify("--deep")
    assert status == 1, f"Expected active verify exit 1, got {status}"
    assert payload["status"] == "Critical", f"Expected Critical verify result, got: {payload}"
    assert any("Overlay mount found" in finding["message"] for finding in payload["findings"]), \
        f"Expected overlay finding, got: {payload}"
    print("✓ Verify reports active overlays as Critical")

    print("\n=== Verifying post-overlay cleanup ===")
    machine.succeed("umount /home")
    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
    machine.succeed("rm -rf /mnt/hidden-volume")

    status, payload = run_verify("--deep")
    post_messages = [finding["message"] for finding in payload["findings"]]
    assert not any("Artifact file found" in message for message in post_messages), \
        f"Post-emergency verify should not report artifact files, got: {payload}"
    assert not any("Overlay mount found" in message for message in post_messages), \
        f"Post-emergency verify should not report mounted overlays, got: {payload}"
    assert payload["status"] == baseline_payload["status"], \
        f"Expected post-emergency verify to match baseline status {baseline_payload['status']}, got: {payload}"
    assert status == baseline_status, \
        f"Expected post-emergency verify exit {baseline_status}, got {status}"
    print("✓ Verify returns to its decoy baseline after emergency cleanup")

    print("\n=== Verify Command Tests Passed ===")
  '';
}
