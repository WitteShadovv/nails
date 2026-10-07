# Scenario `verify` of the `smoke-verify-config` batch:
#   tests/smoke/02-smoke-verify-config.nix
# Formerly the stand-alone test
#   tests/smoke/02-verify.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix);
# its subtests and assertions are unchanged.
#
# Test 02: Verify Command Contract
# Tests clean, dirty and active verification states.
#
# Overlay detection is attributed by upperdir on the configured hidden volume
# (read from /proc/self/mountinfo), not by probing a fixed list of mount points,
# so this test runs verify against the headless config and asserts the new
# "Leftover overlay" finding.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "verify";
  tags = [
    "smoke"
    "contract"
  ];

  helpers = [
    testHelpers.writeHeadlessConfigFn
    testHelpers.runVerifyFn
  ];

  script = ''
    def scenario_verify() -> None:
        machine.wait_for_unit("multi-user.target")

        # Keep the harness config out of /tmp, /var/tmp and /var/log: the deep verify
        # pass sweeps those for nails-named files, and a config left in /tmp would show
        # up as a leftover and make the post-cleanup scan differ from the baseline.
        headless_config = "/run/nails-tests/nails-headless.toml"
        write_headless_config(headless_config)

        baseline_status, baseline_payload = run_verify(config_path=headless_config)
        assert baseline_status in (0, 10, 11), f"Unexpected baseline verify exit {baseline_status}: {baseline_payload}"
        baseline_messages = [finding["message"] for finding in baseline_payload["findings"]]
        assert not any("Artifact file found" in message for message in baseline_messages), \
            f"Baseline verify should not report artifact files, got: {baseline_payload}"
        assert not any("Leftover overlay" in message for message in baseline_messages), \
            f"Baseline verify should not report mounted overlays, got: {baseline_payload}"

        print("\n=== Verifying clean decoy baseline ===")
        print(f"✓ Baseline verify status: {baseline_payload['status']}")

        print("\n=== Verifying artifact detection ===")
        # A stray log under /tmp is not a path NAILS writes, so the standard scan no
        # longer carries it in its registry; the deep scan sweeps /tmp, /var/tmp and
        # /var/log for nails-named leftovers, which is where this leak is reported.
        machine.succeed("touch /tmp/nails.log")
        status, payload = run_verify("--deep", config_path=headless_config)
        assert status in (10, 11), f"Expected artifact verify exit 10/11, got {status}"
        assert payload["status"] in ("warning", "critical"), \
            f"Expected Warning or Critical verify result, got: {payload}"
        assert any("/tmp/nails.log" in finding["message"] for finding in payload["findings"]), \
            f"Expected /tmp/nails.log finding, got: {payload}"
        machine.succeed("rm -f /tmp/nails.log")
        print("✓ Verify reports decoy artifacts")

        print("\n=== Verifying active overlay detection ===")
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mkdir -p /mnt/data/home /mnt/data/.work/home")
        machine.succeed(
            "mount -t overlay overlay -o lowerdir=/home,upperdir=/mnt/data/home,workdir=/mnt/data/.work/home /home"
        )

        status, payload = run_verify("--deep", config_path=headless_config)
        assert status == 11, f"Expected active verify exit 11, got {status}"
        assert payload["status"] == "critical", f"Expected critical verify result, got: {payload}"
        # The overlay's upper layer is on the hidden volume, so it is flagged wherever
        # it is mounted, by upperdir, as a "Leftover overlay".
        assert any("Leftover overlay" in finding["message"] for finding in payload["findings"]), \
            f"Expected leftover-overlay finding, got: {payload}"
        print("✓ Verify reports active overlays as Critical")

        print("\n=== Verifying post-overlay cleanup ===")
        machine.succeed("umount /home")
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
        machine.succeed("rm -rf /mnt/data")

        status, payload = run_verify("--deep", config_path=headless_config)
        post_messages = [finding["message"] for finding in payload["findings"]]
        assert not any("Artifact file found" in message for message in post_messages), \
            f"Post-cleanup verify should not report artifact files, got: {payload}"
        assert not any("Leftover overlay" in message for message in post_messages), \
            f"Post-cleanup verify should not report mounted overlays, got: {payload}"
        assert payload["status"] == baseline_payload["status"], \
            f"Expected post-cleanup verify to match baseline status {baseline_payload['status']}, got: {payload}"
        assert status == baseline_status, \
            f"Expected post-cleanup verify exit {baseline_status}, got {status}"
        print("✓ Verify returns to its decoy baseline after cleanup")

        print("\n=== Verify Command Tests Passed ===")
  '';
}
