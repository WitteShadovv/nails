# Test 16: A disk swap that appears during the hidden session is reported.
#
# Pre-flight refuses disk swap before entering, but something in the hidden
# session (the hidden system's swap.target, or the operator) can still bring a
# disk-backed swap up afterwards. The shared per-device classifier backs both
# the pre-flight check and `verify`, so `verify` run in the hidden session
# reports such a swap as a critical, memory-leaking posture. The swap here is
# a loop device (a disk-type swap; a swap file cannot live on the root
# overlay), backed by a file on the hidden volume.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-swap-reenable";
  meta.tags = [ "preflight" ];

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${preflightHelpers.runCommandCaptureFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/preflight-swap-reenable.toml"
    write_headless_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("activation succeeds with no swap active"):
        machine.succeed("swapoff -a")
        canonical_activate(config_path, "--overlay-only", "swap-reenable-activate")

    def swap_findings(label):
        import json

        result = run_command_capture(label, f"nails --config {config_path} verify --json")
        findings = json.loads(result["stdout"])["data"]["findings"]
        return [
            finding
            for finding in findings
            if finding["category"] == "memory" and "leak memory" in finding["message"]
        ]

    with subtest("verify in the hidden session reports no swap leak first"):
        found = swap_findings("swap-reenable-verify-before")
        assert not found, found

    with subtest("a disk swap brought up in the hidden session is reported by verify"):
        machine.succeed("fallocate -l 256M /mnt/data/swap.img")
        loop = machine.succeed("losetup --find --show /mnt/data/swap.img").strip()
        machine.succeed(f"mkswap {loop} && swapon {loop}")
        machine.succeed(f"grep -q '^{loop} ' /proc/swaps")

        found = swap_findings("swap-reenable-verify")
        assert len(found) == 1, found
        assert found[0]["severity"].lower() == "critical", found
        assert loop in found[0]["message"], found
        machine.succeed(f"swapoff {loop} && losetup -d {loop}")
        machine.succeed("rm -f /mnt/data/swap.img")

    with subtest("the way back is clean once swap is removed"):
        canonical_deactivate(config_path, "swap-reenable-deactivate")
  '';
}
