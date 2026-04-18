# Test 72: Overlay Mount Tracker Integrity
# Uses subtests, deterministic waits, hard assertions, and overlay tags only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  overlayHelpers = import ./../../lib/overlay-helpers.nix;
in {
  name = "overlay-mount-tracker-integrity";
  meta.tags = [ "overlay" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    ${overlayHelpers.writeOrderedOverlayConfigFn}
    ${overlayHelpers.readHiddenStateJsonFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-tracker-integrity.yaml"
    expected_paths = {"/home", "/etc", "/srv"}
    write_ordered_overlay_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("mkdir -p /mnt/hidden-volume/srv /mnt/hidden-volume/.work/srv")

    with subtest("phase 1: inactive state has no tracked or mounted overlays"):
        status = read_status_json(config_path=config_path)
        assert status["state"] == "Inactive", status
        assert status["overlays"] == [], status
        machine.fail("mount | grep 'overlay on /home'")
        machine.fail("mount | grep 'overlay on /etc'")
        machine.fail("mount | grep 'overlay on /srv'")

    with subtest("phase 2: active state matches status, state.json, and real mounts"):
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --no-kill-session -y"
        )
        for path in expected_paths:
            assert_overlay_mounted(path)
        status = read_status_json(config_path=config_path)
        assert {overlay["path"] for overlay in status["overlays"]} == expected_paths, status
        for entry in status["overlays"]:
            assert entry["path"] in expected_paths, entry
            assert entry["status"] == "mounted", entry
        state_json = read_hidden_state_json()
        tracked_paths = set(state_json["overlay_status"].keys())
        assert tracked_paths == expected_paths, state_json

    with subtest("phase 3: deactivation returns tracker state to empty"):
        machine.succeed(f"nails --config {config_path} emergency")
        assert_no_overlays(["/home", "/etc", "/srv"])
        status = read_status_json(config_path=config_path)
        assert status["state"] == "Inactive", status
        assert status["overlays"] == [], status
        state_json = read_hidden_state_json()
        assert state_json["overlay_status"] == {}, state_json
        assert state_json.get("failed_overlays", []) == [], state_json
  '';
}
