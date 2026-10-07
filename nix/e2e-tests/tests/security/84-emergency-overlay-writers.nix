# Test 84: emergency stops overlay writers that hold only a file open
#
# Two writers keep a file open for writing under the /home overlay while their
# working directory sits on the decoy: a Restart=always service and a plain
# process in a transient scope. Overlayfs reports a non-directory file's layer
# device, not the overlay's, so the old device-based check spared both. The
# mount-id check must find them, the service must get a stop job before the
# kill (otherwise systemd restarts it after the overlays are gone and the new
# instance writes to the decoy), and nothing may land on the decoy.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  emergency = import ./../../lib/emergency.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "emergency-overlay-writers";
  meta.tags = [ "security" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      systemd.services = {
        nails-emergency-test = emergency.makeEmergencyUnit self.packages.x86_64-linux.nails "/tmp/nails-headless.toml";
        overlay-writer = {
          description = "Writer holding a file open under an overlay target";
          serviceConfig = {
            WorkingDirectory = "/";
            ExecStart = "${pkgs.bash}/bin/bash -c 'exec 3>>/home/testuser/service-writer.log; while :; do echo beat >&3; sleep 0.2; done'";
            Restart = "always";
            RestartSec = "200ms";
          };
        };
      };
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${emergency.waitForEmergencyUnitFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}

    service_log = "/home/testuser/service-writer.log"
    plain_log = "/home/testuser/plain-writer.log"

    machine.start()
    machine.wait_for_unit("multi-user.target")
    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)

    with subtest("activate and start two writers that hold only a file open"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")
        assert_status_state("active", config_path=headless_config)
        machine.succeed("systemctl start overlay-writer.service")
        machine.succeed(
            "systemd-run --scope --unit=plain-writer --quiet -- ${pkgs.bash}/bin/bash -c "
            + f"'cd /; exec 3>>{plain_log}; while :; do echo beat >&3; sleep 0.2; done' "
            + ">/dev/null 2>&1 &"
        )
        machine.wait_until_succeeds(f"test -s {service_log} && test -s {plain_log}")
        plain_pid = machine.succeed(f"pgrep -f 'exec 3>>{plain_log}'").split()[0]

    with subtest("emergency kills both writers and keeps the service down"):
        clear_emergency_result()
        machine.succeed("systemctl start --no-block nails-emergency-test.service")
        wait_for_emergency_unit(timeout=60)
        assert_no_overlays(["/home", "/etc"])
        # Watch for longer than RestartSec: a revived service would be active
        # again at some point inside the window.
        import time

        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            state = machine.succeed("systemctl is-active overlay-writer.service || true").strip()
            assert state != "active", f"the Restart=always writer was revived: {state}"
            machine.sleep(0.5)
        machine.fail(f"kill -0 {plain_pid}")

    with subtest("nothing was written to the decoy"):
        machine.fail(f"test -e {service_log}")
        machine.fail(f"test -e {plain_log}")
        assert_status_state("inactive", config_path=headless_config)
  '';
}
