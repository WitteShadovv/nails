# Fault test: --poweroff still runs when the teardown is incomplete.
#
# A second NAILS-shaped overlay is stacked on /home after activation, so the
# teardown's single unmount of /home leaves one overlay behind and emergency
# ends incomplete (exit 7). That is exactly when powering off matters most: it
# is the only way left to clear the key and the session from RAM, so the
# requested power-off must run on that outcome too.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "faults-emergency-poweroff-incomplete";
  meta.tags = [
    "faults"
    "security"
  ];

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.waitForStatusStateFn}
    ${assertions.assertOverlayMountedFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/run/nails-headless.toml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("activate and stack a second hidden overlay on /home"):
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep -y"
        )
        wait_for_status_state("Active", config_path=headless_config)
        machine.succeed(
            "mkdir -p /mnt/data/extra/upper /mnt/data/extra/work && "
            "mount -t overlay overlay -o lowerdir=/home,upperdir=/mnt/data/extra/upper,"
            "workdir=/mnt/data/extra/work /home"
        )
        assert_overlay_mounted("/home")

    with subtest("an incomplete emergency still powers the machine off"):
        machine.succeed(
            "systemd-run --no-block --unit=nails-emergency-poweroff "
            f"nails --config {headless_config} emergency --poweroff"
        )
        machine.wait_for_shutdown()
  '';
}
