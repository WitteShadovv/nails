# Scenario `preflight-pending-offline-update` of the `preflight-checks` batch:
#   tests/preflight/19-preflight-checks.nix
#
# A staged offline update refuses check and activation. An updater stages one
# by linking /system-update to it; at the next start of the service manager, a
# soft-reboot's included, systemd-system-update-generator then starts
# system-update.target instead of the default target, so a link the hidden
# root showed would turn the start of the hidden session into the update. The
# pending-offline-update check refuses a link on the decoy, naming the `rm`
# that removes it, and one a hidden session left in the root overlay's upper,
# naming the `discard` that deletes it, which this scenario then runs.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-pending-offline-update";
  tags = [ "preflight" ];

  helpers = [
    testHelpers.writeHeadlessConfigFn
    preflightHelpers.runCommandCaptureFn
    preflightHelpers.commandAssertionsFn
  ];

  script = ''
    def scenario_preflight_pending_offline_update() -> None:
        from nails_e2e import session

        machine.wait_for_unit("multi-user.target")

        config_path = "/mnt/data/config/preflight-offline-update.toml"
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        write_headless_config(config_path)
        check = f"nails --config {config_path} check --overlay-only"
        activate = f"nails --config {config_path} activate -y --overlay-only"
        # What an updater leaves: a link to a staged update this decoy never got.
        payload = "/var/lib/PackageKit/prepared-update"

        def output(result):
            return result["stdout"] + result["stderr"]

        with subtest("a link staged on the decoy refuses check and activation"):
            machine.succeed(f"ln -s {payload} /system-update")
            for label, command in (
                ("offline-update-check", check),
                ("offline-update-activate", activate),
            ):
                result = run_command_capture(label, command)
                assert_command_failed(result)
                assert_text_contains(
                    output(result),
                    [
                        "pending-offline-update",
                        "a pending offline update is staged (/system-update on the decoy)",
                        "rm /system-update",
                    ],
                )
            # Refused before anything was written: no next root, no root upper.
            session.assert_decoy_root(machine)
            machine.succeed("test ! -e /mnt/data/root/upper")
            machine.succeed("rm /system-update")

        with subtest("a link left in the upper refuses until discard deletes it"):
            # A hidden session that staged an update leaves the link in the
            # root overlay's upper, which neither the decoy's updater nor an
            # rm on the decoy reaches.
            machine.succeed(
                "install -d -m 0700 /mnt/data/root /mnt/data/root/upper && "
                f"ln -s {payload} /mnt/data/root/upper/system-update"
            )
            result = run_command_capture("offline-update-upper-check", check)
            assert_command_failed(result)
            assert_text_contains(
                output(result),
                [
                    "/system-update in the hidden session's overlay",
                    "discard /system-update",
                ],
            )
            result = run_command_capture(
                "offline-update-discard",
                f"nails --config {config_path} discard -y /system-update",
            )
            assert_command_succeeded(result)
            machine.succeed("test ! -L /mnt/data/root/upper/system-update")
            result = run_command_capture("offline-update-cleared-check", check)
            assert_text_contains(
                output(result),
                ["pending-offline-update: no pending offline update is staged on the decoy"],
            )

        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
