# Test 50: Notify Malformed Signal

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  notificationHelpers = import ./../../lib/notification-helpers.nix;
in {
  name = "notify-malformed-signal";
  meta.tags = [ "notification" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    import json

    ${notificationHelpers.writeNotificationConfigFn}
    ${notificationHelpers.installNotifySendStubFn}
    ${notificationHelpers.writeNotificationSignalFn}
    ${notificationHelpers.writeRawNotificationFileFn}
    ${notificationHelpers.runCommandCaptureFn}
    ${notificationHelpers.readStubCallsFn}

        machine.start()
        machine.wait_for_unit("multi-user.target")

        config_path = "/tmp/nails-notify.yaml"
        stub_dir = "/tmp/notify-stub/bin"
        stub_log = "/tmp/notify-send.log"
        bad_path = "/mnt/hidden-volume/notifications/20260101T000000000_bad.json"
        good_path = "/mnt/hidden-volume/notifications/20260101T000000001_good.json"

        with subtest("prepare signals and safe notify-send stub"):
            machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
            write_notification_config(config_path)
            install_notify_send_stub(stub_dir, stub_log)
            write_raw_notification_file(bad_path, "{ definitely-not-json")
            write_notification_signal(
                good_path,
                title="Good Notification",
                body="Processed after malformed peer",
                urgency="low",
            )
            machine.succeed(f"chown -R testuser:testuser {stub_dir.rsplit('/', 1)[0]} {stub_log} /mnt/hidden-volume/notifications")

        with subtest("dispatcher skips malformed file and processes valid one"):
            result = run_command_capture(
                f'su - testuser -c "PATH={stub_dir}:$PATH nails --no-logs --config {config_path} notify-dispatch --json"',
                "/tmp/notify-malformed",
            )
            assert result["rc"] == 0, result

            payload = json.loads(result["stdout"].strip())
            assert payload == {"dispatched": 1, "status": "ok"}, payload
            assert "Skipping malformed notification file" in result["stderr"], result["stderr"]

            calls = read_stub_calls(stub_log)
            assert calls == [[
                "--urgency",
                "low",
                "--app-name",
                "NAILS",
                "Good Notification",
                "Processed after malformed peer",
            ]], calls

            machine.succeed(f"test -f {bad_path}")
            machine.fail(f"test -f {good_path}")
  '';
}
