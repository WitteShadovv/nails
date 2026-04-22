# Test 51: Notify No notify-send

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  notificationHelpers = import ./../../lib/notification-helpers.nix;
in
{
  name = "notify-no-notify-send";
  meta.tags = [
    "notification"
    "smoke"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    import json

    ${notificationHelpers.writeNotificationConfigFn}
    ${notificationHelpers.writeNotificationSignalFn}
    ${notificationHelpers.runCommandCaptureFn}

        machine.start()
        machine.wait_for_unit("multi-user.target")

        config_path = "/tmp/nails-notify.yaml"
        signal_path = "/mnt/hidden-volume/notifications/20260101T000000000_missing-notify-send.json"
        nails_path = machine.succeed("command -v nails").strip()

        with subtest("prepare one pending notification without notify-send in PATH"):
            machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
            write_notification_config(config_path)
            write_notification_signal(
                signal_path,
                title="No notify-send",
                body="Dispatcher should degrade cleanly",
            )
            machine.succeed("chown -R testuser:testuser /mnt/hidden-volume/notifications")

        with subtest("dispatcher exits cleanly and preserves pending file"):
            result = run_command_capture(
                f'su - testuser -c "PATH=/run/wrappers/bin:/bin {nails_path} --no-logs --config {config_path} notify-dispatch --json"',
                "/tmp/notify-missing-bin",
            )
            assert result["rc"] == 0, result

            payload = json.loads(result["stdout"].strip())
            assert payload == {"dispatched": 0, "status": "ok"}, payload
            assert "notify-send not found in PATH; skipping desktop notifications" in result["stderr"], result["stderr"]
            machine.succeed(f"test -f {signal_path}")
  '';
}
