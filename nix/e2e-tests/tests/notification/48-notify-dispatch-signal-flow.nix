# Test 48: Notify Dispatch Signal Flow

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  notificationHelpers = import ./../../lib/notification-helpers.nix;
in
{
  name = "notify-dispatch-signal-flow";
  meta.tags = [ "notification" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/graphical-vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    import json

    ${notificationHelpers.writeNotificationConfigFn}
    ${notificationHelpers.installNotifySendStubFn}
    ${notificationHelpers.writeNotificationSignalFn}
    ${notificationHelpers.runCommandCaptureFn}
    ${notificationHelpers.readStubCallsFn}

        machine.start()
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("display-manager.service")

        config_path = "/tmp/nails-notify.yaml"
        stub_dir = "/tmp/notify-stub/bin"
        stub_log = "/tmp/notify-send.log"
        signal_path = "/mnt/hidden-volume/notifications/20260101T000000000_flow.json"

        with subtest("prepare notification runtime with safe stub"):
            machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
            write_notification_config(config_path)
            install_notify_send_stub(stub_dir, stub_log)
            machine.succeed(f"chown -R testuser:testuser {stub_dir.rsplit('/', 1)[0]} {stub_log}")

        with subtest("stage one valid notification signal"):
            write_notification_signal(
                signal_path,
                title="Overlay Active",
                body="Flow reached desktop",
                urgency="critical",
                icon="security-high",
            )
            machine.succeed("chown testuser:testuser /mnt/hidden-volume/notifications")
            machine.succeed(f"chown testuser:testuser {signal_path}")
            machine.succeed(f"test -f {signal_path}")

        with subtest("dispatch signal through notify-send stub and clear queue"):
            result = run_command_capture(
                f'su - testuser -c "PATH={stub_dir}:$PATH nails --no-logs --config {config_path} notify-dispatch --json"',
                "/tmp/notify-flow",
            )
            assert result["rc"] == 0, result

            payload = json.loads(result["stdout"].strip())
            assert payload == {"dispatched": 1, "status": "ok"}, payload

            calls = read_stub_calls(stub_log)
            assert calls == [[
                "--urgency",
                "critical",
                "--app-name",
                "NAILS",
                "--icon",
                "security-high",
                "Overlay Active",
                "Flow reached desktop",
            ]], calls

            machine.fail(f"test -f {signal_path}")
            machine.succeed("test -z \"$(ls -A /mnt/hidden-volume/notifications)\"")
  '';
}
