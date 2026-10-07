# Scenario `notify-no-notify-send` of the `notify-dispatch` batch:
#   tests/notification/48-notify-dispatch.nix
# Formerly the stand-alone test
#   tests/notification/51-notify-no-notify-send.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix);
# its subtests and assertions are unchanged.
#
# Test 51: Notify No notify-send

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  notificationHelpers = import ./../../lib/notification-helpers.nix;
in
{
  name = "notify-no-notify-send";
  tags = [
    "notification"
    "smoke"
  ];

  helpers = [
    notificationHelpers.writeNotificationConfigFn
    notificationHelpers.writeNotificationSignalFn
    notificationHelpers.runCommandCaptureFn
    notificationHelpers.dispatchResultFn
  ];

  script = ''
    def scenario_notify_no_notify_send() -> None:
        import json

        machine.wait_for_unit("multi-user.target")

        config_path = "/tmp/nails-notify.toml"
        signal_path = "/mnt/data/notifications/20260101T000000000_missing-notify-send.json"
        nails_path = machine.succeed("command -v nails").strip()

        with subtest("prepare one pending notification without notify-send in PATH"):
            machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
            write_notification_config(config_path)
            write_notification_signal(
                signal_path,
                title="No notify-send",
                body="Dispatcher should degrade cleanly",
            )

        dispatch_command = f'su - testuser -c "PATH=/run/wrappers/bin:/bin {nails_path} --no-log-file --config {config_path} notify-dispatch --json"'
        missing_record = "/mnt/data/notifications/.notify-send-missing"
        missing_warning = "notify-send not found on PATH; desktop notifications stay queued"

        with subtest("dispatcher exits cleanly, preserves the pending file and records the missing notify-send"):
            result = run_command_capture(dispatch_command, "/tmp/notify-missing-bin")
            assert result["rc"] == 0, result

            data = dispatch_result(result["stdout"])
            assert data == {"dispatched": 0, "status": "ok"}, data
            assert missing_warning in result["stderr"], result["stderr"]
            machine.succeed(f"test -f {signal_path}")
            # Recorded on the hidden volume so status can explain the queue.
            machine.succeed(f"test -f {missing_record}")

        with subtest("the missing notify-send is reported once, not at every dispatch"):
            result = run_command_capture(dispatch_command, "/tmp/notify-missing-bin-again")
            assert result["rc"] == 0, result
            assert missing_warning not in result["stderr"], result["stderr"]
            machine.succeed(f"test -f {signal_path}")

        with subtest("status lists the undelivered notification and why"):
            status = json.loads(
                machine.succeed(f"{nails_path} --no-log-file --config {config_path} status --json")
            )["data"]
            titles = [n["title"] for n in status["undelivered_notifications"]]
            assert titles == ["No notify-send"], status
            assert status["notify_send_missing"] is True, status
            human = machine.succeed(f"{nails_path} --no-log-file --config {config_path} status")
            assert "Undelivered notifications: 1" in human, human
            assert "notify-send was not found" in human, human
  '';
}
