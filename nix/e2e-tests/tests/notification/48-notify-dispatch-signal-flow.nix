# Test 48: Notify Dispatch Signal Flow
#
# The whole path of a notification nails writes itself: activation queues the
# overlay-status signal for the operator, and the dispatcher, run as that
# operator on an ordinary isNormalUser account (primary group `users`), reads
# it, hands it to notify-send and clears the queue. Nothing in the queue is
# staged or re-owned by the test, so a signal left to root, or chowned to a
# group the account is not in, makes the dispatch fail here.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  shellHelpers = import ./../../lib/shell-helpers.nix;
  notificationHelpers = import ./../../lib/notification-helpers.nix;
in
{
  name = "notify-dispatch-signal-flow";
  meta.tags = [ "notification" ];

  testScript = _: ''
    import json

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOwnedByFn}
    ${shellHelpers.activateForUserFn}
    ${notificationHelpers.writeNotificationConfigFn}
    ${notificationHelpers.installNotifySendStubFn}
    ${notificationHelpers.runCommandCaptureFn}
    ${notificationHelpers.readStubCallsFn}
    ${notificationHelpers.dispatchResultFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-headless.toml"
    # The dispatcher only needs the hidden root; keep its config to that.
    notify_config = "/tmp/nails-notify.toml"
    shell_path = "/run/current-system/sw/bin/bash"
    queue_dir = "/mnt/data/notifications"
    # Outside every overlay the headless config mounts, so the stub and its log
    # are the same files before and after activation.
    stub_dir = "/var/lib/notify-stub/bin"
    stub_log = "/var/lib/notify-stub/notify-send.log"

    with subtest("testuser is an ordinary account whose primary group is users"):
        assert machine.succeed("id -gn testuser").strip() == "users"

    with subtest("activation queues notifications owned by the operator"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        write_headless_config(config_path)
        write_notification_config(notify_config)
        machine.fail(f"test -e {queue_dir}")
        activate_for_user(config_path, shell_path)
        assert_status_state("active", config_path=config_path)

        assert_owned_by(queue_dir, "testuser:users", "700")
        queued = machine.succeed(
            f"find {queue_dir} -mindepth 1 -maxdepth 1 -name '*.json' | sort"
        ).split()
        assert queued, "activation queued no notification"
        titles = []
        for signal in queued:
            assert_owned_by(signal, "testuser:users", "600")
            titles.append(json.loads(machine.succeed(f"cat {signal}"))["title"])
        assert "NAILS Overlay Active" in titles, titles

    with subtest("dispatcher run as the operator delivers every queued signal"):
        install_notify_send_stub(stub_dir, stub_log)
        result = run_command_capture(
            f'su - testuser -c "PATH={stub_dir}:$PATH nails --no-log-file --config {notify_config} notify-dispatch --json"',
            "/tmp/notify-flow",
        )
        assert result["rc"] == 0, result

        data = dispatch_result(result["stdout"])
        assert data == {"dispatched": len(queued), "status": "ok"}, (data, result["stderr"])

        calls = read_stub_calls(stub_log)
        assert len(calls) == len(queued), calls
        overlay_calls = [call for call in calls if "NAILS Overlay Active" in call]
        assert len(overlay_calls) == 1, calls
        call = overlay_calls[0]
        assert call[:5] == ["--urgency", "normal", "--app-name", "NAILS", "--icon"], call
        assert call[5] in ("security-high", "security-medium"), call
        assert call[6] == "NAILS Overlay Active", call
        assert call[7].startswith("Security: "), call

        machine.succeed(f"test -z \"$(ls -A {queue_dir})\"")
  '';
}
