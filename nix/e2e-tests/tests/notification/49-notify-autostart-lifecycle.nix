# Test 49: Notify Autostart Lifecycle
#
# A graphical activation queues its login notifications and writes the XDG
# autostart entry that delivers them. The binary is run from the hidden
# volume, as in a real deployment, so the entry's Exec line is the command a
# login would run; the test runs exactly that command as the operator (an
# isNormalUser account, primary group `users`) and asserts the queue is
# delivered. Nothing in the queue is staged or re-owned by the test.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  notificationHelpers = import ./../../lib/notification-helpers.nix;
  sessionHelpers = import ./../../lib/session-helpers.nix;
in
{
  name = "notify-autostart-lifecycle";
  meta.tags = [ "notification" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/graphical-vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.waitForStatusStateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${assertions.assertOwnedByFn}
    ${notificationHelpers.installNotifySendStubFn}
    ${notificationHelpers.runCommandCaptureFn}
    ${notificationHelpers.readStubCallsFn}
    ${notificationHelpers.dispatchResultFn}
    ${sessionHelpers.waitForActivationTransientUnitFn}
    ${sessionHelpers.assertUnitInSystemSliceFn}

    def install_nixos_rebuild_wrapper(log_path):
        machine.succeed(
            f"""mkdir -p /tmp/nails-wrapper/bin
    rm -f {log_path}
    cat > /tmp/nails-wrapper/bin/nixos-rebuild <<'EOF'
    #!/bin/sh
    printf '%s\\n' "$*" >> {log_path}
    exit 0
    EOF
    chmod 755 /tmp/nails-wrapper/bin/nixos-rebuild"""
        )
        return "PATH=/tmp/nails-wrapper/bin:$PATH"

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("display-manager.service")
    machine.wait_until_succeeds("systemctl is-active user@1000.service")

    headless_config = "/tmp/nails-headless.toml"
    autostart_dir = "/home/testuser/.config/autostart"
    desktop_path = f"{autostart_dir}/nails-notify.desktop"
    hidden_desktop_path = "/mnt/data/home/testuser/.config/autostart/nails-notify.desktop"
    hidden_nails = "/mnt/data/nails"
    queue_dir = "/mnt/data/notifications"
    # Outside every overlay the headless config mounts, so the stub and its log
    # are the same files before and after activation.
    stub_dir = "/var/lib/notify-stub/bin"
    stub_log = "/var/lib/notify-stub/notify-send.log"
    wrapper_env = install_nixos_rebuild_wrapper("/tmp/nixos-rebuild-notify-autostart.log")

    with subtest("prepare hidden volume with the binary on it"):
        assert machine.succeed("id -gn testuser").strip() == "users"
        write_headless_config(headless_config)
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(f"install -m 0755 ${self.packages.x86_64-linux.nails}/bin/nails {hidden_nails}")
        machine.fail(f"test -e {queue_dir}")
        machine.fail(f"test -e {desktop_path}")
        machine.fail(f"test -e {hidden_desktop_path}")
        assert_status_state("Inactive")

    with subtest("real graphical activation writes autostart entry and queues login notifications"):
        machine.succeed(
            f"{wrapper_env} env DISPLAY=:0 XDG_SESSION_TYPE=x11 SUDO_UID=1000 SUDO_USER=testuser "
            + "SHELL=/run/current-system/sw/bin/bash "
            + f"{hidden_nails} --config {headless_config} activate -y"
        )
        activation_unit = wait_for_activation_transient_unit()
        assert_unit_in_system_slice(activation_unit)
        machine.wait_until_succeeds("systemctl is-active display-manager.service")
        machine.wait_until_succeeds("systemctl is-active user@1000.service")
        machine.wait_until_succeeds(f"test -f {desktop_path}")
        assert_overlay_mounted("/home")
        # The binary lives in the Nix store, so status must use the headless
        # config to read the hidden-volume state rather than the store-derived
        # default root.
        wait_for_status_state("Active", config_path=headless_config)

        assert_owned_by(autostart_dir, "testuser:users", "700")
        assert_owned_by(desktop_path, "testuser:users", "644")

        # The VM runs no notification daemon, so a dispatcher the login session
        # may have launched cannot deliver anything (notify-send fails and the
        # queue is kept); the stub run below is the only delivery.
        assert_owned_by(queue_dir, "testuser:users", "700")
        queued = machine.succeed(
            f"find {queue_dir} -mindepth 1 -maxdepth 1 -name '*.json' | sort"
        ).split()
        assert queued, "activation queued no login notification"
        for signal in queued:
            assert_owned_by(signal, "testuser:users", "600")

        machine.succeed(f"test -f {hidden_desktop_path}")
        desktop_text = machine.succeed(f"cat {desktop_path}")
        hidden_text = machine.succeed(f"cat {hidden_desktop_path}")
        assert desktop_text == hidden_text, "Visible and hidden autostart entries diverged"
        for expected in [
            "[Desktop Entry]",
            "Type=Application",
            "Name=Notification dispatch",
            "Comment=Dispatches pending desktop notifications on login",
            "Terminal=false",
            "NoDisplay=true",
            "X-GNOME-Autostart-enabled=true",
        ]:
            assert expected in desktop_text, f"Missing {expected!r} in {desktop_text!r}"
        assert "notify-dispatch" in desktop_text, desktop_text
        assert "Exec=nails notify-dispatch" not in desktop_text, desktop_text
        assert "Exec=/" in desktop_text, desktop_text

    with subtest("autostart command run as the operator dispatches the queued login notifications"):
        exec_lines = [line for line in desktop_text.splitlines() if line.startswith("Exec=")]
        assert exec_lines == [f"Exec={hidden_nails} notify-dispatch"], exec_lines
        autostart_command = exec_lines[0][len("Exec="):]

        install_notify_send_stub(stub_dir, stub_log)
        result = run_command_capture(
            f'su - testuser -c "PATH={stub_dir}:$PATH {autostart_command} --json"',
            "/tmp/notify-autostart",
        )
        assert result["rc"] == 0, result

        data = dispatch_result(result["stdout"])
        assert data == {"dispatched": len(queued), "status": "ok"}, (data, result["stderr"])

        calls = read_stub_calls(stub_log)
        assert len(calls) == len(queued), calls
        delivered_titles = [call[-2] for call in calls]
        assert "NAILS Overlay Active" in delivered_titles, calls
        machine.succeed(f"test -z \"$(ls -A {queue_dir})\"")

    with subtest("deactivation removes autostart entry from decoy view"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-notify-autostart")
        machine.wait_until_succeeds("systemctl is-active display-manager.service")
        assert_status_state("Inactive")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        machine.fail(f"test -e {desktop_path}")

    with subtest("hidden upper still contains the autostart entry after reboot"):
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        machine.succeed(f"test -f {hidden_desktop_path}")
        hidden_text = machine.succeed(f"cat {hidden_desktop_path}")
        assert "notify-dispatch" in hidden_text, hidden_text
        assert "Exec=nails notify-dispatch" not in hidden_text, hidden_text
        assert "Exec=/" in hidden_text, hidden_text
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
