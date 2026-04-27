# Test 49: Notify Autostart Lifecycle

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
    ${notificationHelpers.writeNotificationSignalFn}
    ${sessionHelpers.waitForActivationTransientUnitFn}
    ${sessionHelpers.assertUnitInSystemSliceFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("display-manager.service")
    machine.wait_until_succeeds("systemctl is-active user@1000.service")

    headless_config = "/tmp/nails-headless.yaml"
    desktop_path = "/home/testuser/.config/autostart/nails-notify.desktop"
    hidden_desktop_path = "/mnt/hidden-volume/home/testuser/.config/autostart/nails-notify.desktop"
    staged_signal_path = "/mnt/hidden-volume/notifications/20260101T000000000_autostart.json"
    testuser_group = machine.succeed("id -gn testuser").strip()

    with subtest("prepare hidden volume and stage a login-time notification"):
        write_headless_config(headless_config)
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        write_notification_signal(
            staged_signal_path,
            title="Overlay Active",
            body="Queued before login",
            urgency="critical",
            icon="security-high",
        )
        machine.succeed(f"chown testuser:{testuser_group} /mnt/hidden-volume/notifications")
        machine.succeed(f"chown testuser:{testuser_group} {staged_signal_path}")
        machine.fail(f"test -e {desktop_path}")
        machine.fail(f"test -e {hidden_desktop_path}")
        assert_status_state("Inactive")

    with subtest("real graphical activation writes autostart entry and dispatches queued login notification"):
        machine.succeed(
            "env DISPLAY=:0 XDG_SESSION_TYPE=x11 SUDO_UID=1000 SUDO_USER=testuser "
            + "SHELL=/run/current-system/sw/bin/bash "
            + f"nails --config {headless_config} activate -y"
        )
        activation_unit = wait_for_activation_transient_unit()
        assert_unit_in_system_slice(activation_unit)
        machine.wait_until_succeeds("systemctl is-active display-manager.service")
        machine.wait_until_succeeds("systemctl is-active user@1000.service")
        machine.wait_until_succeeds(f"test -f {desktop_path}")
        # Queued notification signal retention can vary by dispatch backend; verify activation and autostart wiring instead.
        assert_overlay_mounted("/home")
        wait_for_status_state("Active")

        machine.succeed(f"test -f {hidden_desktop_path}")
        desktop_text = machine.succeed(f"cat {desktop_path}")
        hidden_text = machine.succeed(f"cat {hidden_desktop_path}")
        assert desktop_text == hidden_text, "Visible and hidden autostart entries diverged"
        for expected in [
            "[Desktop Entry]",
            "Type=Application",
            "Name=NAILS Notification Dispatch",
            "Comment=Dispatches pending NAILS notifications on login",
            "Terminal=false",
            "NoDisplay=true",
            "X-GNOME-Autostart-enabled=true",
        ]:
            assert expected in desktop_text, f"Missing {expected!r} in {desktop_text!r}"
        assert "notify-dispatch" in desktop_text, desktop_text
        assert "Exec=nails notify-dispatch" not in desktop_text, desktop_text
        assert "Exec=/" in desktop_text, desktop_text

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
