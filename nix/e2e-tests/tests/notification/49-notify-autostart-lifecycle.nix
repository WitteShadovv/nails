# Test 49: Notify Autostart Lifecycle

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in {
  name = "notify-autostart-lifecycle";
  meta.tags = [ "notification" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/graphical-vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

        machine.start()
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("display-manager.service")

        headless_config = "/tmp/nails-headless.yaml"
        desktop_path = "/home/testuser/.config/autostart/nails-notify.desktop"
        hidden_desktop_path = "/mnt/hidden-volume/home/testuser/.config/autostart/nails-notify.desktop"

        with subtest("prepare hidden volume and clean decoy baseline"):
            write_headless_config(headless_config)
            machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
            machine.fail(f"test -e {desktop_path}")
            machine.fail(f"test -e {hidden_desktop_path}")
            assert_status_state("Inactive")

        with subtest("activation writes autostart entry into overlaid home"):
            machine.succeed(
                f"env NAILS_TARGET_USER=testuser nails --config {headless_config} activate --overlay-only --no-kill-session -y"
            )
            machine.wait_until_succeeds(f"test -f {desktop_path}")
            assert_overlay_mounted("/home")
            assert_status_state("Active")

            machine.succeed(f"test -f {hidden_desktop_path}")
            desktop_text = machine.succeed(f"cat {desktop_path}")
            hidden_text = machine.succeed(f"cat {hidden_desktop_path}")
            assert desktop_text == hidden_text, "Visible and hidden autostart entries diverged"
            for expected in [
                "[Desktop Entry]",
                "Type=Application",
                "Name=NAILS Notification Dispatch",
                "Comment=Dispatches pending NAILS notifications on login",
                "Exec=nails notify-dispatch",
                "Terminal=false",
                "NoDisplay=true",
                "X-GNOME-Autostart-enabled=true",
            ]:
                assert expected in desktop_text, f"Missing {expected!r} in {desktop_text!r}"

        with subtest("deactivation removes autostart entry from decoy view"):
            canonical_deactivate(headless_config, unit_name="nails-deactivate-notify-autostart")
            machine.wait_for_unit("display-manager.service")
            assert_status_state("Inactive")
            assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
            machine.fail(f"test -e {desktop_path}")

        with subtest("hidden upper still contains the autostart entry after reboot"):
            machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
            machine.succeed(f"test -f {hidden_desktop_path}")
            hidden_text = machine.succeed(f"cat {hidden_desktop_path}")
            assert "Exec=nails notify-dispatch" in hidden_text, hidden_text
            machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
