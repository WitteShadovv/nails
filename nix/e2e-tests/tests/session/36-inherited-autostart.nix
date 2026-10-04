# Test 36: Inherited autostart masking
#
# Seeds the decoy user with an autostart entry and an enabled systemd user
# timer, then activates with `[persona] mask_inherited` covering both. The mask
# must appear in the merged home while the hidden session is active (a
# `Hidden=true` autostart override and a `/dev/null` user-unit mask), and after a
# canonical deactivation the decoy home must be byte-for-byte what it was before,
# because the masks lived only in the hidden overlay's upper layer.
#
# NOTE: this test cannot be evaluated in the development sandbox (the Nix daemon
# is unavailable); it must be run on a Nix host as part of the session E2E suite.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  assertions = import ./../../lib/assertions.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  sessionHelpers = import ./../../lib/session-helpers.nix;
  baseOs = import ./../../lib/base-os-overlays.nix;
in
{
  name = "inherited-autostart";
  meta.tags = [ "session" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/graphical-vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''

    ${testHelpers.readStatusJsonFn}
    ${testHelpers.waitForStatusStateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${sessionHelpers.readSystemdActiveEnterMonotonicFn}
    ${sessionHelpers.waitForUnitRestartedFn}
    ${sessionHelpers.waitForActivationTransientUnitFn}

    config_path = "/tmp/nails-mask.toml"
    autostart_entry = "/home/testuser/.config/autostart/decoy-sync.desktop"
    user_unit_dir = "/home/testuser/.config/systemd/user"
    user_wants = user_unit_dir + "/timers.target.wants"
    user_timer_link = user_wants + "/decoy-sync.timer"
    # The unit load path the /dev/null mask is written to (systemd masks a unit by
    # its name here, not by its *.wants enable symlink).
    user_timer_unit = user_unit_dir + "/decoy-sync.timer"

    def write_mask_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "skip"
    # The hidden data disk is only ~2 GB, below the 4 GB default rebuild floor;
    # lower it so the post-mount space guard lets the stubbed rebuild run.
    rebuild_space_mb = 64

    [persona]
    mask_inherited = ["decoy-sync", "decoy-sync.timer"]

    ${baseOs.toml}
    [[overlays]]
    name = "etc"
    lower = "/etc"
    upper = "/mnt/data/etc"
    work = "/mnt/data/.work/etc"
    target = "/etc"

    [[overlays]]
    name = "home"
    lower = "/home"
    upper = "/mnt/data/home"
    work = "/mnt/data/.work/home"
    target = "/home"

    [[overlays]]
    name = "root"
    lower = "/root"
    upper = "/mnt/data/root"
    work = "/mnt/data/.work/root"
    target = "/root"

    [[overlays]]
    name = "srv"
    lower = "/srv"
    upper = "/mnt/data/srv"
    work = "/mnt/data/.work/srv"
    target = "/srv"

    [[overlays]]
    name = "tmp"
    lower = "/tmp"
    upper = "/mnt/data/tmp"
    work = "/mnt/data/.work/tmp"
    target = "/tmp"
    EOF""" % path
        )

    def seed_decoy_persona():
        # A decoy autostart entry that would run under the decoy identity.
        machine.succeed("mkdir -p /home/testuser/.config/autostart")
        machine.succeed(
            "cat > %s <<'EOF'\n"
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=Decoy Sync\n"
            "Exec=/run/current-system/sw/bin/touch /home/testuser/decoy-autostart-ran\n"
            "X-GNOME-Autostart-enabled=true\n"
            "EOF" % autostart_entry
        )
        # An enabled systemd user timer (an enable symlink under *.wants).
        machine.succeed("mkdir -p " + user_wants)
        machine.succeed(
            "cat > /home/testuser/.config/systemd/user/decoy-sync.timer <<'EOF'\n"
            "[Unit]\n"
            "Description=Decoy Sync Timer\n"
            "[Timer]\n"
            "OnBootSec=1\n"
            "[Install]\n"
            "WantedBy=timers.target\n"
            "EOF"
        )
        machine.succeed(
            "ln -sf ../decoy-sync.timer " + user_timer_link
        )
        machine.succeed("chown -R testuser:users /home/testuser/.config")

    def hash_path(path):
        return machine.succeed("sha256sum " + path + " | cut -d' ' -f1").strip()

    machine.start()
    machine.wait_for_unit("display-manager.service")
    machine.wait_until_succeeds("systemctl is-active user@1000.service")

    with subtest("prepare hidden volume and seed decoy persona state"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        seed_decoy_persona()
        write_mask_config(config_path)
        autostart_hash_before = hash_path(autostart_entry)
        timer_unit_hash_before = hash_path(user_timer_unit)
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        display_manager_before = read_systemd_active_enter_monotonic("display-manager.service")

    with subtest("activate and mask the inherited decoy entries"):
        # --overlay-only: the detached worker runs with a fixed root PATH, so a
        # stub nixos-rebuild on the caller's PATH is never seen and a full
        # activate would run the real rebuild, which the offline VM cannot
        # complete (the switch then fails and the overlays roll back). The
        # persona masks are written before the session restart either way.
        machine.succeed(
            "env DISPLAY=:0 XDG_SESSION_TYPE=x11 SUDO_UID=1000 SUDO_USER=testuser "
            + "SHELL=/run/current-system/sw/bin/bash "
            + f"nails --config {config_path} activate --overlay-only -y"
        )
        wait_for_activation_transient_unit()
        wait_for_unit_restarted("display-manager.service", display_manager_before)
        machine.wait_until_succeeds(
            "/bin/sh -lc 'mountpoint -q /home && [ \"$(findmnt -n -o FSTYPE /home)\" = overlay ]'",
            timeout=180,
        )
        wait_for_status_state("active", config_path=config_path)
        assert_overlay_mounted("/home")

    with subtest("masks are present in the merged hidden home"):
        # The autostart entry is shadowed by a Hidden=true override.
        override = machine.succeed("cat " + autostart_entry)
        assert "Hidden=true" in override, override
        # The user timer is masked with a /dev/null symlink at its unit load path.
        link_target = machine.succeed("readlink " + user_timer_unit).strip()
        assert link_target == "/dev/null", link_target

    with subtest("deactivate and confirm the decoy home is unchanged"):
        canonical_deactivate(config_path, unit_name="nails-deactivate-inherited-autostart")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        assert_status_state("inactive", config_path=config_path)
        # The masks lived only in the upper layer, so both the decoy autostart entry
        # and the decoy user unit are byte-for-byte what they were before activation
        # (the unit file is a real file again, not the /dev/null mask), and the
        # *.wants enable symlink still points at the real unit.
        assert hash_path(autostart_entry) == autostart_hash_before, "decoy autostart entry changed"
        assert hash_path(user_timer_unit) == timer_unit_hash_before, "decoy user unit changed"
        restored_target = machine.succeed("readlink " + user_timer_link).strip()
        assert restored_target == "../decoy-sync.timer", restored_target
  '';
}
