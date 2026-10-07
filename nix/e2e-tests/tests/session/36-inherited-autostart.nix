# Test 36: Inherited autostart masking
#
# Seeds the decoy user with an autostart entry and an enabled systemd user
# timer, then enters the hidden session with `[persona] mask_inherited`
# covering both. NAILS writes the masks into the hidden root's upper at entry,
# so in the hidden session:
#
#   - the merged autostart entry is a `Hidden=true` override and the user timer
#     is masked by a `/dev/null` symlink at its unit load path;
#   - both live under /mnt/data/root/upper/home/testuser, the hidden volume;
#   - the decoy filesystem (mounted read-only at a scratch dir) still holds the
#     original files byte for byte.
#
# After `nails deactivate` the decoy home is byte-for-byte what it was before
# activation: the masks never existed outside the upper. The activation is run
# through sudo by the decoy user, the way an operator runs it, so the masks are
# written for that user's home.
{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "inherited-autostart";
  meta.tags = [ "session" ];

  # A graphical boot and two soft-reboots.
  globalTimeout = 1500;

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/graphical-vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    from nails_e2e import session

    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    UPPER = "/mnt/data/root/upper"
    PEEK = "/run/decoy-peek"
    autostart_entry = "/home/testuser/.config/autostart/decoy-sync.desktop"
    user_unit_dir = "/home/testuser/.config/systemd/user"
    user_timer_link = user_unit_dir + "/timers.target.wants/decoy-sync.timer"
    # The unit load path the /dev/null mask is written to (systemd masks a unit
    # by its name here, not by its *.wants enable symlink).
    user_timer_unit = user_unit_dir + "/decoy-sync.timer"


    def write_mask_config(path):
        machine.succeed(
            f"cat > {path} <<'EOF'\n"
            "hidden_volume_root = \"/mnt/data\"\n"
            "minimum_space_mb = 100\n"
            "\n"
            "[persona]\n"
            "mask_inherited = [\"decoy-sync\", \"decoy-sync.timer\"]\n"
            "EOF"
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
        machine.succeed("mkdir -p " + user_unit_dir + "/timers.target.wants")
        machine.succeed(
            "cat > " + user_timer_unit + " <<'EOF'\n"
            "[Unit]\n"
            "Description=Decoy Sync Timer\n"
            "[Timer]\n"
            "OnBootSec=1\n"
            "[Install]\n"
            "WantedBy=timers.target\n"
            "EOF"
        )
        machine.succeed("ln -sf ../decoy-sync.timer " + user_timer_link)
        machine.succeed("chown -R testuser:users /home/testuser/.config")


    def hash_path(path, root=""):
        return machine.succeed(
            "sha256sum " + root + path + " | cut -d' ' -f1"
        ).strip()


    def peek_decoy(decoy_dev, command):
        """Run `command` against a read-only mount of the decoy root at PEEK.

        The decoy superblock is still mounted read-write (it is the overlay's
        lower), so mount it, then make this mount read-only."""
        machine.succeed(
            f"mkdir -p {PEEK} && mount {decoy_dev} {PEEK} && mount -o remount,bind,ro {PEEK}"
        )
        try:
            return machine.succeed(command)
        finally:
            machine.succeed(f"umount {PEEK} && rmdir {PEEK}")


    machine.start()
    machine.wait_for_unit("display-manager.service")
    machine.wait_until_succeeds("systemctl is-active user@1000.service")
    decoy_dev = machine.succeed("findmnt -no SOURCE /").strip()

    with subtest("prepare hidden volume and seed decoy persona state"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        seed_decoy_persona()
        write_mask_config(CONFIG)
        autostart_hash_before = hash_path(autostart_entry)
        timer_unit_hash_before = hash_path(user_timer_unit)

    with subtest("activate through sudo as the decoy user"):
        log = "/mnt/data/activate.log"
        session.follow_soft_reboot(
            machine,
            f"su testuser -c 'sudo nails --config {CONFIG} activate -y --overlay-only' > {log} 2>&1",
            "activate",
        )
        print(machine.succeed(f"cat {log} || true"))
        session.assert_hidden_root(machine, UPPER)

    with subtest("masks are present in the merged hidden home"):
        override = machine.succeed("cat " + autostart_entry)
        assert "Hidden=true" in override, override
        link_target = machine.succeed("readlink " + user_timer_unit).strip()
        assert link_target == "/dev/null", link_target

    with subtest("the masks live in the hidden root's upper only"):
        upper_override = machine.succeed("cat " + UPPER + autostart_entry)
        assert "Hidden=true" in upper_override, upper_override
        upper_link = machine.succeed("readlink " + UPPER + user_timer_unit).strip()
        assert upper_link == "/dev/null", upper_link
        decoy_hashes = peek_decoy(
            decoy_dev,
            f"sha256sum {PEEK}{autostart_entry} {PEEK}{user_timer_unit} | cut -d' ' -f1",
        ).split()
        assert decoy_hashes == [autostart_hash_before, timer_unit_hash_before], (
            f"the decoy filesystem changed under the hidden session: {decoy_hashes}"
        )

    with subtest("deactivate: the decoy home is byte-for-byte unchanged"):
        canonical_deactivate(CONFIG, "deactivate")
        # The decoy autostart entry and the decoy user unit are what they were
        # before activation (the unit file is a real file, not the /dev/null
        # mask), and the *.wants enable symlink still points at the real unit.
        assert hash_path(autostart_entry) == autostart_hash_before, "decoy autostart entry changed"
        assert hash_path(user_timer_unit) == timer_unit_hash_before, "decoy user unit changed"
        unit_kind = machine.succeed("stat -c %F " + user_timer_unit).strip()
        assert unit_kind == "regular file", f"decoy timer unit is a {unit_kind}"
        restored_target = machine.succeed("readlink " + user_timer_link).strip()
        assert restored_target == "../decoy-sync.timer", restored_target
  '';
}
