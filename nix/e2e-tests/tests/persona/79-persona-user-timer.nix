# Test 79: A masked decoy user timer never fires in the hidden session
#
# Test 36 proves `[persona] mask_inherited` writes a `/dev/null` mask for an
# inherited user unit into the hidden root's upper; this test proves the mask
# has the effect that matters: the decoy's enabled user timer does not run
# under the hidden session's user manager. Two decoy user timers log the
# filesystem type backing `/` on every run, so a line reading `overlay` can only
# come from a run inside the hidden session (whose root is the overlay):
#
# - Positive control: before activation both timers fire in the decoy session.
# - Hidden session: the soft-reboot starts the autologin session again in the
#   hidden root; the unmasked control timer keeps firing there (so the hidden
#   user manager does run timers), while the masked canary timer reports
#   `masked` and logs no run during several of the control timer's periods.
# - After deactivation the decoy canary unit is a regular file again, it fires
#   again, and no hidden-session run reached the decoy's log.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "persona-user-timer";
  meta.tags = [
    "session"
    "graphical"
  ];

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
    canary = "decoy-canary"
    control = "decoy-control"
    user_unit_dir = "/home/testuser/.config/systemd/user"
    user_wants = user_unit_dir + "/timers.target.wants"
    # Control-timer runs in the hidden session that must pass without a single
    # canary run (3 s apart, so about 15 s of armed timers).
    quiet_control_runs = 5


    def canary_log(name):
        return "/var/tmp/" + name + ".log"


    def write_mask_config(path):
        machine.succeed(
            f"cat > {path} <<'EOF'\n"
            "hidden_volume_root = \"/mnt/data\"\n"
            "minimum_space_mb = 100\n"
            "\n"
            "[persona]\n"
            f"mask_inherited = [\"{canary}.timer\"]\n"
            "EOF"
        )


    def seed_decoy_timer(name):
        # A decoy user timer enabled the usual way (a *.wants symlink), firing
        # shortly after the user manager starts and then every few seconds. The
        # service logs which filesystem backs / at the moment it runs.
        machine.succeed("mkdir -p " + user_wants)
        machine.succeed(
            "cat > " + user_unit_dir + "/" + name + ".service <<'EOF'\n"
            "[Unit]\n"
            "Description=Decoy timer " + name + "\n"
            "[Service]\n"
            "Type=oneshot\n"
            "ExecStart=/run/current-system/sw/bin/sh -c "
            "'/run/current-system/sw/bin/findmnt -n -o FSTYPE / "
            ">> " + canary_log(name) + "'\n"
            "EOF"
        )
        machine.succeed(
            "cat > " + user_unit_dir + "/" + name + ".timer <<'EOF'\n"
            "[Unit]\n"
            "Description=Decoy timer " + name + "\n"
            "[Timer]\n"
            "OnStartupSec=1\n"
            "OnUnitActiveSec=3\n"
            "AccuracySec=1\n"
            "[Install]\n"
            "WantedBy=timers.target\n"
            "EOF"
        )
        machine.succeed(
            "ln -sf ../" + name + ".timer " + user_wants + "/" + name + ".timer"
        )
        machine.succeed("rm -f " + canary_log(name))


    def user_systemctl(args):
        # Query testuser's own manager from root; the output is returned even
        # when systemctl exits non-zero (is-active/is-enabled report via both).
        _, out = machine.execute(
            "systemctl --user --machine=testuser@ " + args + " 2>&1"
        )
        return out.strip()


    def runs(name, fstype=None):
        _, out = machine.execute("cat " + canary_log(name) + " 2>/dev/null")
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        if fstype is None:
            return len(lines)
        return sum(1 for line in lines if line == fstype)


    def decoy_runs(name):
        return runs(name) - runs(name, "overlay")


    def wait_for_runs(name, fstype_test, at_least):
        # fstype_test: "-v" counts decoy runs, "" counts hidden-session runs.
        machine.wait_until_succeeds(
            f"test \"$(grep -c {fstype_test} '^overlay$' {canary_log(name)} 2>/dev/null)\" -ge {at_least}",
            timeout=120,
        )


    machine.start()
    machine.wait_for_unit("display-manager.service")
    machine.wait_until_succeeds("systemctl is-active user@1000.service")

    with subtest("seed the decoy timers and prove they fire in the decoy session"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        seed_decoy_timer(canary)
        seed_decoy_timer(control)
        machine.succeed("chown -R testuser:users /home/testuser/.config")
        write_mask_config(CONFIG)
        # The user manager was already running when the units appeared.
        user_systemctl("daemon-reload")
        user_systemctl(f"start {canary}.timer {control}.timer")
        wait_for_runs(canary, "-v", 1)
        wait_for_runs(control, "-v", 1)
        assert user_systemctl(f"is-active {canary}.timer") == "active", (
            "the decoy canary timer is not active in the decoy session"
        )
        assert runs(canary, "overlay") == 0, "a canary run was logged on an overlay"

    with subtest("activate: the hidden session starts with the timer masked"):
        log = "/mnt/data/activate.log"
        session.follow_soft_reboot(
            machine,
            f"su testuser -c 'sudo nails --config {CONFIG} activate -y --overlay-only' > {log} 2>&1",
            "activate",
        )
        print(machine.succeed(f"cat {log} || true"))
        session.assert_hidden_root(machine)
        link_target = machine.succeed(
            f"readlink {user_unit_dir}/{canary}.timer"
        ).strip()
        assert link_target == "/dev/null", link_target

    with subtest("the masked timer never runs while the control timer does"):
        machine.wait_for_unit("display-manager.service")
        machine.wait_until_succeeds("systemctl is-active user@1000.service", timeout=120)
        machine.wait_until_succeeds(
            "systemctl --user --machine=testuser@ is-active timers.target",
            timeout=120,
        )
        enabled = user_systemctl(f"is-enabled {canary}.timer")
        assert enabled == "masked", f"{canary}.timer is {enabled!r} in the hidden session"
        assert user_systemctl(f"is-active {canary}.timer") != "active", (
            f"{canary}.timer is active in the hidden session"
        )
        # The control timer keeps firing in the hidden session: its runs bound
        # the window in which the masked canary would have fired too.
        wait_for_runs(control, "", quiet_control_runs)
        hidden_runs = runs(canary, "overlay")
        assert hidden_runs == 0, (
            f"the masked decoy timer ran {hidden_runs} time(s) in the hidden session"
        )
        decoy_canary_runs = decoy_runs(canary)

    with subtest("deactivate: the decoy timer is unmasked and fires again"):
        canonical_deactivate(CONFIG, "deactivate")
        unit_kind = machine.succeed(
            f"stat -c %F {user_unit_dir}/{canary}.timer"
        ).strip()
        assert unit_kind == "regular file", f"decoy timer unit is a {unit_kind}"
        # The hidden session's runs went to the upper: the decoy's logs hold
        # no overlay line.
        assert runs(control, "overlay") == 0, "a hidden-session run reached the decoy"
        machine.wait_for_unit("display-manager.service")
        machine.wait_until_succeeds("systemctl is-active user@1000.service", timeout=120)
        wait_for_runs(canary, "-v", decoy_canary_runs + 1)
        assert runs(canary, "overlay") == 0, "a hidden-session canary run was logged"
  '';
}
