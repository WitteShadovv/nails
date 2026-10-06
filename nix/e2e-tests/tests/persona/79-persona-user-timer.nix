# Test 79: A masked decoy user timer never fires in the hidden session
#
# Test 36 proves `[persona] mask_inherited` writes a `/dev/null` mask for an
# inherited user unit; this test proves the mask has the effect that matters:
# the decoy's enabled user timer does not run under the hidden session's user
# manager. The canary timer's service appends the filesystem type backing /home
# to a log outside every overlay, so a line reading `overlay` can only come from
# a run inside the hidden session.
#
# - Positive control: before activation the timer fires in the decoy session.
# - Hidden session: after activation restarts the session, the user manager is
#   running again, the timer reports `masked`, and no hidden-session run is
#   logged for several timer periods.
# - After deactivation the decoy timer is unmasked and fires again.
#
# NOTE: this test cannot be evaluated in the development sandbox (the Nix daemon
# is unavailable); it must be run on a Nix host as part of the persona E2E suite.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  assertions = import ./../../lib/assertions.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  sessionHelpers = import ./../../lib/session-helpers.nix;
  baseOs = import ./../../lib/base-os-overlays.nix;
in
{
  name = "persona-user-timer";
  meta.tags = [
    "session"
    "graphical"
  ];

  # A graphical boot, a session restart and a reboot through deactivation.
  globalTimeout = 1800;

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

    config_path = "/tmp/nails-user-timer.toml"
    timer = "decoy-canary.timer"
    user_unit_dir = "/home/testuser/.config/systemd/user"
    user_wants = user_unit_dir + "/timers.target.wants"
    # /var is not overlaid, so this log records every run, decoy or hidden.
    canary_log = "/var/tmp/decoy-canary.log"
    # Several timer periods (3 s each) without a hidden-session run.
    quiet_seconds = 20

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
    mask_inherited = ["decoy-canary.timer"]

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

    def seed_decoy_timer():
        # A decoy user timer enabled the usual way (a *.wants symlink), firing
        # shortly after the user manager starts and then every few seconds. The
        # service logs which filesystem backs /home at the moment it runs.
        machine.succeed("mkdir -p " + user_wants)
        machine.succeed(
            "cat > " + user_unit_dir + "/decoy-canary.service <<'EOF'\n"
            "[Unit]\n"
            "Description=Decoy Canary\n"
            "[Service]\n"
            "Type=oneshot\n"
            "ExecStart=/run/current-system/sw/bin/sh -c "
            "'/run/current-system/sw/bin/findmnt -n -o FSTYPE --target /home "
            ">> " + canary_log + "'\n"
            "EOF"
        )
        machine.succeed(
            "cat > " + user_unit_dir + "/" + timer + " <<'EOF'\n"
            "[Unit]\n"
            "Description=Decoy Canary Timer\n"
            "[Timer]\n"
            "OnStartupSec=1\n"
            "OnUnitActiveSec=3\n"
            "AccuracySec=1\n"
            "[Install]\n"
            "WantedBy=timers.target\n"
            "EOF"
        )
        machine.succeed("ln -sf ../" + timer + " " + user_wants + "/" + timer)
        machine.succeed("chown -R testuser:users /home/testuser/.config")

    def user_systemctl(args):
        # Query testuser's own manager from root; the output is returned even
        # when systemctl exits non-zero (is-active/is-enabled report via both).
        _, out = machine.execute(
            "systemctl --user --machine=testuser@ " + args + " 2>&1"
        )
        return out.strip()

    def canary_runs(fstype=None):
        _, out = machine.execute("cat " + canary_log + " 2>/dev/null")
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        if fstype is None:
            return len(lines)
        return sum(1 for line in lines if line == fstype)

    def wait_for_new_decoy_run(before):
        machine.wait_until_succeeds(
            "test \"$(grep -cv '^overlay$' " + canary_log + " 2>/dev/null)\" -gt "
            + str(before),
            timeout=120,
        )

    machine.start()
    machine.wait_for_unit("display-manager.service")
    machine.wait_until_succeeds("systemctl is-active user@1000.service")

    with subtest("seed the decoy timer and prove it fires in the decoy session"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        seed_decoy_timer()
        write_mask_config(config_path)
        machine.succeed("rm -f " + canary_log)
        # The user manager was already running when the units appeared.
        user_systemctl("daemon-reload")
        user_systemctl("start " + timer)
        wait_for_new_decoy_run(0)
        assert user_systemctl("is-active " + timer) == "active", (
            "the decoy canary timer is not active in the decoy session"
        )
        assert canary_runs("overlay") == 0, "a canary run was logged on an overlay"

    with subtest("activate: the hidden session restarts with the timer masked"):
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        display_manager_before = read_systemd_active_enter_monotonic(
            "display-manager.service"
        )
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
        wait_for_status_state("active", config_path=config_path)
        assert_overlay_mounted("/home")
        link_target = machine.succeed(
            "readlink " + user_unit_dir + "/" + timer
        ).strip()
        assert link_target == "/dev/null", link_target

    with subtest("the masked timer never runs in the hidden session"):
        # The hidden session's user manager is up, so silence is meaningful and
        # not just a missing manager.
        machine.wait_until_succeeds("systemctl is-active user@1000.service", timeout=120)
        # timers.target is reached once the manager has started its timers, so a
        # timer that was going to run would be armed by then.
        machine.wait_until_succeeds(
            "systemctl --user --machine=testuser@ is-active timers.target",
            timeout=120,
        )
        enabled = user_systemctl("is-enabled " + timer)
        assert enabled == "masked", f"{timer} is {enabled!r} in the hidden session"
        assert user_systemctl("is-active " + timer) != "active", (
            f"{timer} is active in the hidden session"
        )
        # sync-lint: allow sleep -- absence window: the masked timer must not fire
        machine.sleep(quiet_seconds)
        hidden_runs = canary_runs("overlay")
        assert hidden_runs == 0, (
            f"the masked decoy timer ran {hidden_runs} time(s) in the hidden session"
        )

    with subtest("deactivate: the decoy timer is unmasked and fires again"):
        canonical_deactivate(config_path, unit_name="nails-deactivate-user-timer")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        assert_status_state("inactive", config_path=config_path)
        unit_kind = machine.succeed(
            "stat -c %F " + user_unit_dir + "/" + timer
        ).strip()
        assert unit_kind == "regular file", f"decoy timer unit is a {unit_kind}"
        machine.wait_for_unit("display-manager.service")
        machine.wait_until_succeeds("systemctl is-active user@1000.service", timeout=120)
        decoy_runs_before = canary_runs() - canary_runs("overlay")
        wait_for_new_decoy_run(decoy_runs_before)
        assert canary_runs("overlay") == 0, "a hidden-session canary run was logged"
  '';
}
