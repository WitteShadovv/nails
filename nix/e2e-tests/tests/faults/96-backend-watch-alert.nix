# Fault test (g): the in-session watcher alerts when the backend fails, and the
# RAM-backed copy stays usable once the hidden volume is gone.
#
# After a session is active NAILS has one long-running component: the backend
# watcher, started at activation from the RAM-backed runtime copy under /run as a
# transient systemd unit with a neutral name. It polls the hidden root every few
# seconds and, the moment a probe fails, raises a desktop alert on the operator's
# session so a lazily-detached or failed backend is explained rather than showing
# up as random application errors. The mirrored binary on tmpfs means the panic
# button still runs after the hidden volume disappears. This test drives that
# whole path: activate, confirm the watcher unit and the /run copy, yank the
# backing device, confirm the alert fires, then run emergency from the /run copy.
#
# notify-send is shadowed by a logging stub on the system PATH so the alert is
# observable headlessly; the stub stands in for the operator's real session bus.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  notificationHelpers = import ./../../lib/notification-helpers.nix;
in
{
  name = "faults-backend-watch-alert";
  meta.tags = [
    "faults"
    "security"
  ];

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        # A notify-send that records its arguments instead of talking to a bus,
        # placed on the system PATH so the watcher's transient unit (started as a
        # system service) resolves it the same way the real binary would resolve
        # the operator's notify-send.
        (pkgs.writeShellScriptBin "notify-send" ''
          log=/var/lib/notify-stub/notify-send.log
          mkdir -p "$(dirname "$log")"
          {
            printf '__CALL__\n'
            for arg in "$@"; do
              printf '%s\n' "$arg"
            done
          } >> "$log"
          exit 0
        '')
      ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.waitForStatusStateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${notificationHelpers.readStubCallsFn}

    overlay_targets = ["/etc", "/home", "/root", "/srv", "/tmp", "/usr", "/bin", "/lib64"]

    # The documented exit codes for emergency: a clean teardown (Ok) or a
    # degraded teardown that asks for a reboot to finish clearing RAM.
    documented_codes = {0, 7}

    # The neutral names the runtime copy and watcher use: nothing here may name
    # the product on screen or in systemctl.
    runtime_dir = "/run/overlay-runtime"
    watch_unit = "overlay-runtime-monitor.service"
    stub_log = "/var/lib/notify-stub/notify-send.log"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)
    # Enable the watcher explicitly and poll fast so the test reacts quickly.
    # auto_emergency stays off: this exercises the alert-only default, so a
    # transient probe failure cannot tear the session down on its own.
    machine.succeed(
        "printf '\\n[backend_watch]\\nenabled = true\\n"
        "auto_emergency = false\\npoll_interval_secs = 2\\n' >> " + headless_config
    )
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("activate a hidden session"):
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep -y"
        )
        wait_for_status_state("Active", config_path=headless_config)
        assert_overlay_mounted("/home")

    with subtest("activation mirrored a RAM-backed copy under /run"):
        # The mirrored binary, config and mount manifest live in a 0700 directory
        # with a neutral name, so emergency stays runnable once the hidden root is
        # gone.
        assert machine.succeed(f"stat -c %a {runtime_dir}").strip() == "700", "runtime copy must be 0700"
        machine.succeed(f"test -x {runtime_dir}/control")
        machine.succeed(f"test -f {runtime_dir}/settings.toml")
        machine.succeed(f"test -f {runtime_dir}/mounts.json")
        # No mirrored name may reveal the product.
        machine.fail(f"ls -R {runtime_dir} | grep -i nails")

    with subtest("the in-session watcher is running as a neutral transient unit"):
        machine.wait_for_unit(watch_unit)
        assert "nails" not in watch_unit

    with subtest("the backing device is yanked out from under the overlays"):
        # Swap the dm target for an error target in place so the hidden filesystem
        # returns EIO. "dmsetup remove" cannot remove the node while /mnt/data and
        # its overlays still hold it open, so wipe_table is used: it loads the error
        # target and resumes the device without removing it, and so succeeds.
        machine.succeed("dmsetup wipe_table --force data")

    with subtest("the watcher alerts the operator about the failed backend"):
        # The poll interval is 2s; give the watcher a generous window to notice.
        machine.wait_until_succeeds(f"test -s {stub_log}", timeout=30)
        calls = read_stub_calls(stub_log)
        assert calls, "watcher raised no desktop alert"
        alert = calls[0]
        # The alert is critical and worded to reveal nothing about a hidden
        # environment to anyone watching the screen.
        assert "--urgency" in alert and "critical" in alert, alert
        assert not any("nails" in token.lower() for token in alert), alert
        assert any("Storage unavailable" in token for token in alert), alert

    with subtest("emergency run from the /run copy tears down every overlay"):
        # Run the mirrored binary, not the one on the (now-gone) hidden root, with
        # no --config so it falls back to the mirrored settings.toml. timeout caps
        # the teardown so a wedge on the dead device is a failure, not a hang.
        rc, output = machine.execute(
            f"timeout 30 {runtime_dir}/control emergency", timeout=60
        )
        assert rc in documented_codes, f"emergency exit {rc} is not documented: {output!r}"
        assert_no_overlays(overlay_targets)

    with subtest("emergency removed the RAM-backed copy and stopped the watcher"):
        machine.fail(f"test -e {runtime_dir}")
        machine.fail(f"systemctl is-active {watch_unit}")
  '';
}
