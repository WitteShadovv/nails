# Test 77: Emergency countdown UX in the whole-root session
#
# In the hidden session:
#   1. `nails emergency --countdown 30` prints an abortable countdown with the
#      Ctrl+C hint; Ctrl+C (SIGINT) during it aborts the emergency: the
#      machine stays in the hidden root, the hidden service keeps running and
#      the backend stays open.
#   2. `nails emergency --countdown 15` counts down 15, 14, ... 1 in order,
#      prints "starting now!", and only then returns to the plain decoy: the
#      soft-reboot back starts at least 15 s after the trigger. Its stderr is
#      written to the hidden volume and read back after reopening it.
#   3. The default `nails emergency` prints no countdown and returns at once:
#      its trigger-to-backdoor time is well below the countdown run's.
_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "emergency-countdown-ux";
  meta.tags = [ "security" ];
  # Three activations and two emergency soft-reboots at about 15-30 s each.
  globalTimeout = 1500;

  testScript = _: ''
    from nails_e2e import session

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    COUNTDOWN = 15

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    write_headless_config(CONFIG)


    def emergency_back(extra_args, err_file, label):
        timings = session.follow_soft_reboot(
            machine,
            f"nails --config {CONFIG} emergency {extra_args} 2> {err_file}",
            label,
        )
        session.assert_decoy_root(machine)
        machine.fail("systemctl is-active hidden-writer.service")
        machine.wait_until_succeeds("test ! -e /dev/mapper/data", timeout=60)
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        return timings, machine.succeed(f"cat {err_file}")


    with subtest("Ctrl+C during the countdown aborts the emergency"):
        canonical_activate(CONFIG, "--overlay-only", "activate-abort")
        machine.succeed("systemd-run --unit hidden-writer --property=Type=exec sleep infinity")
        rc, out = machine.execute(
            f"timeout -s INT -k 5 3 nails --config {CONFIG} emergency --countdown 30 2>&1"
        )
        assert rc == 124, f"the countdown did not run until interrupted (rc={rc}): {out}"
        assert "Emergency in 30... (Ctrl+C to abort)" in out, out
        assert "starting now!" not in out, out
        session.assert_hidden_root(machine)
        machine.succeed("systemctl is-active hidden-writer.service")
        assert session.backend_open(machine), "the aborted emergency closed the backend"
        status = read_status_json(config_path=CONFIG)
        assert status["posture"] == "active", status

    with subtest("--countdown counts down in order, then returns to the decoy"):
        countdown_timings, stderr = emergency_back(
            f"--countdown {COUNTDOWN}", "/mnt/data/countdown.err", "emergency-countdown"
        )
        markers = [f"Emergency in {n}... (Ctrl+C to abort)" for n in range(COUNTDOWN, 0, -1)]
        markers.append("Emergency starting now!")
        cursor = -1
        for marker in markers:
            position = stderr.find(marker, cursor + 1)
            assert position > cursor, f"{marker!r} missing or out of order in: {stderr!r}"
            cursor = position
        # Nothing of the way back can start before the countdown has run out.
        assert countdown_timings["trigger_to_backdoor"] >= COUNTDOWN, countdown_timings

    with subtest("the default emergency is immediate, with no countdown"):
        canonical_activate(CONFIG, "--overlay-only", "activate-immediate")
        machine.succeed("systemd-run --unit hidden-writer --property=Type=exec sleep infinity")
        immediate_timings, stderr = emergency_back(
            "", "/mnt/data/immediate.err", "emergency-immediate"
        )
        assert "Emergency in " not in stderr, stderr
        assert "starting now!" not in stderr, stderr
        # The same switch without the countdown: it must save most of the
        # countdown. The margin absorbs soft-reboot timing variance.
        saved = (
            countdown_timings["trigger_to_backdoor"]
            - immediate_timings["trigger_to_backdoor"]
        )
        assert saved >= COUNTDOWN - 7, (
            f"the default emergency was not immediate: countdown={countdown_timings}, "
            f"immediate={immediate_timings}"
        )
  '';
}
