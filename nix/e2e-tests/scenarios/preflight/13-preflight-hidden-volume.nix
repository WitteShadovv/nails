# Scenario `preflight-hidden-volume` of the `preflight-hidden-root` batch:
#   tests/preflight/13-preflight-hidden-root.nix
# Formerly the stand-alone test
#   tests/preflight/13-preflight-hidden-volume.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix).
#
# Test 13: Preflight Hidden Volume Failure Modes
# The hidden-volume check refuses an unmounted, a store-backed, a read-only and
# an immutable hidden root (exit 4, named in the readiness report); an
# unmounted hidden root (a directory on the decoy disk) is never written to by
# status, verify, a dry run or a refused activation; the log file on an
# attached volume is 0600; and none of this leaves the plain decoy.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-hidden-volume";
  tags = [
    "preflight"
    "smoke"
  ];

  helpers = [
    preflightHelpers.writeTextFileFn
    preflightHelpers.runCommandCaptureFn
    preflightHelpers.commandAssertionsFn
    testHelpers.readStatusJsonFn
  ];

  script = ''
    def scenario_preflight_hidden_volume() -> None:
        def write_hidden_volume_config(path, hidden_root):
            write_text_file(path, f"""
    hidden_volume_root = "{hidden_root}"
    minimum_space_mb = 100
    """.strip() + "\n")

        machine.wait_for_unit("multi-user.target")

        with subtest("unmounted hidden volume is rejected"):
            machine.succeed("mkdir -p /mnt/preflight-unmounted")
            write_hidden_volume_config("/tmp/preflight-unmounted.toml", "/mnt/preflight-unmounted")
            result = run_command_capture(
                "preflight-hidden-unmounted",
                "nails --config /tmp/preflight-unmounted.toml activate --dry-run --overlay-only --ascii",
            )
            # --dry-run is a thin alias for `check`, which exits 4 when any pre-flight
            # check fails. The hidden-volume check is designed to fail here, so the
            # command refuses while still reporting the failure in the readiness
            # report on stdout.
            assert_exit_code(result, 4)
            assert_result_contains(
                result,
                [
                    "hidden-volume",
                    "is not mounted: it is a folder on the filesystem mounted at /",
                    "Where setup happens",
                ],
                stream="stdout",
            )

        with subtest("an unmounted hidden root is never written to"):
            # The directory exists but nothing is mounted there, so it sits on the
            # decoy disk. Read-only commands, a dry run and a refused real activate
            # must all leave it byte-for-byte empty: no log, no staged config, no
            # state file may be dropped onto what is really the persistent disk.
            machine.succeed("mkdir -p /mnt/preflight-empty")
            machine.succeed("touch -m -d '2001-02-03 04:05:06' /mnt/preflight-empty")
            before = machine.succeed("stat -c '%Y %Z' /mnt/preflight-empty").strip()
            write_hidden_volume_config("/tmp/preflight-empty.toml", "/mnt/preflight-empty")
            for args in [
                "status --ascii",
                "verify --ascii",
                "activate --dry-run --overlay-only --ascii",
                "activate --overlay-only --ascii",
            ]:
                machine.execute(f"nails --config /tmp/preflight-empty.toml {args}")
            entries = machine.succeed(
                "find /mnt/preflight-empty -mindepth 1 | wc -l"
            ).strip()
            assert entries == "0", f"unmounted hidden root was written to ({entries} entries)"
            # Not even probed: a write probe would have changed its timestamps.
            after = machine.succeed("stat -c '%Y %Z' /mnt/preflight-empty").strip()
            assert after == before, (before, after)

        with subtest("nix store hidden volume is rejected as non-writable"):
            write_hidden_volume_config("/tmp/preflight-store.toml", "${builtins.storeDir}")
            result = run_command_capture(
                "preflight-hidden-store",
                "nails --config /tmp/preflight-store.toml activate --dry-run --overlay-only --ascii",
            )
            assert_exit_code(result, 4)
            assert_result_contains(result, ["hidden-volume", "${builtins.storeDir}", "not writable"], stream="stdout")

        with subtest("read-only hidden volume is rejected"):
            machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
            machine.succeed("mount -o remount,ro /mnt/data")
            write_hidden_volume_config("/tmp/preflight-readonly.toml", "/mnt/data")
            result = run_command_capture(
                "preflight-hidden-readonly",
                "nails --config /tmp/preflight-readonly.toml activate --dry-run --overlay-only --ascii",
            )
            assert_exit_code(result, 4)
            assert_result_contains(result, ["hidden-volume", "/mnt/data", "not writable"], stream="stdout")
            machine.succeed("mount -o remount,rw /mnt/data")

        with subtest("immutable hidden volume root is treated as non-writable"):
            machine.succeed("command -v chattr >/dev/null")
            machine.succeed("chattr +i /mnt/data")
            result = run_command_capture(
                "preflight-hidden-immutable",
                "nails --config /tmp/preflight-readonly.toml activate --dry-run --overlay-only --ascii",
            )
            assert_exit_code(result, 4)
            assert_result_contains(result, ["hidden-volume", "/mnt/data", "not writable"], stream="stdout")
            machine.succeed("chattr -i /mnt/data")

        with subtest("log files on an attached hidden volume are mode 0600"):
            # A writing command on a positively attached, writable volume creates its
            # log file. It lives on the hidden volume and must be owner-only so it is
            # never group- or world-readable.
            run_command_capture(
                "preflight-hidden-log-mode",
                "nails --config /tmp/preflight-readonly.toml activate --dry-run --overlay-only --ascii",
            )
            machine.succeed("test -f /mnt/data/logs/nails.log")
            log_mode = machine.succeed("stat -c %a /mnt/data/logs/nails.log").strip()
            assert log_mode == "600", f"log file mode is {log_mode}, expected 600"

        with subtest("the machine is still the plain decoy after all hidden volume failures"):
            from nails_e2e import session

            session.assert_decoy_root(machine)
            status = read_status_json(config_path="/tmp/preflight-readonly.toml")
            assert status["posture"] == "decoy", status

        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
