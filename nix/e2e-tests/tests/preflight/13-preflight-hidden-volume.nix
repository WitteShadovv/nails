# Test 13: Preflight Hidden Volume Failure Modes

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-hidden-volume";
  meta.tags = [
    "preflight"
    "smoke"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.e2fsprogs
      ];
    };

  testScript = _: ''
    ${preflightHelpers.writeTextFileFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}

    def write_hidden_volume_config(path, hidden_root):
        write_text_file(path, f"""
    hidden_volume_root = "{hidden_root}"
    overlay_mode = "explicit"

    [[overlays]]
    name = "home"
    lower = "/home"
    upper = "{hidden_root}/home"
    work = "{hidden_root}/.work/home"
    target = "/home"
    """.strip() + "\n")

    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("unmounted hidden volume is rejected"):
        machine.succeed("mkdir -p /mnt/preflight-unmounted")
        write_hidden_volume_config("/tmp/preflight-unmounted.toml", "/mnt/preflight-unmounted")
        result = run_command_capture(
            "preflight-hidden-unmounted",
            "nails --config /tmp/preflight-unmounted.toml activate --dry-run --overlay-only --session keep --ascii",
        )
        assert_command_succeeded(result)
        assert_result_contains(result, ["hidden-volume", "is not mounted"], stream="stdout")

    with subtest("an unmounted hidden root is never written to"):
        # The directory exists but nothing is mounted there, so it sits on the
        # decoy disk. Read-only commands, a dry run and a refused real activate
        # must all leave it byte-for-byte empty: no log, no staged config, no
        # state file may be dropped onto what is really the persistent disk.
        machine.succeed("mkdir -p /mnt/preflight-empty")
        write_hidden_volume_config("/tmp/preflight-empty.toml", "/mnt/preflight-empty")
        for args in [
            "status --ascii",
            "verify --ascii",
            "activate --dry-run --overlay-only --session keep --ascii",
            "activate --overlay-only --session keep --ascii",
        ]:
            machine.execute(f"nails --config /tmp/preflight-empty.toml {args}")
        entries = machine.succeed(
            "find /mnt/preflight-empty -mindepth 1 | wc -l"
        ).strip()
        assert entries == "0", f"unmounted hidden root was written to ({entries} entries)"

    with subtest("nix store hidden volume is rejected as non-writable"):
        write_hidden_volume_config("/tmp/preflight-store.toml", "${builtins.storeDir}")
        result = run_command_capture(
            "preflight-hidden-store",
            "nails --config /tmp/preflight-store.toml activate --dry-run --overlay-only --session keep --ascii",
        )
        assert_command_succeeded(result)
        assert_result_contains(result, ["hidden-volume", "${builtins.storeDir}", "not writable"], stream="stdout")

    with subtest("read-only hidden volume is rejected"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mount -o remount,ro /mnt/data")
        write_hidden_volume_config("/tmp/preflight-readonly.toml", "/mnt/data")
        result = run_command_capture(
            "preflight-hidden-readonly",
            "nails --config /tmp/preflight-readonly.toml activate --dry-run --overlay-only --session keep --ascii",
        )
        assert_command_succeeded(result)
        assert_result_contains(result, ["hidden-volume", "/mnt/data", "not writable"], stream="stdout")
        machine.succeed("mount -o remount,rw /mnt/data")

    with subtest("immutable hidden volume root is treated as non-writable"):
        machine.succeed("command -v chattr >/dev/null")
        machine.succeed("chattr +i /mnt/data")
        result = run_command_capture(
            "preflight-hidden-immutable",
            "nails --config /tmp/preflight-readonly.toml activate --dry-run --overlay-only --session keep --ascii",
        )
        assert_command_succeeded(result)
        assert_result_contains(result, ["hidden-volume", "/mnt/data", "not writable"], stream="stdout")
        machine.succeed("chattr -i /mnt/data")

    with subtest("log files on an attached hidden volume are mode 0600"):
        # A writing command on a positively attached, writable volume creates its
        # log file. It lives on the hidden volume and must be owner-only so it is
        # never group- or world-readable.
        run_command_capture(
            "preflight-hidden-log-mode",
            "nails --config /tmp/preflight-readonly.toml activate --dry-run --overlay-only --session keep --ascii",
        )
        machine.succeed("test -f /mnt/data/logs/nails.log")
        log_mode = machine.succeed("stat -c %a /mnt/data/logs/nails.log").strip()
        assert log_mode == "600", f"log file mode is {log_mode}, expected 600"

    with subtest("status remains inactive after all hidden volume failures"):
        assert_status_state("inactive")

    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
