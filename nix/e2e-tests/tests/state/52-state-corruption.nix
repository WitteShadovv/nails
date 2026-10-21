# Test 52: State Corruption
#
# The one home of the tampered-state handling in the whole-root session:
#   1. In the hidden session, a changed `last_modified` under the stale
#      integrity digest does not hide the session: status reads the live
#      facts, still reports the active posture and exits 0.
#   2. Emergency does not refuse a corrupt state: it kills the session and
#      soft-reboots back to the plain decoy, and the backend closes.
#   3. On the decoy, a changed `version` under the stale digest refuses the
#      next activation with the invalid-state exit 6 before anything is
#      prepared, and status fails closed with the same exit code.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "state-corruption";
  meta.tags = [ "state" ];

  testScript = _: ''
    import json

    from nails_e2e import run_command_capture, session

    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    STATE = "/mnt/data/state.json"


    def write_state(payload):
        machine.succeed(
            """cat > %s <<'EOF'
    %s
    EOF"""
            % (STATE, json.dumps(payload, indent=2, sort_keys=True))
        )


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "EOF"
    )

    with subtest("activate and capture the pristine state file"):
        canonical_activate(CONFIG, "--overlay-only", "state-corruption-activate")
        machine.succeed(f"test -f {STATE}")
        pristine = json.loads(machine.succeed(f"cat {STATE}"))
        assert pristine.get("integrity_sha256"), (
            f"Expected an integrity digest in the persisted state: {pristine}"
        )

    with subtest("a corrupt state does not hide the live hidden session"):
        corrupt = dict(pristine)
        corrupt["last_modified"] = "1970-01-01T00:00:00Z"
        write_state(corrupt)
        rc, status = read_status_json_with_rc(config_path=CONFIG)
        assert rc == 0, f"status must report the live session, got rc={rc}: {status}"
        assert status["place"] == "hidden", status

    with subtest("emergency still runs on a corrupt state and returns to the decoy"):
        session.follow_soft_reboot(
            machine, f"nails --config {CONFIG} emergency", "state-corruption-emergency"
        )
        session.assert_decoy_root(machine)
        machine.wait_until_succeeds("test ! -e /dev/mapper/data", timeout=60)

    with subtest("a tampered version field blocks the next activation"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        tampered = dict(pristine)
        tampered["version"] = tampered["version"] + "-tampered"
        write_state(tampered)

        result = run_command_capture(
            machine,
            "state-corruption-version-activate",
            f"nails --config {CONFIG} activate --overlay-only -y",
        )
        assert result["rc"] == 6, f"Expected the invalid-state exit 6, got {result}"
        assert "corrupt" in result["combined"].lower(), (
            f"Expected a corruption refusal, got {result['combined']!r}"
        )
        session.assert_decoy_root(machine)
        machine.fail("test -e /run/nextroot/etc")
        assert machine.succeed("systemctl show -p SoftRebootsCount --value").strip() == "2"

        # Without a session, the unknown record makes status fail closed.
        rc, status = read_status_json_with_rc(config_path=CONFIG)
        assert rc == 6, f"Expected the invalid-state exit 6, got rc={rc}: {status}"
  '';
}
