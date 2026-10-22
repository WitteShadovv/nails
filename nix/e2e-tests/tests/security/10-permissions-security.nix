# Test 10: Permission and path security
#
# The hidden volume root ends up in the root overlay's mount options, so an
# unsafe one must be refused before anything is prepared:
#   - a root that passes through a symlink, a relative root that climbs with
#     `..`, and a root containing an overlay option separator (`:`) are each
#     refused by `nails activate` with the offending setting named; the
#     machine stays on the plain decoy, nothing is left at /run/nextroot and no
#     root upper is created on the hidden volume;
#   - after a real activation (a soft-reboot into the hidden root) the activity
#     log on the hidden volume is never group- or world-accessible.
_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  symlinkFixture = ./../../fixtures/configs/symlink-target.toml;
  traversalFixture = ./../../fixtures/configs/path-traversal.toml;
in
{
  name = "permissions-security";
  meta.tags = [ "security" ];

  testScript = _: ''
    import shlex

    from nails_e2e import session

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}

    CONFIG = "/mnt/data/config/nails.toml"

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    write_headless_config(CONFIG)


    def assert_config_refused(config_path, problem, description):
        rc, out = machine.execute(
            f"nails --config {shlex.quote(config_path)} activate -y --overlay-only 2>&1"
        )
        # The config loader rejects the unsafe path before anything is
        # prepared. A zero exit would mean the guard is gone.
        assert rc != 0, f"{description}: activation was not refused: {out}"
        assert "hidden_volume_root" in out, out
        assert problem in out, f"{description}: expected {problem!r} in: {out}"
        # A refusal leaves no trace: the plain decoy root, no next root and no
        # root upper on the hidden volume.
        session.assert_decoy_root(machine)
        machine.succeed("test ! -e /run/nextroot || test -z \"$(ls -A /run/nextroot)\"")
        machine.succeed("test ! -e /mnt/data/root/upper")
        status = read_status_json(config_path=CONFIG)
        assert status["place"] == "decoy", status
        print(f"✓ {description} is refused with nothing left behind")


    with subtest("a hidden volume root through a symlink is refused"):
        machine.succeed("ln -sfn /mnt/data /tmp/symlink-to-hidden")
        machine.succeed("cp ${symlinkFixture} /tmp/symlink-config.toml")
        assert_config_refused(
            "/tmp/symlink-config.toml",
            "must not pass through a symlink",
            "symlinked hidden volume root",
        )
        machine.succeed("rm -f /tmp/symlink-to-hidden /tmp/symlink-config.toml")

    with subtest("a relative path-traversal root is refused"):
        machine.succeed("cp ${traversalFixture} /tmp/traversal-config.toml")
        assert_config_refused(
            "/tmp/traversal-config.toml",
            "must be an absolute path",
            "relative path-traversal root",
        )
        machine.succeed("rm -f /tmp/traversal-config.toml")

    with subtest("a root with an overlay option separator is refused"):
        machine.succeed(
            "printf 'hidden_volume_root = \"/mnt/da:ta\"\\n' > /tmp/separator-config.toml"
        )
        assert_config_refused(
            "/tmp/separator-config.toml",
            "must not contain ':'",
            "root with a ':' separator",
        )
        machine.succeed("rm -f /tmp/separator-config.toml")

    with subtest("the activity log is owner-only in the hidden session"):
        canonical_activate(CONFIG, "--overlay-only", "activate")
        status = read_status_json(config_path=CONFIG)
        assert status["place"] == "hidden", status
        logs = machine.succeed("find /mnt/data/logs -type f").split()
        assert logs, "activation wrote no log file under /mnt/data/logs"
        for log_file in logs:
            perms = machine.succeed(f"stat -c %a {shlex.quote(log_file)}").strip()
            mode = int(perms, 8)
            assert (mode & 0o077) == 0, (
                f"log file {log_file} is accessible by group/other (perms={perms})"
            )
            print(f"✓ log file {log_file} is owner-only ({perms})")
  '';
}
