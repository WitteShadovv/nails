# Test 75: fresh-home persona mode hides the decoy home
#
# With `[persona] mode = "fresh-home"` the entry makes the operator's home in
# the root upper an opaque directory, so in the hidden session the decoy home's
# contents are not visible and every write lands in the upper. Back on the
# decoy the home is unchanged.
_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "persona-fresh-home";
  meta.tags = [ "session" ];
  globalTimeout = 1200;

  testScript = _: ''
    from nails_e2e import session

    ${testHelpers.canonicalActivateFn}

    CONFIG = "/var/lib/nails-tests/fresh-home.toml"
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mkdir -p /var/lib/nails-tests")
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "\n"
        "[persona]\n"
        "mode = \"fresh-home\"\n"
        "EOF"
    )
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("su - testuser -c 'printf %s decoy-secret > ~/decoy-secret.txt'")

    with subtest("the decoy home is invisible in the hidden session"):
        # The operator is the sudo caller, as in a real activation.
        uid = machine.succeed("id -u testuser").strip()
        canonical_activate(
            CONFIG, "--overlay-only", "activate", env=f"SUDO_UID={uid} SUDO_USER=testuser"
        )
        machine.fail("test -e /home/testuser/decoy-secret.txt")
        machine.succeed("test -d /home/testuser")

    with subtest("hidden writes land in the upper's opaque home"):
        machine.succeed("su - testuser -c 'printf %s hidden-note > ~/hidden-note.txt'")
        machine.succeed("test -f /mnt/data/root/upper/home/testuser/hidden-note.txt")

    with subtest("emergency returns to the decoy home, unchanged"):
        session.follow_soft_reboot(machine, f"nails --config {CONFIG} emergency", "emergency")
        session.assert_decoy_root(machine)
        decoy = machine.succeed("cat /home/testuser/decoy-secret.txt").strip()
        assert decoy == "decoy-secret", f"decoy home changed: {decoy!r}"
        machine.fail("test -e /home/testuser/hidden-note.txt")
  '';
}
