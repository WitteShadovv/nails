# Test 75: Fresh-home persona mode hides the decoy home
#
# In persona.mode = "fresh-home", once the /home overlay is mounted a clean,
# empty home from the hidden volume is bind-mounted over the operator's home, so
# the decoy home contents are not visible in the hidden session and the hidden
# session's writes land on the hidden volume. Deactivation tears the bind down
# and the decoy home reappears unchanged.
#
# This asserts the core security property of T-046 (decoy home invisible in
# fresh-home mode) on the overlay-only path. It must be evaluated on a real
# runner (the Nix VM driver) — it cannot be checked in the development sandbox.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "persona-fresh-home";
  meta.tags = [ "overlay" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    def write_fresh_home_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/hidden-volume"
    overlay_mode = "explicit"
    risky_services = "skip"

    [persona]
    mode = "fresh-home"

    [[overlays]]
    name = "home"
    lower = "/home"
    upper = "/mnt/hidden-volume/home"
    work = "/mnt/hidden-volume/.work/home"
    target = "/home"
    EOF""" % path
        )

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-fresh-home.toml"
    write_fresh_home_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("phase 1: the decoy home holds a secret before activation"):
        machine.succeed("mkdir -p /home/testuser")
        machine.succeed("printf %s decoy-secret > /home/testuser/decoy-secret.txt")
        machine.succeed("test -f /home/testuser/decoy-secret.txt")

    with subtest("phase 2: fresh-home activation hides the decoy home contents"):
        machine.succeed(
            f"NAILS_TARGET_USER=testuser nails --config {config_path} "
            "activate --overlay-only --session keep -y"
        )
        assert_overlay_mounted("/home")
        # The persona bind shadows the decoy home: the secret is not visible.
        machine.fail("test -e /home/testuser/decoy-secret.txt")

    with subtest("phase 3: hidden-session writes land on the hidden volume persona home"):
        machine.succeed("printf %s hidden-note > /home/testuser/hidden-note.txt")
        machine.succeed("test -f /mnt/hidden-volume/persona/home/hidden-note.txt")
        # The decoy home is untouched by the hidden session's writes.
        machine.fail("test -e /mnt/hidden-volume/home/hidden-note.txt")

    with subtest("phase 4: deactivation restores the decoy home"):
        machine.succeed(f"nails --config {config_path} emergency")
        assert_no_overlays(["/home"])
        # The persona bind is gone; the decoy secret is visible again.
        machine.succeed("test -f /home/testuser/decoy-secret.txt")
        decoy = machine.succeed("cat /home/testuser/decoy-secret.txt").strip()
        assert decoy == "decoy-secret", f"decoy home changed: {decoy!r}"
        machine.fail("test -e /home/testuser/hidden-note.txt")
  '';
}
