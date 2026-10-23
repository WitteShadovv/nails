# Test 74: discard deletes a path's hidden copy from the root upper
#
# A hidden session copies a decoy file up and creates a hidden-only file in the
# operator's home. `discard /home` is refused inside the hidden session; on
# the decoy it deletes /home's subtree from the root upper, and the next
# session sees the decoy's own file again.
_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "overlay-discard";
  meta.tags = [ "session" ];
  globalTimeout = 1200;

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/var/lib/nails-tests/nails-headless.toml"
    write_headless_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("su - testuser -c 'printf %s decoy-data > ~/reset-target.txt'")

    with subtest("a hidden session copies up and adds files in the upper"):
        canonical_activate(config_path, "--overlay-only", "activate-1")
        machine.fail(f"nails --config {config_path} discard /home -y")
        machine.succeed("su - testuser -c 'printf %s hidden-data > ~/reset-target.txt'")
        machine.succeed("su - testuser -c 'printf %s secret > ~/hidden-only.txt'")
        machine.succeed("test -f /mnt/data/root/upper/home/testuser/hidden-only.txt")
        canonical_deactivate(config_path, "deactivate-1")

    with subtest("on the decoy discard deletes /home from the upper"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        machine.succeed("test -f /mnt/data/root/upper/home/testuser/hidden-only.txt")
        machine.succeed(f"nails --config {config_path} discard /home -y")
        machine.fail("test -e /mnt/data/root/upper/home")

    with subtest("the decoy file shows through in the next session"):
        canonical_activate(config_path, "--overlay-only", "activate-2")
        content = machine.succeed("su - testuser -c 'cat ~/reset-target.txt'").strip()
        assert content == "decoy-data", f"expected the decoy file, got {content!r}"
        machine.fail("su - testuser -c 'test -e ~/hidden-only.txt'")
        canonical_deactivate(config_path, "deactivate-2")
  '';
}
