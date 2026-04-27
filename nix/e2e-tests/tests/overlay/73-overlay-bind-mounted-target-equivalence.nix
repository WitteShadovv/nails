# Test 73: Overlay bind-mounted target equivalence
# Reproduces nails-os style ELOOP when the overlay target itself is a bind mount
# and an inner bind mount would derive the target's backing directory as an extra lower.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  overlayHelpers = import ./../../lib/overlay-helpers.nix;
in
{
  name = "overlay-bind-mounted-target-equivalence";
  meta.tags = [ "overlay" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${overlayHelpers.writeSrvOnlyConfigFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-bind-mounted-target-equivalence.yaml"
    write_srv_only_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("mkdir -p /mnt/hidden-volume/srv /mnt/hidden-volume/.work/srv")

    with subtest("phase 1: create a bind-mounted target with a nested bind-mounted subtree"):
        machine.succeed("mkdir -p /persist/srv-real/store /srv/store")
        machine.succeed("printf %s baseline > /persist/srv-real/store/baseline.txt")
        machine.succeed("mount --bind /persist/srv-real /srv")
        machine.succeed("mount --bind /persist/srv-real/store /srv/store")
        machine.succeed("test -f /srv/store/baseline.txt")

    with subtest("phase 2: activation succeeds without deriving a target-equivalent lowerdir"):
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --no-kill-session -y"
        )
        machine.succeed("mount | grep -F 'on /srv type overlay ('")
        baseline = machine.succeed("cat /srv/store/baseline.txt").strip()
        assert baseline == "baseline", f"Expected nested bind-mounted content, got: {baseline!r}"

    with subtest("phase 3: emergency cleanup removes overlay and restores bind mounts"):
        machine.succeed(f"nails --config {config_path} emergency")
        machine.fail("mount | grep -F 'on /srv type overlay ('")
        machine.succeed("test -f /srv/store/baseline.txt")
        machine.succeed("umount /srv/store")
        machine.succeed("umount /srv")
  '';
}
