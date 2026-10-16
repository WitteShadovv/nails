# Research spike that captures a device stack for the block-device walk
# (nails_base::blockdev): an ext4 logical volume on a LUKS2 mapping of a GPT
# partition of a loop device. Building it needs root and device-mapper, which
# a user namespace cannot give, so it runs in a VM. Tagged `research`, so it is
# in no default group (not `ci`, not `all`); run it by name:
#
#   nix build .#e2e.research-blockdev-fixtures -L
#
# and copy the contents of `result/kernel-fixtures/` to
# nails-base/tests/fixtures/kernel/vm/ (see the README there). The scene lives
# on a tmpfs and is torn down before the test ends.
_: {
  name = "research-blockdev-fixtures";
  meta.tags = [ "research" ];

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        pkgs.cryptsetup
        pkgs.e2fsprogs
        pkgs.lvm2
      ];
    };

  testScript = _: ''
    import base64
    import io
    import tarfile

    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("capture the LVM-on-LUKS scene"):
        with open("${../../../../scripts/capture-kernel-fixtures.sh}") as script:
            machine.succeed(
                "cat > /run/capture-kernel-fixtures.sh <<'NAILS_CAPTURE_EOF'\n"
                + script.read()
                + "NAILS_CAPTURE_EOF"
            )
        machine.succeed("bash /run/capture-kernel-fixtures.sh blockdev /run/kernel-fixtures")
        archive = machine.succeed("tar -C /run/kernel-fixtures -cz . | base64 -w0")
        with tarfile.open(fileobj=io.BytesIO(base64.b64decode(archive)), mode="r:gz") as tar:
            tar.extractall(machine.out_dir / "kernel-fixtures", filter="data")

    with subtest("the scene is gone again"):
        machine.fail("cryptsetup status scenecrypt")
        machine.fail("losetup --list --noheadings | grep -q nails-blockdev")
  '';
}
