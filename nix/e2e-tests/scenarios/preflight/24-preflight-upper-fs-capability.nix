# Scenario `preflight-upper-fs-capability` of the `preflight-checks` batch:
#   tests/preflight/19-preflight-checks.nix
# Formerly the stand-alone test
#   tests/preflight/24-preflight-upper-fs-capability.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix).
#
# Test 24: Preflight Upper-Filesystem Capability
#
# Some backends support symlinks (so they clear the early symlink-support gate)
# yet still cannot back an overlayfs *upper* layer: NFS, CIFS/SMB, 9p, most FUSE
# mounts, and the case this test exercises, a local filesystem without extended
# attributes (minix), which cannot store the overlay's trusted xattrs. The
# upper-fs-capability check must probe this and refuse activation before the
# root overlay is prepared, naming the backend, and must leave no probe scratch
# directory behind.
#
# FAT is deliberately NOT used here: FAT lacks symlink support, so it is caught
# by the earlier symlink-support gate (see test 18) and never reaches this check.
# Neither is an overlay or a FUSE mount: the attach gate refuses both, since they
# show no disk they store their data on, before any check probes them.

_:
let
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-upper-fs-capability";
  tags = [
    "preflight"
  ];

  helpers = [
    preflightHelpers.writeTextFileFn
    preflightHelpers.runCommandCaptureFn
    preflightHelpers.commandAssertionsFn
  ];

  script = ''
    def scenario_preflight_upper_fs_capability() -> None:
        def write_minix_hidden_config(path):
            write_text_file(path, """
    hidden_volume_root = "/mnt/minix-hidden"
    minimum_space_mb = 10
    """.strip() + "\n")

        machine.wait_for_unit("multi-user.target")

        with subtest("a root without xattrs is refused with a capability message"):
            # A minix image on a loop device is the hidden root. It supports
            # symlinks (so the early symlink-support gate passes) and is a
            # volume whose image lies in RAM (so the attach gate passes), and it
            # reaches the upper-fs-capability probe, whose trusted xattr it
            # cannot store, so the check fails closed. Version 3 allows the
            # probe directory's long name.
            machine.succeed(
                    "bash -lc '"
                    "mkdir -p /mnt/minix-base /mnt/minix-hidden && "
                    "mount -t tmpfs tmpfs /mnt/minix-base && "
                    "truncate -s 64M /mnt/minix-base/disk.img && "
                    "mkfs.minix -3 /mnt/minix-base/disk.img && "
                    "mount -o loop /mnt/minix-base/disk.img /mnt/minix-hidden"
                    "'"
                )
            # Confirm the hidden root really is minix before probing it.
            machine.succeed("grep -q ' /mnt/minix-hidden minix ' /proc/mounts")
            write_minix_hidden_config("/tmp/preflight-upper-fs-capability.toml")
            result = run_command_capture(
                "preflight-upper-fs-capability",
                "nails --config /tmp/preflight-upper-fs-capability.toml activate --overlay-only -y",
            )
            assert_command_failed(result)
            assert_result_contains(
                result,
                [
                    "cannot host an overlayfs upper layer",
                    "trusted xattr",
                    "minix filesystem",
                    "ext4",
                ],
                stream="stderr",
            )

        with subtest("refusal mounts no overlay and leaves no probe scratch dir"):
            # Pre-flight runs before the next root is prepared, so no overlay
            # backed by the hidden root may exist: neither the root overlay nor
            # a leftover trial-probe mount.
            machine.fail("grep -q 'upperdir=/mnt/minix-hidden' /proc/mounts")
            machine.fail("grep -q ' /run/nextroot' /proc/self/mountinfo")
            # The probe removes its .probe-<unique> scratch dir on every path.
            machine.fail("bash -lc 'ls -d /mnt/minix-hidden/.probe-* 2>/dev/null'")
            machine.succeed("umount /mnt/minix-hidden")
            machine.succeed("umount /mnt/minix-base")
  '';
}
