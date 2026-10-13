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
# mounts, and — the case this test exercises — a filesystem that is itself an
# overlay, which the kernel refuses to stack as another overlay's upperdir. The
# upper-fs-capability check must probe this and refuse activation before the
# root overlay is prepared, naming the backend, and must leave no probe scratch directory
# behind.
#
# FAT is deliberately NOT used here: FAT lacks symlink support, so it is caught
# by the earlier symlink-support gate (see test 18) and never reaches this check.

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
        def write_overlay_hidden_config(path):
            write_text_file(path, """
    hidden_volume_root = "/mnt/overlay-hidden"
    minimum_space_mb = 10
    """.strip() + "\n")

        machine.wait_for_unit("multi-user.target")

        with subtest("an overlay-backed upper is refused with a capability message"):
            # Build an overlayfs and use it as the hidden root. It supports symlinks
            # (so the early symlink-support gate passes), has its own device (so the
            # attach gate passes), and reaches the upper-fs-capability probe — which
            # the kernel refuses to stack as another overlay's upperdir, so the check
            # fails closed. The lower/upper/work live on a tmpfs, which can legally
            # host the base overlay.
            machine.succeed(
                    "bash -lc '"
                    "mkdir -p /mnt/overlay-base /mnt/overlay-hidden && "
                    "mount -t tmpfs tmpfs /mnt/overlay-base && "
                    "mkdir -p /mnt/overlay-base/lower /mnt/overlay-base/upper /mnt/overlay-base/work && "
                    "mount -t overlay overlay "
                    "-o lowerdir=/mnt/overlay-base/lower,upperdir=/mnt/overlay-base/upper,workdir=/mnt/overlay-base/work "
                    "/mnt/overlay-hidden"
                    "'"
                )
            # Confirm the hidden root really is an overlay before probing it.
            machine.succeed("grep -q ' /mnt/overlay-hidden overlay ' /proc/mounts")
            write_overlay_hidden_config("/tmp/preflight-upper-fs-capability.toml")
            result = run_command_capture(
                "preflight-upper-fs-capability",
                "nails --config /tmp/preflight-upper-fs-capability.toml activate --overlay-only -y",
            )
            assert_command_failed(result)
            assert_result_contains(
                result,
                ["cannot host an overlayfs upper layer", "overlay", "ext4"],
                stream="stderr",
            )

        with subtest("refusal mounts no overlay and leaves no probe scratch dir"):
            # Pre-flight runs before the next root is prepared, so no overlay backed
            # by the hidden root's own upper may exist: neither the root overlay nor
            # a leftover trial-probe mount. Matching on an upperdir under the hidden
            # root avoids a false positive from the base overlay that backs it.
            machine.fail("grep -q 'upperdir=/mnt/overlay-hidden' /proc/mounts")
            machine.fail("grep -q ' /run/nextroot' /proc/self/mountinfo")
            # The probe removes its .probe-<unique> scratch dir on every path.
            machine.fail("bash -lc 'ls -d /mnt/overlay-hidden/.probe-* 2>/dev/null'")
            machine.succeed("umount /mnt/overlay-hidden")
            machine.succeed("umount /mnt/overlay-base")
  '';
}
