# Test 06: Decoy filesystem and disk image return to the baseline
#
# Two complementary views of the same activate/populate/deactivate workflow on
# one disk lineage. From inside the booted decoy, the live filesystem is diffed
# against its baseline so a stray artifact with no telltale keyword still turns
# the test red. From outside, the powered-off decoy root is imaged and its fls
# listing (deleted names included) is diffed against the baseline image, catching
# anything that was unlinked before the live view could see it.
#
# Names alone miss a decoy file that was modified in place, or replaced under the
# same name. So each image also yields a sleuthkit bodyfile (`fls -r -m /`, kept
# in the test output under forensics/ and ready for `mactime -b`) and a content
# hash of every file. A control run -- the same number of plain reboots, no
# hidden session -- records which (path, field) pairs boot noise changes; the
# hidden-session run may change nothing beyond that and the volatile allowlist:
# no inode, mode, owner, size, mtime, ctime or crtime of an existing decoy inode,
# and no file contents. atime drift is reported, not asserted.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  diskForensics = import ./../../lib/disk-forensics.nix { inherit pkgs; };
in
{
  name = "snapshot-diff";
  meta.tags = [ "forensic" ];

  # Imaging the root disk three times (baseline, control, post), two extra
  # reboots for the control run and three carve-and-hash passes; generous margin.
  globalTimeout = 2700;

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/forensic-vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      };
  };

  testScript = _: ''
    import re

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}
    ${diskForensics.pythonSetup}

    # Paths that legitimately change on their own across a reboot and an
    # activation cycle. Everything NOT matched here must be byte-identical before
    # and after. /var is runtime state (journal, systemd, dhcp, nixos) and is not
    # an overlay target in this config, so it is treated as wholly volatile;
    # /home and /etc are diffed strictly.
    volatile = re.compile(
        "|".join(
            [
                r"^/var/",
                r"^/etc/resolv\.conf$",
                r"^/etc/machine-id$",
                r"^/etc/ssh/ssh_host_",
                r"^/etc/\.(updated|clean)$",
                r"^/etc/nixos/",
                r"^/home/[^/]+/\.bash_history$",
            ]
        )
    )

    # Image-side allowlist: the same volatile classes, on fls relative paths (no
    # leading slash, deleted entries included); shared with the other image tests.
    image_volatile = disk_forensics.DEFAULT_IMAGE_VOLATILE

    def listed(scope):
        out = machine.succeed(f"find {scope} -type f 2>/dev/null | sort")
        return {line for line in out.splitlines() if line}

    def summed(scope):
        out = machine.succeed(f"find {scope} -type f -exec md5sum {{}} + 2>/dev/null || true")
        sums = {}
        for line in out.splitlines():
            parts = line.split("  ", 1)
            if len(parts) == 2:
                digest, path = parts
                sums[path] = digest
        return sums

    def kept(paths):
        return sorted(path for path in paths if not volatile.search(path))

    def kept_image(paths):
        return sorted(path for path in paths if not image_volatile.search(path))

    machine.start()
    machine.wait_for_unit("multi-user.target")
    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)

    # The decoy's own root inode, the top-level entry list, and the /bin/sh and
    # /usr/bin/env links must survive the workflow unchanged: a hidden switch that
    # rewrote them on the decoy (instead of the overlay upper), or a stray write
    # that created a new top-level directory, would move these.
    def os_root_fingerprint():
        root_stat = machine.succeed("stat -c '%i %Y %Z' /").strip()
        top_level = machine.succeed("ls -1A / | sort").strip()
        # readlink (not stat) so the recorded value is the decoy's own link target,
        # which a rewrite to a hidden store path would change.
        links = machine.succeed(
            "for p in /bin/sh /usr/bin/env; do "
            "printf '%s -> ' \"$p\"; readlink \"$p\" 2>/dev/null || echo '(absent)'; "
            "done"
        ).strip()
        return (root_stat, top_level, links)

    with subtest("capture the decoy baseline (live and image)"):
        # Create the hidden-volume mount point before the baseline. It is a
        # legitimate, permanent part of the decoy; setupHiddenVolume would
        # otherwise create it after the baseline and the new /mnt entry (and the
        # root mtime bump) would read as drift.
        machine.succeed("mkdir -p /mnt/data")
        initial_files = listed("/home /etc /var")
        initial_sums = summed("/home /etc")
        initial_os_root = os_root_fingerprint()
        baseline_image = disk_forensics.snapshot(machine, "baseline")
        baseline_fls = disk_forensics.fls_paths(disk_forensics.run_fls(baseline_image))
        baseline_state = disk_forensics.image_state(baseline_image, "baseline", machine)

    with subtest("control run: plain reboots with no hidden session"):
        # The workflow below spans two boots (the one after the control snapshot
        # and the one after deactivation powers the machine off), so the control
        # spans two plain boots as well. Whatever changes here is boot noise.
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        control_image = disk_forensics.snapshot(machine, "control")
        control_state = disk_forensics.image_state(control_image, "control", machine)
        control_changes = disk_forensics.image_changes(baseline_state, control_state)
        control_atime = disk_forensics.image_changes(
            baseline_state, control_state, disk_forensics.MAC_FIELDS_OBSERVED
        )
        print(
            f"control run: {len(control_changes)} path(s) changed by boot noise, "
            f"{len(control_atime)} with atime drift"
        )

    with subtest("run a full activate/populate/deactivate workflow"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep --accept-persistent-decoy -y"
        )
        machine.succeed("su - testuser -c 'id -un | grep -qx testuser'")
        machine.succeed("su - testuser -c 'mkdir -p ~/work/project'")
        machine.succeed(
            "su - testuser -c 'for i in $(seq 1 50); do echo content > ~/work/project/file_$i.txt; done'"
        )
        machine.succeed("su - testuser -c 'cd ~/work/project && git init 2>/dev/null || true'")
        machine.succeed(
            "su - testuser -c 'printf \"#!/bin/bash\\necho test\\n\" > ~/work/script.sh && chmod +x ~/work/script.sh'"
        )
        canonical_deactivate(headless_config, unit_name="nails-deactivate-snapshot-diff")
        assert_status_state("inactive")
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")

    with subtest("the live decoy filesystem is byte-identical outside volatile paths"):
        final_files = listed("/home /etc /var")
        final_sums = summed("/home /etc")

        appeared = kept(final_files - initial_files)
        assert not appeared, f"files appeared after the workflow: {appeared}"

        vanished = kept(initial_files - final_files)
        assert not vanished, f"files disappeared after the workflow: {vanished}"

        changed = kept(
            path
            for path in (initial_sums.keys() & final_sums.keys())
            if initial_sums[path] != final_sums[path]
        )
        assert not changed, f"file contents changed after the workflow: {changed}"

    with subtest("the decoy root, top-level entries and /bin/sh, /usr/bin/env are unchanged"):
        final_os_root = os_root_fingerprint()
        assert final_os_root[0] == initial_os_root[0], (
            f"the decoy root inode/mtime/ctime changed: "
            f"{initial_os_root[0]!r} -> {final_os_root[0]!r}"
        )
        assert final_os_root[1] == initial_os_root[1], (
            "the top-level entry list changed after the workflow:\n"
            f"before:\n{initial_os_root[1]}\nafter:\n{final_os_root[1]}"
        )
        assert final_os_root[2] == initial_os_root[2], (
            "/bin/sh or /usr/bin/env was rewritten on the decoy:\n"
            f"before:\n{initial_os_root[2]}\nafter:\n{final_os_root[2]}"
        )

    with subtest("no overlay or hidden-volume mount remains"):
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp", "/var", "/opt", "/boot"])
        machine.fail("mount | grep -E '(/mnt/data|/run/nails-pivot|hidden-volume)'")

    with subtest("the powered-off decoy image gained no non-volatile entries"):
        post_image = disk_forensics.snapshot(machine, "post", restart=False)
        post_fls = disk_forensics.fls_paths(disk_forensics.run_fls(post_image))
        appeared_image = kept_image(disk_forensics.diff(baseline_fls, post_fls))
        assert not appeared_image, (
            f"the disk image gained entries outside volatile paths: "
            f"{appeared_image[:40]}"
        )

    with subtest("existing decoy inodes keep their MAC times and contents"):
        post_state = disk_forensics.image_state(post_image, "post", machine)
        disk_forensics.assert_mac_unchanged(
            machine, baseline_state, control_state, post_state, image_volatile
        )
  '';
}
