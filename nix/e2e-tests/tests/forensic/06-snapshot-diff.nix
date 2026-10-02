# Test 06: Snapshot Comparison
# Tests that the decoy filesystem returns to its exact initial state after a
# full activate/populate/deactivate workflow. The comparison is a full diff of
# the file lists and checksums against an explicit allowlist of volatile paths,
# so an artifact with no telltale keyword still turns the test red.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "snapshot-diff";
  meta.tags = [ "forensic" ];

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];
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

    # Paths that legitimately change on their own across a reboot and an
    # activation cycle. Everything NOT matched here must be byte-identical
    # before and after, so a stray artifact with no "nails"/"secret"/"hidden"
    # keyword is still caught. /var is runtime state (journal, systemd, dhcp,
    # nixos) and is not an overlay target in this config, so it is treated as
    # wholly volatile; /home and /etc are diffed strictly.
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

    machine.start()
    machine.wait_for_unit("multi-user.target")
    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)

    with subtest("capture the decoy baseline"):
        initial_files = listed("/home /etc /var")
        initial_sums = summed("/home /etc")

    with subtest("run a full activate/populate/deactivate workflow"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")
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

    with subtest("the decoy filesystem is byte-identical outside volatile paths"):
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

    with subtest("no overlay or hidden-volume mount remains"):
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp", "/var", "/opt", "/boot"])
        machine.fail("mount | grep -E '(/mnt/data|/mnt/nails-pivot|hidden-volume)'")
  '';
}
