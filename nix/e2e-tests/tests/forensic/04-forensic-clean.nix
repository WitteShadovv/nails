# Test 04: Disk-image harness controls (null and positive)
#
# This test does not exercise NAILS. It proves the host-side disk-image harness
# itself is honest: a plain boot leaves no decoy-disk findings beyond a short,
# documented allowlist (the null control), and a leak deliberately written onto
# the decoy root is caught by every scanner -- fls, strings, journal and store
# (the positive control). The old test ran `fls` against the LUKS ciphertext of
# the hidden volume and could neither see a leak nor fail; this one images the
# decoy root while the VM is off, the way a seized disk would be read.

{ self, pkgs, ... }:
let
  diskForensics = import ./../../lib/disk-forensics.nix { inherit pkgs; };
in
{
  name = "forensic-clean";
  meta.tags = [ "forensic" ];

  # Imaging the root disk several times (shutdown, qemu-img convert, restart)
  # takes longer than a single-boot test; measured runtime leaves margin here.
  globalTimeout = 1800;

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

    ${diskForensics.pythonSetup}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    # Paths a stock NixOS boot legitimately churns, so they are not findings.
    # /var/lib/nixos drift is tracked under TODO T-076's /etc/nixos fixture
    # work; the rest is runtime state (journal, systemd, dhcp, machine-id, ssh
    # host keys, /run).
    allowlist = re.compile(
        r"(^|/)("
        r"var/log/|var/lib/nixos|var/lib/systemd|var/lib/dhcp|var/lib/private|"
        r"var/cache/|var/tmp/|var/spool/|etc/machine-id|etc/ssh/ssh_host_|"
        r"etc/\.(updated|clean)|run/|tmp/"
        r")"
    )

    def kept(paths):
        return sorted(p for p in paths if not allowlist.search(p))

    with subtest("null control: a plain boot introduces no disk findings"):
        baseline = disk_forensics.snapshot(machine, "baseline")
        baseline_paths = disk_forensics.fls_paths(disk_forensics.run_fls(baseline))

        # snapshot() already power-cycles the machine, so a second snapshot is a
        # second boot on the same disk lineage: the null control.
        reboot_snap = disk_forensics.snapshot(machine, "reboot")
        reboot_paths = disk_forensics.fls_paths(disk_forensics.run_fls(reboot_snap))

        introduced = kept(disk_forensics.diff(baseline_paths, reboot_paths))
        assert not introduced, (
            "null control failed: a plain boot added disk entries outside the "
            f"allowlist: {introduced[:40]}"
        )
        print(f"✓ null control clean ({len(baseline_paths)} baseline entries)")

    with subtest("positive control: a decoy-root leak is caught by every scanner"):
        # Four distinct tokens so each scanner is proven independently. These are
        # written straight onto the decoy root (no overlay, no hidden volume), so
        # they are a genuine leak the image must expose. Remove these four writes
        # and this subtest fails -- that is the control.
        base = "NAILS_POSCTL_7e1c"
        file_token = f"{base}_FILE"
        str_token = f"{base}_STR"
        jrnl_token = f"{base}_JRNL"
        store_token = f"{base}_STORE"

        machine.succeed("mkdir -p /var/lib/nails-control")
        machine.succeed(
            f"printf '%s\\n' {str_token} > /var/lib/nails-control/{file_token}.txt"
        )
        machine.succeed(f"logger -t nails-control {jrnl_token}")
        machine.succeed(f"printf 'nonce\\n' > /tmp/{store_token}")
        machine.succeed(f"nix store add-file /tmp/{store_token}")
        # Force the journal and filesystem to disk before imaging.
        machine.succeed("journalctl --sync 2>/dev/null || journalctl --flush || true")
        machine.succeed("sync")

        positive = disk_forensics.snapshot(machine, "positive", restart=False)
        offset = disk_forensics.partition_offset(positive)

        fls_names = disk_forensics.fls_paths(disk_forensics.run_fls(positive, offset))
        assert any(file_token in name for name in fls_names), (
            "positive control failed: fls did not see the planted filename"
        )
        assert disk_forensics.run_strings_scan(positive, [str_token]) == {str_token}, (
            "positive control failed: strings did not see the planted content"
        )
        assert disk_forensics.run_journal_scan(
            positive, [jrnl_token], offset=offset
        ) == {jrnl_token}, (
            "positive control failed: the journal scan did not see the logged line"
        )
        assert disk_forensics.run_store_scan(
            positive, [store_token], offset=offset
        ) == {store_token}, (
            "positive control failed: the store scan did not see the added path"
        )
        print("✓ positive control: fls, strings, journal and store all caught the leak")
  '';
}
