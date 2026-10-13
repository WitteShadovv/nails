# Test 04: Disk-image harness controls (null and positive)
#
# This test does not exercise NAILS. It proves the host-side disk-image harness
# itself is honest: a plain boot leaves no decoy-disk findings beyond a short,
# documented allowlist (the null control), and a leak deliberately written onto
# the decoy root is caught by every scanner -- fls, strings, journal and store
# (the positive control). The old test ran `fls` against the LUKS ciphertext of
# the hidden volume and could neither see a leak nor fail; this one images the
# decoy root while the VM is off, the way a seized disk would be read.
#
# The same two controls cover the MAC-time and content-hash diff the other image
# tests assert (forensic/05, 06, 08 and the tcrypt backend test): a decoy file
# created before the baseline and then modified in place must be the one and
# only unexplained change between a plain-boot control span and the positive
# span, so the diff both catches an in-place edit and stays quiet otherwise.

{ self, pkgs, ... }:
let
  diskForensics = import ./../../lib/disk-forensics.nix { inherit pkgs; };
in
{
  name = "forensic-clean";
  meta.tags = [ "forensic" ];

  # Imaging the root disk several times (shutdown, qemu-img convert, restart)
  # and three carve-and-hash passes take longer than a single-boot test;
  # measured runtime leaves margin here.
  globalTimeout = 2400;

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

    # An ordinary decoy document outside every volatile path, edited in place in
    # the positive control below.
    machine.succeed("mkdir -p /srv && printf 'notes\\n' > /srv/decoy-notes.txt && sync")

    with subtest("null control: a plain boot introduces no disk findings"):
        baseline = disk_forensics.snapshot(machine, "baseline")
        baseline_state = disk_forensics.image_state(baseline, "baseline", machine)
        baseline_paths = disk_forensics.fls_paths(disk_forensics.run_fls(baseline))

        # snapshot() already power-cycles the machine, so a second snapshot is a
        # second boot on the same disk lineage: the null control.
        reboot_snap = disk_forensics.snapshot(machine, "reboot")
        reboot_state = disk_forensics.image_state(reboot_snap, "reboot", machine)
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
        # nix-store --add is the stable spelling; `nix store add-file` needs the
        # nix-command experimental feature, which the decoy VM leaves disabled.
        machine.succeed(f"nix-store --add /tmp/{store_token}")
        # An existing decoy file modified in place: no new name, no token, only
        # its MAC times and contents change.
        machine.succeed("printf 'edited\\n' >> /srv/decoy-notes.txt")
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

    with subtest("the MAC-time and content diff catches the in-place edit and nothing else"):
        positive_state = disk_forensics.image_state(positive, "positive", machine)
        # baseline -> reboot is one plain boot; reboot -> positive is one boot
        # plus the writes above, of which only the /srv edit touches an existing
        # inode outside the volatile paths.
        # `nix-store --add` legitimately changes the store's directories, so the
        # whole of /nix is volatile here.
        volatile = re.compile(
            r"(^|/)nix/|" + disk_forensics.DEFAULT_IMAGE_VOLATILE.pattern
        )
        result = disk_forensics.mac_diff(
            baseline_state, reboot_state, positive_state, volatile
        )
        disk_forensics.write_artifact(machine, "mac-diff.txt", result.report or "(none)")
        assert "srv/decoy-notes.txt" in result.left, (
            f"positive control failed: the MAC diff missed the in-place edit:\n{result.report}"
        )
        assert {"content", "mtime", "size"} <= set(result.left["srv/decoy-notes.txt"]), (
            result.report
        )
        others = {p: f for p, f in result.left.items() if p != "srv/decoy-notes.txt"}
        assert not others, (
            f"null control failed: one plain boot left unexplained changes:\n{result.report}"
        )
        print("✓ MAC diff: the in-place edit is the only unexplained change")
  '';
}
