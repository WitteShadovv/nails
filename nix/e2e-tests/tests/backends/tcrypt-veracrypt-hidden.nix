# Backend: a VeraCrypt (tcrypt) hidden volume as the hidden root
#
# README and docs/backends.md document opening the hidden storage with
#   cryptsetup open --type tcrypt --veracrypt --tcrypt-hidden <device> data
# This test opens a real VeraCrypt hidden volume under the neutral mapper name,
# runs a whole-root session over it (a soft-reboot into the root overlay with
# its upper on the tcrypt volume, and a soft-reboot back), checks that the way
# back closed the tcrypt mapping like a LUKS one, and then images the decoy
# root (with the host-side forensic harness) to prove the hidden-session
# canaries never reach the decoy disk when the backend is tcrypt rather than
# LUKS.
#
# The ciphertext lives on the secondary test disk (/dev/disk/by-id/virtio-data),
# which the forensic harness never images -- only the decoy root qcow2 is
# converted and scanned, so the hidden container is out of frame exactly as it
# would be post-seizure.
#
# As in forensic/05, the images are also compared by MAC times and content
# hashes against a control run (one plain reboot: the session spans the boot
# after the baseline and two soft-reboots), so a decoy file modified in place
# fails the test even when it carries no token.
#
# It is not in the `ci` group (`ciNames`): it runs in every E2E run that rebuilds
# the tests (a pull request that changes the code, a push to main) and nightly.
# cryptsetup can open a tcrypt volume but not create one, so the container is
# generated in-VM with the `veracrypt` console tool.

{ self, pkgs, ... }:
let
  testHelpers = import ./../../lib/test-helpers.nix;
  diskForensics = import ./../../lib/disk-forensics.nix { inherit pkgs; };

  # VeraCrypt ships under an unfree licence, and the suite's shared nixpkgs
  # (which runNixOSTest also hands every node read-only) refuses to evaluate it.
  # Allow exactly this one package through a private nixpkgs instance instead of
  # opening the whole suite to unfree software.
  unfreePkgs = import pkgs.path {
    inherit (pkgs.stdenv.hostPlatform) system;
    config.allowUnfreePredicate = pkg: pkgs.lib.getName pkg == "veracrypt";
  };
  inherit (unfreePkgs) veracrypt;
in
{
  name = "tcrypt-veracrypt-hidden";
  meta.tags = [ "forensic" ];

  # VeraCrypt container creation (outer + hidden) plus the imaging lineage, a
  # control reboot and two soft-reboots; generous margin for the slow volume
  # formatting.
  globalTimeout = 3300;

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/forensic-vm-config.nix ];
        environment.systemPackages = [
          self.packages.x86_64-linux.nails
          veracrypt
          pkgs.dosfstools # mkfs.vfat for the outer decoy filesystem
        ];
      };
  };

  testScript = _: ''
    import json

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${diskForensics.pythonSetup}

    from nails_e2e import session

    # Distinctive, run-unique canary tokens planted inside the hidden session.
    canary_file_token = "NAILS_CANARY_FILE_TCRYPT_2026a"
    canary_hist_token = "NAILS_CANARY_HISTORY_TCRYPT_2026a"
    canary_jrnl_token = "NAILS_CANARY_JOURNAL_TCRYPT_2026a"
    hidden_tokens = [canary_file_token, canary_hist_token, canary_jrnl_token]

    # Throwaway container passphrases: the outer volume carries a small decoy
    # filesystem, the hidden volume is what NAILS uses. Weak, hard-coded test
    # fixtures -- never a template for real use.
    outer_pass = "outer-decoy-passphrase"
    hidden_pass = "hidden-root-passphrase"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    # Keep the config file name free of "nails": it is written to the decoy
    # /tmp before the baseline and stays there for the whole lineage.
    headless_config = "/tmp/tcrypt-headless.toml"
    write_headless_config(headless_config)

    with subtest("capture the decoy baseline image"):
        # The hidden-volume mount point is a permanent part of the decoy; create
        # it before the baseline so the new /mnt entry is not read as drift.
        machine.succeed("mkdir -p /mnt/data")
        baseline = disk_forensics.snapshot(machine, "baseline")
        baseline_fls = disk_forensics.fls_paths(disk_forensics.run_fls(baseline))
        registry_tokens = load_registry_tokens()
        # Scan the decoy's files, journal excluded (as forensic/05 does): nails'
        # own diagnostics in the journal are not a trace on the decoy files, and
        # the journal is scanned for the canaries below.
        baseline_registry_hits = disk_forensics.run_decoy_file_scan(
            baseline, registry_tokens, offset=disk_forensics.partition_offset(baseline)
        )
        baseline_state = disk_forensics.image_state(baseline, "baseline", machine)

    with subtest("control run: a plain reboot with no hidden session"):
        # The session below spans the boot after this snapshot and two
        # soft-reboots (the decoy's shutdown and its start again), so the
        # control is one plain reboot. Whatever changes here is boot noise, not
        # the hidden session.
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        control = disk_forensics.snapshot(machine, "control")
        control_state = disk_forensics.image_state(control, "control", machine)

    with subtest("create a VeraCrypt hidden volume on the secondary disk"):
        # The outer volume is created first, then the hidden volume in its
        # reserved tail, both non-interactively with the console tool.
        machine.succeed(
            "veracrypt --text --create /dev/disk/by-id/virtio-data "
            + "--volume-type=normal "
            + "--encryption=AES --hash=sha-512 --filesystem=FAT "
            + f"--password={outer_pass} "
            + "--pim=0 --keyfiles= --random-source=/dev/urandom "
            + "--non-interactive --quick"
        )
        machine.succeed(
            # Size the hidden volume well above the 500 MB activation space floor
            # (the secondary disk is 2 GB, so its outer volume has room): a 64 MB
            # hidden volume left only ~50 MB free and the space pre-flight refused.
            "veracrypt --text --create /dev/disk/by-id/virtio-data "
            + "--volume-type=hidden --size=1200M "
            + "--encryption=AES --hash=sha-512 --filesystem=none "
            + f"--password={hidden_pass} "
            + "--pim=0 --keyfiles= --random-source=/dev/urandom "
            + "--non-interactive --quick"
        )

    with subtest("open the hidden volume under a neutral mapper and mount it"):
        # The mapper name, ext4 label and mount point are all the neutral "data"
        # the rest of the suite uses, so nothing here hints at hidden storage in
        # /dev/mapper, by-label links or generated unit names.
        machine.succeed(
            f"printf '%s' {hidden_pass} | cryptsetup open --type tcrypt --veracrypt "
            + "--tcrypt-hidden --key-file=- /dev/disk/by-id/virtio-data data"
        )
        machine.succeed("mkfs.ext4 -F -L data /dev/mapper/data")
        machine.succeed("mkdir -p /mnt/data", "mount /dev/mapper/data /mnt/data")
        machine.succeed("mkdir -p /mnt/data/root/work /mnt/data/config/nixos")

    with subtest("activate and plant hidden canaries"):
        canonical_activate(
            headless_config, "--overlay-only --allow-persistent-decoy", "activate-tcrypt"
        )
        machine.succeed("su - testuser -c 'id -un | grep -qx testuser'")

        machine.succeed(
            f"su - testuser -c 'echo {canary_file_token} > ~/secret-notes.txt'"
        )
        machine.succeed(
            f"su - testuser -c 'echo {canary_hist_token} >> ~/.bash_history'"
        )
        machine.succeed(f"logger -t session {canary_jrnl_token}")
        machine.succeed("journalctl --sync 2>/dev/null || journalctl --flush || true")
        # The hidden file is in the upper on the tcrypt volume.
        machine.succeed(
            f"grep -q {canary_file_token} /mnt/data/root/upper/home/testuser/secret-notes.txt"
        )

    with subtest("deactivation returns to the plain decoy and closes the tcrypt mapping"):
        # canonical_deactivate also waits for /dev/mapper/data to go away: the
        # deferred close must release a tcrypt mapping like a LUKS one.
        canonical_deactivate(headless_config, "deactivate-tcrypt")
        status = json.loads(
            machine.succeed(f"nails --config {headless_config} status --json")
        )["data"]
        assert status["place"] == "decoy", f"expected the plain decoy, got {status}"
        session.assert_decoy_root(machine)

    with subtest("the decoy disk image is clean of every canary and registry token"):
        post = disk_forensics.snapshot(machine, "post-standard", restart=False)
        offset = disk_forensics.partition_offset(post)

        post_fls = disk_forensics.fls_paths(disk_forensics.run_fls(post, offset))
        new_names = disk_forensics.diff(baseline_fls, post_fls)
        leaked_names = {
            name for name in new_names if any(tok in name for tok in hidden_tokens)
        }
        assert not leaked_names, f"fls found canary-named entries: {sorted(leaked_names)}"

        string_hits = disk_forensics.run_strings_scan(post, hidden_tokens)
        assert not string_hits, f"strings found canary content: {sorted(string_hits)}"

        journal_hits = disk_forensics.run_journal_scan(post, hidden_tokens, offset=offset)
        assert not journal_hits, f"journal retained a canary line: {sorted(journal_hits)}"

        post_registry_hits = disk_forensics.run_decoy_file_scan(
            post, registry_tokens, offset=offset
        )
        new_registry = post_registry_hits - baseline_registry_hits
        assert not new_registry, (
            f"activate/deactivate introduced registry tokens onto the decoy "
            f"image: {sorted(new_registry)}"
        )
        print("✓ post-standard image clean with a VeraCrypt hidden-volume backend")

    with subtest("existing decoy inodes keep their MAC times and contents"):
        post_state = disk_forensics.image_state(post, "post", machine)
        disk_forensics.assert_mac_unchanged(
            machine, baseline_state, control_state, post_state
        )
  '';
}
