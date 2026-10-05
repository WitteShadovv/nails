# Backend: a VeraCrypt (tcrypt) hidden volume as the hidden root
#
# README and docs/backends.md document opening the hidden storage with
#   cryptsetup open --type tcrypt --veracrypt --tcrypt-hidden <device> data
# but no test ever exercised a VeraCrypt volume: every positive path used LUKS2.
# This test opens a real VeraCrypt hidden volume under a neutral mapper name,
# runs a full activate/deactivate cycle over it, and then images the decoy root
# (via the T-075 host-side forensic harness) to prove the hidden-session canaries
# never reach the decoy disk when the backend is tcrypt rather than LUKS.
#
# The ciphertext lives on the secondary test disk (/dev/disk/by-id/virtio-data),
# which the forensic harness never images -- only the decoy root qcow2 is converted and scanned, so
# the hidden container is out of frame exactly as it would be post-seizure.
#
# This is a nightly/manual backend test, not part of the PR smoke lane (it is not
# in `ciNames`). cryptsetup can open a tcrypt volume but not create one, so the
# container is generated in-VM with the `veracrypt` console tool. See the
# "VALIDATE ON A NIX HOST" note on the creation block below.

{ self, pkgs, ... }:
let
  backends = import ./../../lib/backends.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
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

  # VeraCrypt container creation (outer + hidden) plus the imaging lineage and an
  # activate/deactivate cycle; generous margin for the slow volume formatting.
  globalTimeout = 2400;

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
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertNoOverlaysFn}
    ${diskForensics.pythonSetup}

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

    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config, overlay_var=True)

    with subtest("capture the decoy baseline image"):
        baseline = disk_forensics.snapshot(machine, "baseline")
        baseline_fls = disk_forensics.fls_paths(disk_forensics.run_fls(baseline))
        registry_tokens = load_registry_tokens()
        baseline_registry_hits = disk_forensics.run_strings_scan(baseline, registry_tokens)

    with subtest("create a VeraCrypt hidden volume on the secondary disk"):
        # VALIDATE ON A NIX HOST: the exact `veracrypt --text --create` flags for
        # non-interactive hidden-volume creation cannot be evaluated in the build
        # sandbox. The outer volume is created first, then the hidden volume in
        # its reserved tail. If the console tool rejects creating a hidden volume
        # without the outer password in one pass, create the outer, mount it to
        # establish its filesystem, then create the hidden volume with the outer
        # passphrase supplied as well. The alternative is a tcplay-made TrueCrypt
        # volume opened with `--type tcrypt --tcrypt-hidden` (drop `--veracrypt`).
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
        machine.succeed("""${backends.nailsDirStructure "/mnt/data"}""")

    with subtest("activate and plant hidden canaries"):
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep --accept-persistent-decoy -y"
        )
        machine.succeed("su - testuser -c 'id -un | grep -qx testuser'")
        machine.succeed("mount | grep 'overlay on /home'")

        machine.succeed(
            f"su - testuser -c 'echo {canary_file_token} > ~/secret-notes.txt'"
        )
        machine.succeed(
            f"su - testuser -c 'echo {canary_hist_token} >> ~/.bash_history'"
        )
        machine.succeed(f"logger -t session {canary_jrnl_token}")
        machine.succeed("journalctl --sync 2>/dev/null || journalctl --flush || true")

    with subtest("standard deactivation"):
        canonical_deactivate(
            headless_config, unit_name="nails-deactivate-tcrypt-veracrypt-hidden"
        )
        status = json.loads(machine.succeed("nails status --json"))["data"]
        assert status["state"]["kind"] == "inactive", f"expected inactive, got {status}"
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp", "/var"])

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

        post_registry_hits = disk_forensics.run_strings_scan(post, registry_tokens)
        new_registry = post_registry_hits - baseline_registry_hits
        assert not new_registry, (
            f"activate/deactivate introduced registry tokens onto the decoy "
            f"image: {sorted(new_registry)}"
        )
        print("✓ post-standard image clean with a VeraCrypt hidden-volume backend")
  '';
}
