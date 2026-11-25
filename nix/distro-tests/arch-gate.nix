# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The drivers of Arch's admission gate, keyed by name: run before the commit
# that admits Arch, on each Arch image of the gate.
#
#   <image>-gate  the gate scenario (py/arch_gate.py, the Fedora gate's
#                 scenario run on Arch) on the stock image, with a test-only
#                 build of nails that admits Arch (lib/admitted.nix). It
#                 writes <image>-gate.json, every assertion with its outcome,
#                 and <image>-gate.kmsg.txt, the whole kernel log of each
#                 boot, into the directory NAILS_GATE_OUT names (the working
#                 directory when it is unset).
#   <image>-btrfs the btrfs scan controls on the stock image
#                 (py/btrfs_controls.py), as Fedora's gate runs them: a file
#                 kept plain, a compressed one and a compressed one written
#                 and deleted, and what the raw scan, the read of the live
#                 tree through the kernel and the read of the older roots of
#                 the tree each find of them. It writes <image>-btrfs.json.
#                 Defined for an image whose root is btrfs.
#
# The images of the gate are the pinned Arch images that `expectations` names.
# arch-boxes is pinned upstream and needs no mirror. The archinstall image
# (arch-install in images.json) joins once it is pinned: its entry then has a
# mirrored asset, and an `arch-install` row in `expectations` with what its
# gate expects of it (its zram swap, which the cold boot finds, makes the zram
# checks run) adds its drivers; nothing else here moves.
#
# Like the probes they are host drivers: on a KVM-capable host by hand, or in
# the staged suite of distro-e2e.yml, whose job builds the driver, runs it on a
# hosted KVM runner and uploads what it wrote.
{
  self,
  pkgs,
  nix-vm-test,
}:
let
  inherit (pkgs) lib;

  images = import ./images.nix { inherit pkgs; };
  distroVm = import ./lib/distro-vm.nix { inherit pkgs nix-vm-test; };
  # The binary the gate runs: the release binary once the image table enables
  # the image, as the commit that admits Arch does, and until then the release
  # binary with Arch's base row admitted (lib/admitted.nix), whose build fails
  # for a row admitted already.
  admitted = import ./lib/admitted.nix { inherit self; };
  nailsFor = entry: if entry.enabled then self.packages.x86_64-linux.nails else admitted entry.osId;

  # The helpers alone, so a change elsewhere in py/ does not rebuild a driver.
  gatePy = lib.fileset.toSource {
    root = ./py;
    fileset = lib.fileset.unions [
      ./py/arch_gate.py
      ./py/btrfs_controls.py
      ./py/btrfs_scan.py
      ./py/distro_checks.py
      ./py/fedora_gate.py
      ./py/fedora_rpms.py
      ./py/selinux_gate.py
    ];
  };

  # The login- and boot-record readers, shared verbatim with the fast-lane
  # unit tests.
  recordsModule = pkgs.writeTextDir "records.py" (builtins.readFile ../e2e-tests/lib/records.py);

  # What an image's gate expects of it beyond the image: whether the family
  # table validates it (the test-only build admits the rolling release),
  # whether its PAM stack records a login in lastlog2 (Arch's system-login
  # runs pam_lastlog2, as the staged records scenario shows on arch-boxes),
  # and what fstab-policy's warning on the prepared decoy names of the image's
  # own layout, each as "<path>: <verdict>": arch-boxes's swap line, made
  # noauto, the ESP systemd's GPT auto-generator mounts on demand at /efi,
  # and /var/lib/machines, for which systemd ships a mount unit that is not
  # mounted at check time.
  expectations = {
    arch-boxes = {
      validated = true;
      lastlog2 = true;
      fstabPolicy = [
        "/swap/swapfile: masked"
        "/efi: read-only"
        "/efi: masked"
        "/var/lib/machines: masked"
      ];
    };
  };

  # The pinned Arch images the gate runs on.
  gateImages = lib.filterAttrs (
    name: entry: entry.osId == "arch" && expectations ? ${name} && distroVm.imageAvailable entry
  ) images;

  # The image has no Python: the guest runs the driver's, from the Nix store
  # the harness mounts, to read the kernel log and drive a failed login.
  python = "${pkgs.python3}/bin/python3";

  # A run: two power cycles, the decoy's checks, a plain soft-reboot, two
  # sessions and their ways back, a last plain soft-reboot, and the kernel log
  # read whole at every step.
  gateTimeout = 5400;

  gateFor =
    name: entry:
    let
      settings = {
        image = name;
        inherit (entry) osId release;
        inherit python;
      }
      // expectations.${name};
    in
    distroVm.buildVmTest {
      inherit entry;
      target = "driver";
      sharedDirs.tools = {
        source = "${nailsFor entry}/bin";
        target = "/run/tools";
      };
      memorySize = 3072;
      testScript = ''
        import json
        import sys

        sys.path.insert(0, "${../e2e-tests/py}")
        sys.path.insert(0, "${gatePy}")
        sys.path.insert(0, "${recordsModule}")
        from nails_e2e import session, utab  # noqa: E402
        import arch_gate  # noqa: E402
        import records  # noqa: E402

        arch_gate.run(
            vm,
            session,
            utab,
            records,
            json.loads(${builtins.toJSON (builtins.toJSON settings)}),
        )
      '';
    };

  gateDrivers = lib.mapAttrs' (
    name: entry: lib.nameValuePair "${name}-gate" (gateFor name entry)
  ) gateImages;

  # A boot, the controls planted and read through the kernel, the disk imaged
  # whole and read raw, and up to 64 older roots of its tree restored.
  btrfsTimeout = 2400;

  # The host tools the controls run on the image, by their store paths.
  btrfsTools = {
    btrfs = "${pkgs.btrfs-progs}/bin/btrfs";
    "btrfs-find-root" = "${pkgs.btrfs-progs}/bin/btrfs-find-root";
    sfdisk = "${pkgs.util-linux}/bin/sfdisk";
    cp = "${pkgs.coreutils}/bin/cp";
  };

  btrfsFor =
    name: entry:
    distroVm.buildVmTest {
      inherit entry;
      target = "driver";
      memorySize = entry.memory;
      testScript = ''
        import json
        import sys

        sys.path.insert(0, "${gatePy}")
        import btrfs_controls  # noqa: E402

        btrfs_controls.run(
            vm,
            json.loads(${builtins.toJSON (builtins.toJSON { image = name; })}),
            json.loads(${builtins.toJSON (builtins.toJSON btrfsTools)}),
        )
      '';
    };

  btrfsDrivers = lib.mapAttrs' (
    name: entry: lib.nameValuePair "${name}-btrfs" (btrfsFor name entry)
  ) (lib.filterAttrs (_: entry: entry.rootfs == "btrfs") gateImages);

  drivers = gateDrivers // btrfsDrivers;
in
{
  # Driver name -> its host driver.
  inherit drivers;
  # Every driver can boot: only pinned images make drivers.
  runnable = builtins.attrNames drivers;
  # Driver name -> the seconds it gets.
  timeouts =
    lib.mapAttrs (_: _: gateTimeout) gateDrivers // lib.mapAttrs (_: _: btrfsTimeout) btrfsDrivers;
}
