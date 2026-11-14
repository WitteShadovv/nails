# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The drivers of Fedora's admission gate, keyed by name: run before the commit
# that admits Fedora, on each pinned Fedora image.
#
#   <image>-rpms  boots the stock image with the guest's network on and has
#                 its own dnf resolve the closure of one install of tuned,
#                 firewalld and ABRT from the release's own repository
#                 (py/fedora_rpms.py). It writes <image>-rpms.json into the
#                 directory NAILS_GATE_OUT names (the working directory when it
#                 is unset), which ci/e2e/rpm_closure.py turns into the lock
#                 rpms/<image>.json that the gate installs from.
#   <image>-gate  the gate scenario (py/fedora_gate.py) on the image booted with
#                 SELinux enforcing, with a test-only build of nails that admits
#                 Fedora (lib/admitted.nix) and the locked closure shared in
#                 over 9p. It writes <image>-gate.json, every assertion with its
#                 outcome, and <image>-gate.kmsg.txt, the whole kernel log of
#                 each boot. It is defined once the image has a lock.
#   <image>-btrfs the btrfs scan controls on the stock image
#                 (py/btrfs_controls.py): a file kept plain, a compressed one
#                 and a compressed one written and deleted, and what the raw
#                 scan, the read of the live tree through the kernel and the
#                 read of the older roots of the tree each find of them. It
#                 writes <image>-btrfs.json.
#
# Like the probes they are host drivers: on a KVM-capable host by hand, or in
# the gate suite of distro-e2e.yml, whose job builds the driver, runs it on a
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
  admitted = import ./lib/admitted.nix { inherit self; };

  # The helpers alone, so a change elsewhere in py/ does not rebuild a driver.
  gatePy = lib.fileset.toSource {
    root = ./py;
    fileset = lib.fileset.unions [
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

  # The pinned Fedora images.
  fedoraImages = lib.filterAttrs (
    _: entry: entry.osId == "fedora" && distroVm.imageAvailable entry
  ) images;

  # One resolution: a boot, the repository metadata and one install's
  # packages downloaded over the guest's network, and every file described.
  rpmsTimeout = 1800;

  rpmsFor =
    name: entry:
    distroVm.buildVmTest {
      inherit entry;
      target = "driver";
      memorySize = entry.memory;
      testScript = ''
        import os
        import sys

        sys.path.insert(0, "${gatePy}")
        import fedora_rpms  # noqa: E402

        image = ${builtins.toJSON name}
        release = ${builtins.toJSON entry.release}
        image_file = ${builtins.toJSON entry.source.name}
        out_dir = os.environ.get("NAILS_GATE_OUT") or os.getcwd()

        vm.wait_for_unit("multi-user.target")
        vm.execute("nm-online -s -q -t 120", check_return=False)
        print(vm.succeed("cat /etc/os-release; uname -r; rpm -q dnf5 rpm"))

        with subtest("resolve the closure on the image, from the release repository"):
            # What dnf prints goes to a file of its own, so that only the
            # records reach the reading below.
            status, out = vm.execute(
                "( " + fedora_rpms.resolve_command(release) + "\n) 2>/run/rpm-closure.err",
                timeout=1500,
            )
            print(out)
            print(vm.execute("cat /run/rpm-closure.err", check_return=False)[1])
            assert status == 0, f"the resolution exited {status}"
            record = fedora_rpms.parse_resolution(out, release)
            record["image"] = image
            record["imageFile"] = image_file

        target = os.path.join(out_dir, f"{image}-rpms.json")
        os.makedirs(out_dir, exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(fedora_rpms.resolution_json(record))
        names = ", ".join(str(p["nevra"]) for p in record["packages"])
        print(f"{len(record['packages'])} packages to {target}: {names}")
        print(f"what the image holds of {fedora_rpms.REQUESTED}: {record['inImage']}")
      '';
    };

  rpmsDrivers = lib.mapAttrs' (
    name: entry: lib.nameValuePair "${name}-rpms" (rpmsFor name entry)
  ) fedoraImages;

  # The lock of each image's closure, where one is committed.
  lockOf = name: ./rpms + "/${name}.json";
  lockedImages = lib.filterAttrs (name: _: builtins.pathExists (lockOf name)) fedoraImages;

  # The closure a lock pins, as one directory of RPM files the gate shares
  # into its VM. Each file is fetched by its hash from the release repository,
  # or from its archive once the release is past its end of life.
  closureOf =
    name:
    let
      lock = lib.importJSON (lockOf name);
      fetched = map (package: {
        inherit (package) file;
        path = pkgs.fetchurl {
          urls = [
            (lock.repository + package.path)
            (lock.archive + package.path)
          ];
          hash = package.sha256;
          # A store name takes no tilde or caret, which RPM versions may hold.
          name = lib.replaceStrings [ "~" "^" ] [ "_" "_" ] package.file;
        };
      }) lock.packages;
    in
    pkgs.runCommand "${name}-closure" { } (
      "mkdir $out\n"
      + lib.concatMapStrings (f: "cp ${f.path} $out/${lib.escapeShellArg f.file}\n") fetched
    );

  # What a release's gate expects of it beyond the image: whether the family
  # table validates the release (Fedora 45 warns as untested until the
  # commit that admits Fedora validates it), whether the image's PAM stack
  # records a login in lastlog2 (Fedora 44's pam_lastlog2 fails to load, as
  # the D-SEL-EXP cells saw), and the packages the drift steps remove: one in
  # the first hidden session, one on the decoy after it.
  expectations = {
    "44" = {
      validated = true;
      lastlog2 = false;
    };
    "45" = {
      validated = false;
      lastlog2 = true;
    };
  };
  driftPackages = {
    hiddenRemoves = "firewalld";
    decoyRemoves = "abrt";
  };

  # A run: a power cycle, the decoy's checks with an offline install, a plain
  # soft-reboot, two sessions and their ways back, a last plain soft-reboot,
  # and the kernel log read whole at every step.
  gateTimeout = 5400;

  gateFor =
    name: entry:
    let
      enforcing = entry // {
        enforcing = true;
      };
      settings = {
        image = name;
        inherit (entry) osId release;
      }
      // (expectations.${entry.release} or {
        validated = false;
        lastlog2 = false;
      }
      )
      // driftPackages;
    in
    distroVm.buildVmTest {
      entry = enforcing;
      target = "driver";
      sharedDirs = {
        tools = {
          source = "${admitted entry.osId}/bin";
          target = "/run/tools";
        };
        rpms = {
          source = "${closureOf name}";
          target = "/run/rpms";
        };
      };
      memorySize = 3072;
      testScript = ''
        import json
        import sys

        sys.path.insert(0, "${../e2e-tests/py}")
        sys.path.insert(0, "${gatePy}")
        sys.path.insert(0, "${recordsModule}")
        from nails_e2e import session, utab  # noqa: E402
        import fedora_gate  # noqa: E402
        import records  # noqa: E402

        fedora_gate.run(
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
  ) lockedImages;

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
  ) fedoraImages;

  drivers = rpmsDrivers // gateDrivers // btrfsDrivers;
in
{
  # Driver name -> its host driver.
  inherit drivers;
  # Every driver can boot: only pinned images make drivers.
  runnable = builtins.attrNames drivers;
  # Driver name -> the seconds it gets.
  timeouts =
    lib.mapAttrs (_: _: rpmsTimeout) rpmsDrivers
    // lib.mapAttrs (_: _: gateTimeout) gateDrivers
    // lib.mapAttrs (_: _: btrfsTimeout) btrfsDrivers;
}
