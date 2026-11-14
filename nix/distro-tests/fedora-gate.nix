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
#
# Like the probes they are host drivers: on a KVM-capable host by hand, or in
# the staged suite of distro-e2e.yml, whose job builds the driver, runs it on a
# hosted KVM runner and uploads what it wrote.
{
  pkgs,
  nix-vm-test,
}:
let
  inherit (pkgs) lib;

  images = import ./images.nix { inherit pkgs; };
  distroVm = import ./lib/distro-vm.nix { inherit pkgs nix-vm-test; };

  # The helpers alone, so a change elsewhere in py/ does not rebuild a driver.
  gatePy = lib.fileset.toSource {
    root = ./py;
    fileset = lib.fileset.unions [ ./py/fedora_rpms.py ];
  };

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
            status, out = vm.execute(
                fedora_rpms.resolve_command(release) + " 2>/run/rpm-closure.err",
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

  drivers = rpmsDrivers;
in
{
  # Driver name -> its host driver.
  inherit drivers;
  # Every driver can boot: only pinned images make drivers.
  runnable = builtins.attrNames drivers;
  # Driver name -> the seconds it gets.
  timeouts = lib.mapAttrs (_: _: rpmsTimeout) rpmsDrivers;
}
