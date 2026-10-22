# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# A probe boots the stock cloud image of a distribution the smoke suite does not
# admit yet (Fedora, Arch), without nails, and prints the host facts the
# cross-distribution work needs but cannot assert by reading code. A maintainer
# runs one on a KVM-capable host and records its output into the matching
# probe/<image>.json fixture (see probe/README.md). The build server has no KVM,
# so a probe is not part of CI; it is a host driver, run by hand.
{ pkgs, nix-vm-test }:
let
  inherit (pkgs) lib;

  images = import ./images.nix { inherit pkgs; };
  distroVm = import ./lib/distro-vm.nix { inherit pkgs nix-vm-test; };

  # The families the smoke suite does not run yet, so their facts are unknown.
  probeOsIds = [
    "fedora"
    "arch"
  ];
  probeImages = lib.filterAttrs (_: entry: builtins.elem entry.osId probeOsIds) images;

  # Boot the stock image (no nails share, no activation) and print the facts the
  # fixtures record. Every query runs in a subshell with its status discarded
  # (`( ... ) 2>&1 || true`): the host driver does not return a guest command's
  # real exit code, so a probe never trusts one; it reads stdout.
  probeScript = ''
    vm.wait_for_unit("multi-user.target")

    def dump(label, cmd):
        print("=== " + label + " ===")
        print(vm.succeed("( " + cmd + " ) 2>&1 || true"))

    dump("os-release",     "cat /etc/os-release")
    dump("selinux",        "getenforce; sestatus")
    dump("backdoor",       "ps -eo label,args | grep -Ei 'backdoor|mount-store' | grep -v grep")
    dump("mounts",         "findmnt --real -o TARGET,FSTYPE,OPTIONS")
    dump("tools",          "for t in cryptsetup mke2fs swapoff systemd-run modprobe findmnt mount umount cp chown kill sync; do echo $t: $(command -v $t); done")
    dump("journald",       "cat /usr/lib/systemd/journald.conf 2>/dev/null; systemctl show systemd-journald -p Storage")
    dump("failed-units",   "systemctl --failed --no-legend")
    dump("updatedb-prune", "grep -hs PRUNEPATHS /etc/updatedb.conf /usr/lib/updatedb.conf")
    dump("avcs",           "journalctl -k -b | grep -i 'avc:  denied'; ausearch -m avc")
    dump("ninep",          "findmnt -t 9p; mount | grep 9p")
  '';

  probeFor =
    _name: entry:
    distroVm.buildVmTest {
      inherit entry;
      testScript = probeScript;
      memorySize = entry.memory;
      target = "driver";
    };
in
lib.mapAttrs probeFor probeImages
