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

  # Fedora boots SELinux permissive as images.json pins it, which hides what
  # only an enforcing boot shows (denials, whether the 9p share still mounts).
  # Each Fedora image therefore also gets a "<name>-enforcing" variant.
  enforcingImages = lib.mapAttrs' (
    name: entry: lib.nameValuePair "${name}-enforcing" (entry // { enforcing = true; })
  ) (lib.filterAttrs (_: entry: entry.osId == "fedora") probeImages);

  # Boot the stock image (no nails share, no activation) and print the facts the
  # fixtures record. Every query runs in a subshell with its status discarded
  # (`( ... ) 2>&1 || true`): the host driver does not return a guest command's
  # real exit code, so a probe never trusts one; it reads stdout.
  probeScript = ''
    vm.wait_for_unit("multi-user.target")

    def dump(label, cmd):
        print("=== " + label + " ===")
        print(vm.succeed("( " + cmd + " ) 2>&1 || true"))

    # Every command runs in the backdoor's root shell, so the shell's own
    # context is the domain the backdoor unit runs in; its arguments do not
    # name the unit, so a process grep cannot find it.
    dump("os-release",     "cat /etc/os-release")
    dump("selinux",        "getenforce; sestatus")
    dump("backdoor",       "cat /proc/self/attr/current; echo; systemctl show backdoor.service mount-store.service -p Id -p ExecStart")
    dump("mounts",         "findmnt --real -o TARGET,FSTYPE,OPTIONS")
    # The programs the NAILS sources name, resolved with type -P, which searches
    # PATH even for a name the shell has as a builtin (kill).
    dump("tools",          "for t in systemctl loginctl busctl journalctl dmsetup ip cryptsetup veracrypt tcplay sh mount notify-send nix sync swapoff kill systemd-run modprobe cp chown; do echo $t: $(type -P $t); done")
    # The effective configuration with the file each part comes from, and where
    # the journal is actually written.
    dump("journald",       "systemd-analyze cat-config systemd/journald.conf | grep -E '^# /|Storage'; ls -d /var/log/journal /run/log/journal")
    dump("failed-units",   "systemctl --failed --no-legend")
    # Every masked unit; the test harness masks some, and a unit it masks can
    # never show up in failed-units.
    dump("masked-units",   "systemctl list-unit-files --state=masked --no-legend")
    dump("updatedb-prune", "grep -hs PRUNEPATHS /etc/updatedb.conf /usr/lib/updatedb.conf; for t in updatedb plocate locate; do echo $t: $(type -P $t); done")
    dump("avcs",           "journalctl -k -b | grep -i 'avc:  denied'; ausearch -m avc")
    # Whether the harness's 9p store share is mounted and a file reads through
    # it. A virtio 9p channel takes one mount only, so the share cannot be
    # mounted a second time to test it; the enforcing variant answers whether
    # it mounts and reads under enforcing.
    dump("ninep",          "findmnt -t 9p; f=$(find /nix/.ro-store -maxdepth 3 -type f -print -quit); if [ -n \"$f\" ] && head -c 64 \"$f\" >/dev/null; then echo read-ok; else echo read-failed; fi")

    # Last, a plain soft-reboot with no NAILS involved: the units that fail
    # after it are the ones the way back has to mask, since every way back is
    # a soft-reboot, and a cold boot cannot show them.
    import sys
    sys.path.insert(0, "${../e2e-tests/py}")
    from nails_e2e import session  # noqa: E402

    session.follow_soft_reboot(vm, "systemctl soft-reboot", "probe-soft-reboot")
    vm.wait_for_unit("multi-user.target")
    dump("soft-reboot-failed-units", "systemctl --failed --no-legend")
    dump("soft-reboot-boot-id",      "cat /proc/sys/kernel/random/boot_id; systemctl show -p SoftRebootsCount --value")
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
lib.mapAttrs probeFor (probeImages // enforcingImages)
