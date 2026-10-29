# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Real btrfs decoy images for the forensic oracle: before / control /
# control2 / after of a Fedora 44 Cloud decoy, keyed "<name>-oracle-images".
#
# The NixOS oracle-images test (nix/e2e-tests/tests/forensic/13-oracle-images.nix)
# retains an ext4 decoy root. Fedora and Arch keep their root on btrfs, which
# plaso cannot read, and the oracle scans such images without the timeline
# (ci/oracle/run-scan.sh). This driver produces the real images that scan
# needs, on the stock Fedora 44 Cloud image (btrfs, zstd compressed, with the
# root, /boot, /home and /var subvolumes next to a vfat ESP):
#
#   before    the decoy as prepared, powered off;
#   control   the same disk after one plain reboot, powered off;
#   control2  the same disk after a second plain reboot, powered off: no
#             hidden session has run on it;
#   after     the same disk after one more boot, a full hidden session
#             (activate, work in the session, deactivate) and the way back,
#             powered off.
#
# The oracle scans before, control and after, and before, control and
# control2 the same way, with control2 in the place of after. That second
# scan has no session to find: whatever it reports, two plain reboots made.
#
# Each image is the whole disk, written as a raw into
# $NAILS_ORACLE_OUT/forensics (the working directory when it is unset), as
# before.raw, control.raw, control2.raw and after.raw: the first three and
# the last are the names run-scan.sh's ORACLE_IMAGES_DIR mode reads.
#
# nix-vm-test boots the image under QEMU -snapshot, so the guest's writes live
# only as long as the QEMU process, and a shutdown and start boots the pristine
# image again. The images must be one disk's lineage, so the whole run
# stays in one QEMU process: QEMU is told (QMP set-action) to pause on a guest
# power-off instead of exiting, each image is a QMP blockdev-backup of the
# paused disk, and system_reset then boots the same disk again.
#
# Fedora is not admitted yet: the release `nails` refuses it (the refusal
# scenario, refusal.nix, proves that). So this driver runs a test-only build
# of the release binary in which the one Fedora row of the family table is
# admitted, and nothing else changes. That build is never shipped. What the
# images prove is what a session on a Fedora 44 Cloud decoy leaves on its
# disk, not that NAILS supports Fedora.
#
# The decoy is prepared before the before image, so all three hold it alike:
# its journal volatile and auditd masked (lib/hidden-root.nix's
# makeDecoyAmnesic, the posture NAILS requires), /mnt/data created, and the
# coverage canary written. The canary file has btrfs compression turned off,
# and the driver checks its bytes are on the root partition in clear: on a
# compressed extent bulk_extractor could not see it, and the oracle would
# call the scan blind. The hidden root is backed by a file on a tmpfs
# (lib/hidden-root.nix), so nothing of the session should reach the decoy
# disk; inside the session a token is written, synced and deleted, and the
# driver checks its bytes are on the hidden root's device, so their absence
# from after.raw means something.
#
# Like the probes and the refusal scenario it is a host driver, run by the
# oracle real-image nightly on a hosted KVM runner, not part of the smoke
# matrix.
{
  self,
  pkgs,
  nix-vm-test,
}:
let
  images = import ./images.nix { inherit pkgs; };
  distroVm = import ./lib/distro-vm.nix { inherit pkgs nix-vm-test; };
  hiddenRoot = import ./lib/hidden-root.nix;

  # The release binary with the Fedora base row admitted, for this driver
  # only. The build fails unless exactly that one row changes.
  nailsFedoraAdmitted = self.packages.x86_64-linux.nails.overrideAttrs (old: {
    pname = "nails-test-fedora-admitted";
    postPatch = (old.postPatch or "") + ''
      table=nails-platform/src/platform/family.rs
      awk '
        /^        id: "fedora",$/ { row = 1 }
        row && /^        admitted: false,$/ { sub(/false/, "true"); row = 0; flipped++ }
        { print }
        END { if (flipped != 1) exit 1 }
      ' "$table" > "$table.new" || {
        echo "the Fedora row of $table did not change exactly once" >&2
        exit 1
      }
      mv "$table.new" "$table"
    '';
    meta = old.meta // {
      description = "nails with the Fedora row admitted, for the btrfs oracle images only; never released";
    };
  });

  binShare = {
    tag = "tools";
    target = "/run/tools";
  };

  oracleImagesFor =
    entry:
    distroVm.buildVmTest {
      inherit entry;
      target = "driver";

      sharedDirs.${binShare.tag} = {
        source = "${nailsFedoraAdmitted}/bin";
        inherit (binShare) target;
      };

      memorySize = entry.memory;

      testScript = ''
        import json
        import os
        import shlex
        import sys
        import time

        sys.path.insert(0, "${../e2e-tests/py}")
        from nails_e2e import session  # noqa: E402

        nails = "${binShare.target}/nails"
        config = "/run/nails-oracle.toml"
        nails_cmd = f"{nails} --config {shlex.quote(config)}"

        # The committed coverage canary of ci/oracle/controls-real.json and
        # run-scan.sh, at the path run-scan.sh's real-image mode checks.
        CANARY = "canary@oracle.example"
        CANARY_FILE = "/var/lib/nails-oracle/canary"

        # Session data bulk_extractor recognises, written in the session only.
        SESSION_ADDRESS = "hidden-session@session.oracle.example"
        SESSION_URL = "https://session.oracle.example/hidden-session"

        out_dir = os.environ.get("NAILS_ORACLE_OUT") or os.getcwd()
        forensics = os.path.join(out_dir, "forensics")
        os.makedirs(forensics, exist_ok=True)


        def qmp(command, arguments=None):
            client = vm.qmp_client
            assert client is not None, "the QMP socket is not connected"
            reply = client.send(command, arguments or {})
            assert "return" in reply, f"QMP {command} failed: {reply}"
            return reply["return"]


        def root_device():
            roots = [
                block
                for block in qmp("query-block")
                if block.get("inserted") and not block.get("removable", False)
            ]
            assert len(roots) == 1, f"cannot identify the root drive: {roots}"
            return roots[0]["device"], roots[0]["inserted"]["image"]["virtual-size"]


        def write_config():
            vm.succeed(
                "printf '%s\\n' 'hidden_volume_root = \"/mnt/data\"' "
                + "'minimum_space_mb = 100' > "
                + shlex.quote(config)
            )


        def prepare_boot():
            # A boot loses the 9p share (nix-vm-test mounts it once, before
            # this script) and the /run configuration.
            vm.wait_for_unit("multi-user.target")
            vm.succeed(
                "mkdir -p ${binShare.target} && "
                + "{ mountpoint -q ${binShare.target} || "
                + "mount -t 9p -o defaults,trans=virtio,version=9p2000.L,cache=loose,msize=268435456 "
                + "${binShare.tag} ${binShare.target}; }"
            )
            vm.succeed(f"test -x {nails}")
            write_config()


        def settle():
            # A boot is imaged once it is up: every unit started, the network
            # configured, and its writes on the disk.
            vm.wait_until_succeeds(
                "state=$(systemctl is-system-running || true); "
                + "[ \"$state\" = running ] || [ \"$state\" = degraded ]",
                timeout=600,
            )
            vm.execute("nm-online -s -q -t 60", check_return=False)
            print(vm.execute("systemctl --failed --no-pager", check_return=False)[1])
            vm.succeed("sync")


        def wait_status(wanted, deadline_s=600):
            deadline = time.monotonic() + deadline_s
            while True:
                status = qmp("query-status")["status"]
                if status == wanted:
                    return
                assert time.monotonic() < deadline, f"QEMU is {status}, not {wanted}"
                time.sleep(1)


        def image(name):
            # Power the guest off; QEMU pauses instead of exiting (set-action
            # below), so the paused disk is copied whole, and the guest's
            # shell is gone until the next boot.
            device, size = root_device()
            assert vm.shell is not None
            vm.shell.send(b"poweroff\n")
            vm.connected = False
            wait_status("shutdown")
            target = os.path.join(forensics, f"{name}.raw")
            if os.path.exists(target):
                os.remove(target)
            with open(target, "wb") as handle:
                handle.truncate(size)
            job = f"oracle-{name}"
            qmp(
                "blockdev-add",
                {
                    "driver": "raw",
                    "node-name": job,
                    "file": {"driver": "file", "filename": target},
                },
            )
            qmp(
                "blockdev-backup",
                {
                    "job-id": job,
                    "device": device,
                    "target": job,
                    "sync": "full",
                    "auto-dismiss": False,
                },
            )
            deadline = time.monotonic() + 900
            while True:
                jobs = [entry for entry in qmp("query-jobs") if entry["id"] == job]
                assert jobs, f"the backup job {job} is gone"
                if jobs[0]["status"] == "concluded":
                    break
                assert time.monotonic() < deadline, f"the backup of {device} did not finish"
                time.sleep(1)
            assert "error" not in jobs[0], f"the backup of {device} failed: {jobs[0]}"
            qmp("job-dismiss", {"id": job})
            qmp("blockdev-del", {"node-name": job})
            stat = os.stat(target)
            assert stat.st_size == size and stat.st_blocks > 0, f"{target}: {stat}"
            print(
                f"retained {name}.raw: {size} bytes, "
                + f"{stat.st_blocks * 512} allocated"
            )


        def boot_again():
            qmp("system_reset")
            deadline = time.monotonic() + 60
            while qmp("query-status")["status"] == "shutdown":
                assert time.monotonic() < deadline, "the reset did not leave the shutdown state"
                time.sleep(0.5)
            qmp("cont")
            prepare_boot()


        def follow(trigger, label):
            timings = session.follow_soft_reboot(vm, trigger, label)
            print(f"{label}: {timings}")
            prepare_boot()


        def on_partition(token, device):
            # Whether the token's bytes are on the device, read past the page
            # cache.
            vm.succeed("sync && echo 3 > /proc/sys/vm/drop_caches")
            return vm.execute(f"grep -qaF {shlex.quote(token)} {device}")[0] == 0


        # A guest power-off pauses QEMU, and a reset reboots in place.
        qmp("set-action", {"shutdown": "pause", "reboot": "reset"})
        prepare_boot()
        print(vm.succeed("cat /etc/os-release; uname -r; findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS /"))
        root_partition = vm.succeed("findmnt -rn -o SOURCE / | sed 's/\\[.*//'").strip()
        print(f"the decoy root is on {root_partition}")

        with subtest("prepare the decoy and image it: before"):
            vm.succeed("""${hiddenRoot.makeDecoyAmnesic}""")
            vm.succeed("mkdir -p /mnt/data /var/lib/nails-oracle")
            # Compression off before the first byte is written, so the
            # canary's bytes are on the partition as they are.
            vm.succeed(
                f"touch {CANARY_FILE} && "
                + f"{{ btrfs property set {CANARY_FILE} compression none || chattr +m {CANARY_FILE}; }}"
            )
            vm.succeed(
                "printf '# NAILS forensic-oracle coverage canary (synthetic)\\n"
                + "canary address: "
                + CANARY
                + "\\n' > "
                + CANARY_FILE
            )
            assert on_partition(CANARY, root_partition), (
                f"the canary is not on {root_partition} in clear"
            )
            settle()
            image("before")

        with subtest("a plain reboot, imaged: control"):
            boot_again()
            settle()
            image("control")

        with subtest("a second plain reboot, imaged: control2"):
            boot_again()
            settle()
            image("control2")

        with subtest("a full hidden session and the way back"):
            boot_again()
            vm.succeed("""${hiddenRoot.setupHiddenRoot}""")
            print(vm.succeed(f"{nails_cmd} check --overlay-only 2>&1"))
            follow(f"{nails_cmd} activate -y > /mnt/data/activate.log 2>&1", "activate")
            print(vm.succeed("cat /mnt/data/activate.log"))
            status = json.loads(vm.succeed(f"{nails_cmd} status --json"))["data"]
            assert status["place"] == "hidden", f"expected the hidden session, got {status}"
            vm.succeed(
                "mkdir -p /home/oracle/work /root/work /var/tmp/oracle && "
                + "for i in $(seq 1 50); do echo content > /home/oracle/work/file_$i.txt; done && "
                + "printf '#!/bin/sh\\necho test\\n' > /root/work/script.sh && "
                + "chmod +x /root/work/script.sh && echo state > /var/tmp/oracle/state && sync"
            )
            # The token, written, synced and deleted: its bytes stay on the
            # hidden root's device, and must never reach the decoy's.
            note = "/home/oracle/work/note.txt"
            vm.succeed(
                f"printf '%s\\n%s\\n' {SESSION_ADDRESS} {SESSION_URL} > {note} && sync"
            )
            vm.succeed(f"rm {note} && sync")
            hidden_device = vm.succeed("cat /run/blk.dev").strip()
            if vm.execute("test -e /dev/mapper/data")[0] == 0:
                hidden_device = "/dev/mapper/data"
            assert on_partition(SESSION_ADDRESS, hidden_device), (
                f"the session token is not on the hidden root's device {hidden_device}"
            )
            follow(f"{nails_cmd} deactivate -y", "deactivate")
            status = json.loads(vm.succeed(f"{nails_cmd} status --json"))["data"]
            assert status["place"] == "decoy", f"expected the plain decoy, got {status}"
            session.assert_decoy_root(vm)
            vm.fail("test -e /home/oracle")
            vm.fail("grep -E ' /mnt/data|/dev/mapper/data' /proc/mounts")

        with subtest("image the decoy after the way back: after"):
            settle()
            image("after")

        print(f"before.raw, control.raw, control2.raw and after.raw are in {forensics}")
      '';
    };
in
{
  "fedora-44-oracle-images" = oracleImagesFor images."fedora-44";
}
