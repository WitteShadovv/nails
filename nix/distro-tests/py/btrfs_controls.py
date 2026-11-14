"""The btrfs scan controls on a Fedora decoy's disk, for Fedora's admission.

``nix/distro-tests/fedora-gate.nix`` builds one host driver per pinned Fedora
image (``<image>-btrfs``) and calls :func:`run` with the driver's machine. Fedora
keeps its root on btrfs mounted ``compress=zstd:1``, and a raw scan of a disk
image reads the bytes as they lie on the disk: it cannot see what a compressed
extent holds, and it never tells a deleted file from free space. Three planted
controls show what each read of such a decoy sees, on the image itself:

- (a) a file btrfs keeps plain (its folder's compression property ``none``):
  the raw scan finds its token;
- (b) a compressed file (its folder's property ``zstd``, a poison of one short
  unit repeated): the raw scan must not find its token, which proves the file
  is stored compressed, and the read of the live tree through the decoy's own
  kernel must;
- (c) a compressed file written, kept through a few commits, then deleted: the
  read of the live tree must not find it, and a read of the older roots of the
  tree, which btrfs's copy-on-write leaves on the disk, must find it at its
  path (``btrfs_scan``: ``btrfs-find-root``, then ``btrfs restore -t``).

The decoy is the stock image; no NAILS runs here. The disk is imaged whole once
the controls are synced, as the oracle images driver images it: QEMU pauses at
the guest's power-off, and the image is a QMP backup of the paused disk. The
driver writes ``<image>-btrfs.json``, every assertion with its outcome, into the
directory ``NAILS_GATE_OUT`` names, and fails when one does not hold.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from typing import Any

import btrfs_scan

# The controls' folder on the decoy: /var/tmp, on the var subvolume.
CONTROLS = "/var/tmp/scan-controls"
# How many older roots the history reads, newest first.
ROOTS = 64


def poison_unit(name: str) -> str:
    """The 15-byte unit a poison repeats."""
    return f"NAILS-POISON-{name}-"


def poison_token(name: str) -> str:
    """What the scans look for: four units in a row. btrfs's zstd stores a run
    of the unit as one copy and a back-reference, so the token is on the disk
    in plain bytes only where the file is stored plain."""
    return poison_unit(name) * 4


class Controls:
    """One run of the controls on the machine ``vm``."""

    def __init__(
        self, vm: Any, settings: dict[str, Any], tools: dict[str, str], out_dir: str
    ) -> None:
        self.vm = vm
        self.image = str(settings["image"])
        self.tools = tools
        self.out_dir = out_dir
        self.checks: list[dict[str, Any]] = []
        self.facts: dict[str, Any] = {}

    def check(self, name: str, passed: bool, detail: object = "") -> None:
        text = detail if isinstance(detail, str) else repr(detail)
        self.checks.append({"name": name, "passed": bool(passed), "detail": text})
        print(f"GATE {'PASS' if passed else 'FAIL'}: {name}: {text[:2000]}")

    # --- the guest -------------------------------------------------------

    def plant(self) -> None:
        vm = self.vm
        vm.succeed(f"mkdir -p {CONTROLS}/plain {CONTROLS}/compressed")
        self.facts["properties"] = vm.succeed(
            f"btrfs property set {CONTROLS}/plain compression none && "
            f"btrfs property set {CONTROLS}/compressed compression zstd && "
            f"btrfs property get {CONTROLS}/plain compression; "
            f"btrfs property get {CONTROLS}/compressed compression"
        )
        # (a): the token on a line of its own, then 64 KiB of random bytes.
        vm.succeed(
            f"{{ printf '%s\\n' {poison_token('A')}; head -c 65536 /dev/urandom; }} "
            f"> {CONTROLS}/plain/a"
        )
        # (b) and (c): 17476 units, 262140 bytes, two compressed extents.
        for name, file in (("B", "b"), ("C", "c")):
            vm.succeed(
                f"printf '{poison_unit(name)}%.0s' $(seq 17476) > "
                f"{CONTROLS}/compressed/{file}"
            )
        for tick in range(3):
            vm.succeed(f"echo {tick} > {CONTROLS}/tick && sync")
        vm.succeed(f"rm {CONTROLS}/compressed/c && sync")
        self.facts["listing"] = vm.succeed(
            f"ls -la {CONTROLS}/plain {CONTROLS}/compressed; "
            f"compsize {CONTROLS} 2>/dev/null || true"
        )

    def live_tokens(self, tokens: list[str]) -> set[str]:
        """Which of ``tokens`` the files of the controls' folder hold, read
        through the decoy's own kernel from a read-only bind of the folder,
        which moves no access time."""
        vm = self.vm
        view = "/run/live-view"
        vm.succeed(
            f"mkdir -p {view} && mount --bind {CONTROLS} {view} && "
            f"mount -o remount,bind,ro {view}"
        )
        patterns = " ".join(f"-e {shlex.quote(token)}" for token in tokens)
        rc, out = vm.execute(
            f"grep -rhoazF -D skip {patterns} {view} 2>/dev/null | tr '\\0' '\\n' | "
            "sort -u"
        )
        vm.succeed(f"umount {view} && rmdir {view}")
        self.facts["live-read-exit"] = rc
        return {line for line in out.splitlines() if line in tokens}

    def where_on_root(self) -> tuple[str, str]:
        """The device of the controls' filesystem and the controls' path in
        it, as btrfs restore writes it out."""
        fields = self.vm.succeed(
            f"findmnt -rn -o TARGET,SOURCE,OPTIONS -T {CONTROLS}"
        ).split()
        target, source, options = fields[0], fields[1], fields[2]
        subvol = next(
            (o.split("=", 1)[1] for o in options.split(",") if o.startswith("subvol=")),
            "/",
        )
        device = source.split("[", 1)[0]
        return device, btrfs_scan.filesystem_path(subvol, target, CONTROLS)

    # --- the image -------------------------------------------------------

    def qmp(self, command: str, arguments: dict[str, Any] | None = None) -> Any:
        client = self.vm.qmp_client
        assert client is not None, "the QMP socket is not connected"
        reply = client.send(command, arguments or {})
        assert "return" in reply, f"QMP {command} failed: {reply}"
        return reply["return"]

    def image_disk(self, target: str) -> None:
        """Power the guest off, QEMU paused instead of exiting, and copy the
        paused disk whole into ``target``, sparse."""
        roots = [
            block
            for block in self.qmp("query-block")
            if block.get("inserted") and not block.get("removable", False)
        ]
        assert len(roots) == 1, f"cannot identify the root drive: {roots}"
        device = roots[0]["device"]
        size = roots[0]["inserted"]["image"]["virtual-size"]
        self.qmp("set-action", {"shutdown": "pause"})
        assert self.vm.shell is not None
        self.vm.shell.send(b"poweroff\n")
        self.vm.connected = False
        deadline = time.monotonic() + 600
        while self.qmp("query-status")["status"] != "shutdown":
            assert time.monotonic() < deadline, "the guest did not power off"
            time.sleep(1)
        full = target + ".full"
        with open(full, "wb") as handle:
            handle.truncate(size)
        self.qmp(
            "blockdev-add",
            {
                "driver": "raw",
                "node-name": "controls",
                "file": {"driver": "file", "filename": full},
            },
        )
        self.qmp(
            "blockdev-backup",
            {
                "job-id": "controls",
                "device": device,
                "target": "controls",
                "sync": "full",
                "auto-dismiss": False,
            },
        )
        deadline = time.monotonic() + 900
        while True:
            jobs = [job for job in self.qmp("query-jobs") if job["id"] == "controls"]
            assert jobs, "the backup job is gone"
            if jobs[0]["status"] == "concluded":
                break
            assert time.monotonic() < deadline, "the backup did not finish"
            time.sleep(1)
        assert "error" not in jobs[0], f"the backup failed: {jobs[0]}"
        self.qmp("job-dismiss", {"id": "controls"})
        self.qmp("blockdev-del", {"node-name": "controls"})
        subprocess.run([self.tools["cp"], "--sparse=always", full, target], check=True)
        os.remove(full)

    # --- the run ---------------------------------------------------------

    def run(self) -> None:
        vm = self.vm
        vm.wait_for_unit("multi-user.target")
        a, b, c = poison_token("A"), poison_token("B"), poison_token("C")
        work = tempfile.mkdtemp(prefix="gate-btrfs-")
        try:
            self.facts["root"] = vm.succeed(
                "findmnt -no SOURCE,FSTYPE,OPTIONS /"
            ).strip()
            self.facts["var"] = vm.succeed(
                "findmnt -no SOURCE,FSTYPE,OPTIONS /var"
            ).strip()
            self.plant()
            device, in_fs = self.where_on_root()
            self.facts["controls"] = {"device": device, "path": in_fs}
            vm.succeed("sync")
            live = self.live_tokens([a, b, c])
            self.facts["live"] = sorted(live)
            self.check(
                "the read through the kernel finds the plain control (a)", a in live
            )
            self.check(
                "the read through the kernel finds the compressed control (b)",
                b in live,
                sorted(live),
            )
            self.check(
                "the read through the kernel does not find the deleted control (c)",
                c not in live,
                sorted(live),
            )
            disk_dir = os.path.join(work, "disk")
            os.makedirs(disk_dir)
            raw = os.path.join(disk_dir, "disk.raw")
            self.image_disk(raw)
            found = btrfs_scan.tokens_in_tree(disk_dir, [a, b, c])
            self.facts["raw"] = sorted(found)
            self.check(
                "the raw scan finds the plain control (a)", a in found, sorted(found)
            )
            self.check(
                "the raw scan does not find the compressed control (b): btrfs "
                "stored it compressed",
                b not in found,
                sorted(found),
            )
            table = subprocess.run(
                [self.tools["sfdisk"], "--json", raw],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            number = btrfs_scan.partition_number(device)
            start, size = btrfs_scan.partition_extent(table, number)
            part = os.path.join(work, "root.btrfs")
            btrfs_scan.extract_partition(raw, start, size, part)
            os.remove(raw)
            self.facts["generation"] = btrfs_scan.read_generation(part)
            roots = btrfs_scan.find_roots(self.tools["btrfs-find-root"], part)
            self.facts["roots"] = [root.generation for root in roots]
            regex = btrfs_scan.path_filter([os.path.dirname(in_fs)], below=True)
            deleted = os.path.join(in_fs, "compressed", "c")
            older: set[str] = set()
            kept: set[str] = set()
            for root in roots[:ROOTS]:
                dest = tempfile.mkdtemp(prefix=f"root-{root.generation}-", dir=work)
                done = btrfs_scan.restore(
                    self.tools["btrfs"], part, dest, root=root.bytenr, regex=regex
                )
                here = btrfs_scan.tokens_in_tree(dest, [c])
                there = btrfs_scan.paths_in_tree(dest, [deleted])
                print(
                    f"gen {root.generation}: btrfs restore exited {done.returncode}, "
                    f"found {sorted(here) or 'nothing'}, paths {there or 'none'}"
                )
                older |= here
                kept |= set(there)
                shutil.rmtree(dest)
            self.check(
                "an older root of the tree keeps the deleted control (c) at its path",
                c in older and deleted in kept,
                {"tokens": sorted(older), "paths": sorted(kept)},
            )
        except Exception as error:  # noqa: BLE001 - recorded, then the run fails
            self.check("the run reaches its end", False, repr(error))
        finally:
            shutil.rmtree(work, ignore_errors=True)
            self.write()
        failed = [entry["name"] for entry in self.checks if not entry["passed"]]
        assert not failed, f"btrfs controls that do not hold: {failed}"

    def write(self) -> None:
        os.makedirs(self.out_dir, exist_ok=True)
        path = os.path.join(self.out_dir, f"{self.image}-btrfs.json")
        failed = [entry["name"] for entry in self.checks if not entry["passed"]]
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "image": self.image,
                    "passed": not failed,
                    "failed": failed,
                    "checks": self.checks,
                    "facts": self.facts,
                },
                handle,
                indent=1,
                sort_keys=True,
                default=str,
            )
        held = len(self.checks) - len(failed)
        print(
            f"=== the btrfs controls of {self.image}: {held} of {len(self.checks)} hold"
        )


def run(vm: Any, settings: dict[str, Any], tools: dict[str, str]) -> None:
    """Run the controls on ``vm``, with the host tools ``tools`` names."""
    out_dir = os.environ.get("NAILS_GATE_OUT") or os.getcwd()
    Controls(vm, settings, tools, out_dir).run()
