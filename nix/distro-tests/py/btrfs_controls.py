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
  path, and its contents (``btrfs_scan``: ``btrfs-find-root``, then ``btrfs
  restore -t``).

The read of the newest root must find (b) as well: that shows the history's
reader decompresses what the decoy's kernel compressed, so a deleted file it
does not find is not a file it could not read. Each compressed control fills
whole blocks, and all of them are written before one is deleted, so that no
control takes the blocks another freed. For every root that holds a control,
the run records what the restore wrote of it and what it said, and where the
extents of each deleted control lay, with the first bytes the image holds
there.

Fedora mounts its btrfs with ``discard=async`` where the disk takes discards,
as the VM's disk does: once a deleted file's blocks are free, the kernel
discards them. So the file (c) is deleted with discard turned off (a remount
with ``nodiscard``), as on a disk that takes no discard, the case where the
history keeps the most. A fourth file, deleted before that remount with the
image's own ``discard=async``, shows what such a deletion leaves: the run
records which older roots keep its path and whether any keeps its contents,
and asserts nothing of it.

The decoy is the stock image made amnesic as NAILS requires it, before the
controls are planted: its journal volatile and auditd off. No NAILS runs here.
The disk is imaged whole twice, each image a QMP backup of the paused disk.
The first is taken right after the deletion, the guest paused for the copy, as
a machine that loses its power leaves its disk, and every assertion is judged
on it. The second is taken at the guest's power-off, as the oracle images
driver takes the oracle's images, and is recorded only: earlier runs found
the blocks of the deleted control taken again before such an image, by the
stock image's persistent journal and, on the amnesic decoy, by small files
whose first bytes read as NetworkManager's state and timestamps files. The driver writes ``<image>-btrfs.json``, every
assertion with its outcome, into the directory ``NAILS_GATE_OUT`` names, and
fails when one does not hold.
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

# The controls' folder on the decoy: /var/tmp, on the var subvolume, and the
# mount it is on.
CONTROLS = "/var/tmp/scan-controls"
CONTROLS_MOUNT = "/var"
# How many older roots the history reads, newest first.
ROOTS = 64
# The size of each compressed control: two extents of 128 KiB.
POISON_BYTES = 256 * 1024
# The size of a block of the decoy's btrfs.
BLOCK = 4096
# The first bytes of a zstd frame, as each compressed extent of the decoy's
# btrfs starts.
ZSTD_MAGIC = "28b52ffd"
# What NAILS requires of the decoy before a session: journald keeps its journal
# in RAM, and auditd does not run.
AMNESIC = (
    "mkdir -p /etc/systemd/journald.conf.d && "
    "printf '[Journal]\\nStorage=volatile\\n' "
    "> /etc/systemd/journald.conf.d/50-volatile.conf && "
    "systemctl restart systemd-journald && "
    "systemctl disable auditd.service; systemctl mask auditd.service; "
    "auditctl --signal stop; "
    "for i in $(seq 30); do pgrep -x auditd >/dev/null || break; sleep 1; done; "
    "{ journalctl --header 2>/dev/null || true; } | grep -m1 '^File path' || true; "
    "pgrep -x auditd || echo auditd gone"
)


def poison_unit(name: str) -> str:
    """The 15-byte unit a poison repeats."""
    return f"NAILS-POISON-{name}-"


def poison_token(name: str) -> str:
    """What the scans look for: four units in a row. btrfs's zstd stores a run
    of the unit as one copy and a back-reference, so the token is on the disk
    in plain bytes only where the file is stored plain."""
    return poison_unit(name) * 4


def encoded_extents(filefrag: str) -> list[int]:
    """The byte addresses in the filesystem of the extents ``filefrag -v``
    lists, each a btrfs logical address."""
    found = []
    for line in filefrag.splitlines():
        fields = line.replace("..", " ").replace(":", " ").split()
        if len(fields) >= 5 and fields[0].isdigit() and fields[3].isdigit():
            found.append(int(fields[3]) * BLOCK)
    return found


def restore_messages(done: subprocess.CompletedProcess[str]) -> list[str]:
    """What btrfs restore said, without its prompts, at most twenty lines."""
    lines = [
        line.strip()
        for line in (done.stdout + "\n" + done.stderr).splitlines()
        if line.strip() and "do you want to keep going on" not in line
    ]
    return lines[:20]


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
        # (b), (c) and the discarded one: 256 KiB each, two compressed
        # extents of whole blocks, all written before either is deleted, so
        # that neither deleted file's blocks are taken by another control.
        self.write_poison("B", "b")
        self.write_poison("D", "d")
        self.write_poison("C", "c")
        self.commits()
        for control in ("c", "d"):
            self.facts[f"{control}-extents"] = vm.succeed(
                f"filefrag -v {CONTROLS}/compressed/{control} 2>&1 || true"
            )
        # Deleted with the image's own discard=async: recorded only.
        vm.succeed(f"rm {CONTROLS}/compressed/d && sync")
        self.commits()
        # Async discard runs in the background: wait until the filesystem has
        # no extent left to discard, or three minutes.
        self.facts["discard-wait"] = vm.succeed(
            f"uuid=$(findmnt -no UUID -T {CONTROLS}); "
            "stats=/sys/fs/btrfs/$uuid/discard; "
            "for i in $(seq 180); do "
            '[ "$(cat $stats/discardable_extents 2>/dev/null || echo 0)" = 0 ] '
            "&& break; sleep 1; done; "
            'echo "after ${i}s: $(cat $stats/discardable_extents 2>/dev/null) '
            'extents, $(cat $stats/discardable_bytes 2>/dev/null) bytes left"'
        )
        self.facts["discard"] = vm.succeed(
            f"findmnt -no OPTIONS -T {CONTROLS}; "
            f"mount -o remount,nodiscard {CONTROLS_MOUNT} && "
            f"findmnt -no OPTIONS -T {CONTROLS}"
        )
        # (c): deleted with discard off.
        vm.succeed(f"rm {CONTROLS}/compressed/c && sync")
        self.facts["listing"] = vm.succeed(
            f"ls -la {CONTROLS}/plain {CONTROLS}/compressed; "
            f"compsize {CONTROLS} 2>/dev/null || true"
        )

    def write_poison(self, name: str, file: str) -> None:
        """256 KiB of the unit, which fill two compressed extents of whole
        blocks."""
        path = f"{CONTROLS}/compressed/{file}"
        self.vm.succeed(
            f"printf '{poison_unit(name)}%.0s' $(seq 17477) > {path} && "
            f"truncate -s {POISON_BYTES} {path}"
        )

    def commits(self) -> None:
        """A few commits of the filesystem, so that older roots of the tree
        hold what was written before them."""
        for tick in range(3):
            self.vm.succeed(f"echo {tick} > {CONTROLS}/tick && sync")

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

    def image_disk(self, target: str, power_off: bool) -> None:
        """Copy the guest's disk whole into ``target``, sparse: with
        ``power_off``, once the guest has powered off, QEMU paused instead of
        exiting, as the oracle images are taken; otherwise from the running
        guest paused for the copy, as a machine that loses its power leaves
        its disk, and the guest goes on after it."""
        roots = [
            block
            for block in self.qmp("query-block")
            if block.get("inserted") and not block.get("removable", False)
        ]
        assert len(roots) == 1, f"cannot identify the root drive: {roots}"
        device = roots[0]["device"]
        size = roots[0]["inserted"]["image"]["virtual-size"]
        if power_off:
            self.qmp("set-action", {"shutdown": "pause"})
            assert self.vm.shell is not None
            self.vm.shell.send(b"poweroff\n")
            self.vm.connected = False
            wanted = "shutdown"
        else:
            self.qmp("stop")
            wanted = "paused"
        deadline = time.monotonic() + 600
        while self.qmp("query-status")["status"] != wanted:
            assert time.monotonic() < deadline, f"the guest is not {wanted}"
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
        if not power_off:
            self.qmp("cont")
        subprocess.run([self.tools["cp"], "--sparse=always", full, target], check=True)
        os.remove(full)

    def read_image(
        self, work: str, label: str, device: str, in_fs: str, power_off: bool
    ) -> dict[str, Any]:
        """Image the disk (``image_disk``), scan it raw for every token, and
        read up to ``ROOTS`` roots of its tree with btrfs restore, newest
        first: what each found, kept under ``label`` in the facts too."""
        tokens = {name: poison_token(name) for name in "ABCD"}
        disk_dir = os.path.join(work, label)
        os.makedirs(disk_dir)
        raw = os.path.join(disk_dir, "disk.raw")
        self.image_disk(raw, power_off)
        found = btrfs_scan.tokens_in_tree(disk_dir, list(tokens.values()))
        table = subprocess.run(
            [self.tools["sfdisk"], "--json", raw],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        number = btrfs_scan.partition_number(device)
        start, size = btrfs_scan.partition_extent(table, number)
        part = os.path.join(work, f"{label}.btrfs")
        btrfs_scan.extract_partition(raw, start, size, part)
        os.remove(raw)
        roots = btrfs_scan.find_roots(self.tools["btrfs-find-root"], part)
        regex = btrfs_scan.path_filter([os.path.dirname(in_fs)], below=True)
        paths = {
            name: os.path.join(in_fs, "compressed", name.lower()) for name in "BCD"
        }
        result: dict[str, Any] = {
            "raw": sorted(found),
            "generation": btrfs_scan.read_generation(part),
            "roots": [root.generation for root in roots],
            "extents": {
                control: self.extent_heads(part, control) for control in ("c", "d")
            },
            "newest": [],
            "older": [],
            "kept": [],
            "reads": [],
        }
        older: set[str] = set()
        kept: set[str] = set()
        for index, root in enumerate(roots[:ROOTS]):
            dest = tempfile.mkdtemp(prefix=f"{label}-{root.generation}-", dir=work)
            done = btrfs_scan.restore(
                self.tools["btrfs"], part, dest, root=root.bytenr, regex=regex
            )
            wanted = [tokens["B"], tokens["C"], tokens["D"]]
            here = btrfs_scan.tokens_in_tree(dest, wanted)
            there = btrfs_scan.paths_in_tree(dest, list(paths.values()))
            print(
                f"{label} gen {root.generation}: btrfs restore exited "
                f"{done.returncode}, found {sorted(here) or 'nothing'}, paths "
                f"{there or 'none'}"
            )
            if index == 0:
                result["newest"] = sorted(here)
            if index == 0 or set(there) - {paths["B"]}:
                result["reads"].append(
                    {
                        "generation": root.generation,
                        "exit": done.returncode,
                        "tokens": sorted(here),
                        "sizes": {
                            path: os.lstat(os.path.join(dest, path.lstrip("/"))).st_size
                            for path in there
                        },
                        "messages": restore_messages(done),
                    }
                )
            older |= here - {tokens["B"]}
            kept |= set(there) - {paths["B"]}
            shutil.rmtree(dest)
        os.remove(part)
        result["older"] = sorted(older)
        result["kept"] = sorted(kept)
        self.facts[label] = result
        return result

    def extent_heads(self, part: str, control: str) -> list[dict[str, Any]]:
        """For each extent of the deleted ``control`` the guest listed, the
        first bytes the image holds at its address: a zstd frame
        (``ZSTD_MAGIC``) while the extent was neither discarded nor reused."""
        heads = []
        listing = str(self.facts.get(f"{control}-extents", ""))
        for logical in encoded_extents(listing):
            with tempfile.NamedTemporaryFile() as out:
                done = subprocess.run(
                    [
                        self.tools["btrfs-map-logical"],
                        "-l",
                        str(logical),
                        "-b",
                        str(BLOCK),
                        "-o",
                        out.name,
                        part,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                data = out.read(BLOCK)
            heads.append(
                {
                    "logical": logical,
                    "exit": done.returncode,
                    "head": data[:8].hex(),
                    "zstd": data[:4].hex() == ZSTD_MAGIC,
                    "zeros": bool(data) and not data.strip(b"\0"),
                    "said": done.stdout.strip()[-300:] + done.stderr.strip()[-300:],
                }
            )
        return heads

    # --- the run ---------------------------------------------------------

    def run(self) -> None:
        vm = self.vm
        vm.wait_for_unit("multi-user.target")
        a, b, c = poison_token("A"), poison_token("B"), poison_token("C")
        d = poison_token("D")
        work = tempfile.mkdtemp(prefix="gate-btrfs-")
        try:
            self.facts["amnesic"] = vm.succeed(AMNESIC)
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
            live = self.live_tokens([a, b, c, d])
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
                c not in live and d not in live,
                sorted(live),
            )
            deleted = os.path.join(in_fs, "compressed", "c")
            discarded = os.path.join(in_fs, "compressed", "d")
            # The disk as the guest left it right after the deletion, the
            # guest paused for the copy: what the history keeps before
            # anything else is written.
            paused = self.read_image(work, "paused", device, in_fs, False)
            self.check(
                "the raw scan finds the plain control (a)",
                a in paused["raw"],
                paused["raw"],
            )
            self.check(
                "the raw scan does not find the compressed control (b): btrfs "
                "stored it compressed",
                b not in paused["raw"],
                paused["raw"],
            )
            self.check(
                "the read of the newest root finds the compressed control (b): the "
                "history's reader decompresses what the decoy's kernel compressed",
                b in paused["newest"],
                paused["newest"],
            )
            self.check(
                "an older root of the tree keeps the deleted control (c) at its "
                "path, with its contents",
                c in paused["older"] and deleted in paused["kept"],
                {"tokens": paused["older"], "paths": paused["kept"]},
            )
            # The disk at the guest's power-off, as the oracle images are
            # taken: recorded only, with what the shutdown wrote.
            off = self.read_image(work, "powered-off", device, in_fs, True)
            self.facts["after-power-off"] = {
                "rawFindsPlain": a in off["raw"],
                "rawFindsCompressed": b in off["raw"],
                "deletedPathInAnOlderRoot": deleted in off["kept"],
                "deletedContentsInAnOlderRoot": c in off["older"],
            }
            self.facts["discarded-file"] = {
                "pathInAnOlderRoot": discarded in paused["kept"],
                "contentsInAnOlderRoot": d in paused["older"],
                "pathAfterPowerOff": discarded in off["kept"],
                "contentsAfterPowerOff": d in off["older"],
            }
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
