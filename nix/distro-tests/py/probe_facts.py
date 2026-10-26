"""The distribution probe's queries, and the fixture record made of their output.

A probe (``nix/distro-tests/probe.nix``) boots the stock cloud image of a family
the smoke suite does not admit yet, without NAILS, and runs the queries listed
here in the guest: :func:`cold_boot_queries` on the plain boot, then one plain
``systemctl soft-reboot``, then :func:`soft_reboot_queries`. It keeps each
query's output under the query's label, and :func:`record` turns those outputs
into the record a ``nix/distro-tests/probe/<probe>.json`` fixture holds. With
the queries and their reading in one module of pure functions with a unit-test
suite, a fixture holds what the run printed, read the same way on every run,
and the ``distro-checks`` flake check locks the reading without a VM.

Nothing here imports Nix or the test driver, so it runs under a plain
``python3 -m unittest``. The probe loads it on the driver the way the smoke
scenario loads ``distro_checks`` (a ``sys.path`` entry plus an import).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

# The programs the NAILS sources name. The probe resolves each with
# ``type -P``, which searches PATH even for a name the shell has as a builtin
# (kill).
TOOLS = (
    "systemctl",
    "loginctl",
    "busctl",
    "journalctl",
    "dmsetup",
    "ip",
    "iw",
    "nft",
    "cryptsetup",
    "veracrypt",
    "tcplay",
    "sh",
    "mount",
    "notify-send",
    "nix",
    "sync",
    "swapoff",
    "kill",
    "systemd-run",
    "modprobe",
    "cp",
    "chown",
)

# The services the decoy-posture checks judge on Fedora: the audit daemon, the
# tuning daemon, the firewall and the crash reporter.
SERVICES = ("auditd", "tuned", "firewalld", "abrtd")

# The Fedora packages that ship them, as ``rpm -q`` names them.
RPM_PACKAGES = ("audit", "tuned", "firewalld", "abrt")

# The paths whose SELinux label the probe reads before and after the
# soft-reboot: the root a session replaces and the runtime tree it keeps.
LABELLED_PATHS = ("/", "/run", "/run/systemd")

# The directories systemd's generators write their units into (the fstab and
# gpt-auto mount, swap and automount units among them), each with the label of
# the query that lists it.
GENERATOR_DIRS = {
    "/run/systemd/generator": "generator",
    "/run/systemd/generator.late": "generator-late",
}

# Every mount, swap and automount unit systemd knows, whatever its state.
_MOUNT_UNITS = (
    "systemctl list-units --all --type=mount,swap,automount "
    "--no-legend --plain --full"
)

# The file each of those units was loaded from, and the file it was generated
# from. The unit name is printed first, because `systemctl show` would name a
# unit by its primary name rather than the one listed, and passed after `--`,
# because the root's unit, `-.mount`, would otherwise read as an option.
_MOUNT_UNIT_SOURCES = (
    _MOUNT_UNITS + " | while read -r u _; do "
    'echo "Unit=$u"; systemctl show -p FragmentPath -p SourcePath -- "$u"; done'
)

# Each service's unit-file state and active state, one labelled line each, so a
# missing unit answers on its own line instead of ending the list.
_SERVICES = (
    "for u in " + " ".join(SERVICES) + "; do "
    'echo "$u is-enabled: $(systemctl is-enabled $u.service 2>&1 | head -n 1)"; '
    'echo "$u is-active: $(systemctl is-active $u.service 2>&1 | head -n 1)"; done'
)

# The shell's own context, which is the domain the backdoor unit runs in, since
# every query runs in the backdoor's root shell (its arguments do not name the
# unit, so a process grep cannot find it), and the harness's two units.
_BACKDOOR = (
    "cat /proc/self/attr/current; echo; "
    "systemctl show backdoor.service mount-store.service -p Id -p ExecStart"
)

# Whether the harness's 9p store share is mounted and a file reads through it.
# A virtio 9p channel takes one mount only, so the share cannot be mounted a
# second time to test it; the enforcing variant answers whether it mounts and
# reads under enforcing.
_NINEP = (
    "findmnt -t 9p; f=$(find /nix/.ro-store -maxdepth 3 -type f -print -quit); "
    'if [ -n "$f" ] && head -c 64 "$f" >/dev/null; then echo read-ok; '
    "else echo read-failed; fi"
)

# The SELinux labels, policy loads and denials, read once at the end of the
# plain boot and again after the soft-reboot. The kernel log holds every policy
# load of this kernel's life, which a soft-reboot keeps, and PID 1 loads the
# policy again when it starts after one. Denials come from the kernel log and
# from the audit log, since auditd takes them off the kernel log while it runs;
# USER_AVC records are the denials of systemd and dbus-broker.
_LABELS = "ls -Zd " + " ".join(LABELLED_PATHS)
_POLICY = "dmesg | grep -F 'SELinux policy'"
_AVCS = "journalctl -k -b | grep -F 'avc:  denied'; ausearch -m avc,user_avc"

_FAILED_UNITS = "systemctl --failed --no-legend --plain"

# Run once, right before the soft-reboot. From the stop of auditd on the way
# down to its start after the soft-reboot, the kernel log is the only record of
# a denial: the kernel holds no record for an audit daemon that is not there
# (the images boot without audit=1). The units stopping on the way down fill
# the rate limit of that log within the same seconds, so the limit is lifted
# for the rest of the probe, or a denial of the soft-reboot could be dropped
# unseen.
BEFORE_SOFT_REBOOT = "echo 0 > /proc/sys/kernel/printk_ratelimit"

Query = tuple[str, str]


def cold_boot_queries(os_id: str) -> list[Query]:
    """The ``(label, command)`` queries of the plain boot, in the order run.

    The label, policy and denial queries come last, right before the
    soft-reboot, so that what :func:`soft_reboot_queries` reads beyond them
    happened at or after the soft-reboot. ``rpm`` is queried on Fedora only.
    """
    queries: list[Query] = [
        ("os-release", "cat /etc/os-release"),
        ("selinux", "getenforce; sestatus"),
        ("backdoor", _BACKDOOR),
        ("kernel", "uname -r"),
        ("modules", "ls -1 /usr/lib/modules"),
        ("mounts", "findmnt --real -rn -o TARGET,FSTYPE,OPTIONS"),
        ("fstab", "cat /etc/fstab"),
        ("swaps", "swapon --show=NAME,TYPE,SIZE,PRIO --noheadings --raw --bytes"),
        ("mount-units", _MOUNT_UNITS),
        ("mount-unit-sources", _MOUNT_UNIT_SOURCES),
    ]
    queries += [(label, f"ls -1A {path}") for path, label in GENERATOR_DIRS.items()]
    queries += [
        (
            "tools",
            "for t in " + " ".join(TOOLS) + "; do echo $t: $(type -P $t); done",
        ),
        ("services", _SERVICES),
        (
            "auditd-unit",
            "systemctl show auditd.service -p LoadState -p RefuseManualStop",
        ),
    ]
    if os_id == "fedora":
        queries.append(("rpm", "rpm -q " + " ".join(RPM_PACKAGES)))
    queries += [
        # The effective configuration with the file each part comes from, and
        # where the journal is actually written.
        (
            "journald",
            "systemd-analyze cat-config systemd/journald.conf "
            "| grep -E '^# /|Storage'; ls -d /var/log/journal /run/log/journal",
        ),
        ("failed-units", _FAILED_UNITS),
        # Every masked unit: the test harness masks some, and a unit it masks
        # can never show up as failed.
        ("masked-units", "systemctl list-unit-files --state=masked --no-legend"),
        (
            "updatedb-prune",
            "grep -hs PRUNEPATHS /etc/updatedb.conf /usr/lib/updatedb.conf; "
            "for t in updatedb plocate locate; do echo $t: $(type -P $t); done",
        ),
        ("ninep", _NINEP),
        ("selinux-labels", _LABELS),
        ("selinux-policy", _POLICY),
        ("avcs", _AVCS),
    ]
    return queries


def soft_reboot_queries() -> list[Query]:
    """The ``(label, command)`` queries after the plain soft-reboot."""
    return [
        ("soft-reboot-failed-units", _FAILED_UNITS),
        (
            "soft-reboot-boot-id",
            "cat /proc/sys/kernel/random/boot_id; "
            "systemctl show -p SoftRebootsCount --value",
        ),
        ("soft-reboot-selinux-labels", _LABELS),
        ("soft-reboot-selinux-policy", _POLICY),
        ("soft-reboot-avcs", _AVCS),
    ]


def probe_name(image: str, enforcing: bool) -> str:
    """The probe's name, which names its fixture: the image key, plus
    ``-enforcing`` for a Fedora image booted with SELinux enforcing."""
    return f"{image}-enforcing" if enforcing else image


_UNIT = re.compile(
    r"\S+\.(service|socket|device|mount|automount|swap|target|path|timer|slice|scope)"
)
_HEX_ESCAPE = re.compile(rb"\\x([0-9a-fA-F]{2})")
_MODES = ("enforcing", "permissive", "disabled")
_CONTEXT = re.compile(r"([^:\s]+):([^:\s]+):([^:\s]+)(:\S*)?")
_DMESG = re.compile(r"\[\s*\d+\.\d+\]\s*(.*)")
# The time a policy load took, which PID 1 appends and which differs from run
# to run.
_LOAD_TIME = re.compile(r" in \d[\w. ]*\.$")
_AVC_EVENT = re.compile(r"audit\((\d+\.\d+:\d+)\)")
# A kernel release as ``uname -r`` prints it: 6.19.10-300.fc44.x86_64.
_RELEASE = re.compile(r"\d+\.\d+\S*")
_SERVICE_LINE = re.compile(r"(\S+) (is-enabled|is-active):\s*(.*)")
_PRUNEPATHS = re.compile(r'PRUNEPATHS\s*=\s*"([^"]*)"')
_HEADER = re.compile(r"# (/\S+)")
_STORAGE = re.compile(r"Storage\s*=\s*(\S*)")
_DOCUMENTED_STORAGE = re.compile(r"#\s*Storage\s*=\s*(\S*)")


def _lines(text: str | None) -> list[str]:
    """The non-blank lines of a query's output, stripped. A NUL byte, which
    ends an attribute read from /proc, is dropped."""
    out = (text or "").replace("\x00", "")
    return [line.strip() for line in out.splitlines() if line.strip()]


def _unescape(text: str) -> str:
    r"""Decode the ``\xNN`` byte escapes of findmnt, swapon and unit names."""
    raw = _HEX_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), text.encode())
    return raw.decode("utf-8", errors="replace")


def _number(text: str) -> int | str:
    """An integer field as an int, or the text as printed if it is none."""
    return int(text) if re.fullmatch(r"-?\d+", text) else text


def _properties(text: str | None) -> dict[str, str]:
    """``KEY=value`` lines, as ``systemctl show`` prints them."""
    values: dict[str, str] = {}
    for line in _lines(text):
        key, sep, value = line.partition("=")
        if sep:
            values[key] = value
    return values


def _listing(text: str | None) -> list[str] | None:
    """The names an ``ls -1`` printed, sorted (ls sorts by the guest's locale),
    or None when it could not list the directory (or did not run)."""
    if text is None:
        return None
    lines = _lines(text)
    if any(line.startswith("ls: ") for line in lines):
        return None
    return sorted(lines)


def _harness(path: str) -> bool:
    """Whether a path belongs to the test harness, not to the image: the
    harness mounts the host's Nix store at /nix (a 9p share, a tmpfs and an
    overlay over them)."""
    return path == "/nix" or path.startswith("/nix/")


def unit_path(unit: str) -> str:
    """The path a mount, swap or automount unit's name stands for (the reverse
    of systemd's path escaping): ``boot-efi.mount`` is ``/boot/efi``."""
    stem = unit.rsplit(".", 1)[0]
    if stem == "-":
        return "/"
    return "/" + "/".join(_unescape(part) for part in stem.split("-"))


def selinux_mode(text: str | None) -> str | None:
    """``getenforce``'s answer in lower case, or None without SELinux."""
    lines = _lines(text)
    if lines and lines[0].lower() in _MODES:
        return lines[0].lower()
    return None


def selinux_type(text: str | None) -> str | None:
    """The type of the context the first line of ``text`` holds, or None when
    it holds none (a kernel without SELinux refuses the read)."""
    lines = _lines(text)
    if not lines:
        return None
    match = _CONTEXT.fullmatch(lines[0].split()[0])
    return match.group(3) if match else None


def selinux_labels(text: str | None) -> dict[str, str | None]:
    """Each of :data:`LABELLED_PATHS` mapped to its label (``ls -Zd``), or to
    None where ``ls`` printed none."""
    found: dict[str, str | None] = {}
    for line in _lines(text):
        label, _, path = line.partition(" ")
        path = path.strip()
        if path in LABELLED_PATHS:
            found[path] = None if label == "?" else label
    return {path: found.get(path) for path in LABELLED_PATHS}


def policy_loads(text: str | None) -> list[tuple[str, str]]:
    """The SELinux policy lines of the kernel log, as ``(line, message)``: the
    line as dmesg printed it, timestamp included, and the message without the
    timestamp and without the time the load took."""
    loads: list[tuple[str, str]] = []
    for line in _lines(text):
        match = _DMESG.fullmatch(line)
        message = match.group(1) if match else line
        if "SELinux policy" in message:
            loads.append((line, _LOAD_TIME.sub(".", message)))
    return loads


def avc_events(text: str | None) -> list[tuple[str | None, str]]:
    """The denials in ``text``, as ``(event, denial)``, each event once.

    ``event`` is the audit event's ``stamp:serial`` and ``denial`` the record
    from ``avc:  denied`` on, without the enrichment auditd appends after a
    group separator, and without the quote that closes a USER_AVC message. The
    same denial reaches the kernel log and the audit log, so it is kept once;
    two denials of one event are both kept.
    """
    seen: set[tuple[str | None, str]] = set()
    events: list[tuple[str | None, str]] = []
    for line in _lines(text):
        start = line.find("avc:  denied")
        if start < 0:
            continue
        denial = line[start:].split("\x1d", 1)[0].rstrip().rstrip("'").rstrip()
        match = _AVC_EVENT.search(line)
        key = (match.group(1) if match else None, denial)
        if key not in seen:
            seen.add(key)
            events.append(key)
    return events


def parse_mounts(text: str | None) -> list[dict[str, str]]:
    """``findmnt --real -rn -o TARGET,FSTYPE,OPTIONS`` as a list of mounts,
    sorted by target (findmnt lists them in the order they were mounted, which
    differs between boots), without the harness's own."""
    mounts: list[dict[str, str]] = []
    for line in _lines(text):
        fields = line.split()
        if len(fields) not in (2, 3) or not fields[0].startswith("/"):
            continue
        target = _unescape(fields[0])
        if _harness(target):
            continue
        options = fields[2] if len(fields) == 3 else ""
        mounts.append({"target": target, "fstype": fields[1], "options": options})
    return sorted(mounts, key=lambda mount: mount["target"])


def parse_fstab(text: str | None) -> list[dict[str, Any]] | None:
    """The entries of ``/etc/fstab`` in file order, or None when the image has
    none. A missing options, dump or pass field takes fstab(5)'s default."""
    if text is None or "No such file or directory" in text:
        return None
    entries: list[dict[str, Any]] = []
    for line in _lines(text):
        if line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 3:
            continue
        entries.append(
            {
                "source": fields[0],
                "target": fields[1],
                "fstype": fields[2],
                "options": fields[3] if len(fields) > 3 else "defaults",
                "dump": _number(fields[4]) if len(fields) > 4 else 0,
                "pass": _number(fields[5]) if len(fields) > 5 else 0,
            }
        )
    return entries


def parse_swaps(text: str | None) -> list[dict[str, Any]]:
    """The active swap areas (``swapon --show``), with size in bytes."""
    swaps: list[dict[str, Any]] = []
    for line in _lines(text):
        fields = line.split()
        if len(fields) != 4 or not fields[0].startswith("/"):
            continue
        swaps.append(
            {
                "name": _unescape(fields[0]),
                "type": fields[1],
                "size": _number(fields[2]),
                "priority": _number(fields[3]),
            }
        )
    return swaps


def _unit_sources(text: str | None) -> dict[str, dict[str, str]]:
    """The ``Unit=`` blocks of the unit-source query, by unit name."""
    sources: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in _lines(text):
        key, sep, value = line.partition("=")
        if not sep:
            continue
        if key == "Unit":
            current = sources.setdefault(value, {})
        elif current is not None:
            current[key] = value
    return sources


def parse_mount_units(
    listing: str | None, sources: str | None
) -> list[dict[str, str | None]]:
    """The mount, swap and automount units in ``systemctl list-units`` order,
    with their states and the file each was loaded and generated from (None
    where systemd names none), without the harness's own."""
    origin = _unit_sources(sources)
    units: list[dict[str, str | None]] = []
    for line in _lines(listing):
        fields = line.split(None, 4)
        if len(fields) < 4 or not _UNIT.fullmatch(fields[0]):
            continue
        unit = fields[0]
        if _harness(unit_path(unit)):
            continue
        where = origin.get(unit, {})
        units.append(
            {
                "unit": unit,
                "load": fields[1],
                "active": fields[2],
                "sub": fields[3],
                "fragmentPath": where.get("FragmentPath") or None,
                "sourcePath": where.get("SourcePath") or None,
            }
        )
    return units


def parse_tools(text: str | None) -> dict[str, str]:
    """Each of :data:`TOOLS` the image has, mapped to its path."""
    tools: dict[str, str] = {}
    for line in _lines(text):
        name, sep, path = line.partition(":")
        path = path.strip()
        if sep and name in TOOLS and path.startswith("/"):
            tools[name] = path
    return tools


def _unit_state(service: str, answer: str) -> str | None:
    """One ``systemctl is-enabled`` or ``is-active`` answer for ``service``.

    A unit the image does not have is ``not-found``, as systemctl names it, or
    as an older systemctl fails on its unit file. Any other answer is kept as
    printed, so that a query that failed (no bus, say) reads as its error and
    never as a unit that is not there.
    """
    answer = answer.strip()
    if not answer:
        return None
    missing = (
        f"Failed to get unit file state for {service}.service: "
        "No such file or directory"
    )
    if answer == missing:
        return "not-found"
    return answer


def parse_services(text: str | None) -> dict[str, dict[str, str | None]]:
    """Each of :data:`SERVICES` mapped to its ``enabled`` (unit-file) state and
    ``active`` state; None where the query printed nothing."""
    states: dict[str, dict[str, str | None]] = {
        name: {"enabled": None, "active": None} for name in SERVICES
    }
    for line in _lines(text):
        match = _SERVICE_LINE.fullmatch(line)
        if match is None or match.group(1) not in states:
            continue
        key = "enabled" if match.group(2) == "is-enabled" else "active"
        states[match.group(1)][key] = _unit_state(match.group(1), match.group(3))
    return states


def refuse_manual_stop(text: str | None) -> bool | None:
    """auditd's ``RefuseManualStop``, or None when its unit is not loaded (a
    unit that is not loaded reports the default, which says nothing)."""
    values = _properties(text)
    if values.get("LoadState") != "loaded":
        return None
    return {"yes": True, "no": False}.get(values.get("RefuseManualStop", ""))


def parse_rpm(text: str | None) -> dict[str, str | None]:
    """Each of :data:`RPM_PACKAGES` mapped to its installed name-version-release
    (``rpm -q``), or None when rpm answers that it is not installed.

    A package rpm gives neither answer for holds what the query printed (an
    error, such as a missing rpm), so that a query that failed never reads as
    a package that is absent. Empty when the query has not run.
    """
    lines = _lines(text)
    if not lines:
        return {}
    found: dict[str, str | None] = {}
    for line in lines:
        for name in RPM_PACKAGES:
            if re.fullmatch(re.escape(name) + r"-\d\S*", line):
                found[name] = line
            elif line == f"package {name} is not installed":
                found.setdefault(name, None)
    printed = "\n".join(lines)
    return {name: found.get(name, printed) for name in RPM_PACKAGES}


def parse_journald(text: str | None) -> dict[str, Any]:
    """The effective ``Storage=`` and the files that set it.

    ``systemd-analyze cat-config`` prints each file after a ``# <path>`` line.
    The last ``Storage=`` that is set wins; when no file sets it, the value the
    vendor file documents in its commented-out line is the compiled-in default,
    and ``sources`` is empty.
    """
    current: str | None = None
    set_by: list[tuple[str | None, str]] = []
    documented: str | None = None
    for line in _lines(text):
        header = _HEADER.fullmatch(line)
        if header:
            current = header.group(1)
            continue
        setting = _STORAGE.fullmatch(line)
        if setting:
            set_by.append((current, setting.group(1)))
            continue
        comment = _DOCUMENTED_STORAGE.fullmatch(line)
        if comment and documented is None:
            documented = comment.group(1)
    if set_by:
        sources: list[str] = []
        for source, _ in set_by:
            if source is not None and source not in sources:
                sources.append(source)
        return {"storage": set_by[-1][1], "sources": sources}
    return {"storage": documented, "sources": []}


def unit_names(text: str | None) -> list[str]:
    """The unit names that lead the lines of a ``systemctl`` unit listing."""
    names: list[str] = []
    for line in _lines(text):
        fields = line.replace("●", " ").split()
        if fields and _UNIT.fullmatch(fields[0]):
            names.append(fields[0])
    return names


def prune_paths(text: str | None) -> list[str]:
    """The ``PRUNEPATHS`` the image's updatedb configuration ships, in order."""
    paths: list[str] = []
    for line in _lines(text):
        if line.startswith("#"):
            continue
        match = _PRUNEPATHS.search(line)
        if match:
            paths += [path for path in match.group(1).split() if path not in paths]
    return paths


def nine_p_reads(text: str | None) -> bool | None:
    """Whether the 9p share is mounted and a file reads through it."""
    lines = _lines(text)
    if not lines:
        return None
    mounted = any(line.split()[2:3] == ["9p"] for line in lines)
    return mounted and "read-ok" in lines


def parse_os_release(text: str | None) -> dict[str, str]:
    """``/etc/os-release`` as a mapping, quotes removed."""
    values: dict[str, str] = {}
    for line in _lines(text):
        if line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def derivative_os_release(text: str | None, os_id: str) -> dict[str, str]:
    """For an image whose ``ID`` is not the family's, the ``ID``, ``ID_LIKE``
    and ``VARIANT_ID`` it carries; empty for the family's own image."""
    values = parse_os_release(text)
    if not values or values.get("ID") == os_id:
        return {}
    keys = ("ID", "ID_LIKE", "VARIANT_ID")
    return {key: values[key] for key in keys if key in values}


def soft_reboots(text: str | None) -> int | None:
    """``SoftRebootsCount``, the last line of the boot-id query."""
    lines = _lines(text)
    if lines and lines[-1].isdigit():
        return int(lines[-1])
    return None


def facts(blocks: Mapping[str, str], os_id: str) -> dict[str, Any]:
    """The facts of one probe run, from its outputs by query label.

    A fact whose query did not run is null, or empty for a list or map. The
    SELinux facts are null on an image without SELinux, and
    ``ninePUnderEnforcing`` is null unless the image ran enforcing. What
    happened after the soft-reboot is what the queries after it read beyond the
    same queries at the end of the plain boot.
    """
    mode = selinux_mode(blocks.get("selinux"))
    has_selinux = mode in ("enforcing", "permissive")
    cold_avcs = avc_events(blocks.get("avcs"))
    after_avcs = avc_events(blocks.get("soft-reboot-avcs"))
    cold_loads = policy_loads(blocks.get("selinux-policy"))
    after_loads = policy_loads(blocks.get("soft-reboot-selinux-policy"))
    seen_avcs = set(cold_avcs)
    seen_loads = {line for line, _ in cold_loads}
    nine_p = nine_p_reads(blocks.get("ninep"))

    def when_selinux(value: Any) -> Any:
        return value if has_selinux else None

    return {
        "selinuxMode": mode,
        "selinuxBackdoorDomain": selinux_type(blocks.get("backdoor")),
        "selinuxLabels": when_selinux(selinux_labels(blocks.get("selinux-labels"))),
        "selinuxPolicyLoads": when_selinux([message for _, message in cold_loads]),
        "kernelRelease": next(iter(_lines(blocks.get("kernel"))), None),
        "moduleDirs": _listing(blocks.get("modules")),
        "mounts": parse_mounts(blocks.get("mounts")),
        "fstab": parse_fstab(blocks.get("fstab")),
        "swaps": parse_swaps(blocks.get("swaps")),
        "mountUnits": parse_mount_units(
            blocks.get("mount-units"), blocks.get("mount-unit-sources")
        ),
        "generatorUnits": {
            path: _listing(blocks.get(label))
            for path, label in GENERATOR_DIRS.items()
        },
        "tools": parse_tools(blocks.get("tools")),
        "services": parse_services(blocks.get("services")),
        "auditdRefuseManualStop": refuse_manual_stop(blocks.get("auditd-unit")),
        "packages": parse_rpm(blocks.get("rpm")) if os_id == "fedora" else None,
        "journaldVendorConfig": parse_journald(blocks.get("journald")),
        "failedBootUnits": unit_names(blocks.get("failed-units")),
        "maskedUnits": unit_names(blocks.get("masked-units")),
        "updatedbPrunePaths": prune_paths(blocks.get("updatedb-prune")),
        "avcs": [denial for _, denial in cold_avcs],
        "ninePUnderEnforcing": nine_p if mode == "enforcing" else None,
        "derivativeOsRelease": derivative_os_release(blocks.get("os-release"), os_id),
        "softRebootsCount": soft_reboots(blocks.get("soft-reboot-boot-id")),
        "failedUnitsAfterSoftReboot": unit_names(
            blocks.get("soft-reboot-failed-units")
        ),
        "avcsAfterSoftReboot": [
            denial for event, denial in after_avcs if (event, denial) not in seen_avcs
        ],
        "selinuxLabelsAfterSoftReboot": when_selinux(
            selinux_labels(blocks.get("soft-reboot-selinux-labels"))
        ),
        "selinuxPolicyLoadsAfterSoftReboot": when_selinux(
            [message for line, message in after_loads if line not in seen_loads]
        ),
    }


def complete(found: Mapping[str, Any]) -> bool:
    """Whether a run's facts hold the two that every run on a booted image
    reads: the kernel's release, and a ``SoftRebootsCount`` of 1 after the
    soft-reboot. A run without them read nothing it can be trusted for (its
    queries failed, or the soft-reboot never happened), so its record is not
    recorded.
    """
    release = found.get("kernelRelease")
    return (
        isinstance(release, str)
        and _RELEASE.fullmatch(release) is not None
        and found.get("softRebootsCount") == 1
    )


def record(
    blocks: Mapping[str, str],
    *,
    image: str,
    os_id: str,
    enforcing: bool,
    image_file: str | None,
) -> dict[str, Any]:
    """The fixture record of one probe run (see ``probe/README.md``).

    ``image`` is the image table key, ``enforcing`` whether SELinux was left
    enforcing, and ``image_file`` the name of the pinned image file the run
    booted, so a fixture says which pin its facts came from. ``recorded`` is
    whether the facts are :func:`complete`, so with no blocks the record is the
    placeholder of a probe that has not run.
    """
    found = facts(blocks, os_id)
    return {
        "image": image,
        "osId": os_id,
        "enforcing": enforcing,
        "imageFile": image_file,
        "recorded": complete(found),
        "facts": found,
    }


def dumps(document: Mapping[str, Any]) -> str:
    """A record (or the raw outputs) as the fixture files hold it."""
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
