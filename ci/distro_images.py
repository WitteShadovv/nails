"""Tend the distribution image table: schema, link health, and pin bumps.

The table is plain data in ``nix/distro-tests/images.json``; the flake turns it
into VM tests (nix/distro-tests/images.nix). This module is the other half of
the mirror seam: it validates the table, it is the weekly link check that fails
before a pinned upstream image is due to lapse or once its URL is gone (a staged
entry's as well as an enabled one's), and it bumps a pin to the latest upstream
build (an SHA256 the distribution publishes, converted to the
subresource-integrity form ``fetchurl`` expects -- the image itself is never
downloaded here).

Subcommands::

    python3 -m ci.distro_images check
    python3 -m ci.distro_images link-check [--date YYYY-MM-DD] [--offline]
    python3 -m ci.distro_images repin (--all | <name> ...)

``check`` and ``link-check`` are what CI runs; ``repin`` is the pin bump, run
from a networked host (or the scheduled lane) and committed as a one-line diff.

A ``nix-vm-test`` entry is a dated upstream URL as well: nix-vm-test pins it in
its own ``<distro>/images.json``, at the revision ``flake.lock`` locks, and the
upstream mirror can prune it like any other build. The link check reads that
list and probes the URL; a newer nix-vm-test lock is what repins such an entry.

A ``mirror`` entry is an image the project builds itself and publishes to the
assets repository that ``nix/distro-tests/mirrors.nix`` names (the archinstall
image). The link check probes the asset it pins there, and ``repin`` moves it
to the newest build, which the release's ``<family>-latest.json`` manifest
names.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import http.client
import json
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TABLE_PATH = REPO / "nix" / "distro-tests" / "images.json"
LOCK_PATH = REPO / "flake.lock"
MIRRORS_PATH = REPO / "nix" / "distro-tests" / "mirrors.nix"
# The pinned inputs of each image the project builds itself, by mirror family:
# the test-images workflow rebuilds it from them every night, so the link
# check probes them as well as the published asset.
BUILDER_INPUTS = {
    "arch-install": REPO / "nix" / "distro-tests" / "arch-install" / "inputs.json",
}

# The placeholder hash an entry carries until it is pinned for real. It is the
# well-known Nix "fake" SHA256, so an enabled entry that still has it is caught
# by the schema check and never reaches a VM build.
FAKE_HASH = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

KNOWN_OS_IDS = frozenset({"debian", "ubuntu", "fedora", "arch"})
KNOWN_PREPARE = frozenset({"nix-vm-test", "fedora", "archlinux"})
KNOWN_KINDS = frozenset({"nix-vm-test", "upstream", "mirror", "pending"})
KNOWN_FIRMWARE = frozenset({"bios", "uefi"})

# How far before an entry's upstreamUntil the link check starts failing, so
# there is time to repin before the image drops off its download mirror.
LEAD_DAYS = 14

# A plain User-Agent: the download mirrors serve automated clients, and the
# request must never carry anything that identifies who is running it.
USER_AGENT = "nails-distro-images/1"

FEDORA_RELEASES = "https://download.fedoraproject.org/pub/fedora/linux/releases"
ARCH_IMAGES = "https://geo.mirror.pkgbuild.com/images"

# Where a locked GitHub revision's files are served raw, and the system whose
# image a nix-vm-test pin names (the VM tests are x86_64-linux only).
RAW_GITHUB = "https://raw.githubusercontent.com"
NIX_VM_TEST_SYSTEM = "x86_64-linux"


class RepinError(Exception):
    """A pin could not be resolved from upstream."""


class LinkError(Exception):
    """The URL an entry pins could not be worked out."""


# --- mirror -------------------------------------------------------------------

# mirrors.nix keeps `base` and the shape of `tagFor` as plain strings, so that
# this module reads the same values the Nix side fetches from.
_MIRROR_BASE = re.compile(r'^\s*base = "(?P<base>[^"$]*)";', re.MULTILINE)
_MIRROR_TAG = re.compile(
    r'^\s*tagFor = family: "(?P<prefix>[^"$]*)\$\{family\}";', re.MULTILINE
)


@dataclass(frozen=True)
class Mirror:
    """The assets repository's download root and its per-family tag prefix."""

    base: str
    tag_prefix: str

    def configured(self) -> bool:
        return self.base != ""

    def url_for(self, family: str, asset: str) -> str:
        """The download URL of one asset, as mirrors.nix's urlFor builds it."""
        return f"{self.base}/{self.tag_prefix}{family}/{asset}"

    def latest_url(self, family: str) -> str:
        """The manifest of a family's newest build, beside its assets."""
        return self.url_for(family, f"{family}-latest.json")


def load_mirror(path: Path = MIRRORS_PATH) -> Mirror:
    """Read the mirror seam out of mirrors.nix."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise LinkError(f"cannot read {path.name}: {error}") from None
    base = _MIRROR_BASE.search(text)
    tag = _MIRROR_TAG.search(text)
    if base is None or tag is None:
        raise LinkError(
            f"{path.name} names no plain-string base and tagFor; see its header"
        )
    return Mirror(base=base.group("base").rstrip("/"), tag_prefix=tag.group("prefix"))


def load_table(path: Path = TABLE_PATH) -> dict[str, dict]:
    """Read the image table from JSON."""
    with path.open(encoding="utf-8") as handle:
        table = json.load(handle)
    if not isinstance(table, dict):
        raise ValueError(f"{path}: the image table must be a JSON object")
    return table


def sri_from_hex(hexdigest: str) -> str:
    """Convert an upstream hex SHA256 to the SRI form ``fetchurl`` wants."""
    raw = bytes.fromhex(hexdigest.strip())
    if len(raw) != 32:
        raise RepinError(f"not a SHA256 digest: {hexdigest!r}")
    return "sha256-" + base64.b64encode(raw).decode("ascii")


# --- schema -------------------------------------------------------------------

_FIELD_TYPES: dict[str, type] = {
    "osId": str,
    "release": str,
    "rootfs": str,
    "enforcing": bool,
    "memory": int,
    "enabled": bool,
    "prepare": str,
    "source": Mapping,
}


def _problems_for_entry(name: str, entry: object) -> list[str]:
    out: list[str] = []
    if not isinstance(entry, Mapping):
        return [f"{name}: entry must be an object"]
    for key, kind in _FIELD_TYPES.items():
        if key not in entry:
            out.append(f"{name}: missing {key!r}")
        elif not isinstance(entry[key], kind):
            out.append(f"{name}: {key} must be {kind.__name__}")
    if out:
        return out
    if entry["osId"] not in KNOWN_OS_IDS:
        out.append(f"{name}: unknown osId {entry['osId']!r}")
    if entry["prepare"] not in KNOWN_PREPARE:
        out.append(f"{name}: unknown prepare {entry['prepare']!r}")
    memory = entry["memory"]
    if isinstance(memory, bool) or memory <= 0:
        out.append(f"{name}: memory must be a positive integer")
    until = entry.get("upstreamUntil")
    if until is not None:
        try:
            datetime.date.fromisoformat(str(until))
        except ValueError:
            out.append(f"{name}: upstreamUntil must be null or YYYY-MM-DD")
    firmware = entry.get("firmware", "bios")
    if not isinstance(firmware, str) or firmware not in KNOWN_FIRMWARE:
        out.append(f"{name}: firmware must be \"bios\" or \"uefi\", not {firmware!r}")
    out.extend(_source_problems(name, entry, entry["source"]))
    out.extend(_known_failed_problems(name, entry.get("knownFailedUnits")))
    return out


# The optional ``knownFailedUnits`` of an entry: the units the smoke scenario
# must find failed in each phase, mapped to a line their failed start logs, and
# the units the release's warning names that the image does not install
# (nix/distro-tests/images.nix describes it and asserts the same shape).
KNOWN_FAILED_PHASES = ("hiddenSession", "afterReturn")
KNOWN_FAILED_KEYS = frozenset({*KNOWN_FAILED_PHASES, "notInImage"})

# A systemd unit name: no slash or space, and a unit type as its suffix. The
# space class is POSIX's [:space:], which images.nix matches with.
_UNIT_NAME = re.compile(
    r"[^/ \t\n\v\f\r]+\."
    r"(?:automount|device|mount|path|scope|service|slice|socket|swap|target|timer)"
)


def _is_unit_name(unit: object) -> bool:
    return isinstance(unit, str) and _UNIT_NAME.fullmatch(unit) is not None


def _known_failed_problems(name: str, known: object) -> list[str]:
    if known is None:
        return []
    if not isinstance(known, Mapping) or set(known) != KNOWN_FAILED_KEYS:
        return [
            f"{name}: knownFailedUnits must be null or have exactly the keys"
            " hiddenSession, afterReturn and notInImage"
        ]
    out: list[str] = []
    named: set[str] = set()
    for phase in KNOWN_FAILED_PHASES:
        units = known[phase]
        if not isinstance(units, Mapping):
            out.append(f"{name}: knownFailedUnits.{phase} must be an object")
            continue
        for unit, line in units.items():
            if not _is_unit_name(unit):
                out.append(
                    f"{name}: knownFailedUnits.{phase}: {unit!r} is not a unit name"
                )
            if not isinstance(line, str) or not line:
                out.append(
                    f"{name}: knownFailedUnits.{phase}.{unit} must be the non-empty"
                    " line its failed start logs"
                )
            named.add(unit)
    absent = known["notInImage"]
    if not isinstance(absent, list):
        return [*out, f"{name}: knownFailedUnits.notInImage must be a list"]
    for unit in absent:
        if not _is_unit_name(unit):
            out.append(
                f"{name}: knownFailedUnits.notInImage: {unit!r} is not a unit name"
            )
    both = sorted(named.intersection(unit for unit in absent if isinstance(unit, str)))
    if both:
        out.append(
            f"{name}: knownFailedUnits names {', '.join(both)}"
            " in notInImage and in a phase"
        )
    return out


def _source_problems(name: str, entry: Mapping, source: object) -> list[str]:
    out: list[str] = []
    if not isinstance(source, Mapping):
        return [f"{name}: source must be an object"]
    kind = source.get("kind")
    if kind not in KNOWN_KINDS:
        return [f"{name}: unknown source.kind {kind!r}"]
    if kind == "nix-vm-test":
        for field in ("distro", "image"):
            if not source.get(field):
                out.append(f"{name}: a nix-vm-test source needs {field!r}")
    elif kind == "upstream":
        for field in ("url", "name", "sha256"):
            if not source.get(field):
                out.append(f"{name}: an upstream source needs {field!r}")
    elif kind == "mirror":
        out.extend(_mirror_problems(name, entry, source))
    enabled = bool(entry.get("enabled"))
    if enabled and kind == "pending":
        out.append(f"{name}: a pending source cannot be enabled")
    if enabled and kind == "upstream" and source.get("sha256") == FAKE_HASH:
        out.append(f"{name}: still has the placeholder hash; repin before enabling")
    return out


def _is_asset_name(asset: object) -> bool:
    return (
        isinstance(asset, str)
        and asset not in ("", ".", "..")
        and "/" not in asset
        and not any(char.isspace() for char in asset)
    )


def _mirror_problems(name: str, entry: Mapping, source: Mapping) -> list[str]:
    """A mirror pin names its family's asset and that asset's hash, or neither."""
    out: list[str] = []
    family = source.get("family")
    if not isinstance(family, str) or not family:
        out.append(f"{name}: a mirror source needs 'family'")
    asset, sha256 = source.get("asset"), source.get("sha256")
    if (asset is None) != (sha256 is None):
        out.append(f"{name}: a mirror source names its asset and its sha256 together")
    if asset is not None and not _is_asset_name(asset):
        out.append(f"{name}: a mirror asset must be a plain file name")
    if sha256 is not None and not (
        isinstance(sha256, str) and sha256.startswith("sha256-")
    ):
        out.append(f"{name}: a mirror sha256 must be an SRI hash (sha256-...)")
    if entry.get("enabled") and asset is None:
        out.append(f"{name}: a mirror source cannot be enabled before it is pinned")
    return out


def validate(table: Mapping[str, object]) -> list[str]:
    """Return every schema problem in the table, most useful first."""
    problems: list[str] = []
    for name, entry in table.items():
        problems.extend(_problems_for_entry(name, entry))
    return problems


# --- network ------------------------------------------------------------------

Fetcher = Callable[[str], bytes]


def _fetch(url: str, *, timeout: float = 60.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _url_ok(url: str, *, timeout: float = 30.0) -> bool:
    headers = {"User-Agent": USER_AGENT}
    request = urllib.request.Request(url, method="HEAD", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return 200 <= response.status < 400
    except urllib.error.HTTPError as error:
        # Some mirrors refuse HEAD; a 405 is not a dead link.
        return error.code == 405
    except (OSError, http.client.HTTPException, ValueError):
        return False


# --- link check ---------------------------------------------------------------


def load_lock(path: Path = LOCK_PATH) -> dict:
    """Read the flake lock, which pins the nix-vm-test revision."""
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def nix_vm_test_list_url(lock: Mapping, distro: str) -> str:
    """Where the nix-vm-test revision ``flake.lock`` locks lists a distro's images."""
    try:
        locked = lock["nodes"]["nix-vm-test"]["locked"]
        kind, owner, repo, rev = (
            locked["type"],
            locked["owner"],
            locked["repo"],
            locked["rev"],
        )
    except (KeyError, TypeError):
        raise LinkError("flake.lock locks no nix-vm-test revision") from None
    if kind != "github":
        raise LinkError(f"flake.lock locks nix-vm-test as {kind!r}, not on GitHub")
    return f"{RAW_GITHUB}/{owner}/{repo}/{rev}/{distro}/images.json"


def nix_vm_test_url(source: Mapping, lock: Mapping, fetch: Fetcher) -> str:
    """The upstream image URL a nix-vm-test pin stands for.

    nix-vm-test lists its images per system as ``{image: {"name": <url>,
    "hash": <sha256>}}`` and fetches ``name`` with ``fetchurl``.
    """
    listing = nix_vm_test_list_url(lock, str(source.get("distro")))
    image = str(source.get("image"))
    try:
        url = json.loads(fetch(listing))[NIX_VM_TEST_SYSTEM][image]["name"]
    except (OSError, http.client.HTTPException, ValueError) as error:
        raise LinkError(f"cannot read {listing}: {error}") from None
    except (KeyError, TypeError):
        raise LinkError(
            f"{listing} pins no {NIX_VM_TEST_SYSTEM} image {image!r}"
        ) from None
    if not isinstance(url, str) or not url:
        raise LinkError(f"{listing} names no URL for image {image!r}")
    return url


def _locked_nix_vm_test_url() -> Callable[[Mapping], str]:
    """Resolve nix-vm-test pins against flake.lock, read once on first use."""
    lock: dict | None = None

    def resolve(source: Mapping) -> str:
        nonlocal lock
        if lock is None:
            try:
                lock = load_lock()
            except (OSError, ValueError) as error:
                raise LinkError(f"cannot read {LOCK_PATH.name}: {error}") from None
        return nix_vm_test_url(source, lock, _fetch)

    return resolve


def _pinned_url(source: Mapping, resolve: Callable[[Mapping], str]) -> str:
    """The image URL an upstream or a nix-vm-test source pins."""
    if source.get("kind") == "nix-vm-test":
        return resolve(source)
    url = source.get("url")
    if not url:
        raise LinkError("its upstream source names no URL")
    return str(url)


@dataclass
class LinkReport:
    """The link check's failures, and which entries it checked.

    ``checked`` and ``unchecked`` hold one line per entry: its name, marked
    "(staged)" for a disabled entry, and what was checked, or why nothing could
    be.
    """

    failures: list[str] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)
    unchecked: list[str] = field(default_factory=list)


def link_check(
    table: Mapping[str, dict],
    *,
    today: datetime.date | None = None,
    offline: bool = False,
    url_ok: Callable[[str], bool] = _url_ok,
    pin_url: Callable[[Mapping], str] | None = None,
    mirror: Mirror | None = None,
    builder_inputs: Mapping[str, Path] | None = None,
) -> LinkReport:
    """Check the pin of every entry, the staged ones as well as the enabled.

    An entry fails when its pin is within ``LEAD_DAYS`` of ``upstreamUntil`` or
    past it (so there is time to repin before the image drops off its mirror)
    and, unless ``offline``, when the image URL it pins does not answer: an
    upstream entry's own URL, or the one nix-vm-test pins for a nix-vm-test
    entry (``pin_url``, by default read from nix-vm-test's image list at the
    revision ``flake.lock`` locks). A staged (disabled) entry stays out of the
    smoke matrix until a change enables it, and the probes boot the Fedora and
    Arch ones before then; its pin lapses all the same, so it is checked like
    an enabled one. A mirror entry is probed at the asset it pins in the
    assets repository (``mirror``, by default read from mirrors.nix). The
    inputs its builder pins (``builder_inputs``, by default
    ``BUILDER_INPUTS``) are probed too, the installer ISO and the package
    snapshot, since the nightly rebuild fails once either is gone; that
    happens before its first asset is pinned as well. An entry that pins no
    asset yet, or a mirror with no base, names that in its line when its
    build inputs were probed and could be read, and is among the unchecked
    ones when nothing of it was probed; where a probe failed, the entry is
    among the checked ones and the run fails. A
    run that could check no enabled entry fails as well: a pass would claim a
    check of the images CI boots that never happened, whatever it found for
    the staged ones.
    """
    today = today or datetime.date.today()
    resolve = pin_url or _locked_nix_vm_test_url()
    report = LinkReport()
    no_probe: dict[str, str] = {}
    inputs = BUILDER_INPUTS if builder_inputs is None else builder_inputs
    checked_enabled = False
    for name, entry in table.items():
        enabled = bool(entry.get("enabled"))
        label = name if enabled else f"{name} (staged)"
        source = entry.get("source", {})
        kind = source.get("kind")
        done: list[str] = []
        until = entry.get("upstreamUntil")
        if until is not None:
            try:
                lapses = datetime.date.fromisoformat(str(until))
            except ValueError:
                done.append("its upstreamUntil unreadable")
                report.failures.append(
                    f"{label}: upstreamUntil {until!r} is not a YYYY-MM-DD date"
                )
            else:
                done.append(f"lapses {until}")
                if today >= lapses - datetime.timedelta(days=LEAD_DAYS):
                    report.failures.append(
                        f"{label}: upstream pin lapses {until}"
                        f" (within {LEAD_DAYS} days or past); repin it"
                    )
        url: str | None = None
        if not offline and kind in ("upstream", "nix-vm-test"):
            try:
                url = _pinned_url(source, resolve)
            except LinkError as error:
                done.append("its pin unreadable")
                report.failures.append(f"{label}: {error}")
        elif not offline and kind == "mirror":
            try:
                mirror = mirror or load_mirror()
            except LinkError as error:
                done.append("its mirror unreadable")
                report.failures.append(f"{label}: {error}")
            else:
                url, why = _mirror_url(source, mirror)
                if url is None:
                    no_probe[name] = why
            family = str(source.get("family"))
            if family in inputs:
                try:
                    build_urls = builder_urls(inputs[family])
                except LinkError as error:
                    done.append("its build inputs unreadable")
                    report.failures.append(f"{label}: {error}")
                else:
                    for build_url in build_urls:
                        done.append(f"probed {build_url}")
                        if not url_ok(build_url):
                            report.failures.append(
                                f"{label}: build input is unreachable: {build_url}"
                            )
                    # The entry counts as checked by its build inputs; its
                    # line still says why its asset was not probed.
                    if name in no_probe:
                        done.append(no_probe.pop(name))
        if url is not None:
            done.append(f"probed {url}")
            if not url_ok(url):
                report.failures.append(f"{label}: image URL is unreachable: {url}")
        if done:
            report.checked.append(f"{label}: {', '.join(done)}")
            checked_enabled = checked_enabled or enabled
        elif offline and kind in ("upstream", "nix-vm-test", "mirror"):
            report.unchecked.append(f"{label}: offline, and no upstreamUntil")
        elif name in no_probe:
            report.unchecked.append(f"{label}: {no_probe[name]}")
        else:
            report.unchecked.append(f"{label}: a {kind} source has no URL to probe")
    if not checked_enabled:
        report.failures.append(
            "no enabled entry could be checked, so no image CI boots is known"
            " to be current"
        )
    return report


def builder_urls(path: Path) -> list[str]:
    """The URLs a builder's inputs.json pins: its ISO and its package snapshot.

    The snapshot is probed at its core repository database, the first file
    pacman fetches from it.
    """
    try:
        inputs = json.loads(path.read_text(encoding="utf-8"))
        iso, server = inputs["iso"]["url"], inputs["packages"]["server"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise LinkError(f"cannot read {path.name}: {error}") from None
    if not isinstance(iso, str) or not isinstance(server, str):
        raise LinkError(f"{path.name} names no ISO URL and package server")
    core = server.replace("$repo", "core").replace("$arch", "x86_64")
    return [iso, f"{core}/core.db"]


def _mirror_url(source: Mapping, mirror: Mirror) -> tuple[str | None, str]:
    """The URL a mirror source pins, or None and why there is none to probe."""
    if not mirror.configured():
        return None, "the mirror is not configured yet"
    asset = source.get("asset")
    if asset is None:
        return None, "no asset pinned yet"
    return mirror.url_for(str(source.get("family")), str(asset)), ""


# --- repin --------------------------------------------------------------------

# A directory listing (the mirrors' autoindex) links each file and dated build
# directory by href; these pull the image name or the build out of that listing.
_FEDORA_QCOW2 = re.compile(
    r"Fedora-Cloud-Base-Generic-(?P<release>\d+)-(?P<point>[\d.]+)\.x86_64\.qcow2"
)
_ARCH_BUILD = re.compile(r'href="v(?P<date>\d{8})\.(?P<build>\d+)/"')
_ARCH_SHA = re.compile(r"^(?P<hex>[0-9a-f]{64}) ", re.MULTILINE)


def _text(fetch: Fetcher, url: str) -> str:
    return fetch(url).decode("utf-8", "replace")


def resolve_fedora(release: str, fetch: Fetcher) -> dict[str, str]:
    """The newest Generic Cloud qcow2 pin for a Fedora release.

    The release directory lists the image and its signed CHECKSUM file; the
    CHECKSUM file name carries the point release, so the image is found first.
    """
    base = f"{FEDORA_RELEASES}/{release}/Cloud/x86_64/images/"
    points = [
        m.group("point")
        for m in _FEDORA_QCOW2.finditer(_text(fetch, base))
        if m.group("release") == release
    ]
    if not points:
        raise RepinError(f"no Generic Cloud qcow2 in the Fedora {release} listing")
    point = max(points, key=lambda p: tuple(int(n) for n in p.split(".")))
    name = f"Fedora-Cloud-Base-Generic-{release}-{point}.x86_64.qcow2"
    checksum = _text(fetch, f"{base}Fedora-Cloud-{release}-{point}-x86_64-CHECKSUM")
    match = re.search(rf"SHA256 \({re.escape(name)}\) = ([0-9a-f]{{64}})", checksum)
    if match is None:
        raise RepinError(f"{name} is not in its CHECKSUM file")
    sha256 = sri_from_hex(match.group(1))
    return {"url": f"{base}{name}", "name": name, "sha256": sha256}


def resolve_arch_boxes(release: str, fetch: Fetcher) -> dict[str, str]:
    """The arch-boxes basic qcow2 pin for a dated build (or the newest).

    ``release`` is an eight-digit date (pinned to that day's build) or one of
    latest/rolling/"" (the newest build on the mirror). The dated build
    directory is the stable URL; the mirror keeps only the recent ones, which
    is what ``upstreamUntil`` tracks.
    """
    builds = [
        (m.group("date"), m.group("build"))
        for m in _ARCH_BUILD.finditer(_text(fetch, f"{ARCH_IMAGES}/"))
    ]
    if release not in {"", "latest", "rolling"}:
        builds = [b for b in builds if b[0] == release]
    if not builds:
        raise RepinError(f"no arch-boxes build {release!r} on the mirror")
    date, build = max(builds, key=lambda b: (b[0], int(b[1])))
    stamp = f"{date}.{build}"
    name = f"Arch-Linux-x86_64-basic-{stamp}.qcow2"
    url = f"{ARCH_IMAGES}/v{stamp}/{name}"
    match = _ARCH_SHA.search(_text(fetch, f"{url}.SHA256"))
    if match is None:
        raise RepinError(f"no SHA256 for arch-boxes {stamp}")
    return {"url": url, "name": name, "sha256": sri_from_hex(match.group("hex"))}


RESOLVERS: dict[str, Callable[[str, Fetcher], dict[str, str]]] = {
    "fedora": resolve_fedora,
    "arch-boxes": resolve_arch_boxes,
}


def resolve_mirror(family: str, mirror: Mirror, fetch: Fetcher) -> dict[str, str]:
    """The newest build of a mirrored family, from its latest-build manifest.

    The test-images workflow uploads each build under a name of its own and
    then replaces ``<family>-latest.json`` with that build's manifest, which
    names the asset and its SHA-256 in the SRI form.
    """
    if not mirror.configured():
        raise RepinError("the mirror is not configured yet (mirrors.nix base)")
    url = mirror.latest_url(family)
    try:
        manifest = json.loads(fetch(url))
        asset, sha256 = manifest["asset"], manifest["sha256"]
    except (KeyError, TypeError, ValueError):
        raise RepinError(f"{url} is no manifest with an asset and a sha256") from None
    if not _is_asset_name(asset) or not str(asset).startswith(f"{family}-"):
        raise RepinError(f"{url} names no asset of {family}: {asset!r}")
    if not isinstance(sha256, str) or not sha256.startswith("sha256-"):
        raise RepinError(f"{url} names no SRI sha256 for {asset}")
    return {"asset": asset, "sha256": sha256}


def repin_entry(entry: dict, fetch: Fetcher, mirror: Mirror | None = None) -> bool:
    """Resolve and write an entry's pin. True when it changed.

    An upstream entry gets the newest upstream build; a mirror entry stays a
    mirror entry and gets the newest build in the assets repository.
    """
    source = entry.get("source", {})
    family = str(source.get("family"))
    if source.get("kind") == "mirror":
        resolved = resolve_mirror(family, mirror or load_mirror_for_repin(), fetch)
    else:
        resolver = RESOLVERS.get(family)
        if resolver is None:
            raise RepinError(f"no upstream resolver for family {family!r}")
        resolved = resolver(str(source.get("release", "")), fetch)
    changed = any(source.get(key) != value for key, value in resolved.items())
    source.update(resolved)
    if source.get("kind") != "mirror":
        source["kind"] = "upstream"
    return changed


def load_mirror_for_repin() -> Mirror:
    """mirrors.nix's seam, with a failure to read it as a repin failure."""
    try:
        return load_mirror()
    except LinkError as error:
        raise RepinError(str(error)) from None


@dataclass
class RepinResult:
    """The entries a repin changed, and those it could not resolve, with why."""

    changed: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)


def repin(
    table: dict[str, dict],
    names: Sequence[str],
    *,
    fetch: Fetcher | None = None,
) -> RepinResult:
    """Repin the named entries, or with no names every pinned resolvable one.

    A mirror entry is resolvable: it moves to the newest build its family's
    release holds. Without names, a pending entry is left out: it is declared before its
    release exists (Fedora 45 before it ships), so its upstream has nothing to
    pin yet, and it is pinned for the first time by naming it. An entry that
    does not resolve is recorded in ``failed`` and the others are still
    repinned, so one missing release never holds back the bumps of the rest.
    An unknown name is a RepinError before anything is fetched.
    """
    unknown = [name for name in names if name not in table]
    if unknown:
        raise RepinError(f"unknown entry {unknown[0]!r}")
    if not names:
        names = [
            name
            for name, entry in table.items()
            if (
                str(entry.get("source", {}).get("family")) in RESOLVERS
                or entry.get("source", {}).get("kind") == "mirror"
            )
            and entry.get("source", {}).get("kind") != "pending"
        ]
    result = RepinResult()
    for name in names:
        try:
            changed = repin_entry(table[name], fetch or _fetch)
        except (RepinError, OSError, http.client.HTTPException, ValueError) as error:
            result.failed[name] = str(error)
            continue
        if changed:
            result.changed.append(name)
    return result


def write_table(table: Mapping[str, dict], path: Path = TABLE_PATH) -> None:
    path.write_text(json.dumps(table, indent=2) + "\n", encoding="utf-8")


# --- cli ----------------------------------------------------------------------


def _cmd_check(_: argparse.Namespace) -> int:
    problems = validate(load_table())
    if problems:
        for problem in problems:
            print(f"images.json: {problem}", file=sys.stderr)
        return 1
    print("images.json: the distribution table is well-formed.")
    return 0


def _cmd_link_check(args: argparse.Namespace) -> int:
    today = datetime.date.fromisoformat(args.date) if args.date else None
    report = link_check(load_table(), today=today, offline=args.offline)
    for line in report.checked:
        print(f"distro images link check: checked {line}")
    for line in report.unchecked:
        print(f"distro images link check: not checked {line}")
    if report.failures:
        for failure in report.failures:
            print(f"distro images link check: {failure}", file=sys.stderr)
        return 1
    print(
        f"distro images link check: the {len(report.checked)} checked pin(s) "
        "are current."
    )
    return 0


def _cmd_repin(args: argparse.Namespace) -> int:
    table = load_table()
    names: list[str] = [] if args.all else list(args.names)
    if not args.all and not names:
        print("repin: name an entry or pass --all", file=sys.stderr)
        return 2
    try:
        result = repin(table, names)
    except RepinError as error:
        print(f"repin: {error}", file=sys.stderr)
        return 1
    if result.changed:
        write_table(table)
        print("repinned: " + ", ".join(result.changed))
        # How long an image stays on its mirror is the mirror's policy, which
        # no listing states, so the lapse date is left for a person to set.
        for name in result.changed:
            until = table[name].get("upstreamUntil")
            if until is not None:
                print(
                    f"repin: {name}: upstreamUntil is left at {until}; "
                    "check it against the new image"
                )
    for name, why in result.failed.items():
        print(f"repin: {name}: {why}", file=sys.stderr)
    if result.failed:
        return 1
    if not result.changed:
        print("repin: every pin was already current.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="distro_images", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="validate the image table schema")
    check.set_defaults(func=_cmd_check)

    link = sub.add_parser(
        "link-check", help="fail before a pin lapses, a staged entry's as well"
    )
    link.add_argument("--date", help="treat this YYYY-MM-DD as today")
    link.add_argument(
        "--offline",
        action="store_true",
        help="check the upstreamUntil dates only, with no network request",
    )
    link.set_defaults(func=_cmd_link_check)

    rep = sub.add_parser("repin", help="bump upstream pins to the latest build")
    rep.add_argument("names", nargs="*", help="entries to repin")
    rep.add_argument(
        "--all",
        action="store_true",
        help="repin every pinned entry (a pending one only by its name)",
    )
    rep.set_defaults(func=_cmd_repin)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
