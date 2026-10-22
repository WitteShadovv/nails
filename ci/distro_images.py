"""Tend the distribution image table: schema, link health, and pin bumps.

The table is plain data in ``nix/distro-tests/images.json``; the flake turns it
into VM tests (nix/distro-tests/images.nix). This module is the other half of
the mirror seam: it validates the table, it is the weekly link check that fails
before a pinned upstream image is due to lapse, and it bumps a pin to the latest
upstream build (an SHA256 the distribution publishes, converted to the
subresource-integrity form ``fetchurl`` expects -- the image itself is never
downloaded here).

Subcommands::

    python3 -m ci.distro_images check
    python3 -m ci.distro_images link-check [--date YYYY-MM-DD] [--offline]
    python3 -m ci.distro_images repin (--all | <name> ...)

``check`` and ``link-check`` are what CI runs; ``repin`` is the pin bump, run
from a networked host (or the scheduled lane) and committed as a one-line diff.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import json
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TABLE_PATH = REPO / "nix" / "distro-tests" / "images.json"

# The placeholder hash an entry carries until it is pinned for real. It is the
# well-known Nix "fake" SHA256, so an enabled entry that still has it is caught
# by the schema check and never reaches a VM build.
FAKE_HASH = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

KNOWN_OS_IDS = frozenset({"debian", "ubuntu", "fedora", "arch"})
KNOWN_PREPARE = frozenset({"nix-vm-test", "fedora", "archlinux"})
KNOWN_KINDS = frozenset({"nix-vm-test", "upstream", "mirror", "pending"})

# How far before an enabled entry's upstreamUntil the link check starts failing,
# so there is time to repin before the image drops off its download mirror.
LEAD_DAYS = 14

# A plain User-Agent: the download mirrors serve automated clients, and the
# request must never carry anything that identifies who is running it.
USER_AGENT = "nails-distro-images/1"

FEDORA_RELEASES = "https://download.fedoraproject.org/pub/fedora/linux/releases"
ARCH_IMAGES = "https://geo.mirror.pkgbuild.com/images"


class RepinError(Exception):
    """A pin could not be resolved from upstream."""


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
    for field, kind in _FIELD_TYPES.items():
        if field not in entry:
            out.append(f"{name}: missing {field!r}")
        elif not isinstance(entry[field], kind):
            out.append(f"{name}: {field} must be {kind.__name__}")
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
    out.extend(_source_problems(name, entry, entry["source"]))
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
    enabled = bool(entry.get("enabled"))
    if enabled and kind == "pending":
        out.append(f"{name}: a pending source cannot be enabled")
    if enabled and kind == "upstream" and source.get("sha256") == FAKE_HASH:
        out.append(f"{name}: still has the placeholder hash; repin before enabling")
    return out


def validate(table: Mapping[str, object]) -> list[str]:
    """Return every schema problem in the table, most useful first."""
    problems: list[str] = []
    for name, entry in table.items():
        problems.extend(_problems_for_entry(name, entry))
    return problems


# --- link check ---------------------------------------------------------------


def _url_ok(url: str, *, timeout: float = 30.0) -> bool:
    headers = {"User-Agent": USER_AGENT}
    request = urllib.request.Request(url, method="HEAD", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return 200 <= response.status < 400
    except urllib.error.HTTPError as error:
        # Some mirrors refuse HEAD; a 405 is not a dead link.
        return error.code == 405
    except (urllib.error.URLError, TimeoutError, ValueError):
        return False


def link_check(
    table: Mapping[str, dict],
    *,
    today: datetime.date | None = None,
    offline: bool = False,
    url_ok: Callable[[str], bool] = _url_ok,
) -> list[str]:
    """Return the failures for the enabled, upstream-pinned entries.

    An entry fails when its pin is within ``LEAD_DAYS`` of ``upstreamUntil`` (so
    there is time to repin before the image drops off its mirror) or, unless
    ``offline``, when its URL is unreachable. Disabled entries are never a
    failure here; they are staged on purpose.
    """
    today = today or datetime.date.today()
    failures: list[str] = []
    for name, entry in table.items():
        if not entry.get("enabled"):
            continue
        source = entry.get("source", {})
        if source.get("kind") != "upstream":
            continue
        until = entry.get("upstreamUntil")
        if until is not None:
            lapses = datetime.date.fromisoformat(str(until))
            if today >= lapses - datetime.timedelta(days=LEAD_DAYS):
                failures.append(
                    f"{name}: upstream pin lapses {until}"
                    f" (within {LEAD_DAYS} days or past); repin it"
                )
        if not offline:
            url = source.get("url")
            if url and not url_ok(url):
                failures.append(f"{name}: upstream image URL is unreachable: {url}")
    return failures


# --- repin --------------------------------------------------------------------

Fetcher = Callable[[str], bytes]


def _fetch(url: str, *, timeout: float = 60.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


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


def repin_entry(entry: dict, fetch: Fetcher) -> bool:
    """Resolve and write an entry's upstream pin. True when it changed."""
    source = entry.get("source", {})
    family = str(source.get("family"))
    resolver = RESOLVERS.get(family)
    if resolver is None:
        raise RepinError(f"no upstream resolver for family {family!r}")
    resolved = resolver(str(source.get("release", "")), fetch)
    changed = any(source.get(key) != value for key, value in resolved.items())
    source.update(resolved)
    source["kind"] = "upstream"
    return changed


def repin(
    table: dict[str, dict],
    names: Sequence[str],
    *,
    fetch: Fetcher = _fetch,
) -> list[str]:
    """Repin the named entries (or every resolvable one); returns those changed."""
    if not names:
        names = [
            name
            for name, entry in table.items()
            if str(entry.get("source", {}).get("family")) in RESOLVERS
        ]
    changed: list[str] = []
    for name in names:
        if name not in table:
            raise RepinError(f"unknown entry {name!r}")
        if repin_entry(table[name], fetch):
            changed.append(name)
    return changed


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
    failures = link_check(load_table(), today=today, offline=args.offline)
    if failures:
        for failure in failures:
            print(f"distro images link check: {failure}", file=sys.stderr)
        return 1
    print("distro images link check: every enabled upstream pin is current.")
    return 0


def _cmd_repin(args: argparse.Namespace) -> int:
    table = load_table()
    names: list[str] = [] if args.all else list(args.names)
    if not args.all and not names:
        print("repin: name an entry or pass --all", file=sys.stderr)
        return 2
    try:
        changed = repin(table, names)
    except RepinError as error:
        print(f"repin: {error}", file=sys.stderr)
        return 1
    if changed:
        write_table(table)
        print("repinned: " + ", ".join(changed))
    else:
        print("repin: every pin was already current.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="distro_images", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="validate the image table schema")
    check.set_defaults(func=_cmd_check)

    link = sub.add_parser("link-check", help="fail before an enabled pin lapses")
    link.add_argument("--date", help="treat this YYYY-MM-DD as today")
    link.add_argument("--offline", action="store_true", help="skip the URL probe")
    link.set_defaults(func=_cmd_link_check)

    rep = sub.add_parser("repin", help="bump upstream pins to the latest build")
    rep.add_argument("names", nargs="*", help="entries to repin")
    rep.add_argument("--all", action="store_true", help="repin every entry")
    rep.set_defaults(func=_cmd_repin)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
