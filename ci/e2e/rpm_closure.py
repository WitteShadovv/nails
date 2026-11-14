"""Pin the offline package closures of Fedora's admission gate.

The gate scenarios (``nix/distro-tests/fedora-gate.nix``) install tuned,
firewalld and ABRT on a Fedora decoy whose VM has no network, so the packages
come from a lock: every file of one install's closure, pinned by its SHA-256,
from the release's own repository, which does not change once the release is
out. The closure is resolved on the image itself, by its own dnf (the
``<image>-rpms`` driver of the staged suite writes ``<image>-rpms.json``), since
only the image knows what it holds already. This module turns that resolution
into the lock, on a networked host::

    python3 -m ci.e2e.rpm_closure lock <image>-rpms.json
    python3 -m ci.e2e.rpm_closure check

``lock`` fetches every package of the resolution again from the release
repository, with a plain User-Agent, and writes
``nix/distro-tests/rpms/<image>.json`` only when each file has the SHA-256 and
size the image's dnf saw: a mirror that served another file stops it.
``check`` is offline: every lock is well-formed and was resolved for the very
image file ``images.json`` pins for its image, so a repin of an image leaves
its lock failing until it is resolved again.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
LOCK_DIR = REPO / "nix" / "distro-tests" / "rpms"
TABLE_PATH = REPO / "nix" / "distro-tests" / "images.json"

# A plain User-Agent: nothing in it says who runs it. The guest's resolution
# sends the same (nix/distro-tests/py/fedora_rpms.py).
USER_AGENT = "nails-rpm-closure/1"

RELEASES = "https://download.fedoraproject.org/pub/fedora/linux/releases"
ARCHIVE = "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases"

# A package's path in the repository: its first letter's folder and its file.
_PATH = re.compile(r"Packages/[0-9a-z]/[A-Za-z0-9._+^~-]+\.rpm")
_HEX = re.compile(r"[0-9a-f]{64}")
_SRI = re.compile(r"sha256-[A-Za-z0-9+/]{43}=")
_FILE = re.compile(r"[A-Za-z0-9._+^~-]+\.rpm")

# A fetch of one URL, returning its bytes.
Fetcher = Callable[[str], bytes]


class ClosureError(Exception):
    """A resolution or a lock that cannot be used."""


def repository(release: str) -> str:
    """The release repository of Fedora ``release``, with its trailing slash."""
    return f"{RELEASES}/{release}/Everything/x86_64/os/"


def archive(release: str) -> str:
    """The same repository once the release is past its end of life."""
    return f"{ARCHIVE}/{release}/Everything/x86_64/os/"


def sri(hexdigest: str) -> str:
    """A hex SHA-256 in the SRI form ``fetchurl`` takes."""
    if not _HEX.fullmatch(hexdigest):
        raise ClosureError(f"not a SHA-256 digest: {hexdigest!r}")
    return "sha256-" + base64.b64encode(bytes.fromhex(hexdigest)).decode("ascii")


def fetch(url: str, *, attempts: int = 3, timeout: float = 120.0) -> bytes:
    """The bytes at ``url``, tried up to ``attempts`` times."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data: bytes = response.read()
                return data
        except (urllib.error.URLError, OSError) as error:
            last = error
            time.sleep(2 * (attempt + 1))
    raise ClosureError(f"{url}: {last}")


def _text(value: object, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise ClosureError(f"{what} must be a non-empty string")
    return value


def read_resolution(payload: object) -> dict[str, Any]:
    """The resolution the ``<image>-rpms`` driver wrote, checked."""
    if not isinstance(payload, Mapping):
        raise ClosureError("a resolution is a JSON object")
    release = _text(payload.get("release"), "release")
    if not release.isdigit():
        raise ClosureError(f"release {release!r} is no Fedora release")
    if payload.get("repository") != repository(release):
        raise ClosureError(
            f"the resolution used {payload.get('repository')!r}, "
            f"not the release repository {repository(release)}"
        )
    if payload.get("weakDependencies") is not False:
        raise ClosureError("the resolution must leave weak dependencies out")
    packages = payload.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ClosureError("the resolution holds no package")
    files = set()
    for package in packages:
        if not isinstance(package, Mapping):
            raise ClosureError(f"a package is a JSON object: {package!r}")
        file = _text(package.get("file"), "a package's file")
        path = _text(package.get("path"), f"{file}: path")
        if not _FILE.fullmatch(file) or not _PATH.fullmatch(path):
            raise ClosureError(f"{file}: not a package path of the repository: {path}")
        if not path.endswith("/" + file):
            raise ClosureError(f"{file}: its path names another file: {path}")
        if file in files:
            raise ClosureError(f"{file} is in the resolution twice")
        files.add(file)
        if not _HEX.fullmatch(str(package.get("sha256"))):
            raise ClosureError(f"{file}: no SHA-256 digest")
        if not isinstance(package.get("size"), int) or package["size"] <= 0:
            raise ClosureError(f"{file}: no size")
        _text(package.get("nevra"), f"{file}: nevra")
    in_image = payload.get("inImage")
    if not isinstance(in_image, Mapping):
        raise ClosureError("inImage must say what the image holds of each package")
    _text(payload.get("image"), "image")
    _text(payload.get("imageFile"), "imageFile")
    return dict(payload)


def lock_from(
    resolution: Mapping[str, Any], fetcher: Fetcher = fetch
) -> dict[str, Any]:
    """The lock of ``resolution``, each package fetched again and checked."""
    resolution = read_resolution(resolution)
    release = str(resolution["release"])
    base = repository(release)
    packages = []
    for package in sorted(resolution["packages"], key=lambda p: str(p["file"])):
        url = base + str(package["path"])
        data = fetcher(url)
        digest = hashlib.sha256(data).hexdigest()
        if digest != package["sha256"] or len(data) != package["size"]:
            raise ClosureError(
                f"{url} served {len(data)} bytes with SHA-256 {digest}, "
                f"where the image's dnf had {package['size']} bytes "
                f"with {package['sha256']}"
            )
        packages.append(
            {
                "file": package["file"],
                "nevra": package["nevra"],
                "path": package["path"],
                "sha256": sri(digest),
                "size": len(data),
            }
        )
    return {
        "image": resolution["image"],
        "imageFile": resolution["imageFile"],
        "release": release,
        "repository": base,
        "archive": archive(release),
        "requested": sorted(str(name) for name in resolution["inImage"]),
        "inImage": dict(sorted(resolution["inImage"].items())),
        "weakDependencies": False,
        "packages": packages,
    }


def lock_problems(name: str, lock: object, table: Mapping[str, Any]) -> list[str]:
    """Why the lock ``name`` (an image's name) cannot be used, if it cannot."""
    if not isinstance(lock, Mapping):
        return [f"{name}: a lock is a JSON object"]
    problems = []
    entry = table.get(name)
    if not isinstance(entry, Mapping):
        return [f"{name}: images.json has no entry {name}"]
    source = entry.get("source")
    image_file = source.get("name") if isinstance(source, Mapping) else None
    if lock.get("image") != name:
        problems.append(f"{name}: the lock is of {lock.get('image')!r}")
    if lock.get("imageFile") != image_file:
        problems.append(
            f"{name}: resolved for {lock.get('imageFile')!r}, but images.json pins "
            f"{image_file!r}; run the {name}-rpms driver and lock it again"
        )
    release = str(lock.get("release"))
    if release != str(entry.get("release")):
        problems.append(f"{name}: of release {release}, not {entry.get('release')}")
    if lock.get("repository") != repository(release):
        problems.append(f"{name}: not from the release repository of {release}")
    if lock.get("archive") != archive(release):
        problems.append(f"{name}: its archive is not that of {release}")
    if lock.get("weakDependencies") is not False:
        problems.append(f"{name}: a lock leaves weak dependencies out")
    packages = lock.get("packages")
    if not isinstance(packages, list) or not packages:
        return problems + [f"{name}: the lock holds no package"]
    files = [p.get("file") for p in packages if isinstance(p, Mapping)]
    if files != sorted(set(str(f) for f in files)):
        problems.append(f"{name}: the packages are not each once, by file")
    for package in packages:
        if not isinstance(package, Mapping):
            problems.append(f"{name}: a package is a JSON object")
            continue
        file = str(package.get("file"))
        path = str(package.get("path"))
        if not _PATH.fullmatch(path) or not path.endswith("/" + file):
            problems.append(f"{name}: {file}: not a package path: {path}")
        if not _SRI.fullmatch(str(package.get("sha256"))):
            problems.append(f"{name}: {file}: no SRI SHA-256")
        if not isinstance(package.get("size"), int) or package["size"] <= 0:
            problems.append(f"{name}: {file}: no size")
    return problems


def check(lock_dir: Path = LOCK_DIR, table_path: Path = TABLE_PATH) -> list[str]:
    """The problems of every lock in ``lock_dir``."""
    table = json.loads(table_path.read_text(encoding="utf-8"))
    problems = []
    for path in sorted(lock_dir.glob("*.json")):
        lock = json.loads(path.read_text(encoding="utf-8"))
        problems.extend(lock_problems(path.stem, lock, table))
        if path.read_text(encoding="utf-8") != lock_json(lock):
            problems.append(f"{path.stem}: not written the way lock writes it")
    return problems


def lock_json(lock: Mapping[str, Any]) -> str:
    """A lock as ``lock`` writes it."""
    return json.dumps(lock, indent=2, sort_keys=True) + "\n"


def _cmd_lock(args: argparse.Namespace) -> int:
    resolution = json.loads(Path(args.resolution).read_text(encoding="utf-8"))
    try:
        lock = lock_from(resolution)
    except ClosureError as error:
        print(f"rpm_closure lock: {error}", file=sys.stderr)
        return 1
    table = json.loads(TABLE_PATH.read_text(encoding="utf-8"))
    problems = lock_problems(str(lock["image"]), lock, table)
    if problems:
        for problem in problems:
            print(f"rpm_closure lock: {problem}", file=sys.stderr)
        return 1
    target = Path(args.out) if args.out else LOCK_DIR / f"{lock['image']}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(lock_json(lock), encoding="utf-8")
    print(f"rpm_closure lock: {len(lock['packages'])} packages to {target}")
    return 0


def _cmd_check(_: argparse.Namespace) -> int:
    problems = check()
    for problem in problems:
        print(f"rpm_closure check: {problem}", file=sys.stderr)
    if problems:
        return 1
    print("rpm_closure check: every lock is well-formed and current.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rpm_closure", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    lock = sub.add_parser("lock", help="pin a resolution the rpms driver wrote")
    lock.add_argument("resolution", help="<image>-rpms.json")
    lock.add_argument("--out", help="where to write the lock")
    lock.set_defaults(func=_cmd_lock)
    chk = sub.add_parser("check", help="validate the committed locks, offline")
    chk.set_defaults(func=_cmd_check)
    args = parser.parse_args(argv)
    code: int = args.func(args)
    return code


if __name__ == "__main__":
    sys.exit(main())
