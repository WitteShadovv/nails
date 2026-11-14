"""The offline package closures of the Fedora gate: what to install, from where.

The gate scenarios (``nix/distro-tests/fedora-gate.nix``) install tuned,
firewalld and ABRT on a Fedora decoy so that the posture checks meet them as a
Fedora system that runs them has them. The VMs have no network, so the
packages come as a closure pinned by hash: every package the install needs
that the image does not already hold, from the release's own repository,
which never changes once the release is out (its updates go to another one).

Only the image's own package manager knows what the image holds, so the
closure is resolved on the image itself: the ``<image>-rpms`` driver boots it
with the guest's network on, has dnf download the transaction of one
``dnf install`` of :data:`REQUESTED` from the release repository alone, and
reads every package dnf chose (:func:`resolve_command`,
:func:`parse_resolution`). ``ci/e2e/rpm_closure.py`` then fetches each
package again on the host, checks it is the same file and writes the lock
the gate's Nix code fetches the closure from. The gate shares the closure
into its VM and installs it with every repository disabled
(:func:`install_command`), so dnf takes nothing but those files.

Nothing here imports Nix or the test driver.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Sequence
from typing import Any

# What the gate installs: the three daemons the Fedora posture checks judge.
REQUESTED = ("tuned", "firewalld", "abrt")

# The release repository of a Fedora release, through the download redirector.
# Its tree is fixed once the release is out; at its end of life it moves to
# ARCHIVE.
RELEASES = "https://download.fedoraproject.org/pub/fedora/linux/releases"
ARCHIVE = "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases"

# A plain User-Agent for every download, the guest's and the host's: nothing
# in it says who runs it.
USER_AGENT = "nails-rpm-closure/1"

# dnf's cache in the guest, where the resolution leaves the packages: on the
# decoy's disk, which the driver's VM keeps in a temporary layer that goes
# with it.
GUEST_DIR = "/var/tmp/rpm-closure"

# The repository id dnf gets for the release repository.
REPO_ID = "release"

_LINE = re.compile(r"^(?P<kind>in-image|package|checksig|location) (?P<rest>.*)$")


def repository(release: str) -> str:
    """The URL of the release repository of Fedora ``release``, with its
    trailing slash."""
    if not release.isdigit():
        raise ValueError(f"not a Fedora release: {release!r}")
    return f"{RELEASES}/{release}/Everything/x86_64/os/"


def archive_repository(release: str) -> str:
    """Where the release repository of ``release`` is once the release is
    past its end of life."""
    if not release.isdigit():
        raise ValueError(f"not a Fedora release: {release!r}")
    return f"{ARCHIVE}/{release}/Everything/x86_64/os/"


def find_key(release: str) -> str:
    """The guest command that sets ``key`` to the release key file the image's
    own repositories check packages with, or fails naming what it found.

    It takes the first ``gpgkey`` of the image's ``fedora.repo``, with dnf's
    ``$releasever`` and ``$basearch`` filled in, where that names a file the
    image holds, and otherwise the first key file of the release the image
    ships under ``/etc/pki/rpm-gpg``. ``release`` may be a shell expansion."""
    base = "/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora"
    return (
        "key=$(sed -n 's|^gpgkey=file://||p' /etc/yum.repos.d/fedora.repo "
        "2>/dev/null | head -n 1 | cut -d' ' -f1 | "
        f"sed 's/[$]releasever/{release}/g; s/[$]basearch/x86_64/g'); "
        '[ -n "$key" ] && [ -e "$key" ] || key=; '
        f"for candidate in {base}-{release}-x86_64 {base}-{release}-primary; do "
        '[ -n "$key" ] && break; [ -e "$candidate" ] && key=$candidate; done; '
        '[ -n "$key" ] || { grep -h "^gpgkey" /etc/yum.repos.d/*.repo >&2; '
        "ls -la /etc/pki/rpm-gpg >&2; "
        f'echo "no release key of Fedora {release}" >&2; exit 3; }}'
    )


def repo_file(release: str, key: str) -> str:
    """The dnf repository file of the release repository alone: its packages
    checked against the release key file ``key``, which the image ships."""
    return "\n".join(
        (
            f"[{REPO_ID}]",
            f"name=Fedora {release} release",
            f"baseurl={repository(release)}",
            "enabled=1",
            "gpgcheck=1",
            "repo_gpgcheck=0",
            f"gpgkey=file://{key}",
            "",
        )
    )


def resolve_command(release: str, requested: Sequence[str] = REQUESTED) -> str:
    """The guest command that resolves the closure of ``requested``.

    It says which of them the image holds already (``in-image``), adds the
    release repository as the one repository dnf may use, has dnf download one
    install's transaction from it (``install --downloadonly``, which keeps the
    packages in dnf's cache, here a directory of its own), with weak
    dependencies left out, and describes every file dnf downloaded: its
    name, NEVRA, SHA-256 and size (``package``), what ``rpm -K`` says of it
    once the release key is imported (``checksig``), and the URL dnf has for
    it (``location``). The guest is the driver's own, which keeps every write
    in a temporary layer. What dnf prints goes to the standard error.
    """
    names = " ".join(shlex.quote(name) for name in requested)
    dnf = (
        f"dnf --assumeyes --quiet --repo={REPO_ID} "
        "--setopt=install_weak_deps=False "
        f"--setopt=system_cachedir={GUEST_DIR} --setopt=cachedir={GUEST_DIR} "
        "--setopt=keepcache=True "
        f"--setopt=user_agent={shlex.quote(USER_AGENT)}"
    )
    # Every line of the repository file as one word of printf, the key's
    # path from the shell's own variable.
    repo_lines = " ".join(
        '"gpgkey=file://$key"' if line.startswith("gpgkey=") else shlex.quote(line)
        for line in repo_file(release, "").splitlines()
    )
    return "\n".join(
        (
            "set -eu",
            f"dest={GUEST_DIR}",
            'rm -rf "$dest" && mkdir -p "$dest"',
            f"for name in {names}; do",
            '  printf "in-image %s %s\\n" "$name" "$(rpm -q "$name" 2>&1 || true)"',
            "done",
            find_key(release),
            f"printf '%s\\n' {repo_lines} > /etc/yum.repos.d/{REPO_ID}.repo",
            f"{dnf} install --downloadonly {names} >&2",
            'rpm --import "$key"',
            'find "$dest" -name "*.rpm" | sort > "$dest.list"',
            "while read -r file; do",
            '  nevra=$(rpm -qp --qf "%{NEVRA}" "$file")',
            '  printf "package %s %s %s %s\\n" "$(basename "$file")" "$nevra" '
            '"$(sha256sum < "$file" | cut -d" " -f1)" "$(stat -c %s "$file")"',
            '  printf "checksig %s %s\\n" "$(basename "$file")" '
            '"$(rpm -K "$file" | sed "s/^[^:]*: //")"',
            f'  printf "location %s %s\\n" "$(basename "$file")" "$({dnf} '
            'repoquery --location "$nevra" < /dev/null | head -n 1)"',
            'done < "$dest.list"',
        )
    )


def parse_resolution(text: str, release: str) -> dict[str, Any]:
    """The closure :func:`resolve_command` printed, as the driver records it.

    Every downloaded file must have its NEVRA, digest and size, a signature
    ``rpm -K`` finds good, and a location inside the release repository;
    anything else raises ``ValueError``, so that a closure is never recorded
    from a resolution that went wrong.
    """
    repo = repository(release)
    in_image: dict[str, str | None] = {}
    packages: dict[str, dict[str, Any]] = {}
    checks: dict[str, str] = {}
    locations: dict[str, str] = {}
    for line in text.splitlines():
        match = _LINE.match(line.strip())
        if match is None:
            continue
        kind, rest = match["kind"], match["rest"]
        if kind == "in-image":
            name, _, answer = rest.partition(" ")
            installed = not answer.startswith("package ") and " " not in answer
            in_image[name] = answer if installed and answer else None
        elif kind == "package":
            parts = rest.split(" ")
            if len(parts) != 4:
                raise ValueError(f"malformed package line: {line!r}")
            file, nevra, digest, size = parts
            if not re.fullmatch(r"[0-9a-f]{64}", digest) or not size.isdigit():
                raise ValueError(f"malformed package line: {line!r}")
            packages[file] = {
                "file": file,
                "nevra": nevra,
                "sha256": digest,
                "size": int(size),
            }
        elif kind == "checksig":
            file, _, answer = rest.partition(" ")
            checks[file] = answer
        else:
            file, _, url = rest.partition(" ")
            locations[file] = url.strip()
    if not packages:
        raise ValueError("the resolution downloaded no package")
    for file, package in packages.items():
        check = checks.get(file, "")
        if "signatures OK" not in check or "NOT OK" in check:
            raise ValueError(
                f"{file}: rpm -K does not find its signature good: {check}"
            )
        url = locations.get(file, "")
        if not url.startswith(repo) or not url.endswith("/" + file):
            raise ValueError(f"{file}: its location is not in {repo}: {url!r}")
        package["path"] = url[len(repo) :]
    return {
        "release": release,
        "repository": repo,
        "requested": sorted(in_image),
        "inImage": dict(sorted(in_image.items())),
        "weakDependencies": False,
        "packages": sorted(packages.values(), key=lambda p: str(p["file"])),
    }


def install_command(share: str, requested: Sequence[str] = REQUESTED) -> str:
    """The guest command that installs the shared closure with every
    repository disabled, the release key imported as dnf imports it on a
    first install, and then says what is installed of ``requested``."""
    names = " ".join(shlex.quote(name) for name in requested)
    return (
        f"{find_key('$(rpm -E %fedora)')}; "
        'rpm --import "$key" && '
        "dnf --assumeyes --disablerepo='*' --setopt=install_weak_deps=False "
        f"install {shlex.quote(share)}/*.rpm && rpm -q {names}"
    )


def resolution_json(record: dict[str, Any]) -> str:
    """The record as the driver writes it."""
    return json.dumps(record, indent=2, sort_keys=True) + "\n"
