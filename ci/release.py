#!/usr/bin/env python3
"""Check a release tag against its tree, write its notes, complete its SBOM.

release.yml runs this from a checkout of the tag. Three subcommands:

check
    Fails unless the tag is ``v`` plus the workspace version, that version is
    not a ``-dev`` version, every workspace package in Cargo.lock carries it,
    and CHANGELOG.md has a non-empty section for it. Writes the release notes
    (that section and a pointer to docs/verify-release.md) to ``--notes`` and
    prints ``version=`` and ``prerelease=`` lines, the format of
    ``$GITHUB_OUTPUT``.
sbom-libc
    Adds musl to the CycloneDX SBOM of the nails binary. cargo-cyclonedx only
    sees crates, but the release binary links musl statically, so the C
    library it ships would otherwise be missing from the bill of materials.
    The musl component carries a CPE, so scanners match it against
    vulnerability data. Each ``--musl-cve`` names a vulnerability that the
    linked musl is patched against on top of its release; the SBOM records it
    as a backported fix in the component's pedigree. Also gives the SBOM the
    serial number that actions/attest requires and cargo-cyclonedx leaves out
    under SOURCE_DATE_EPOCH: a UUIDv5 of the file's download URL on the
    release, the same on every run for the tag.
musl-vex
    Writes an OpenVEX document that marks each ``--musl-cve`` as fixed in the
    linked musl. Scanners ignore the SBOM's pedigree, so without this
    document they report the patched CVEs as open (``grype --vex`` reads it).

Every check runs before the first build, so a mistake costs one short job
instead of a release run.

Exit status: 0 on success, 1 when a check fails, 2 when an input is missing
or unreadable.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Semantic versioning without build metadata, which a tag cannot express
# usefully and cargo ignores for ordering.
_VERSION = re.compile(
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)
# A Keep a Changelog release heading: "## [0.3.0] - 2026-10-02"; the date is
# optional so a forgotten one never costs a version number.
_SECTION = re.compile(r"##\s+\[(?P<version>[^\]]+)\](?:\s+-\s+\S.*)?\s*")
# The next section, or the link reference definitions that end the file.
_SECTION_END = re.compile(r"(##\s|\[[^\]]+\]:\s)")
_LIST_ITEM = re.compile(r"([-*+]|\d+[.)])\s")
_MUSL_VERSION = re.compile(r"\d+\.\d+\.\d+")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")

TARGET_TRIPLE = "x86_64-unknown-linux-musl"
SBOM_ASSET = "sbom.cdx.json"
VEX_ASSET = "musl.openvex.json"
_OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
BINARY = "nails"
_TRIPLE_PROPERTY = "cdx:rustc:sbom:target:triple"


class ReleaseError(Exception):
    """The tag, the tree or the SBOM is not fit for a release."""


@dataclass(frozen=True)
class Release:
    tag: str
    version: str
    prerelease: bool


def _toml(text: str, name: str) -> dict[str, Any]:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as err:
        raise ReleaseError(f"{name} is not valid TOML: {err}") from err


def workspace_version(cargo_toml: str) -> str:
    """Return ``[workspace.package] version`` of the root Cargo.toml."""
    workspace = _toml(cargo_toml, "Cargo.toml").get("workspace", {})
    version = workspace.get("package", {}).get("version")
    if not isinstance(version, str):
        raise ReleaseError("Cargo.toml has no [workspace.package] version")
    return version


def check_version(tag: str, version: str) -> Release:
    """Match the tag with the version and classify the release."""
    match = _VERSION.fullmatch(version)
    if not match:
        raise ReleaseError(f"workspace version {version!r} is not X.Y.Z[-pre]")
    if tag != f"v{version}":
        raise ReleaseError(
            f"tag {tag!r} does not match the workspace version {version!r}; "
            f"the tag for this tree is v{version}"
        )
    pre = match["pre"]
    if pre is not None and "dev" in pre.split("."):
        raise ReleaseError(
            f"{version} marks main between releases and is never released; "
            "set the release version (X.Y.Z or X.Y.Z-rc.N) first"
        )
    return Release(tag=tag, version=version, prerelease=pre is not None)


def stale_lock_packages(cargo_lock: str, version: str) -> list[str]:
    """Name the workspace packages whose Cargo.lock entry lacks ``version``.

    Packages without a ``source`` are the workspace's own. A version bump
    committed without Cargo.lock leaves them behind, and the release build
    runs cargo with --locked, so it would fail an hour later.
    """
    packages = _toml(cargo_lock, "Cargo.lock").get("package", [])
    local = [p for p in packages if isinstance(p, dict) and "source" not in p]
    if not local:
        raise ReleaseError("Cargo.lock lists no workspace package")
    return sorted(
        f"{p.get('name')} {p.get('version')}"
        for p in local
        if p.get("version") != version
    )


def changelog_section(changelog: str, version: str) -> str:
    """Return the body of the ``## [version]`` section of CHANGELOG.md."""
    lines = changelog.splitlines()
    start = next(
        (
            index
            for index, line in enumerate(lines)
            if (match := _SECTION.fullmatch(line)) and match["version"] == version
        ),
        None,
    )
    if start is None:
        raise ReleaseError(
            f"CHANGELOG.md has no '## [{version}] - YYYY-MM-DD' section; "
            "rename [Unreleased] to it before tagging"
        )
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if _SECTION_END.match(lines[index])
        ),
        len(lines),
    )
    body = "\n".join(lines[start + 1 : end]).strip()
    if not body:
        raise ReleaseError(f"the CHANGELOG.md section for {version} is empty")
    return body


def unwrap(markdown: str) -> str:
    """Join the indented continuation lines of hard-wrapped list items.

    CHANGELOG.md wraps at 100 columns, but a release page renders every
    newline as a line break, which would split each long entry mid-sentence.
    Fenced code blocks and new list items stay as they are.
    """
    out: list[str] = []
    fenced = False
    for line in markdown.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            fenced = not fenced
        elif (
            not fenced
            and line[:1].isspace()
            and stripped
            and out
            and out[-1].strip()
            and not out[-1].lstrip().startswith("```")
            and not _LIST_ITEM.match(stripped)
        ):
            out[-1] = f"{out[-1]} {stripped}"
            continue
        out.append(line)
    return "\n".join(out)


def release_notes(section: str, tag: str, repo: str) -> str:
    """Append the verification pointer to a CHANGELOG section."""
    guide = f"https://github.com/{repo}/blob/{tag}/docs/verify-release.md"
    return (
        f"{unwrap(section)}\n\n"
        "---\n\n"
        "Verify what you download before you run it, and not on the decoy "
        f"system: see [docs/verify-release.md]({guide}).\n"
    )


def check_release(source: Path, tag: str) -> tuple[Release, str]:
    """Run every check on the tree at ``source``; return the release and section."""
    try:
        cargo_toml = (source / "Cargo.toml").read_text(encoding="utf-8")
        cargo_lock = (source / "Cargo.lock").read_text(encoding="utf-8")
        changelog = (source / "CHANGELOG.md").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as err:
        raise OSError(f"cannot read the release inputs: {err}") from err
    release = check_version(tag, workspace_version(cargo_toml))
    stale = stale_lock_packages(cargo_lock, release.version)
    if stale:
        raise ReleaseError(
            f"Cargo.lock still records {', '.join(stale)}; run 'cargo update "
            f"--workspace' and commit Cargo.lock with the {release.version} bump"
        )
    return release, changelog_section(changelog, release.version)


def _check_musl(musl_version: str, cves: Sequence[str]) -> None:
    if not _MUSL_VERSION.fullmatch(musl_version):
        raise ReleaseError(f"musl version {musl_version!r} is not X.Y.Z")
    for cve in cves:
        if not _CVE.fullmatch(cve):
            raise ReleaseError(f"{cve!r} is not a CVE ID")


def musl_purl(musl_version: str) -> str:
    return f"pkg:generic/musl@{musl_version}"


def musl_cpe(musl_version: str) -> str:
    """The CPE under which NVD lists musl's vulnerabilities."""
    return f"cpe:2.3:a:musl-libc:musl:{musl_version}:*:*:*:*:*:*:*"


def add_musl(
    sbom: dict[str, Any],
    version: str,
    musl_version: str,
    cves: Sequence[str] = (),
) -> None:
    """Record musl as a statically linked dependency of the nails binary.

    ``cves`` are the vulnerabilities the linked musl carries fixes for on top
    of ``musl_version``; each becomes a backported patch in its pedigree.
    """
    _check_musl(musl_version, cves)
    root = sbom.get("metadata", {}).get("component", {})
    if root.get("name") != BINARY or root.get("version") != version:
        raise ReleaseError(
            f"the SBOM describes {root.get('name')} {root.get('version')}, "
            f"not {BINARY} {version}"
        )
    triples = {
        prop.get("value")
        for prop in sbom.get("metadata", {}).get("properties", [])
        if prop.get("name") == _TRIPLE_PROPERTY
    }
    if triples != {TARGET_TRIPLE}:
        raise ReleaseError(
            f"the SBOM was generated for {sorted(map(str, triples))}, "
            f"not {TARGET_TRIPLE}"
        )
    components = sbom.setdefault("components", [])
    if any(component.get("name") == "musl" for component in components):
        raise ReleaseError("the SBOM already lists musl")

    ref = musl_purl(musl_version)
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": ref,
        "name": "musl",
        "version": musl_version,
        "description": (
            f"C standard library, statically linked into {BINARY} ({TARGET_TRIPLE})"
        ),
        "scope": "required",
        "licenses": [{"license": {"id": "MIT"}}],
        "purl": ref,
        "cpe": musl_cpe(musl_version),
        "externalReferences": [
            {"type": "website", "url": "https://musl.libc.org"},
            {
                "type": "distribution",
                "url": f"https://musl.libc.org/releases/musl-{musl_version}.tar.gz",
            },
        ],
    }
    if cves:
        component["pedigree"] = {
            "patches": [
                {
                    "type": "backport",
                    "resolves": [
                        {
                            "type": "security",
                            "id": cve,
                            "source": {
                                "name": "NVD",
                                "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                            },
                        }
                    ],
                }
                for cve in sorted(set(cves))
            ],
            "notes": (
                f"The release links musl {musl_version} as nixpkgs builds it, "
                "with these fixes applied on top of the release."
            ),
        }
    components.append(component)
    dependencies = sbom.setdefault("dependencies", [])
    entry = next((d for d in dependencies if d.get("ref") == root["bom-ref"]), None)
    if entry is None:
        entry = {"ref": root["bom-ref"], "dependsOn": []}
        dependencies.append(entry)
    entry.setdefault("dependsOn", []).append(ref)
    dependencies.append({"ref": ref, "dependsOn": []})


def asset_url(repo: str, tag: str, asset: str) -> str:
    """Where ``asset`` of the release ``tag`` is downloaded once published."""
    return f"https://github.com/{repo}/releases/download/{tag}/{asset}"


def sbom_serial_number(repo: str, tag: str) -> str:
    """The serial number of the release's SBOM, as a ``urn:uuid:`` URN.

    cargo-cyclonedx leaves out its random serial number under
    SOURCE_DATE_EPOCH to keep the file reproducible, and actions/attest
    refuses a CycloneDX SBOM without one. A UUIDv5 of the file's download URL
    is the same on every run for the tag and differs from release to release.
    """
    name = asset_url(repo, tag, SBOM_ASSET)
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, name)}"


def with_serial_number(sbom: dict[str, Any], serial: str) -> dict[str, Any]:
    """Return ``sbom`` with ``serial`` as its serial number.

    The field goes after ``version``, where cargo-cyclonedx writes it. A
    serial number already there is replaced, so the result does not depend on
    whether the generator wrote a random one.
    """
    completed: dict[str, Any] = {}
    for key, value in sbom.items():
        if key != "serialNumber":
            completed[key] = value
        if key == "version":
            completed["serialNumber"] = serial
    completed.setdefault("serialNumber", serial)
    return completed


def musl_vex(
    musl_version: str, cves: Sequence[str], repo: str, tag: str, epoch: int
) -> dict[str, Any]:
    """An OpenVEX document that marks each CVE as fixed in the linked musl.

    The product is musl itself, not nails: grype applies a statement only to
    the package it names. ``epoch`` is the tagged commit's time, so the
    document is the same for every run on the tag.
    """
    _check_musl(musl_version, cves)
    purl = musl_purl(musl_version)
    return {
        "@context": _OPENVEX_CONTEXT,
        "@id": asset_url(repo, tag, VEX_ASSET),
        "author": f"https://github.com/{repo}",
        "timestamp": datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": 1,
        "statements": [
            {
                "vulnerability": {"name": cve},
                "products": [
                    {
                        "@id": purl,
                        "identifiers": {"purl": purl, "cpe23": musl_cpe(musl_version)},
                    }
                ],
                "status": "fixed",
                "status_notes": (
                    f"{BINARY} {tag} links musl {musl_version} as nixpkgs builds "
                    "it, with a backported fix for this vulnerability."
                ),
            }
            for cve in sorted(set(cves))
        ],
    }


def _check(args: argparse.Namespace) -> int:
    release, section = check_release(args.source, args.tag)
    notes = release_notes(section, release.tag, args.repo)
    args.notes.write_text(notes, encoding="utf-8")
    print(f"version={release.version}")
    print(f"prerelease={'true' if release.prerelease else 'false'}")
    kind = "prerelease" if release.prerelease else "release"
    print(f"{release.tag}: {kind} {release.version}", file=sys.stderr)
    return 0


def _sbom_libc(args: argparse.Namespace) -> int:
    if args.tag != f"v{args.version}":
        raise ReleaseError(
            f"tag {args.tag!r} is not v{args.version}, the tag of nails {args.version}"
        )
    try:
        sbom = json.loads(args.sbom.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as err:
        raise OSError(f"cannot read {args.sbom}: {err}") from err
    add_musl(sbom, args.version, args.musl_version, args.musl_cve)
    serial = sbom_serial_number(args.repo, args.tag)
    sbom = with_serial_number(sbom, serial)
    args.output.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
    fixes = f" with fixes for {', '.join(args.musl_cve)}" if args.musl_cve else ""
    print(
        f"{args.output}: added musl {args.musl_version}{fixes}; serial number {serial}",
        file=sys.stderr,
    )
    return 0


def _musl_vex(args: argparse.Namespace) -> int:
    vex = musl_vex(args.musl_version, args.musl_cve, args.repo, args.tag, args.epoch)
    args.output.write_text(json.dumps(vex, indent=2) + "\n", encoding="utf-8")
    fixed = ", ".join(s["vulnerability"]["name"] for s in vex["statements"])
    print(
        f"{args.output}: musl {args.musl_version} fixed: {fixed or 'none'}",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="check the tag and write the notes")
    check.add_argument("--tag", required=True, help="the release tag, vX.Y.Z")
    check.add_argument(
        "--source", type=Path, default=Path("."), help="checkout of the tag"
    )
    check.add_argument("--repo", required=True, help="OWNER/NAME on GitHub")
    check.add_argument(
        "--notes", type=Path, required=True, help="where to write the notes"
    )
    check.set_defaults(run=_check)

    libc = sub.add_parser(
        "sbom-libc", help="add musl and the serial number to the SBOM"
    )
    libc.add_argument("--sbom", type=Path, required=True, help="cargo-cyclonedx output")
    libc.add_argument("--version", required=True, help="the nails version")
    libc.add_argument("--musl-version", required=True, help="the linked musl")
    libc.add_argument(
        "--musl-cve",
        action="append",
        default=[],
        help="a CVE the linked musl is patched against; repeatable",
    )
    libc.add_argument("--repo", required=True, help="OWNER/NAME on GitHub")
    libc.add_argument("--tag", required=True, help="the release tag, v<version>")
    libc.add_argument("--output", type=Path, required=True, help="completed SBOM")
    libc.set_defaults(run=_sbom_libc)

    vex = sub.add_parser("musl-vex", help="mark musl's patched CVEs as fixed")
    vex.add_argument("--musl-version", required=True, help="the linked musl")
    vex.add_argument(
        "--musl-cve",
        action="append",
        default=[],
        help="a CVE the linked musl is patched against; repeatable",
    )
    vex.add_argument("--repo", required=True, help="OWNER/NAME on GitHub")
    vex.add_argument("--tag", required=True, help="the release tag, vX.Y.Z")
    vex.add_argument(
        "--epoch", type=int, required=True, help="the tagged commit's Unix time"
    )
    vex.add_argument("--output", type=Path, required=True, help="the document")
    vex.set_defaults(run=_musl_vex)

    args = parser.parse_args(argv)
    try:
        return int(args.run(args))
    except ReleaseError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    except OSError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
