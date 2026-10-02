#!/usr/bin/env python3
"""Check a release tag against its tree, write its notes, complete its SBOM.

release.yml runs this from a checkout of the tag. Two subcommands:

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
from dataclasses import dataclass
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

TARGET_TRIPLE = "x86_64-unknown-linux-musl"
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


def add_musl(sbom: dict[str, Any], version: str, musl_version: str) -> None:
    """Record musl as a statically linked dependency of the nails binary."""
    if not _MUSL_VERSION.fullmatch(musl_version):
        raise ReleaseError(f"musl version {musl_version!r} is not X.Y.Z")
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

    ref = f"pkg:generic/musl@{musl_version}"
    components.append(
        {
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
            "externalReferences": [
                {"type": "website", "url": "https://musl.libc.org"},
                {
                    "type": "distribution",
                    "url": (
                        f"https://musl.libc.org/releases/musl-{musl_version}.tar.gz"
                    ),
                },
            ],
        }
    )
    dependencies = sbom.setdefault("dependencies", [])
    entry = next((d for d in dependencies if d.get("ref") == root["bom-ref"]), None)
    if entry is None:
        entry = {"ref": root["bom-ref"], "dependsOn": []}
        dependencies.append(entry)
    entry.setdefault("dependsOn", []).append(ref)
    dependencies.append({"ref": ref, "dependsOn": []})


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
    try:
        sbom = json.loads(args.sbom.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as err:
        raise OSError(f"cannot read {args.sbom}: {err}") from err
    add_musl(sbom, args.version, args.musl_version)
    args.output.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
    print(f"{args.output}: added musl {args.musl_version}", file=sys.stderr)
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

    libc = sub.add_parser("sbom-libc", help="add musl to the SBOM")
    libc.add_argument("--sbom", type=Path, required=True, help="cargo-cyclonedx output")
    libc.add_argument("--version", required=True, help="the nails version")
    libc.add_argument("--musl-version", required=True, help="the linked musl")
    libc.add_argument("--output", type=Path, required=True, help="completed SBOM")
    libc.set_defaults(run=_sbom_libc)

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
