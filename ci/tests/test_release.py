"""Tests for ci/release.py, the checks and notes of the release workflow."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from ci import release
from ci.release import ReleaseError

CARGO_TOML = """\
[workspace]
members = ["nails-cli", "nails-core"]

[workspace.package]
version = "{version}"
"""

CARGO_LOCK = """\
version = 4

[[package]]
name = "clap"
version = "4.6.1"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "nails-cli"
version = "{cli}"

[[package]]
name = "nails-core"
version = "{core}"
"""

CHANGELOG = """\
# Changelog

## [Unreleased]

### Added
- Something not yet released.

## [0.3.0] - 2026-10-02

### Added
- A single release workflow.

### Fixed
- The archive name.

## [0.2.0] - 2026-05-08

### Changed
- Bumped the version.

## Contributing

See CONTRIBUTING.md.
"""


def sbom(version: str = "0.3.0", triple: str = release.TARGET_TRIPLE) -> dict[str, Any]:
    """Return the skeleton of a cargo-cyclonedx SBOM of the nails binary."""
    root = "path+file:///work/nails-cli#" + version
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root,
                "name": "nails",
                "version": version,
            },
            "properties": [{"name": "cdx:rustc:sbom:target:triple", "value": triple}],
        },
        "components": [
            {"type": "library", "bom-ref": "registry#clap@4.6.1", "name": "clap"}
        ],
        "dependencies": [
            {"ref": root, "dependsOn": ["registry#clap@4.6.1"]},
            {"ref": "registry#clap@4.6.1", "dependsOn": []},
        ],
    }


class VersionTest(unittest.TestCase):
    def test_stable_tag_matches(self) -> None:
        self.assertEqual(
            release.check_version("v0.3.0", "0.3.0"),
            release.Release("v0.3.0", "0.3.0", prerelease=False),
        )

    def test_suffixed_version_is_a_prerelease(self) -> None:
        for version in ("0.3.0-rc.1", "1.0.0-beta.2", "1.0.0-alpha"):
            with self.subTest(version=version):
                found = release.check_version(f"v{version}", version)
                self.assertTrue(found.prerelease)

    def test_mismatched_tag_fails_and_names_the_right_one(self) -> None:
        for tag in ("v0.3.1", "0.3.0", "v0.3.0-rc.1", "release-0.3.0", "v0.3"):
            with self.subTest(tag=tag):
                with self.assertRaisesRegex(
                    ReleaseError, "the tag for this tree is v0.3.0"
                ):
                    release.check_version(tag, "0.3.0")

    def test_dev_version_is_never_released(self) -> None:
        for version in ("0.4.0-dev", "0.4.0-dev.1"):
            with self.subTest(version=version):
                with self.assertRaisesRegex(ReleaseError, "never released"):
                    release.check_version(f"v{version}", version)

    def test_development_in_an_identifier_is_not_dev(self) -> None:
        self.assertTrue(release.check_version("v1.0.0-devel", "1.0.0-devel").prerelease)

    def test_malformed_version_fails(self) -> None:
        for version in ("0.3", "01.2.3", "0.3.0+build.1", "0.3.0-", "0.3.0-rc..1"):
            with self.subTest(version=version):
                with self.assertRaisesRegex(ReleaseError, "is not X.Y.Z"):
                    release.check_version(f"v{version}", version)

    def test_workspace_version_is_read_from_the_manifest(self) -> None:
        self.assertEqual(
            release.workspace_version(CARGO_TOML.format(version="0.3.0")), "0.3.0"
        )

    def test_manifest_without_a_workspace_version_fails(self) -> None:
        with self.assertRaisesRegex(ReleaseError, r"no \[workspace.package\] version"):
            release.workspace_version('[package]\nname = "x"\nversion = "1.0.0"\n')

    def test_invalid_manifest_fails(self) -> None:
        with self.assertRaisesRegex(ReleaseError, "Cargo.toml is not valid TOML"):
            release.workspace_version("[workspace\n")


class LockfileTest(unittest.TestCase):
    def test_current_lockfile_passes(self) -> None:
        lock = CARGO_LOCK.format(cli="0.3.0", core="0.3.0")
        self.assertEqual(release.stale_lock_packages(lock, "0.3.0"), [])

    def test_stale_workspace_packages_are_named(self) -> None:
        lock = CARGO_LOCK.format(cli="0.2.0", core="0.3.0")
        self.assertEqual(
            release.stale_lock_packages(lock, "0.3.0"), ["nails-cli 0.2.0"]
        )

    def test_registry_packages_are_ignored(self) -> None:
        lock = CARGO_LOCK.format(cli="4.6.1", core="4.6.1")
        self.assertEqual(release.stale_lock_packages(lock, "4.6.1"), [])

    def test_lockfile_without_workspace_packages_fails(self) -> None:
        lock = (
            'version = 4\n\n[[package]]\nname = "a"\nversion = "1.0.0"\nsource = "x"\n'
        )
        with self.assertRaisesRegex(ReleaseError, "no workspace package"):
            release.stale_lock_packages(lock, "1.0.0")


class ChangelogTest(unittest.TestCase):
    def test_section_runs_to_the_next_release(self) -> None:
        self.assertEqual(
            release.changelog_section(CHANGELOG, "0.3.0"),
            "### Added\n- A single release workflow.\n\n### Fixed\n- The archive name.",
        )

    def test_last_section_stops_at_a_non_release_heading(self) -> None:
        self.assertEqual(
            release.changelog_section(CHANGELOG, "0.2.0"),
            "### Changed\n- Bumped the version.",
        )

    def test_section_stops_at_link_reference_definitions(self) -> None:
        text = (
            "## [1.0.0] - 2027-01-01\n\n- Done.\n\n"
            "[1.0.0]: https://example.invalid/compare/v0.9.0...v1.0.0\n"
        )
        self.assertEqual(release.changelog_section(text, "1.0.0"), "- Done.")

    def test_date_is_optional(self) -> None:
        text = "## [1.0.0]\n\n- Done.\n"
        self.assertEqual(release.changelog_section(text, "1.0.0"), "- Done.")

    def test_version_must_match_exactly(self) -> None:
        text = "## [0.3.0-rc.1] - 2026-09-30\n\n- Candidate.\n"
        with self.assertRaisesRegex(ReleaseError, r"no '## \[0.3.0\] - YYYY-MM-DD'"):
            release.changelog_section(text, "0.3.0")

    def test_unreleased_changes_are_not_a_release(self) -> None:
        with self.assertRaisesRegex(ReleaseError, r"rename \[Unreleased\]"):
            release.changelog_section(CHANGELOG, "0.4.0")

    def test_empty_section_fails(self) -> None:
        text = "## [1.0.0] - 2027-01-01\n\n\n## [0.9.0] - 2026-12-01\n\n- Old.\n"
        with self.assertRaisesRegex(ReleaseError, "section for 1.0.0 is empty"):
            release.changelog_section(text, "1.0.0")

    def test_notes_end_with_the_verification_guide_of_the_tag(self) -> None:
        notes = release.release_notes("- Done.", "v1.0.0", "owner/nails")
        self.assertTrue(notes.startswith("- Done.\n\n---\n\n"))
        self.assertIn(
            "(https://github.com/owner/nails/blob/v1.0.0/docs/verify-release.md)",
            notes,
        )
        self.assertIn("not on the decoy", notes)

    def test_wrapped_list_items_become_one_line(self) -> None:
        section = (
            "### Fixed\n"
            "- The archive is named after the\n"
            "  version alone.\n"
            "  - A nested item\n"
            "    that wraps.\n"
            "1. A numbered item\n"
            "   that wraps.\n"
            "\n"
            "A paragraph line\n"
            "next to another."
        )
        self.assertEqual(
            release.unwrap(section),
            "### Fixed\n"
            "- The archive is named after the version alone.\n"
            "  - A nested item that wraps.\n"
            "1. A numbered item that wraps.\n"
            "\n"
            "A paragraph line\n"
            "next to another.",
        )

    def test_fenced_code_is_left_alone(self) -> None:
        section = "- Run:\n\n  ```bash\n  nails check\n    --json\n  ```\n  after it."
        self.assertEqual(release.unwrap(section), section)

    def test_notes_unwrap_the_section(self) -> None:
        notes = release.release_notes("- One\n  entry.", "v1.0.0", "owner/nails")
        self.assertTrue(notes.startswith("- One entry.\n\n---"))


class CheckCommandTest(unittest.TestCase):
    def tree(self, version: str, lock_version: str | None = None) -> Path:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        locked = lock_version or version
        (root / "Cargo.toml").write_text(CARGO_TOML.format(version=version))
        (root / "Cargo.lock").write_text(CARGO_LOCK.format(cli=locked, core=locked))
        (root / "CHANGELOG.md").write_text(CHANGELOG)
        return root

    def run_check(self, root: Path, tag: str) -> tuple[int, str, str, Path]:
        notes = root / "notes.md"
        out, err = io.StringIO(), io.StringIO()
        argv = [
            "check",
            "--tag",
            tag,
            "--source",
            str(root),
            "--repo",
            "owner/nails",
            "--notes",
            str(notes),
        ]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = release.main(argv)
        return code, out.getvalue(), err.getvalue(), notes

    def test_release_prints_outputs_and_writes_notes(self) -> None:
        code, out, _, notes = self.run_check(self.tree("0.3.0"), "v0.3.0")
        self.assertEqual(code, 0)
        self.assertEqual(out, "version=0.3.0\nprerelease=false\n")
        self.assertTrue(notes.read_text().startswith("### Added\n- A single release"))

    def test_mismatched_tag_fails_before_writing_notes(self) -> None:
        code, out, err, notes = self.run_check(self.tree("0.3.0"), "v0.3.1")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("does not match the workspace version", err)
        self.assertFalse(notes.exists())

    def test_stale_lockfile_fails(self) -> None:
        code, _, err, _ = self.run_check(self.tree("0.3.0", "0.2.0"), "v0.3.0")
        self.assertEqual(code, 1)
        self.assertIn("Cargo.lock still records nails-cli 0.2.0, nails-core 0.2.0", err)

    def test_missing_changelog_section_fails(self) -> None:
        code, _, err, _ = self.run_check(self.tree("0.4.0"), "v0.4.0")
        self.assertEqual(code, 1)
        self.assertIn("no '## [0.4.0]", err)

    def test_missing_input_is_exit_2(self) -> None:
        root = self.tree("0.3.0")
        (root / "CHANGELOG.md").unlink()
        code, _, err, _ = self.run_check(root, "v0.3.0")
        self.assertEqual(code, 2)
        self.assertIn("cannot read the release inputs", err)


class MuslTest(unittest.TestCase):
    def test_musl_becomes_a_component_and_a_dependency_of_nails(self) -> None:
        bom = sbom()
        release.add_musl(bom, "0.3.0", "1.2.5")
        musl = bom["components"][-1]
        self.assertEqual(musl["name"], "musl")
        self.assertEqual(musl["version"], "1.2.5")
        self.assertEqual(musl["bom-ref"], "pkg:generic/musl@1.2.5")
        self.assertEqual(musl["licenses"], [{"license": {"id": "MIT"}}])
        root = bom["metadata"]["component"]["bom-ref"]
        depends = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
        self.assertEqual(
            depends[root], ["registry#clap@4.6.1", "pkg:generic/musl@1.2.5"]
        )
        self.assertEqual(depends["pkg:generic/musl@1.2.5"], [])

    def test_missing_dependency_entry_of_nails_is_created(self) -> None:
        bom = sbom()
        bom["dependencies"] = []
        release.add_musl(bom, "0.3.0", "1.2.5")
        root = bom["metadata"]["component"]["bom-ref"]
        self.assertIn(
            {"ref": root, "dependsOn": ["pkg:generic/musl@1.2.5"]}, bom["dependencies"]
        )

    def test_sbom_of_another_version_fails(self) -> None:
        with self.assertRaisesRegex(
            ReleaseError, "describes nails 0.2.0, not nails 0.3.0"
        ):
            release.add_musl(sbom("0.2.0"), "0.3.0", "1.2.5")

    def test_sbom_of_the_host_target_fails(self) -> None:
        with self.assertRaisesRegex(ReleaseError, "x86_64-unknown-linux-gnu"):
            release.add_musl(sbom(triple="x86_64-unknown-linux-gnu"), "0.3.0", "1.2.5")

    def test_musl_is_added_once(self) -> None:
        bom = sbom()
        release.add_musl(bom, "0.3.0", "1.2.5")
        before = copy.deepcopy(bom)
        with self.assertRaisesRegex(ReleaseError, "already lists musl"):
            release.add_musl(bom, "0.3.0", "1.2.5")
        self.assertEqual(bom, before)

    def test_malformed_musl_version_fails(self) -> None:
        for version in ("", "1.2", "1.2.5\n", "latest"):
            with self.subTest(version=version):
                with self.assertRaisesRegex(ReleaseError, "is not X.Y.Z"):
                    release.add_musl(sbom(), "0.3.0", version)

    def test_without_cves_musl_has_no_pedigree(self) -> None:
        bom = sbom()
        release.add_musl(bom, "0.3.0", "1.2.6")
        self.assertNotIn("pedigree", bom["components"][-1])

    def test_each_cve_becomes_a_backported_security_fix(self) -> None:
        bom = sbom()
        cves = ["CVE-2026-6042", "CVE-2026-40200", "CVE-2026-6042"]
        release.add_musl(bom, "0.3.0", "1.2.6", cves)
        patches = bom["components"][-1]["pedigree"]["patches"]
        self.assertEqual([p["type"] for p in patches], ["backport", "backport"])
        resolves = [r for p in patches for r in p["resolves"]]
        self.assertEqual(
            [r["id"] for r in resolves], ["CVE-2026-40200", "CVE-2026-6042"]
        )
        self.assertEqual({r["type"] for r in resolves}, {"security"})
        self.assertEqual(
            resolves[1]["source"],
            {"name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-6042"},
        )

    def test_malformed_cve_fails_before_the_sbom_changes(self) -> None:
        for cve in ("", "CVE-2026-1", "cve-2026-6042", "CVE-2026-6042\n", "GHSA-x"):
            with self.subTest(cve=cve):
                bom = sbom()
                before = copy.deepcopy(bom)
                with self.assertRaisesRegex(ReleaseError, "is not a CVE ID"):
                    release.add_musl(bom, "0.3.0", "1.2.6", [cve])
                self.assertEqual(bom, before)

    def test_command_records_repeated_musl_cves(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        source, output = root / "in.cdx.json", root / "sbom.cdx.json"
        source.write_text(json.dumps(sbom()))
        argv = [
            "sbom-libc",
            "--sbom",
            str(source),
            "--version",
            "0.3.0",
            "--musl-version",
            "1.2.6",
            "--musl-cve",
            "CVE-2026-6042",
            "--musl-cve",
            "CVE-2026-40200",
            "--output",
            str(output),
        ]
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(release.main(argv), 0)
        musl = json.loads(output.read_text())["components"][-1]
        ids = [r["id"] for p in musl["pedigree"]["patches"] for r in p["resolves"]]
        self.assertEqual(ids, ["CVE-2026-40200", "CVE-2026-6042"])
        self.assertIn("with fixes for CVE-2026-6042, CVE-2026-40200", err.getvalue())

    def test_command_writes_the_completed_sbom(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        source, output = root / "in.cdx.json", root / "sbom.cdx.json"
        source.write_text(json.dumps(sbom()))
        argv = [
            "sbom-libc",
            "--sbom",
            str(source),
            "--version",
            "0.3.0",
            "--musl-version",
            "1.2.5",
            "--output",
            str(output),
        ]
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(release.main(argv), 0)
        names = [c["name"] for c in json.loads(output.read_text())["components"]]
        self.assertEqual(names, ["clap", "musl"])

    def test_command_rejects_unreadable_json(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        source = root / "in.cdx.json"
        source.write_text("{")
        argv = [
            "sbom-libc",
            "--sbom",
            str(source),
            "--version",
            "0.3.0",
            "--musl-version",
            "1.2.5",
            "--output",
            str(root / "out.json"),
        ]
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(release.main(argv), 2)
        self.assertIn("cannot read", err.getvalue())


if __name__ == "__main__":
    unittest.main()
