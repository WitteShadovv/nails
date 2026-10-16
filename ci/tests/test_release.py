"""Tests for ci/release.py, the checks and notes of the release workflow."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import re
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Any
from unittest import mock

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

# serialNumber as the CycloneDX 1.5 JSON schema defines it: a UUID URN.
CYCLONEDX_SERIAL = re.compile(
    r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


def sbom(version: str = "0.3.0", triple: str = release.TARGET_TRIPLE) -> dict[str, Any]:
    """Return the skeleton of a cargo-cyclonedx SBOM of the nails binary."""
    root = "path+file:///work/nails-cli#" + version
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
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

    def test_musl_carries_the_cpe_nvd_lists_it_under(self) -> None:
        bom = sbom()
        release.add_musl(bom, "0.3.0", "1.2.6")
        self.assertEqual(
            bom["components"][-1]["cpe"],
            "cpe:2.3:a:musl-libc:musl:1.2.6:*:*:*:*:*:*:*",
        )

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
            "--repo",
            "o/n",
            "--tag",
            "v0.3.0",
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
            "--repo",
            "o/n",
            "--tag",
            "v0.3.0",
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
            "--repo",
            "o/n",
            "--tag",
            "v0.3.0",
            "--output",
            str(root / "out.json"),
        ]
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(release.main(argv), 2)
        self.assertIn("cannot read", err.getvalue())


class SerialNumberTest(unittest.TestCase):
    def test_serial_number_is_the_uuid5_of_the_download_url(self) -> None:
        serial = release.sbom_serial_number("WitteShadovv/nails", "v0.3.0-rc.2")
        # UUIDv5 in the URL namespace of
        # https://github.com/WitteShadovv/nails/releases/download/v0.3.0-rc.2/sbom.cdx.json
        self.assertEqual(serial, "urn:uuid:c08ff0fc-e839-52e9-9e20-d4068d1ebcfd")
        self.assertIsNotNone(CYCLONEDX_SERIAL.fullmatch(serial))
        self.assertEqual(uuid.UUID(serial.removeprefix("urn:uuid:")).version, 5)

    def test_serial_number_is_fixed_by_the_release(self) -> None:
        serial = release.sbom_serial_number("o/n", "v0.3.0")
        self.assertEqual(serial, release.sbom_serial_number("o/n", "v0.3.0"))
        self.assertNotEqual(serial, release.sbom_serial_number("o/n", "v0.3.1"))
        self.assertNotEqual(serial, release.sbom_serial_number("fork/n", "v0.3.0"))

    def test_serial_number_goes_after_the_bom_version(self) -> None:
        bom = release.with_serial_number(sbom(), "urn:uuid:x")
        self.assertEqual(
            list(bom),
            [
                "bomFormat",
                "specVersion",
                "version",
                "serialNumber",
                "metadata",
                "components",
                "dependencies",
            ],
        )
        self.assertEqual(bom["serialNumber"], "urn:uuid:x")

    def test_serial_number_of_the_generator_is_replaced(self) -> None:
        random = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
        generated = release.with_serial_number(sbom(), random)
        bom = release.with_serial_number(generated, "urn:uuid:x")
        self.assertEqual(list(bom), list(generated))
        self.assertEqual(bom["serialNumber"], "urn:uuid:x")
        self.assertEqual(generated["serialNumber"], random)

    def test_sbom_without_a_bom_version_still_gets_a_serial_number(self) -> None:
        bare = sbom()
        del bare["version"]
        bom = release.with_serial_number(bare, "urn:uuid:x")
        self.assertEqual(list(bom)[-1], "serialNumber")
        self.assertEqual(bom["serialNumber"], "urn:uuid:x")

    def run_libc(self, tag: str = "v0.3.0") -> tuple[int, str, Path]:
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
            "--repo",
            "o/n",
            "--tag",
            tag,
            "--output",
            str(output),
        ]
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = release.main(argv)
        return code, err.getvalue(), output

    def test_command_gives_the_sbom_the_serial_number_of_the_release(self) -> None:
        code, err, output = self.run_libc()
        self.assertEqual(code, 0)
        serial = json.loads(output.read_text())["serialNumber"]
        self.assertEqual(serial, "urn:uuid:178eae2d-133d-5030-9a6b-daecb92bcdeb")
        self.assertIn(f"serial number {serial}", err)

    def test_command_writes_the_same_file_on_every_run(self) -> None:
        self.assertEqual(
            self.run_libc()[2].read_bytes(), self.run_libc()[2].read_bytes()
        )

    def test_command_refuses_the_tag_of_another_version(self) -> None:
        code, err, output = self.run_libc(tag="v0.3.1")
        self.assertEqual(code, 1)
        self.assertIn("tag 'v0.3.1' is not v0.3.0, the tag of nails 0.3.0", err)
        self.assertFalse(output.exists())


class AttestCheckTest(unittest.TestCase):
    def completed(self) -> dict[str, Any]:
        serial = release.sbom_serial_number("o/n", "v0.3.0")
        return release.with_serial_number(sbom(), serial)

    def test_completed_sbom_passes(self) -> None:
        release.check_attestable(self.completed(), 1000)

    def test_sbom_without_a_serial_number_fails(self) -> None:
        # What cargo-cyclonedx writes under SOURCE_DATE_EPOCH.
        with self.assertRaisesRegex(
            ReleaseError, "has no serialNumber: actions/attest accepts CycloneDX only"
        ):
            release.check_attestable(sbom(), 1000)

    def test_each_field_needs_a_non_empty_string(self) -> None:
        for field in ("bomFormat", "serialNumber", "specVersion"):
            for value in (None, "", 1.5, ["CycloneDX"]):
                with self.subTest(field=field, value=value):
                    bom = self.completed()
                    bom[field] = value
                    with self.assertRaisesRegex(ReleaseError, f"has no {field}:"):
                        release.check_attestable(bom, 1000)
            with self.subTest(field=field, value="absent"):
                bom = self.completed()
                del bom[field]
                with self.assertRaisesRegex(ReleaseError, f"has no {field}:"):
                    release.check_attestable(bom, 1000)

    def test_every_missing_field_is_named(self) -> None:
        with self.assertRaisesRegex(
            ReleaseError, "has no bomFormat and no serialNumber and no specVersion:"
        ):
            release.check_attestable({"metadata": {}}, 20)

    def test_document_that_is_not_an_object_fails(self) -> None:
        documents: list[Any] = [[], "CycloneDX", None]
        for document in documents:
            with self.subTest(document=document):
                with self.assertRaisesRegex(ReleaseError, "not a JSON object"):
                    release.check_attestable(document, 20)

    def test_file_over_16_mib_fails(self) -> None:
        limit = 16 * 1024 * 1024
        release.check_attestable(self.completed(), limit)
        with self.assertRaisesRegex(
            ReleaseError, f"has {limit + 1} bytes; actions/attest takes at most {limit}"
        ):
            release.check_attestable(self.completed(), limit + 1)

    def run_check(self, path: Path) -> tuple[int, str]:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = release.main(["sbom-check", "--sbom", str(path)])
        return code, err.getvalue()

    def write(self, text: str) -> Path:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = root / "sbom.cdx.json"
        path.write_text(text)
        return path

    def test_command_accepts_what_sbom_libc_writes(self) -> None:
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
            "--repo",
            "o/n",
            "--tag",
            "v0.3.0",
            "--output",
            str(output),
        ]
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(release.main(argv), 0)
        code, err = self.run_check(output)
        self.assertEqual(code, 0)
        self.assertIn(
            "actions/attest accepts it as CycloneDX 1.5, serial number "
            "urn:uuid:178eae2d-133d-5030-9a6b-daecb92bcdeb",
            err,
        )

    def test_command_fails_on_cargo_cyclonedx_output(self) -> None:
        code, err = self.run_check(self.write(json.dumps(sbom())))
        self.assertEqual(code, 1)
        self.assertIn("error: the SBOM has no serialNumber", err)

    def test_command_checks_the_size_of_the_file(self) -> None:
        path = self.write(json.dumps(self.completed()))
        with mock.patch.object(release, "ATTEST_MAX_SBOM_BYTES", 10):
            code, err = self.run_check(path)
        self.assertEqual(code, 1)
        self.assertIn("actions/attest takes at most 10", err)

    def test_command_rejects_a_missing_or_unparsable_file(self) -> None:
        unparsable = self.write("{")
        for path in (unparsable, unparsable.with_name("absent.json")):
            with self.subTest(path=path.name):
                code, err = self.run_check(path)
                self.assertEqual(code, 2)
                self.assertIn("cannot read", err)


class MuslVexTest(unittest.TestCase):
    # 2026-10-14T00:00:00Z
    EPOCH = 1791936000

    def vex(self, cves: list[str]) -> dict[str, Any]:
        return release.musl_vex("1.2.6", cves, "o/n", "v0.3.0", self.EPOCH)

    def test_each_cve_is_fixed_in_musl_itself(self) -> None:
        doc = self.vex(["CVE-2026-6042", "CVE-2026-40200", "CVE-2026-6042"])
        self.assertEqual(doc["@context"], "https://openvex.dev/ns/v0.2.0")
        names = [s["vulnerability"]["name"] for s in doc["statements"]]
        self.assertEqual(names, ["CVE-2026-40200", "CVE-2026-6042"])
        for statement in doc["statements"]:
            self.assertEqual(statement["status"], "fixed")
            self.assertEqual(
                [p["@id"] for p in statement["products"]], ["pkg:generic/musl@1.2.6"]
            )

    def test_document_is_fixed_by_the_tag_and_its_commit_time(self) -> None:
        doc = self.vex(["CVE-2026-6042"])
        self.assertEqual(
            doc["@id"],
            "https://github.com/o/n/releases/download/v0.3.0/musl.openvex.json",
        )
        self.assertEqual(doc["timestamp"], "2026-10-14T00:00:00Z")
        self.assertEqual(doc, self.vex(["CVE-2026-6042"]))

    def test_no_cves_gives_an_empty_document(self) -> None:
        self.assertEqual(self.vex([])["statements"], [])

    def test_malformed_input_fails(self) -> None:
        with self.assertRaisesRegex(ReleaseError, "is not a CVE ID"):
            self.vex(["CVE-26-1"])
        with self.assertRaisesRegex(ReleaseError, "is not X.Y.Z"):
            release.musl_vex("1.2", [], "o/n", "v0.3.0", self.EPOCH)

    def test_command_writes_the_document(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        output = root / "musl.openvex.json"
        argv = [
            "musl-vex",
            "--musl-version",
            "1.2.6",
            "--musl-cve",
            "CVE-2026-6042",
            "--repo",
            "o/n",
            "--tag",
            "v0.3.0",
            "--epoch",
            str(self.EPOCH),
            "--output",
            str(output),
        ]
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(release.main(argv), 0)
        doc = json.loads(output.read_text())
        self.assertEqual(doc["statements"][0]["vulnerability"]["name"], "CVE-2026-6042")


if __name__ == "__main__":
    unittest.main()
