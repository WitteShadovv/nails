"""Tests for fedora_rpms, the offline package closures of the Fedora gate."""

from __future__ import annotations

import json
import unittest

import fedora_rpms as fr

REPO = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Everything/x86_64/os/"
DIGEST = "a" * 64


def resolution(*extra: str, location: str | None = None) -> str:
    tuned = "tuned-2.25.1-1.fc44.noarch.rpm"
    lines = [
        "in-image tuned package tuned is not installed",
        "in-image firewalld package firewalld is not installed",
        "in-image abrt abrt-2.17.6-4.fc44.x86_64",
        "Some dnf chatter that is not a record",
        f"package {tuned} tuned-2.25.1-1.fc44.noarch {DIGEST} 4096",
        f"checksig {tuned} digests signatures OK",
        f"location {tuned} {location or REPO + 'Packages/t/' + tuned}",
        *extra,
    ]
    return "\n".join(lines) + "\n"


class RepositoryTest(unittest.TestCase):
    def test_the_release_repository_and_its_archive(self) -> None:
        self.assertEqual(fr.repository("44"), REPO)
        self.assertTrue(fr.archive_repository("45").startswith(fr.ARCHIVE + "/45/"))

    def test_a_release_is_a_number(self) -> None:
        for release in ("rawhide", "44; rm -rf /", ""):
            with self.subTest(release=release):
                with self.assertRaises(ValueError):
                    fr.repository(release)

    def test_the_repo_file_enables_the_release_alone_with_its_key(self) -> None:
        text = fr.repo_file("45")
        self.assertIn("baseurl=" + fr.repository("45"), text)
        self.assertIn("gpgcheck=1", text)
        self.assertIn("RPM-GPG-KEY-fedora-45-x86_64", text)


class ResolveCommandTest(unittest.TestCase):
    def test_it_downloads_one_install_from_the_release_alone(self) -> None:
        command = fr.resolve_command("44")
        self.assertIn("--repo=release", command)
        self.assertIn("install --downloadonly", command)
        self.assertIn("install_weak_deps=False", command)
        self.assertIn("user_agent=nails-rpm-closure/1", command)
        for name in fr.REQUESTED:
            self.assertIn(name, command)
        self.assertNotIn("updates", command)


class ParseResolutionTest(unittest.TestCase):
    def test_reads_the_closure_and_what_the_image_holds(self) -> None:
        record = fr.parse_resolution(resolution(), "44")
        self.assertEqual(record["repository"], REPO)
        self.assertEqual(
            record["inImage"],
            {"abrt": "abrt-2.17.6-4.fc44.x86_64", "firewalld": None, "tuned": None},
        )
        self.assertEqual(record["requested"], ["abrt", "firewalld", "tuned"])
        (package,) = record["packages"]
        self.assertEqual(package["path"], "Packages/t/tuned-2.25.1-1.fc44.noarch.rpm")
        self.assertEqual(package["sha256"], DIGEST)
        self.assertEqual(package["size"], 4096)
        self.assertIs(record["weakDependencies"], False)
        # It round-trips through the JSON the driver writes.
        self.assertEqual(json.loads(fr.resolution_json(record)), record)

    def test_refuses_a_signature_rpm_does_not_find_good(self) -> None:
        text = resolution().replace(
            "digests signatures OK", "digests SIGNATURES NOT OK"
        )
        with self.assertRaisesRegex(ValueError, "signature"):
            fr.parse_resolution(text, "44")

    def test_refuses_a_file_without_a_signature_check(self) -> None:
        text = "\n".join(
            line for line in resolution().splitlines() if not line.startswith("check")
        )
        with self.assertRaisesRegex(ValueError, "signature"):
            fr.parse_resolution(text, "44")

    def test_refuses_a_location_outside_the_release_repository(self) -> None:
        for url in (
            "https://download.fedoraproject.org/pub/fedora/linux/updates/44/"
            "Everything/x86_64/Packages/t/tuned-2.25.1-1.fc44.noarch.rpm",
            REPO + "Packages/t/another-file.rpm",
            "",
        ):
            with self.subTest(url=url):
                with self.assertRaisesRegex(ValueError, "location"):
                    fr.parse_resolution(resolution(location=url or " "), "44")

    def test_refuses_a_malformed_package_line(self) -> None:
        for line in (
            "package x.rpm x-1-1.noarch nothex 1",
            "package x.rpm x-1-1.noarch " + DIGEST,
        ):
            with self.subTest(line=line):
                with self.assertRaisesRegex(ValueError, "malformed"):
                    fr.parse_resolution(resolution(line), "44")

    def test_refuses_a_resolution_that_downloaded_nothing(self) -> None:
        with self.assertRaisesRegex(ValueError, "no package"):
            fr.parse_resolution("in-image tuned package tuned is not installed\n", "44")


class InstallCommandTest(unittest.TestCase):
    def test_it_installs_the_share_with_every_repository_off(self) -> None:
        command = fr.install_command("/run/rpms")
        self.assertIn("--disablerepo='*'", command)
        self.assertIn("/run/rpms/*.rpm", command)
        self.assertTrue(command.endswith("rpm -q tuned firewalld abrt"))


if __name__ == "__main__":
    unittest.main()
