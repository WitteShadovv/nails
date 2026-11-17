"""Tests for ci/e2e/rpm_closure.py, the locks of the Fedora gate's closures."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from typing import Any

from ci.e2e import rpm_closure as rc

DATA = b"an rpm, as far as this test is concerned\n"
HEX = hashlib.sha256(DATA).hexdigest()
FILE = "tuned-2.25.1-1.fc44.noarch.rpm"
IMAGE_FILE = "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2"


def resolution(**changes: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "image": "fedora-44",
        "imageFile": IMAGE_FILE,
        "release": "44",
        "repository": rc.repository("44"),
        "requested": ["abrt", "firewalld", "tuned"],
        "inImage": {"abrt": None, "firewalld": None, "tuned": None},
        "weakDependencies": False,
        "packages": [
            {
                "file": FILE,
                "nevra": "tuned-2.25.1-1.fc44.noarch",
                "path": f"Packages/t/{FILE}",
                "sha256": HEX,
                "size": len(DATA),
            }
        ],
    }
    record.update(changes)
    return record


def table(image_file: str = IMAGE_FILE) -> dict[str, Any]:
    return {
        "fedora-44": {
            "release": "44",
            "source": {"kind": "upstream", "name": image_file},
        }
    }


def serve(data: bytes = DATA) -> rc.Fetcher:
    def fetcher(url: str) -> bytes:
        assert url == rc.repository("44") + f"Packages/t/{FILE}", url
        return data

    return fetcher


class SriTest(unittest.TestCase):
    def test_converts_a_hex_digest(self) -> None:
        self.assertEqual(
            rc.sri("0" * 64), "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        )

    def test_refuses_what_is_no_digest(self) -> None:
        for value in ("abc", "G" * 64, "0" * 63):
            with self.subTest(value=value):
                with self.assertRaises(rc.ClosureError):
                    rc.sri(value)


class LockFromTest(unittest.TestCase):
    def test_pins_each_package_it_fetched_again(self) -> None:
        lock = rc.lock_from(resolution(), serve())
        (package,) = lock["packages"]
        self.assertEqual(package["sha256"], rc.sri(HEX))
        self.assertEqual(package["size"], len(DATA))
        self.assertEqual(lock["repository"], rc.repository("44"))
        self.assertEqual(lock["archive"], rc.archive("44"))
        self.assertEqual(rc.lock_problems("fedora-44", lock, table()), [])

    def test_refuses_a_file_another_than_the_images_dnf_saw(self) -> None:
        with self.assertRaisesRegex(rc.ClosureError, "served"):
            rc.lock_from(resolution(), serve(DATA + b"!"))

    def test_refuses_a_resolution_that_cannot_be_used(self) -> None:
        package = resolution()["packages"][0]
        cases: dict[str, dict[str, Any]] = {
            "another repository": {
                "repository": "https://example.invalid/fedora/44/updates/"
            },
            "weak dependencies": {"weakDependencies": True},
            "no package": {"packages": []},
            "no release": {"release": "rawhide"},
            "a path outside the packages": {
                "packages": [{**package, "path": f"../updates/{FILE}"}]
            },
            "a path naming another file": {
                "packages": [{**package, "path": "Packages/t/other.rpm"}]
            },
            "no digest": {"packages": [{**package, "sha256": "x"}]},
            "no size": {"packages": [{**package, "size": 0}]},
            "a package twice": {"packages": [package, package]},
            "no record of the image": {"inImage": None},
        }
        for case, changes in cases.items():
            with self.subTest(case=case):
                with self.assertRaises(rc.ClosureError):
                    rc.lock_from(resolution(**changes), serve())


class LockProblemsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = rc.lock_from(resolution(), serve())

    def test_a_lock_of_another_image_file_is_stale(self) -> None:
        problems = rc.lock_problems("fedora-44", self.lock, table("other.qcow2"))
        self.assertEqual(len(problems), 1)
        self.assertIn("lock it again", problems[0])

    def test_names_what_is_wrong(self) -> None:
        cases: dict[str, tuple[str, Any]] = {
            "of": ("image", "fedora-45"),
            "release repository": ("repository", "https://example.invalid/"),
            "archive": ("archive", "https://example.invalid/"),
            "weak": ("weakDependencies", True),
        }
        for fragment, (key, value) in cases.items():
            with self.subTest(key=key):
                lock = copy.deepcopy(self.lock)
                lock[key] = value
                problems = rc.lock_problems("fedora-44", lock, table())
                self.assertTrue(any(fragment in p for p in problems), problems)

    def test_names_a_bad_package(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["packages"][0]["sha256"] = HEX
        problems = rc.lock_problems("fedora-44", lock, table())
        self.assertTrue(any("SRI" in p for p in problems), problems)

    def test_an_image_without_entry(self) -> None:
        self.assertEqual(
            rc.lock_problems("fedora-46", self.lock, table()),
            ["fedora-46: images.json has no entry fedora-46"],
        )


class CheckTest(unittest.TestCase):
    def test_every_committed_lock_is_current(self) -> None:
        self.assertEqual(rc.check(), [])

    def test_check_reads_a_directory_of_locks(self) -> None:
        lock = rc.lock_from(resolution(), serve())
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            (root / "images.json").write_text(json.dumps(table()), encoding="utf-8")
            locks = root / "rpms"
            locks.mkdir()
            (locks / "fedora-44.json").write_text(rc.lock_json(lock), encoding="utf-8")
            self.assertEqual(rc.check(locks, root / "images.json"), [])
            (locks / "fedora-44.json").write_text(json.dumps(lock), encoding="utf-8")
            problems = rc.check(locks, root / "images.json")
            self.assertEqual(
                problems, ["fedora-44: not written the way lock writes it"]
            )

    def test_the_command_reports_and_fails(self) -> None:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            with unittest.mock.patch.object(rc, "check", return_value=["x: bad"]):
                self.assertEqual(rc.main(["check"]), 1)
        self.assertIn("rpm_closure check: x: bad", err.getvalue())


if __name__ == "__main__":
    unittest.main()
