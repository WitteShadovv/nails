"""Tests for the distribution image table tooling (ci/distro_images.py)."""

from __future__ import annotations

import contextlib
import copy
import datetime
import email.message
import io
import json
import unittest
import urllib.error
from unittest import mock

from ci import distro_images as di

# The empty-string SHA256, as a cross-check of the hex -> SRI conversion.
EMPTY_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
EMPTY_SRI = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="

THE_DAY = datetime.date(2026, 10, 20)


def upstream_entry(**overrides: object) -> dict:
    entry: dict = {
        "osId": "fedora",
        "release": "44",
        "rootfs": "btrfs",
        "enforcing": False,
        "memory": 2048,
        "enabled": True,
        "upstreamUntil": "2099-01-01",
        "prepare": "fedora",
        "source": {
            "kind": "upstream",
            "family": "fedora",
            "release": "44",
            "url": "https://example.invalid/image.qcow2",
            "name": "image.qcow2",
            "sha256": EMPTY_SRI,
        },
    }
    entry.update(overrides)
    return entry


class SriTest(unittest.TestCase):
    def test_hex_to_sri(self) -> None:
        self.assertEqual(di.sri_from_hex(EMPTY_HEX), EMPTY_SRI)

    def test_rejects_non_sha256(self) -> None:
        with self.assertRaises(di.RepinError):
            di.sri_from_hex("abcd")


class ValidateTest(unittest.TestCase):
    def test_shipped_table_is_well_formed(self) -> None:
        # The table committed to the repository must always pass its own schema.
        self.assertEqual(di.validate(di.load_table()), [])

    def test_good_entry_has_no_problems(self) -> None:
        self.assertEqual(di.validate({"fedora-44": upstream_entry()}), [])

    def test_unknown_os_id_is_flagged(self) -> None:
        problems = di.validate({"x": upstream_entry(osId="plan9")})
        self.assertTrue(any("osId" in p for p in problems), problems)

    def test_enabled_pending_is_rejected(self) -> None:
        source = {"kind": "pending", "family": "fedora"}
        entry = upstream_entry(enabled=True, source=source)
        problems = di.validate({"fedora-45": entry})
        self.assertTrue(any("pending" in p for p in problems), problems)

    def test_enabled_placeholder_hash_is_rejected(self) -> None:
        entry = upstream_entry()
        entry["source"]["sha256"] = di.FAKE_HASH
        problems = di.validate({"fedora-44": entry})
        self.assertTrue(any("placeholder" in p for p in problems), problems)

    def test_bad_upstream_until_is_flagged(self) -> None:
        problems = di.validate({"x": upstream_entry(upstreamUntil="soon")})
        self.assertTrue(any("upstreamUntil" in p for p in problems), problems)


def nvt_entry(distro: str, image: str, **overrides: object) -> dict:
    """An enabled entry pinned through nix-vm-test, as Debian and Ubuntu are."""
    entry = upstream_entry(
        osId=distro,
        upstreamUntil=None,
        prepare="nix-vm-test",
        source={"kind": "nix-vm-test", "distro": distro, "image": image},
    )
    entry.update(overrides)
    return entry


# The shape of nix-vm-test's <distro>/images.json and of the flake.lock node
# that pins nix-vm-test.
NVT_LOCK = {
    "nodes": {
        "nix-vm-test": {
            "locked": {
                "type": "github",
                "owner": "numtide",
                "repo": "nix-vm-test",
                "rev": "0123abcd",
            }
        }
    }
}
NVT_LIST = f"{di.RAW_GITHUB}/numtide/nix-vm-test/0123abcd/debian/images.json"
DEBIAN_URL = "https://cloud.example.invalid/trixie/daily/debian-13.qcow2"
NVT_IMAGES = {
    "aarch64-linux": {"13": {"hash": "0", "name": "https://arm.invalid/x"}},
    "x86_64-linux": {"13": {"hash": "0", "name": DEBIAN_URL}},
}


class LinkCheckTest(unittest.TestCase):
    def test_shipped_table_offline_checks_nothing_and_says_so(self) -> None:
        # Debian and Ubuntu, the enabled entries, are nix-vm-test pins with no
        # lapse date: offline, nothing about them can be checked, and a pass
        # would claim a check that never ran.
        report = di.link_check(di.load_table(), offline=True)
        self.assertEqual(report.checked, [])
        self.assertTrue(report.unchecked)
        self.assertEqual(len(report.failures), 1, report.failures)
        self.assertIn("no enabled entry could be checked", report.failures[0])

    def test_shipped_table_probes_every_enabled_nix_vm_test_pin(self) -> None:
        probed: list[str] = []

        def url_ok(url: str) -> bool:
            probed.append(url)
            return True

        report = di.link_check(
            di.load_table(),
            today=THE_DAY,
            url_ok=url_ok,
            pin_url=lambda source: f"https://x.invalid/{source['image']}",
        )
        self.assertEqual(report.failures, [])
        enabled = [n for n, e in di.load_table().items() if e["enabled"]]
        self.assertEqual([line.split(":")[0] for line in report.checked], enabled)
        self.assertEqual(len(probed), len(enabled))

    def test_expired_enabled_pin_fails(self) -> None:
        # The property the brief names: a deliberately expired upstreamUntil on
        # an enabled entry makes the link check fail.
        table = {"fedora-44": upstream_entry(upstreamUntil="2020-01-01")}
        failures = di.link_check(table, today=THE_DAY, offline=True).failures
        self.assertEqual(len(failures), 1, failures)
        self.assertIn("fedora-44", failures[0])

    def test_fails_within_the_lead_window(self) -> None:
        table = {"fedora-44": upstream_entry(upstreamUntil="2026-10-25")}
        failures = di.link_check(table, today=THE_DAY, offline=True).failures
        self.assertEqual(len(failures), 1, failures)

    def test_current_pin_passes(self) -> None:
        table = {"fedora-44": upstream_entry(upstreamUntil="2027-01-01")}
        report = di.link_check(table, today=THE_DAY, offline=True)
        self.assertEqual(report.failures, [])
        self.assertEqual(report.checked, ["fedora-44: lapses 2027-01-01"])

    def test_disabled_entry_is_never_checked(self) -> None:
        table = {
            "fedora-44": upstream_entry(upstreamUntil="2027-01-01"),
            "fedora-45": upstream_entry(enabled=False, upstreamUntil="2020-01-01"),
        }
        report = di.link_check(table, today=THE_DAY, offline=True)
        self.assertEqual(report.failures, [])
        self.assertEqual(len(report.checked), 1)
        self.assertEqual(report.unchecked, [])

    def test_a_table_with_nothing_enabled_fails(self) -> None:
        entry = upstream_entry(enabled=False, upstreamUntil="2099-01-01")
        report = di.link_check({"fedora-44": entry}, today=THE_DAY, offline=True)
        self.assertEqual(len(report.failures), 1, report.failures)
        self.assertIn("no enabled entry", report.failures[0])

    def test_unreachable_url_fails_when_online(self) -> None:
        table = {"fedora-44": upstream_entry(upstreamUntil="2099-01-01")}
        failures = di.link_check(
            table, today=THE_DAY, url_ok=lambda _url: False
        ).failures
        self.assertEqual(len(failures), 1, failures)
        self.assertIn("unreachable", failures[0])

    def test_a_nix_vm_test_pin_is_probed_at_the_url_nix_vm_test_pins(self) -> None:
        fetched: list[str] = []

        def fetch(url: str) -> bytes:
            fetched.append(url)
            return json.dumps(NVT_IMAGES).encode()

        probed: list[str] = []

        def url_ok(url: str) -> bool:
            probed.append(url)
            return True

        report = di.link_check(
            {"debian-13": nvt_entry("debian", "13")},
            today=THE_DAY,
            url_ok=url_ok,
            pin_url=lambda source: di.nix_vm_test_url(source, NVT_LOCK, fetch),
        )
        self.assertEqual(report.failures, [])
        self.assertEqual(fetched, [NVT_LIST])
        self.assertEqual(probed, [DEBIAN_URL])
        self.assertEqual(report.checked, [f"debian-13: probed {DEBIAN_URL}"])

    def test_a_pruned_nix_vm_test_image_fails(self) -> None:
        report = di.link_check(
            {"debian-13": nvt_entry("debian", "13")},
            today=THE_DAY,
            url_ok=lambda _url: False,
            pin_url=lambda _source: DEBIAN_URL,
        )
        self.assertEqual(
            report.failures, [f"debian-13: image URL is unreachable: {DEBIAN_URL}"]
        )

    def test_an_unreadable_nix_vm_test_list_fails(self) -> None:
        def fetch(url: str) -> bytes:
            raise urllib.error.URLError("no route")

        report = di.link_check(
            {"debian-13": nvt_entry("debian", "13")},
            today=THE_DAY,
            url_ok=lambda _url: True,
            pin_url=lambda source: di.nix_vm_test_url(source, NVT_LOCK, fetch),
        )
        self.assertEqual(len(report.failures), 1, report.failures)
        self.assertIn(f"cannot read {NVT_LIST}", report.failures[0])

    def test_an_image_nix_vm_test_does_not_pin_fails(self) -> None:
        with self.assertRaisesRegex(di.LinkError, "pins no x86_64-linux image '12'"):
            di.nix_vm_test_url(
                {"kind": "nix-vm-test", "distro": "debian", "image": "12"},
                NVT_LOCK,
                lambda _url: json.dumps(NVT_IMAGES).encode(),
            )

    def test_the_nix_vm_test_list_needs_a_github_lock(self) -> None:
        lock = copy.deepcopy(NVT_LOCK)
        lock["nodes"]["nix-vm-test"]["locked"]["type"] = "path"
        with self.assertRaisesRegex(di.LinkError, "not on GitHub"):
            di.nix_vm_test_list_url(lock, "debian")
        with self.assertRaisesRegex(di.LinkError, "locks no nix-vm-test"):
            di.nix_vm_test_list_url({"nodes": {}}, "debian")

    def test_a_mirror_entry_is_listed_as_not_checked(self) -> None:
        mirror = upstream_entry(
            upstreamUntil=None,
            source={"kind": "mirror", "family": "arch-install", "asset": "a"},
        )
        table = {
            "fedora-44": upstream_entry(upstreamUntil="2099-01-01"),
            "arch-install": mirror,
        }
        report = di.link_check(table, today=THE_DAY, url_ok=lambda _url: True)
        self.assertEqual(report.failures, [])
        self.assertEqual(
            report.unchecked, ["arch-install: a mirror source has no URL to probe"]
        )


class LinkCheckCommandTest(unittest.TestCase):
    def run_main(self, table: dict, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(di, "load_table", return_value=table),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = di.main(["link-check", *args])
        return code, out.getvalue(), err.getvalue()

    def test_a_pass_names_what_it_checked(self) -> None:
        table = {"fedora-44": upstream_entry(upstreamUntil="2099-01-01")}
        code, out, _err = self.run_main(table, "--offline", "--date", "2026-10-20")
        self.assertEqual(code, 0)
        self.assertIn("checked fedora-44: lapses 2099-01-01", out)
        self.assertIn("the 1 checked pin(s) are current", out)

    def test_checking_nothing_is_no_pass(self) -> None:
        table = {"debian-13": nvt_entry("debian", "13")}
        code, out, err = self.run_main(table, "--offline")
        self.assertEqual(code, 1)
        self.assertIn("not checked debian-13", out)
        self.assertIn("no enabled entry could be checked", err)
        self.assertNotIn("current", out)


# The upstream layouts the resolvers walk: a directory listing, then the
# checksum file it points at. These mirror the real autoindex and checksum
# formats (an HTML index of hrefs; Fedora's signed CHECKSUM; Arch's per-image
# .SHA256).
FEDORA_BASE = f"{di.FEDORA_RELEASES}/44/Cloud/x86_64/images/"
FEDORA_LISTING = (
    '<a href="Fedora-Cloud-44-1.7-x86_64-CHECKSUM">CHECKSUM</a>\n'
    '<a href="Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2">qcow2</a>\n'
    '<a href="Fedora-Cloud-Base-UEFI-UKI-44-1.7.x86_64.qcow2">uki</a>\n'
)
FEDORA_CHECKSUM = (
    "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
    f"SHA256 (Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2) = {EMPTY_HEX}\n"
)
FEDORA_FIX = {
    FEDORA_BASE: FEDORA_LISTING,
    f"{FEDORA_BASE}Fedora-Cloud-44-1.7-x86_64-CHECKSUM": FEDORA_CHECKSUM,
}

ARCH_LISTING = (
    '<a href="latest/">latest/</a>\n'
    '<a href="v20260915.594445/">v20260915.594445/</a>\n'
    '<a href="v20261001.604814/">v20261001.604814/</a>\n'
)
ARCH_NAME = "Arch-Linux-x86_64-basic-20261001.604814.qcow2"
ARCH_SHA_URL = f"{di.ARCH_IMAGES}/v20261001.604814/{ARCH_NAME}.SHA256"
ARCH_FIX = {
    f"{di.ARCH_IMAGES}/": ARCH_LISTING,
    ARCH_SHA_URL: f"{EMPTY_HEX}  {ARCH_NAME}\n",
}


def not_found(url: str) -> bytes:
    """A fetch of a URL the mirror does not serve, such as an unreleased one."""
    raise urllib.error.HTTPError(url, 404, "Not Found", email.message.Message(), None)


def fetcher(mapping: dict[str, str]) -> di.Fetcher:
    """Serve the mapping's pages; any other URL is a 404."""

    def fetch(url: str) -> bytes:
        if url not in mapping:
            return not_found(url)
        return mapping[url].encode()

    return fetch


# A Fedora 44 pin the FEDORA_FIX listing moves forward.
PINNED_44 = {
    "kind": "upstream",
    "family": "fedora",
    "release": "44",
    "url": "https://old.invalid/old.qcow2",
    "name": "old.qcow2",
    "sha256": EMPTY_SRI,
}


class RepinTest(unittest.TestCase):
    def test_resolve_fedora(self) -> None:
        pin = di.resolve_fedora("44", fetcher(FEDORA_FIX))
        self.assertEqual(pin["name"], "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2")
        self.assertEqual(pin["sha256"], EMPTY_SRI)
        self.assertTrue(pin["url"].endswith(pin["name"]))

    def test_resolve_arch_boxes_by_date(self) -> None:
        pin = di.resolve_arch_boxes("20261001", fetcher(ARCH_FIX))
        self.assertEqual(pin["name"], ARCH_NAME)
        self.assertEqual(pin["sha256"], EMPTY_SRI)
        self.assertIn("v20261001.604814", pin["url"])

    def test_resolve_arch_boxes_latest_picks_newest(self) -> None:
        pin = di.resolve_arch_boxes("latest", fetcher(ARCH_FIX))
        self.assertIn("v20261001.604814", pin["url"])

    def test_resolve_arch_unknown_date_errors(self) -> None:
        with self.assertRaises(di.RepinError):
            di.resolve_arch_boxes("29990101", fetcher(ARCH_FIX))

    def test_repin_updates_entry_and_reports_change(self) -> None:
        source = {
            "kind": "upstream",
            "family": "fedora",
            "release": "44",
            "url": "https://old.invalid/old.qcow2",
            "name": "old.qcow2",
            "sha256": di.FAKE_HASH,
        }
        table = {"fedora-44": upstream_entry(source=source)}
        before = copy.deepcopy(table)
        result = di.repin(table, ["fedora-44"], fetch=fetcher(FEDORA_FIX))
        self.assertEqual(result.changed, ["fedora-44"])
        self.assertEqual(result.failed, {})
        self.assertEqual(table["fedora-44"]["source"]["sha256"], EMPTY_SRI)
        self.assertEqual(table["fedora-44"]["source"]["kind"], "upstream")
        self.assertNotEqual(table, before)

    def test_repin_all_selects_resolvable_families(self) -> None:
        nvt = {"source": {"kind": "nix-vm-test", "distro": "debian", "image": "13"}}
        table = {"fedora-44": upstream_entry(), "debian-13": nvt}
        result = di.repin(table, [], fetch=fetcher(FEDORA_FIX))
        self.assertEqual(result.changed, ["fedora-44"])

    def test_repin_all_leaves_a_pending_entry_alone(self) -> None:
        # Fedora 45 is staged before it ships: its release directory answers
        # 404, and a bulk bump must neither crash on it nor pin it.
        pending = upstream_entry(
            enabled=False,
            release="45",
            source={"kind": "pending", "family": "fedora", "release": "45"},
        )
        table = {
            "fedora-44": upstream_entry(source={**PINNED_44, "sha256": di.FAKE_HASH}),
            "fedora-45": pending,
        }
        before = copy.deepcopy(pending)
        result = di.repin(table, [], fetch=fetcher(FEDORA_FIX))
        self.assertEqual(result.changed, ["fedora-44"])
        self.assertEqual(result.failed, {})
        self.assertEqual(table["fedora-45"], before)

    def test_a_pending_entry_named_on_its_own_reports_its_404(self) -> None:
        pending = {"kind": "pending", "family": "fedora", "release": "45"}
        table = {"fedora-45": upstream_entry(enabled=False, source=pending)}
        result = di.repin(table, ["fedora-45"], fetch=not_found)
        self.assertEqual(result.changed, [])
        self.assertIn("404", result.failed["fedora-45"])
        self.assertEqual(table["fedora-45"]["source"]["kind"], "pending")

    def test_one_entry_that_does_not_resolve_holds_back_no_other(self) -> None:
        table = {
            "arch-boxes": upstream_entry(
                osId="arch",
                source={"kind": "upstream", "family": "arch-boxes", "release": "1"},
            ),
            "fedora-44": upstream_entry(source={**PINNED_44, "sha256": di.FAKE_HASH}),
        }
        result = di.repin(table, [], fetch=fetcher(FEDORA_FIX))
        self.assertEqual(result.changed, ["fedora-44"])
        self.assertEqual(list(result.failed), ["arch-boxes"])

    def test_repin_unknown_family_is_reported(self) -> None:
        source = {"kind": "upstream", "family": "gentoo", "release": "1"}
        table = {"x": upstream_entry(source=source)}
        result = di.repin(table, ["x"], fetch=lambda _url: b"")
        self.assertIn("no upstream resolver", result.failed["x"])

    def test_repin_unknown_name_errors_before_any_fetch(self) -> None:
        def fetch(url: str) -> bytes:
            raise AssertionError(f"fetched {url}")

        table = {"fedora-44": upstream_entry()}
        with self.assertRaisesRegex(di.RepinError, "unknown entry 'fedora-46'"):
            di.repin(table, ["fedora-44", "fedora-46"], fetch=fetch)


class RepinCommandTest(unittest.TestCase):
    def test_repin_all_writes_what_resolved_beside_a_pending_entry(self) -> None:
        table = {
            "fedora-44": upstream_entry(source={**PINNED_44, "sha256": di.FAKE_HASH}),
            "fedora-45": upstream_entry(
                enabled=False,
                source={"kind": "pending", "family": "fedora", "release": "45"},
            ),
        }
        out = io.StringIO()
        with (
            mock.patch.object(di, "load_table", return_value=table),
            mock.patch.object(di, "write_table") as write,
            mock.patch.object(di, "_fetch", side_effect=fetcher(FEDORA_FIX)),
            contextlib.redirect_stdout(out),
        ):
            code = di.main(["repin", "--all"])
        self.assertEqual(code, 0)
        write.assert_called_once()
        written = write.call_args.args[0]
        self.assertEqual(written["fedora-44"]["source"]["sha256"], EMPTY_SRI)
        self.assertEqual(written["fedora-45"]["source"]["kind"], "pending")
        self.assertIn("repinned: fedora-44", out.getvalue())
        self.assertIn("upstreamUntil is left at 2099-01-01", out.getvalue())

    def test_a_failure_is_reported_and_fails_the_command(self) -> None:
        pending = {"kind": "pending", "family": "fedora", "release": "45"}
        table = {"fedora-45": upstream_entry(enabled=False, source=pending)}
        err = io.StringIO()
        with (
            mock.patch.object(di, "load_table", return_value=table),
            mock.patch.object(di, "write_table") as write,
            mock.patch.object(di, "_fetch", side_effect=not_found),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(err),
        ):
            code = di.main(["repin", "fedora-45"])
        self.assertEqual(code, 1)
        write.assert_not_called()
        self.assertIn("repin: fedora-45: HTTP Error 404", err.getvalue())


if __name__ == "__main__":
    unittest.main()
