"""Tests for the distribution image table tooling (ci/distro_images.py)."""

from __future__ import annotations

import copy
import datetime
import unittest

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


class LinkCheckTest(unittest.TestCase):
    def test_shipped_table_passes_offline(self) -> None:
        # Nothing enabled in the shipped table is a fetchurl pin, so the offline
        # date logic never fails on it.
        self.assertEqual(di.link_check(di.load_table(), offline=True), [])

    def test_expired_enabled_pin_fails(self) -> None:
        # The property the brief names: a deliberately expired upstreamUntil on
        # an enabled entry makes the link check fail.
        table = {"fedora-44": upstream_entry(upstreamUntil="2020-01-01")}
        failures = di.link_check(table, today=THE_DAY, offline=True)
        self.assertEqual(len(failures), 1, failures)
        self.assertIn("fedora-44", failures[0])

    def test_fails_within_the_lead_window(self) -> None:
        table = {"fedora-44": upstream_entry(upstreamUntil="2026-10-25")}
        failures = di.link_check(table, today=THE_DAY, offline=True)
        self.assertEqual(len(failures), 1, failures)

    def test_current_pin_passes(self) -> None:
        table = {"fedora-44": upstream_entry(upstreamUntil="2027-01-01")}
        self.assertEqual(di.link_check(table, today=THE_DAY, offline=True), [])

    def test_disabled_entry_never_fails(self) -> None:
        entry = upstream_entry(enabled=False, upstreamUntil="2020-01-01")
        table = {"fedora-44": entry}
        self.assertEqual(di.link_check(table, today=THE_DAY, offline=True), [])

    def test_unreachable_url_fails_when_online(self) -> None:
        table = {"fedora-44": upstream_entry(upstreamUntil="2099-01-01")}
        failures = di.link_check(table, today=THE_DAY, url_ok=lambda _url: False)
        self.assertEqual(len(failures), 1, failures)
        self.assertIn("unreachable", failures[0])


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


def fetcher(mapping: dict[str, str]) -> di.Fetcher:
    return lambda url: mapping[url].encode()


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
        changed = di.repin(table, ["fedora-44"], fetch=fetcher(FEDORA_FIX))
        self.assertEqual(changed, ["fedora-44"])
        self.assertEqual(table["fedora-44"]["source"]["sha256"], EMPTY_SRI)
        self.assertEqual(table["fedora-44"]["source"]["kind"], "upstream")
        self.assertNotEqual(table, before)

    def test_repin_all_selects_resolvable_families(self) -> None:
        nvt = {"source": {"kind": "nix-vm-test", "distro": "debian", "image": "13"}}
        table = {"fedora-44": upstream_entry(), "debian-13": nvt}
        changed = di.repin(table, [], fetch=fetcher(FEDORA_FIX))
        self.assertEqual(changed, ["fedora-44"])

    def test_repin_unknown_family_errors(self) -> None:
        source = {"kind": "upstream", "family": "gentoo", "release": "1"}
        table = {"x": upstream_entry(source=source)}
        with self.assertRaises(di.RepinError):
            di.repin(table, ["x"], fetch=lambda _url: b"")


if __name__ == "__main__":
    unittest.main()
