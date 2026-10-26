"""Tests for ci/deny_ignores.py, the deny.toml ignore expiry check."""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ci import deny_ignores
from ci.deny_ignores import ConfigError, Ignore, parse_ignores

TODAY = dt.date(2026, 10, 1)
MAX_DAYS = 180


def config(body: str) -> str:
    """Return a deny.toml text whose [advisories] ignore array holds ``body``.

    The ignore array opens on line 4, so the first line of ``body`` is line 5.
    """
    return (
        "[advisories]\n"
        'yanked = "deny"\n'
        "# expires: 2000-01-01 (outside the array, so never attached)\n"
        "ignore = [\n"
        f"{body}"
        "]\n"
        "\n"
        "[bans]\n"
        "skip = []\n"
    )


def single(expires: str) -> str:
    """Return an ignore array body with one entry below an expiry comment."""
    return f'    # expires: {expires}\n    "RUSTSEC-2099-0001",\n'


def check(body: str) -> list[str]:
    return deny_ignores.problems(parse_ignores(config(body)), TODAY, MAX_DAYS)


class ExpiryTest(unittest.TestCase):
    def test_expired_ignore_fails(self) -> None:
        out = check(
            "    # expires: 2026-09-30\n"
            '    { id = "RUSTSEC-2099-0001", reason = "dev-only" },\n'
        )
        self.assertEqual(len(out), 1)
        self.assertIn("line 6: RUSTSEC-2099-0001: expired on 2026-09-30", out[0])

    def test_future_expiry_passes(self) -> None:
        out = check(
            "    # Only reachable from the benchmarks.\n"
            "    # expires: 2026-12-31\n"
            '    { id = "RUSTSEC-2099-0001", reason = "dev-only" },\n'
        )
        self.assertEqual(out, [])

    def test_missing_expiry_fails(self) -> None:
        out = check(
            "    # Only reachable from the benchmarks.\n"
            '    { id = "RUSTSEC-2099-0001", reason = "dev-only" },\n'
        )
        self.assertEqual(len(out), 1)
        self.assertIn("no '# expires: YYYY-MM-DD' comment", out[0])

    def test_ignore_is_valid_through_its_expiry_day(self) -> None:
        self.assertEqual(check(single("2026-10-01")), [])

    def test_expiry_at_the_horizon_passes(self) -> None:
        horizon = TODAY + dt.timedelta(days=MAX_DAYS)
        self.assertEqual(check(single(horizon.isoformat())), [])

    def test_expiry_beyond_the_horizon_fails(self) -> None:
        out = check(single("2099-01-01"))
        self.assertEqual(len(out), 1)
        self.assertIn("more than 180 days ahead", out[0])

    def test_malformed_expiry_fails(self) -> None:
        for value in ("soon", "20261231", "2026-12-31 or later", "2026-02-30"):
            with self.subTest(value=value):
                out = check(single(value))
                self.assertEqual(len(out), 1)
                self.assertIn(f"{value!r} is not a YYYY-MM-DD date", out[0])

    def test_expiry_keyword_is_case_insensitive(self) -> None:
        body = '    # Expires: 2026-09-30\n    "RUSTSEC-2099-0001",\n'
        self.assertIn("expired on 2026-09-30", check(body)[0])

    def test_two_expiry_comments_fail(self) -> None:
        out = check(
            "    # expires: 2026-11-01\n"
            "    # expires: 2026-12-01\n"
            '    "RUSTSEC-2099-0001",\n'
        )
        self.assertEqual(len(out), 1)
        self.assertIn("more than one '# expires:' comment", out[0])


class AssociationTest(unittest.TestCase):
    def test_blank_line_detaches_expiry(self) -> None:
        out = check('    # expires: 2026-12-31\n\n    "RUSTSEC-2099-0001",\n')
        self.assertEqual(len(out), 1)
        self.assertIn("no '# expires: YYYY-MM-DD' comment", out[0])

    def test_expiry_covers_only_the_next_entry(self) -> None:
        out = check(single("2026-12-31") + '    "RUSTSEC-2099-0002",\n')
        self.assertEqual(len(out), 1)
        self.assertIn("RUSTSEC-2099-0002", out[0])

    def test_entries_report_their_own_line_and_expiry(self) -> None:
        ignores = parse_ignores(
            config(
                single("2026-12-31")
                + "    # Reason on its own line.\n"
                + "    # expires: 2026-11-30\n"
                + "    { crate = 'example@1.0.0', reason = 'dev-only' },\n"
            )
        )
        self.assertEqual(
            ignores,
            [
                Ignore("RUSTSEC-2099-0001", 6, ("2026-12-31",)),
                Ignore("example@1.0.0", 9, ("2026-11-30",)),
            ],
        )

    def test_trailing_comment_is_not_an_expiry(self) -> None:
        out = check('    "RUSTSEC-2099-0001", # expires: 2026-12-31\n')
        self.assertEqual(len(out), 1)
        self.assertIn("no '# expires: YYYY-MM-DD' comment", out[0])


class StructureTest(unittest.TestCase):
    def test_empty_ignore_array_has_no_entries(self) -> None:
        self.assertEqual(parse_ignores(config("")), [])
        self.assertEqual(parse_ignores("[advisories]\nignore = []\n"), [])

    def test_missing_ignore_key_has_no_entries(self) -> None:
        self.assertEqual(parse_ignores('[advisories]\nyanked = "deny"\n'), [])

    def test_missing_advisories_table_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, r"no \[advisories\] table"):
            parse_ignores("[bans]\nskip = []\n")

    def test_invalid_toml_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "invalid TOML"):
            parse_ignores("[advisories]\nignore = [\n")

    def test_two_entries_on_one_line_are_rejected(self) -> None:
        body = single("2026-12-31").replace(",\n", ', "RUSTSEC-2099-0002",\n')
        with self.assertRaisesRegex(ConfigError, "cannot match"):
            parse_ignores(config(body))

    def test_entry_on_the_opening_line_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "cannot match"):
            parse_ignores('[advisories]\nignore = ["RUSTSEC-2099-0001",\n]\n')

    def test_dotted_key_without_advisories_header_is_rejected(self) -> None:
        text = "advisories.ignore = [\n" + single("2026-12-31") + "]\n"
        with self.assertRaisesRegex(ConfigError, "cannot locate"):
            parse_ignores(text)

    def test_entry_without_id_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "unsupported"):
            parse_ignores(config('    { reason = "no id" },\n'))


class MainTest(unittest.TestCase):
    def run_main(self, text: str, *extra: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deny.toml"
            path.write_text(text, encoding="utf-8")
            argv = ["--config", str(path), "--today", TODAY.isoformat(), *extra]
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = deny_ignores.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_current_ignores_exit_zero(self) -> None:
        code, stdout, stderr = self.run_main(config(single("2026-12-31")))
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("1 advisory ignore(s)", stdout)

    def test_expired_ignore_exits_one(self) -> None:
        code, stdout, stderr = self.run_main(config(single("2026-09-30")))
        self.assertEqual((code, stdout), (1, ""))
        self.assertIn("deny.toml: line 6: RUSTSEC-2099-0001: expired", stderr)

    def test_max_days_and_today_are_configurable(self) -> None:
        text = config(single("2026-10-31"))
        self.assertEqual(self.run_main(text, "--max-days", "29")[0], 1)
        self.assertEqual(self.run_main(text, "--max-days", "30")[0], 0)
        self.assertEqual(self.run_main(text, "--today", "2026-11-01")[0], 1)

    def test_invalid_config_exits_two(self) -> None:
        code, stdout, stderr = self.run_main("[advisories]\nignore = [\n")
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("deny.toml: error: invalid TOML", stderr)

    def test_missing_config_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "deny.toml"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = deny_ignores.main(["--config", str(missing)])
        self.assertEqual(code, 2)
        self.assertIn(f"{missing}: error:", stderr.getvalue())

    def test_negative_max_days_is_a_usage_error(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                deny_ignores.main(["--max-days", "-1"])
        self.assertEqual(raised.exception.code, 2)

    def run_configs(self, texts: list[str], *extra: str) -> tuple[int, str, str]:
        """Run main over one file per text, each named with its index."""
        stdout, stderr = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            argv = ["--today", TODAY.isoformat(), *extra]
            for index, text in enumerate(texts):
                path = Path(tmp) / f"deny-{index}.toml"
                path.write_text(text, encoding="utf-8")
                argv += ["--config", str(path)]
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = deny_ignores.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_every_config_is_checked_and_reported(self) -> None:
        code, stdout, stderr = self.run_configs(
            [config(single("2026-12-31")), config(single("2026-09-30"))]
        )
        self.assertEqual(code, 1)
        self.assertIn("deny-0.toml: 1 advisory ignore(s)", stdout)
        self.assertIn("deny-1.toml: line 6: RUSTSEC-2099-0001: expired", stderr)

    def test_an_expired_ignore_in_a_later_config_fails(self) -> None:
        code, _, stderr = self.run_configs(
            [config(""), config(""), config(single("2026-09-30"))]
        )
        self.assertEqual(code, 1)
        self.assertIn("deny-2.toml: line 6", stderr)

    def test_an_unreadable_config_outranks_an_expired_ignore(self) -> None:
        for texts in (
            ["[advisories]\nignore = [\n", config(single("2026-09-30"))],
            [config(single("2026-09-30")), "[advisories]\nignore = [\n"],
        ):
            with self.subTest(texts=texts):
                code, _, stderr = self.run_configs(texts)
                self.assertEqual(code, 2)
                self.assertIn("error: invalid TOML", stderr)
                self.assertIn("expired", stderr)

    def test_without_config_every_default_is_checked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            current, expired = Path(tmp) / "deny.toml", Path(tmp) / "gui.toml"
            current.write_text(config(single("2026-12-31")), encoding="utf-8")
            expired.write_text(config(single("2026-09-30")), encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            with (
                mock.patch.object(deny_ignores, "DEFAULT_CONFIGS", (current, expired)),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                code = deny_ignores.main(["--today", TODAY.isoformat()])
        self.assertEqual(code, 1)
        self.assertIn(f"{current}: 1 advisory ignore(s)", stdout.getvalue())
        self.assertIn(f"{expired}: line 6", stderr.getvalue())

    def test_default_configs_are_the_repository_policies(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        self.assertEqual(
            deny_ignores.DEFAULT_CONFIGS,
            (repo_root / "deny.toml", repo_root / "gui" / "deny.toml"),
        )
        for path in deny_ignores.DEFAULT_CONFIGS:
            with self.subTest(path=path):
                self.assertTrue(path.is_file())


if __name__ == "__main__":
    unittest.main()
