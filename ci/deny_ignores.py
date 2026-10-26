#!/usr/bin/env python3
"""Fail when an advisory ignore in a deny.toml lacks a current expiry date.

cargo-deny accepts only ``id`` and ``reason`` in an ignore entry, so the
expiry lives in a comment: every entry of ``[advisories] ignore`` needs a
``# expires: YYYY-MM-DD`` line in the comment block directly above it. An
ignore is valid through its expiry day, and that day may lie at most
``--max-days`` ahead, so each exception is re-reviewed instead of silently
outliving its reason.

Without ``--config`` every cargo-deny policy of the repository is checked: the
main workspace's deny.toml and the gui/ workspace's gui/deny.toml.

tomllib decides which entries exist. The line scan only attaches comments to
them, and any disagreement between the two is an error rather than a guess.

Exit status: 0 when every ignore is current, 1 when at least one is not, and
2 when a deny.toml cannot be read or its ignore entries cannot be matched to
lines. Every file is checked and reported, and the worst status is returned.
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# Every cargo-deny policy of the repository: the main workspace's and that of
# the gui/ workspace, which is a Cargo workspace of its own.
DEFAULT_CONFIGS = (REPO / "deny.toml", REPO / "gui" / "deny.toml")
DEFAULT_MAX_DAYS = 180

_ADVISORIES_HEADER = re.compile(r"\s*\[\s*advisories\s*\]\s*(?:#.*)?")
_TABLE_HEADER = re.compile(r"\s*\[")
_IGNORE_START = re.compile(r"\s*ignore\s*=\s*\[")
_EXPIRES = re.compile(r"#\s*expires\s*:\s*(?P<value>.*?)\s*", re.IGNORECASE)
_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


class ConfigError(Exception):
    """deny.toml is unreadable or its ignore entries cannot be matched to lines."""


@dataclass(frozen=True)
class Ignore:
    """One ``[advisories] ignore`` entry and the expiry comments above it."""

    ident: str
    line: int
    expires: tuple[str, ...]


def _entry_ident(entry: object) -> str:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        ident = entry.get("id", entry.get("crate"))
        if isinstance(ident, str):
            return ident
    raise ConfigError(f"unsupported [advisories] ignore entry: {entry!r}")


def _expected_idents(text: str) -> list[str]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as err:
        raise ConfigError(f"invalid TOML: {err}") from err
    advisories = data.get("advisories")
    if not isinstance(advisories, dict):
        raise ConfigError("no [advisories] table")
    entries = advisories.get("ignore", [])
    if not isinstance(entries, list):
        raise ConfigError("[advisories] ignore is not an array")
    return [_entry_ident(entry) for entry in entries]


def _ignore_start(lines: list[str]) -> int:
    """Return the index of the ``ignore = [`` line of the [advisories] table."""
    header = next(
        (i for i, line in enumerate(lines) if _ADVISORIES_HEADER.fullmatch(line)),
        None,
    )
    if header is not None:
        for index in range(header + 1, len(lines)):
            if _IGNORE_START.match(lines[index]):
                return index
            if _TABLE_HEADER.match(lines[index]):
                break
    raise ConfigError("cannot locate the [advisories] ignore array")


def parse_ignores(text: str) -> list[Ignore]:
    """Return the advisory ignores of a deny.toml text with their expiry comments."""
    expected = _expected_idents(text)
    if not expected:
        return []

    lines = text.splitlines()
    found: list[tuple[int, tuple[str, ...]]] = []
    pending: list[str] = []
    for index in range(_ignore_start(lines) + 1, len(lines)):
        stripped = lines[index].strip()
        if stripped.startswith("]") or _TABLE_HEADER.match(stripped):
            break
        if not stripped:
            pending = []
        elif stripped.startswith("#"):
            match = _EXPIRES.fullmatch(stripped)
            if match:
                pending.append(match["value"])
        else:
            found.append((index, tuple(pending)))
            pending = []

    if len(found) != len(expected) or any(
        f'"{ident}"' not in lines[index] and f"'{ident}'" not in lines[index]
        for ident, (index, _) in zip(expected, found, strict=True)
    ):
        raise ConfigError(
            "cannot match the ignore entries to lines; write each entry on a "
            "line of its own and close the array with ']' on a separate line"
        )
    return [
        Ignore(ident, index + 1, expires)
        for ident, (index, expires) in zip(expected, found, strict=True)
    ]


def _iso_date(value: str) -> dt.date | None:
    # fromisoformat alone also accepts forms such as 20261231 and 2026-W53-4
    if not _ISO_DATE.fullmatch(value):
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:  # well-formed but not a calendar date, e.g. 2026-02-30
        return None


def problems(ignores: list[Ignore], today: dt.date, max_days: int) -> list[str]:
    """Describe every ignore whose expiry is missing, malformed, past or too late."""
    out = []
    for ignore in ignores:
        where = f"line {ignore.line}: {ignore.ident}"
        if not ignore.expires:
            out.append(f"{where}: no '# expires: YYYY-MM-DD' comment directly above")
            continue
        if len(ignore.expires) > 1:
            out.append(f"{where}: more than one '# expires:' comment")
            continue
        value = ignore.expires[0]
        expires = _iso_date(value)
        if expires is None:
            out.append(f"{where}: expiry {value!r} is not a YYYY-MM-DD date")
            continue
        if expires < today:
            out.append(f"{where}: expired on {expires}; fix or re-evaluate the ignore")
        elif (expires - today).days > max_days:
            out.append(f"{where}: expiry {expires} is more than {max_days} days ahead")
    return out


def check_config(config: Path, today: dt.date, max_days: int) -> int:
    """Report on the ignores of one deny.toml and return its exit status."""
    try:
        ignores = parse_ignores(config.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ConfigError) as err:
        print(f"{config}: error: {err}", file=sys.stderr)
        return 2
    found = problems(ignores, today, max_days)
    for problem in found:
        print(f"{config}: {problem}", file=sys.stderr)
    if found:
        return 1
    count = len(ignores)
    print(f"{config}: {count} advisory ignore(s), all with a current expiry")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument(
        "--config",
        dest="configs",
        type=Path,
        action="append",
        help=(
            "deny.toml to check, repeated for several (default: the "
            "repository's deny.toml and gui/deny.toml)"
        ),
    )
    parser.add_argument(
        "--today",
        type=dt.date.fromisoformat,
        default=dt.datetime.now(dt.UTC).date(),
        help="reference date as YYYY-MM-DD (default: today in UTC)",
    )
    parser.add_argument(
        "--max-days",
        type=int,
        default=DEFAULT_MAX_DAYS,
        help="latest allowed expiry, in days after --today (default: %(default)s)",
    )
    args = parser.parse_args(argv)
    if args.max_days < 0:
        parser.error("--max-days must not be negative")

    configs = args.configs or DEFAULT_CONFIGS
    return max(check_config(config, args.today, args.max_days) for config in configs)


if __name__ == "__main__":
    sys.exit(main())
