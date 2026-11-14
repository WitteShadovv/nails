"""Unit tests for admit-row.awk, the row flip of the test-only build that admits
a family (nix/distro-tests/lib/admitted.nix).

They run the script on the family table itself
(nails-platform/src/platform/family.rs), as the build does, and on copies of
it with a row admitted the way a family's admission commit admits it. Each
base row the table refuses must change in exactly one line, its own
`admitted: false`; a row already admitted, a derivative's row and an id the
table lacks must each fail the script, so that a test build can never admit
another family than the one it names.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "nix" / "distro-tests" / "lib" / "admit-row.awk"
TABLE = REPO / "nails-platform" / "src" / "platform" / "family.rs"

ROW_START = "    FamilyRow {"
ROW_END = "    },"
REFUSED = "        admitted: false,"
ADMITTED = "        admitted: true,"
_ID = re.compile(r'^        id: "([^"]+)",$')
_KIND = re.compile(r"^        kind: Kind::(\w+),$")
_ADMITTED = re.compile(r"^        admitted: (true|false),$")


@dataclass(frozen=True)
class Row:
    """One row of the family table: where it lies (0-based, inclusive)."""

    id: str
    kind: str
    admitted: bool
    start: int
    end: int


def rows(lines: list[str]) -> list[Row]:
    """The rows of the family table, read the way the script reads them."""
    found: list[Row] = []
    start: int | None = None
    fields: dict[str, str] = {}
    for number, line in enumerate(lines):
        if line == ROW_START:
            start, fields = number, {}
            continue
        if start is None:
            continue
        for key, pattern in (("id", _ID), ("kind", _KIND), ("admitted", _ADMITTED)):
            match = pattern.match(line)
            if match:
                fields[key] = match.group(1)
        if line == ROW_END:
            found.append(
                Row(
                    fields["id"],
                    fields["kind"],
                    fields["admitted"] == "true",
                    start,
                    number,
                )
            )
            start = None
    return found


class AdmitRowTest(unittest.TestCase):
    def setUp(self) -> None:
        awk = shutil.which("awk")
        if awk is None:
            self.fail("awk is not on PATH")
        self.awk = awk
        self.work = Path(tempfile.mkdtemp(prefix="admit-row-"))
        self.addCleanup(shutil.rmtree, self.work)
        self.lines = TABLE.read_text().splitlines()
        self.rows = rows(self.lines)

    def admit(self, row_id: str, lines: list[str]) -> tuple[int, list[str]]:
        table = self.work / "family.rs"
        table.write_text("\n".join(lines) + "\n")
        done = subprocess.run(
            [self.awk, "-v", f"id={row_id}", "-f", str(SCRIPT), str(table)],
            capture_output=True,
            text=True,
            check=False,
        )
        return done.returncode, done.stdout.splitlines()

    def refused_base(self, lines: list[str]) -> list[Row]:
        return [r for r in rows(lines) if r.kind == "Base" and not r.admitted]

    def assert_flips_only(self, row: Row, lines: list[str]) -> list[str]:
        rc, out = self.admit(row.id, lines)
        self.assertEqual(rc, 0, f"{row.id} was not admitted")
        self.assertEqual(len(out), len(lines), row.id)
        changed = [n for n, (a, b) in enumerate(zip(lines, out, strict=True)) if a != b]
        self.assertEqual(len(changed), 1, f"{row.id}: lines {changed} changed")
        (number,) = changed
        self.assertTrue(row.start < number < row.end, f"{row.id}: line {number}")
        self.assertEqual((lines[number], out[number]), (REFUSED, ADMITTED))
        return out

    def test_the_table_has_rows_of_every_kind_to_test(self) -> None:
        # Without them the tests below would test nothing.
        kinds = {(r.kind, r.admitted) for r in self.rows}
        self.assertIn(("Base", False), kinds)
        self.assertIn(("Base", True), kinds)
        self.assertIn(("Derivative", False), kinds)
        ids = [r.id for r in self.rows]
        self.assertEqual(len(ids), len(set(ids)), "an id is in two rows")

    def test_each_refused_base_row_changes_in_its_own_admitted_line_only(self) -> None:
        for row in self.refused_base(self.lines):
            with self.subTest(row=row.id):
                self.assert_flips_only(row, self.lines)

    def test_a_row_already_admitted_fails(self) -> None:
        admitted = [r for r in self.rows if r.kind == "Base" and r.admitted]
        for row in admitted:
            with self.subTest(row=row.id):
                rc, _ = self.admit(row.id, self.lines)
                self.assertNotEqual(rc, 0, f"{row.id} is admitted already")

    def test_a_family_admitted_since_fails_and_leaves_the_others_their_own_rows(
        self,
    ) -> None:
        # The table after one family's admission commit: its row admitted.
        # Asking for that family again must fail, not admit the next row, and
        # every other refused base row still changes in its own line only.
        for first in self.refused_base(self.lines):
            with self.subTest(admitted_since=first.id):
                after = self.assert_flips_only(first, self.lines)
                rc, _ = self.admit(first.id, after)
                self.assertNotEqual(rc, 0, f"{first.id} admitted twice")
                for other in self.refused_base(after):
                    self.assert_flips_only(other, after)

    def test_a_derivative_row_fails(self) -> None:
        derivatives = [r for r in self.rows if r.kind != "Base"]
        for row in derivatives:
            with self.subTest(row=row.id):
                rc, _ = self.admit(row.id, self.lines)
                self.assertNotEqual(rc, 0, f"{row.id} is a derivative")

    def test_an_id_the_table_lacks_fails(self) -> None:
        for row_id in ("", "nosuch", "fedor", "arch\nx", '"arch"'):
            with self.subTest(row=row_id):
                rc, _ = self.admit(row_id, self.lines)
                self.assertNotEqual(rc, 0, f"{row_id!r} is not in the table")

    def test_a_row_that_never_closes_fails(self) -> None:
        row = self.refused_base(self.lines)[0]
        rc, _ = self.admit(row.id, self.lines[: row.end])
        self.assertNotEqual(rc, 0)

    def test_a_row_with_two_admitted_lines_fails(self) -> None:
        row = self.refused_base(self.lines)[0]
        lines = list(self.lines)
        lines.insert(row.end, REFUSED)
        rc, _ = self.admit(row.id, lines)
        self.assertNotEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
