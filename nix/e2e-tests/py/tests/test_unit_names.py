"""Host-side tests for the unit names the way back asks PID 1 about."""

from __future__ import annotations

import subprocess
import unittest

from nails_e2e import unit_names


class FakeMachine:
    """Answers ``systemctl is-active`` with ``answers``, one call after the
    other, and records every command."""

    def __init__(self, answers: list[str]) -> None:
        self.answers = answers
        self.commands: list[str] = []

    def succeed(self, command: str) -> str:
        self.commands.append(command)
        if command.startswith("systemctl is-active"):
            return self.answers.pop(0)
        return ""


class UnitNamesTest(unittest.TestCase):
    def test_every_case_is_a_unit_name_of_fewer_than_256_characters(self) -> None:
        for folder, name in unit_names.CASES:
            self.assertTrue(name.startswith(unit_names.PREFIX), name)
            self.assertTrue(name.endswith(".mount"), name)
            self.assertLess(len(name), 256, folder)
            self.assertTrue(name.isascii(), name)

    def test_the_shell_word_gives_the_path_byte_for_byte(self) -> None:
        for path in [unit_names.BASE + folder for folder, _ in unit_names.CASES]:
            word = unit_names.shell_path(path)
            self.assertTrue(word.isascii(), word)
            out = subprocess.run(
                ["bash", "-c", f"{word}; printf '%s' \"$p\""],
                check=True,
                capture_output=True,
            ).stdout
            self.assertEqual(out, path)

    def test_the_check_wants_every_unit_up_then_down(self) -> None:
        count = len(unit_names.CASES)
        good = FakeMachine(["active\n" * count, "inactive\n" * count])
        unit_names.check(good)
        asked = [c for c in good.commands if c.startswith("systemctl is-active")]
        self.assertEqual(len(asked), 2)
        for _, name in unit_names.CASES:
            self.assertIn(f"'{name}'", asked[0])
        missed = FakeMachine(["inactive\n" * count, "inactive\n" * count])
        with self.assertRaises(AssertionError):
            unit_names.check(missed)


if __name__ == "__main__":
    unittest.main()
