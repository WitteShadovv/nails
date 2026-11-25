"""Host-side tests for ``install_nixos_rebuild_wrapper``.

A fake machine captures the commands the helper runs so the generated shim and
the returned PATH prefix are checked without a VM.
"""

from __future__ import annotations

import unittest

from nails_e2e import install_nixos_rebuild_wrapper


class FakeMachine:
    def __init__(self, reads: dict[str, str] | None = None) -> None:
        self.commands: list[str] = []
        self._reads = reads or {}

    def succeed(self, *commands: str) -> str:
        outputs = []
        for command in commands:
            self.commands.append(command)
            outputs.append(self._reads.get(command, ""))
        return "".join(outputs)

    def shim_body(self) -> str:
        """The here-doc'd shim, extracted from the recorded write command."""
        for command in self.commands:
            if command.startswith("cat > ") and "NAILS_REBUILD_EOF" in command:
                _, _, rest = command.partition("\n")
                body, _, _ = rest.rpartition("NAILS_REBUILD_EOF")
                return body
        raise AssertionError("no shim was written")


class InstallRebuildWrapperTest(unittest.TestCase):
    def test_default_shim_logs_and_exits_zero(self) -> None:
        machine = FakeMachine()

        prefix = install_nixos_rebuild_wrapper(machine, "/tmp/rebuild.log")

        self.assertEqual(prefix, "PATH=/tmp/nails-wrapper/bin:$PATH")
        self.assertIn("rm -f /tmp/rebuild.log", machine.commands)
        self.assertIn("mkdir -p /tmp/nails-wrapper/bin", machine.commands)
        self.assertIn(
            "chmod 755 /tmp/nails-wrapper/bin/nixos-rebuild", machine.commands
        )
        body = machine.shim_body()
        self.assertIn("#!/bin/sh", body)
        self.assertIn('printf \'%s\\n\' "$*" >> /tmp/rebuild.log', body)
        self.assertIn("exit 0", body)
        self.assertNotIn("exec", body)

    def test_marker_is_written_on_the_test_subcommand(self) -> None:
        machine = FakeMachine()

        install_nixos_rebuild_wrapper(
            machine,
            "/tmp/rebuild.log",
            marker_path="/etc/nails-marker",
            marker_content="switch-fired",
        )

        body = machine.shim_body()
        self.assertIn('if [ "$1" = test ]; then', body)
        self.assertIn('mkdir -p "$(dirname /etc/nails-marker)"', body)
        self.assertIn("printf '%s\\n' switch-fired > /etc/nails-marker", body)

    def test_passthrough_execs_the_real_rebuild(self) -> None:
        real = "/run/current-system/sw/bin/nixos-rebuild"
        machine = FakeMachine({"bash -lc 'command -v nixos-rebuild'": real + "\n"})

        install_nixos_rebuild_wrapper(machine, "/tmp/rebuild.log", passthrough=True)

        body = machine.shim_body()
        self.assertIn(f'exec {real} "$@"', body)
        self.assertNotIn("exit 0", body)

    def test_bin_dir_overrides_the_path_prefix(self) -> None:
        machine = FakeMachine()

        prefix = install_nixos_rebuild_wrapper(
            machine, "/tmp/rebuild.log", bin_dir="/var/lib/nails-tests/bin"
        )

        self.assertEqual(prefix, "PATH=/var/lib/nails-tests/bin:$PATH")
        self.assertIn(
            "chmod 755 /var/lib/nails-tests/bin/nixos-rebuild", machine.commands
        )


if __name__ == "__main__":
    unittest.main()
