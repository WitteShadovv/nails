"""Install a recording ``nixos-rebuild`` shim on a guest, for the test driver.

The real ``nixos-rebuild`` is slow and, for most tests, unnecessary: they only
need activation to reach the Active state and to prove which switch was asked
for. This puts a shim first on ``PATH`` that logs every invocation and, by
default, exits 0. The caller prepends the returned ``PATH=...`` string to the
activation command. Like the other helpers, it takes the node as its first
argument rather than reading a global, so multi-node tests pass the node they
mean.
"""

from __future__ import annotations

import shlex
from typing import Protocol


class Machine(Protocol):
    """The slice of the driver's machine object this helper uses."""

    def succeed(self, *commands: str) -> str: ...


def install_nixos_rebuild_wrapper(
    machine: Machine,
    log_path: str,
    *,
    marker_path: str | None = None,
    marker_content: str = "rebuild-active",
    passthrough: bool = False,
    bin_dir: str = "/tmp/nails-wrapper/bin",
) -> str:
    """Install the shim and return the ``PATH`` prefix that selects it.

    Every invocation appends its arguments to ``log_path`` (truncated first).
    With ``passthrough`` the shim execs the real ``nixos-rebuild`` after logging,
    so a test can observe the arguments while still performing the switch;
    otherwise it exits 0. When ``marker_path`` is given the shim writes
    ``marker_content`` there on the ``test`` subcommand, which lets a test prove
    the activation path reached the rebuild. ``bin_dir`` is where the shim is
    written, for tests whose ``/tmp`` is itself under an overlay.
    """
    if passthrough:
        real_rebuild = machine.succeed("bash -lc 'command -v nixos-rebuild'").strip()
        tail = f'exec {shlex.quote(real_rebuild)} "$@"'
    else:
        tail = "exit 0"

    lines = [
        "#!/bin/sh",
        f'printf \'%s\\n\' "$*" >> {shlex.quote(log_path)}',
    ]
    if marker_path is not None:
        quoted_marker = shlex.quote(marker_path)
        lines += [
            'if [ "$1" = test ]; then',
            f'  mkdir -p "$(dirname {quoted_marker})"',
            f"  printf '%s\\n' {shlex.quote(marker_content)} > {quoted_marker}",
            "fi",
        ]
    lines.append(tail)
    shim = "\n".join(lines) + "\n"

    bin_path = f"{bin_dir}/nixos-rebuild"
    machine.succeed(f"mkdir -p {shlex.quote(bin_dir)}")
    machine.succeed(f"rm -f {shlex.quote(log_path)}")
    # A quoted heredoc delimiter writes the shim verbatim, so the guest shell
    # that assembles the file never expands the shim's own "$*"/"$@"/"$1".
    machine.succeed(
        f"cat > {shlex.quote(bin_path)} <<'NAILS_REBUILD_EOF'\n"
        + shim
        + "NAILS_REBUILD_EOF"
    )
    machine.succeed(f"chmod 755 {shlex.quote(bin_path)}")
    return f"PATH={bin_dir}:$PATH"
