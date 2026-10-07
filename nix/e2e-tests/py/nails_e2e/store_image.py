"""Reuse a VM's erofs Nix store image across restarts within one test.

With ``virtualisation.useNixStoreImage`` the VM start script from nixpkgs'
``qemu-vm.nix`` packs the whole system closure into an erofs image
(``"$TMPDIR"/store.img``, where the driver sets ``TMPDIR`` to the machine's state
directory) every time it runs. The image depends only on the closure, which is
fixed for the lifetime of a test, but the forensic tests start the same machine
three or more times (every disk snapshot and every deactivation power-cycles
it), and each start packed the closure again: 79 s per start in the driver log
of standard-deactivation-forensic, before QEMU even ran.

:func:`cache_store_image` points the machine at a copy of its start script in
which that step is skipped when an image built by an earlier start of the same
machine is still there and unchanged. The image is reused only if its size and
modification time match a stamp written right after it was built: the guest
mounts it read-only (erofs cannot be written), so a mismatch means something
outside the guest touched it, and the script then rebuilds it exactly as before.
A partial image from an interrupted build never has a stamp, because the stamp
is written only after ``mkfs.erofs`` succeeded under the script's ``set -e``.

The block is found by the two ``echo`` lines nixpkgs prints around it. If a
nixpkgs bump changes them, nothing is patched and the machine keeps the stock
script; the ``store image cache`` line in the driver log says which happened.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

BEGIN_MARKER = 'echo "Creating Nix store image..."'
END_MARKER = 'echo "Created Nix store image."'
REUSE_MESSAGE = "Reusing Nix store image."

_STAMP = '"$TMPDIR"/store.img.nails-stamp'
_IMAGE = '"$TMPDIR"/store.img'
# GNU stat with nanosecond mtime: a write by anything outside the guest moves it.
_FINGERPRINT = f"stat -c '%s %.9Y' {_IMAGE}"


def patch_start_script(text: str) -> str | None:
    """Return ``text`` with the store image build made conditional, or None.

    None means the script builds no store image (a 9p-store VM) or the markers
    are not where this code expects them, so it must be left alone.
    """
    lines = text.splitlines(keepends=True)
    begins = [i for i, line in enumerate(lines) if line.strip() == BEGIN_MARKER]
    ends = [i for i, line in enumerate(lines) if line.strip() == END_MARKER]
    if len(begins) != 1 or len(ends) != 1 or ends[0] <= begins[0]:
        return None
    begin, end = begins[0], ends[0]
    guard = (
        f"if [ -f {_IMAGE} ] && [ -f {_STAMP} ] "
        f'&& [ "$({_FINGERPRINT})" = "$(cat {_STAMP})" ]; then\n'
        f'  echo "{REUSE_MESSAGE}"\n'
        "else\n"
        f"  rm -f {_STAMP}\n"
    )
    stamp = f"  {_FINGERPRINT} > {_STAMP}\nfi\n"
    return "".join(
        lines[:begin] + [guard] + lines[begin : end + 1] + [stamp] + lines[end + 1 :]
    )


def cache_store_image(machine: object, scratch_dir: str | None = None) -> bool:
    """Make ``machine`` reuse its store image on every start after the first.

    Returns True when the start script was swapped for the patched copy. The
    copy lives in a fresh directory (``scratch_dir`` or a temporary one) and
    keeps every other line of the original, including the store paths it calls.
    Must be called before the machine's first start to save that start's image.
    ``machine`` is the driver's QemuMachine; any object without a
    ``start_command._cmd`` script path (an nspawn container) is left alone.
    """
    start_command = getattr(machine, "start_command", None)
    script = getattr(start_command, "_cmd", None)
    name = getattr(machine, "name", "machine")
    if not isinstance(script, str) or not os.path.isfile(script):
        print(f"store image cache: {name}: no start script to patch")
        return False
    patched = patch_start_script(Path(script).read_text(encoding="utf-8"))
    if patched is None:
        print(f"store image cache: {name}: no store image step, left unchanged")
        return False
    directory = Path(scratch_dir or tempfile.mkdtemp(prefix="nails-start-script-"))
    # Keep the run-<name>-vm basename: the driver derives nothing from it after
    # construction, but a recognisable name helps when reading process lists.
    copy = directory / Path(script).name
    copy.write_text(patched, encoding="utf-8")
    copy.chmod(0o755)
    setattr(start_command, "_cmd", str(copy))  # noqa: B010 - private driver field
    print(f"store image cache: {name}: enabled ({copy})")
    return True
