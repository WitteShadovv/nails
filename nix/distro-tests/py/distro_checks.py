"""Distribution-agnostic helpers for the portable smoke scenario.

The smoke scenario (``nix/distro-tests/tests/smoke.nix``) runs the same
whole-root lifecycle on every distribution in the image table. A few of its
assertions have to know the decoy's own shape -- where a hidden write lands
depends on whether the tree it writes to is a filesystem of its own, and which
boot filesystems a distribution mounts differs between families. Keeping that
logic here, as pure functions with a unit-test suite, means the scenario itself
stays a thin driver script and the layout rules cannot drift unnoticed: the
``distro-checks`` flake check locks them on every ``nix flake check``, without a
VM.

Nothing here imports Nix or the test driver, so it runs under a plain
``python3 -m unittest``. The scenario loads it on the driver the same way it
loads ``nails_e2e`` (a ``sys.path`` entry plus ``import distro_checks``).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

# The hidden-volume layout the whole-root session writes, mirrored from
# ``nails_session::session::layout``. A hidden write to a path on the decoy
# root lands under ``<hidden>/root/upper``; a hidden write to a path on a decoy
# filesystem that is overlaid on its own lands under
# ``<hidden>/root/mounts/<unit>/upper``, where ``<unit>`` is the mount point as
# systemd escapes it. These two constants and :func:`escape_path` are the only
# coupling to that Rust layout; the Rust side carries the upgrade note if it
# moves.
ROOT_LAYER = "root/upper"
MOUNT_LAYERS = "root/mounts"

# The boot filesystems a hidden root must never be able to write to. A
# distribution may mount any subset of these; the scenario checks exactly the
# ones that are mounted. ``/boot/efi`` must come before ``/boot`` nowhere here --
# the order is only the order the scenario reports them in.
BOOT_FILESYSTEMS = ("/boot", "/boot/efi", "/efi")

# Overlay feature options whose "on" form would let the overlay diverge from a
# plain copy-up (an index that survives into the upper, a metadata-only copy
# that leaves data in the lower, a redirect created on a rename or followed back
# into the lower). NAILS pins all three off on every overlay it mounts
# (``nails_teardown::whole_root::nextroot::OVERLAY_FEATURE_OPTIONS``:
# ``index=off,metacopy=off,redirect_dir=nofollow``). None of the dangerous
# states may ever appear in the mount table.
FORBIDDEN_OVERLAY_OPTIONS = (
    "index=on",
    "metacopy=on",
    "redirect_dir=on",
    "redirect_dir=follow",
)

# The kernel echoes a feature option only when it differs from its own
# compiled default, so the absence of the "on" states proves nothing on a
# kernel whose defaults are those states: an overlay mounted without the pins
# echoes nothing there. ``redirect_dir`` defaults to ``nofollow`` only on a
# kernel built without ``CONFIG_OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW``, which the
# upstream default and the kernels of the image table keep: Debian's and
# Ubuntu's default to ``follow``, Arch's to ``on``. So every overlay NAILS
# mounts must echo the pin, and one that does not was mounted without the pins.
# ``index`` and ``metacopy`` default to their pinned "off" on Debian and
# Ubuntu, where nothing is echoed either way. This mirrors the kernel-tier twin
# in ``nails-core/tests/kernel_semantics.rs``, which asserts the same pin.
REQUIRED_OVERLAY_OPTIONS = ("redirect_dir=nofollow",)


def escape_path(path: str) -> str:
    """Escape a mount point as systemd does for a unit name, minus the suffix.

    A faithful port of ``nails_base::fstab::escape_path`` (which itself follows
    ``systemd-escape --path``): the leading slash and ``.`` components are
    dropped, ``..`` leading an absolute path is dropped, ``/`` becomes ``-`` and
    any byte outside ``[A-Za-z0-9:_.]`` becomes ``\\xNN``, with a leading ``.``
    escaped so a unit name never starts with a dot. The empty path is ``-``.

    The scenario needs this to name a decoy filesystem's layer directory on the
    hidden volume (``root/mounts/<escape_path(target)>/upper``), exactly as the
    session does, so a canary written to a separately mounted ``/home`` is read
    back from the right place.
    """
    absolute = path.startswith("/")
    kept: list[str] = []
    for component in path.split("/"):
        if not component or component == ".":
            continue
        if absolute and not kept and component == "..":
            continue
        kept.append(component)
    if not kept:
        return "-"
    joined = "/".join(kept)
    out: list[str] = []
    for index, byte in enumerate(joined.encode("utf-8")):
        char = chr(byte)
        if char == "/":
            out.append("-")
        elif char == "." and index == 0:
            out.append("\\x2e")
        elif char.isascii() and (char.isalnum() or char in ":_."):
            out.append(char)
        else:
            out.append(f"\\x{byte:02x}")
    return "".join(out)


def canary_name(tree: str) -> str:
    """The canary file the smoke scenario plants at the root of ``/<tree>``."""
    return f"nails-canary-{tree}"


def parse_mount_targets(findmnt_output: str) -> list[str]:
    """The mount points in ``findmnt -rn -o TARGET`` output, in order.

    One target per line; blank lines are dropped. The cloud images the suite
    boots have no mount point with a space in it, so the raw targets are taken
    verbatim.
    """
    return [line.strip() for line in findmnt_output.splitlines() if line.strip()]


def parse_findmnt_pairs(findmnt_output: str) -> list[tuple[str, str]]:
    """Parse ``findmnt -rn -o TARGET,OPTIONS`` output into ``(target, options)``.

    Each line is a target, a single space, then the comma-separated options; the
    options never contain a space, so splitting on the first run of whitespace is
    exact. A line with no options yields an empty option string.
    """
    pairs: list[tuple[str, str]] = []
    for line in findmnt_output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 1)
        target = parts[0]
        options = parts[1] if len(parts) > 1 else ""
        pairs.append((target, options))
    return pairs


def _is_under(path: str, mount: str) -> bool:
    """Whether ``path`` lies on the filesystem mounted at ``mount``."""
    if mount == "/":
        return True
    mount = mount.rstrip("/")
    return path == mount or path.startswith(mount + "/")


def containing_mount(path: str, mounts: Iterable[str]) -> str:
    """The deepest mount point from ``mounts`` that ``path`` lies on.

    ``/`` is always an implicit candidate, so a path on no other mount resolves
    to ``/``. When two mount points both contain the path (a mount below a
    mount), the longer one wins -- the filesystem the path is actually on.
    """
    best = "/"
    for mount in mounts:
        if _is_under(path, mount) and len(mount.rstrip("/")) > len(best.rstrip("/")):
            best = mount
    return best


def canary_upper(hidden_root: str, tree: str, mounts: Iterable[str]) -> str:
    """Where a canary written into ``/<tree>`` lands on the hidden volume.

    The canary file sits at ``/<tree>/<canary_name(tree)>``. If ``/<tree>`` is
    part of the decoy root, the write lands in the root overlay's upper under
    ``<hidden>/root/upper/<tree>/...``. If ``/<tree>`` (or an ancestor of it) is
    a decoy filesystem of its own, the write lands in that filesystem's overlay
    upper under ``<hidden>/root/mounts/<unit>/upper/...``, with the path taken
    relative to the mount point. This assumes a writable tree gets an overlay,
    which is how the session treats the decoy's own home, ``/var`` and the like;
    a read-only bind would refuse the write instead, which the scenario never
    plants a canary into.
    """
    hidden_root = hidden_root.rstrip("/")
    full = f"/{tree.strip('/')}/{canary_name(tree)}"
    mount = containing_mount(f"/{tree.strip('/')}", mounts)
    if mount == "/":
        relative = full.lstrip("/")
        return f"{hidden_root}/{ROOT_LAYER}/{relative}"
    unit = escape_path(mount)
    relative = full[len(mount.rstrip("/")) :].lstrip("/")
    return f"{hidden_root}/{MOUNT_LAYERS}/{unit}/upper/{relative}"


def boot_mounts(mounts: Iterable[str]) -> list[str]:
    """The boot filesystems that are mounted, in :data:`BOOT_FILESYSTEMS` order.

    The scenario checks each of these is read-only in the hidden root; a
    distribution that mounts none of them (a BIOS host with ``/boot`` on the
    root filesystem) yields an empty list and the scenario skips the check.
    """
    present = set(mounts)
    return [target for target in BOOT_FILESYSTEMS if target in present]


def overlay_option_violations(options: str) -> list[str]:
    """How an overlay's options break the feature-option pins.

    ``options`` is a comma-separated mount-option list as ``findmnt`` prints it.
    The result lists the members of :data:`FORBIDDEN_OVERLAY_OPTIONS` present,
    in declaration order, then ``missing <pin>`` for each member of
    :data:`REQUIRED_OVERLAY_OPTIONS` absent; an empty result means the overlay
    pins the feature options as NAILS requires.
    """
    tokens = {token.strip() for token in options.split(",") if token.strip()}
    found = [option for option in FORBIDDEN_OVERLAY_OPTIONS if option in tokens]
    for option in REQUIRED_OVERLAY_OPTIONS:
        if option not in tokens:
            found.append(f"missing {option}")
    return found


def upperdir(options: str) -> str | None:
    """The ``upperdir=`` of an overlay's options, or None for a read-only one."""
    for token in options.split(","):
        key, _, value = token.strip().partition("=")
        if key == "upperdir":
            return value
    return None


def nails_overlays(
    pairs: Sequence[tuple[str, str]], hidden_root: str
) -> list[tuple[str, str]]:
    """The overlays NAILS mounted, from parsed ``findmnt`` ``(target, options)``.

    They are the ones whose upper is a layer directory on the hidden volume
    (``hidden_root``): its :data:`ROOT_LAYER` for the root overlay, a directory
    below its :data:`MOUNT_LAYERS` for a decoy filesystem overlaid on its own.
    Any other overlay (one the image itself mounts) is not NAILS's to pin and
    is left out.
    """
    hidden_root = hidden_root.rstrip("/")
    root_upper = f"{hidden_root}/{ROOT_LAYER}"
    mount_layers = f"{hidden_root}/{MOUNT_LAYERS}/"
    picked: list[tuple[str, str]] = []
    for target, options in pairs:
        upper = upperdir(options) or ""
        if upper == root_upper or upper.startswith(mount_layers):
            picked.append((target, options))
    return picked


def overlay_targets_with_violations(
    pairs: Sequence[tuple[str, str]],
) -> dict[str, list[str]]:
    """Map each overlay mount that violates the option pins to its violations.

    ``pairs`` is parsed ``findmnt -rn -t overlay -o TARGET,OPTIONS`` output,
    narrowed to NAILS's overlays (:func:`nails_overlays`). An overlay with no
    violation is omitted, so an empty mapping means every one of them pins the
    feature options correctly.
    """
    violations: dict[str, list[str]] = {}
    for target, options in pairs:
        found = overlay_option_violations(options)
        if found:
            violations[target] = found
    return violations
