"""Print the disk layout archinstall suggests for one disk, as its config JSON.

Runs inside the Arch live ISO, with the archinstall the ISO ships. It calls
archinstall's own `suggest_single_disk_layout`, the code its menu runs for
"Use a best-effort default partition layout", and gives it the answers a user
gives there for btrfs: the default subvolume structure, and compression. The
two prompts are answered here instead of on a screen; everything else (the
1 GiB ESP at /boot, the btrfs root over the rest of the disk, the @, @home,
@log and @pkg subvolumes, the sizes and alignment) is archinstall's own.

    python3 disk_layout.py /dev/sda > disk_config.json
"""

import asyncio
import json
import sys
from pathlib import Path

from archinstall.lib.disk import default_layouts
from archinstall.lib.disk.device_handler import device_handler
from archinstall.lib.models.device import (
    BtrfsMountOption,
    DiskLayoutConfiguration,
    DiskLayoutType,
    FilesystemType,
)
from archinstall.tui.menu_item import MenuItem


class _Answered:
    """The result of a yes or no prompt that a user answered yes."""

    def item(self) -> MenuItem:
        return MenuItem.yes()


class _Yes:
    """Stands in for the prompt that asks for the default subvolumes."""

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    async def show(self) -> _Answered:
        return _Answered()


async def _compression() -> list[str]:
    """The answer "Use compression" to the btrfs mount option prompt."""
    return [BtrfsMountOption.compress.value]


def main(device_path: str) -> int:
    device = device_handler.get_device(Path(device_path))
    if device is None:
        print(f"disk_layout: no block device {device_path}", file=sys.stderr)
        return 1
    default_layouts.Confirmation = _Yes
    default_layouts.select_mount_options = _compression
    modification = asyncio.run(
        default_layouts.suggest_single_disk_layout(
            device, filesystem_type=FilesystemType.BTRFS
        )
    )
    config = DiskLayoutConfiguration(
        config_type=DiskLayoutType.Default,
        device_modifications=[modification],
    )
    layout = config.json()
    partitions = layout["device_modifications"][0]["partitions"]
    subvolumes = [vol["name"] for part in partitions for vol in part["btrfs"]]
    if len(partitions) != 2 or subvolumes != ["@", "@home", "@log", "@pkg"]:
        print(f"disk_layout: unexpected suggestion: {layout}", file=sys.stderr)
        return 1
    print(json.dumps(layout, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
