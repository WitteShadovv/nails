# Threat model

This document records invariants NAILS must preserve against an adversary who
later gains full, offline access to the host's disks and firmware. Anything that
survives a session and reveals that a hidden mode ever existed is evidence, even
when the hidden data itself stays encrypted.

## Bootloader, ESP and EFI NVRAM stay unchanged

**Invariant:** activating and then deactivating the hidden environment must not
change any boot entry, ESP file or EFI NVRAM variable relative to a plain
reboot. A boot entry, bootloader config file or NVRAM variable that enables the
hidden mode is itself evidence, and none of it is captured by the overlay, so it
cannot be rolled back by unmounting.

How the code upholds this:

- **Activation never installs.** The hidden generation is activated with
  `switch-to-configuration test`, which activates for the running session only
  and never touches the bootloader, ESP or NVRAM. The boot default therefore
  always remains the decoy.
- **Deactivation never installs.** Standard deactivation restores the decoy by
  re-pointing the `/run/current-system` symlink and then rebooting; the reboot
  boots the decoy from the unchanged bootloader default. It never runs
  `switch-to-configuration switch`, which would reinstall the bootloader, write
  the ESP, rewrite EFI NVRAM and rewrite `/var/lib/nixos`.
- **The action type forbids installing.** The action passed to
  `switch-to-configuration` / `nixos-rebuild` is the `SwitchAction` enum, which
  can only express `test`. No caller — activation, rollback, or the reboot
  fallback — can request `switch` or `boot`.
- **The reboot fallback is non-installing.** If the reboot command itself fails,
  deactivation falls back to `switch-to-configuration test` so the decoy is
  still restored for the running session, again without touching the bootloader,
  ESP or NVRAM.

This invariant is checked by a UEFI persistent-root end-to-end test (in the E2E
suite): it hashes the ESP file listing and captures the EFI variable list
(`efibootmgr -v` / efivarfs) and `/var/lib/nixos` contents before activation and
after deactivation, and asserts both are unchanged relative to a plain-reboot
control.
