# Threat model

This document records invariants NAILS must preserve against an adversary who
later gains full, offline access to the host's disks and firmware. Anything that
survives a session and reveals that a hidden mode ever existed is evidence, even
when the hidden data itself stays encrypted.

The overlay model assumes an **amnesic decoy**: a base system that keeps no
durable record of the hidden session (volatile journald, no classic syslog or
audit daemon, no swap or hibernation, no persistent crash dumps). NAILS enforces
the load-bearing parts of this at pre-flight and fails closed otherwise. See
[decoy-requirements.md](decoy-requirements.md) for the full list and how to
satisfy it per platform.

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

## Shared remote, account and network identifiers are out of scope

**Statement:** the overlay isolates the on-disk filesystem, not online identity or
network identity. In the default `shared-home` persona the hidden session runs as
the decoy user, so it inherits the decoy account's autostart entries, enabled
systemd user services and timers, lingering and display-manager autologin, and it
shares the host's machine-id, hostname, MAC addresses and NetworkManager profiles
(including VPN autoconnect).

Two consequences are explicitly **not** defended against:

- **Remote and account state is shared and never rolled back.** Anything the
  hidden session touches through a shared account, token or sync client lives on
  the remote service, not on the host, so unmounting the overlay cannot undo it.
  NAILS inventories the inherited autostart/user-service/autologin state
  (`nails check`, activation confirmation) and can mask autostart entries and user
  units for the hidden session (`[persona] mask_inherited`), but masking only
  stops them from running — it does not reach the remote side.
- **Correlation through shared network identifiers is out of scope.** The overlay
  does not change machine-id, hostname, MAC or NetworkManager state;
  `clean_stale_network_config` preserves only DNS. An optional hidden
  network-identity configuration (random MAC, distinct hostname; VPN autoconnect
  is disabled per profile) can be applied in the hidden NixOS generation or as a NetworkManager
  drop-in, but it is opt-in and takes effect only when the hidden switch runs
  before the session restarts.

Fresh-home persona mode reduces the first consequence by starting the hidden
session from a clean home, so the decoy's accounts and clients are not visible; it
does not change the shared network identity.

## Known residual changes: /var/lib/nixos drift

On a NixOS decoy, `/var/lib/nixos` holds the declarative account bookkeeping
(`declarative-users`, `declarative-groups`, `uid-map`, `gid-map`,
`auto-subuid-map`). Earlier evaluation saw these files change across a hidden
session and could not say whether NAILS caused it, because there was no control
run and the comparison was by mtime rather than by contents.

The drift is now bounded by a disk-forensic E2E test on the impermanent decoy
profile (`nix/e2e-tests/tests/nixos/34-var-lib-nixos-drift.nix`), where only
`/persist/var/lib/nixos` survives a power-off. It snapshots that tree by content
hash and compares three runs:

- **Control** — a plain reboot with no hidden session. The decoy's own
  boot-time `update-users-groups` and `switch-to-configuration` rewrite the
  declarative-account and id-map files on every boot, so this churn is ordinary
  boot noise, not a NAILS artefact. It is the baseline every other run is measured
  against.
- **Standard deactivation** and **emergency deactivation** — a hidden session is
  activated with `/var` overlaid, so the hidden `switch-to-configuration` writes
  its user state into the overlay upper on the hidden volume, not onto the decoy.
  After teardown the persisted `/var/lib/nixos` must show no change beyond the
  control set and the allowlisted boot churn above.

To make containment falsifiable, the hidden configuration declares a canary user
and group (`hiddencanary`, uid/gid 64123) that exist nowhere in the decoy. The
test proves the canary is live during the hidden session and then asserts its
name and id appear on **no** persisted or regenerated decoy state — not in
`/persist/var/lib/nixos`, `/etc/passwd`, `/etc/group`, or the journal — after both
deactivation modes. A leak means the overlay is not covering the `/var/lib/nixos`
bind submount and the hidden account reached the decoy disk; that is a
containment failure to fix in the overlay handling for `/var/lib/nixos`
(evaluating `userborn`/`systemd-sysusers`), never to document away.

Confirming the containment requires a Nix host: the overlay semantics for the
`/var/lib/nixos` bind and the offline closure of the canary-augmented fixture
cannot be evaluated in the offline sandbox. Run
`nix build .#checks.x86_64-linux.var-lib-nixos-drift`.
