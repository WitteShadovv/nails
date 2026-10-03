# Threat model

This is the only place the NAILS threat model is written down. The README, the
[operator guide](operator-guide.md) and [SECURITY.md](../SECURITY.md) link here
instead of restating it; per-platform setup lives in
[decoy-requirements.md](decoy-requirements.md).

## Adversary

The adversary gains full, **offline** access to the host's disks and firmware
after the fact — typically after seizing a powered-off device — and runs a
dead-disk forensic analysis to prove that a hidden environment ever existed.
They can image every disk, read every unencrypted block, filesystem journal and
log, inspect the ESP and EFI variables, and compare the decoy against what a
plain installation would contain.

Anything that survives a session and reveals that a hidden mode existed is
evidence, even when the hidden data itself stays encrypted. The adversary does
not need the hidden data; a single trace of its use is enough.

## Assumptions

The claims below hold only when all of these are true:

- **Outer encryption.** The decoy's disk is protected by full-disk encryption
  the operator can unlock for the adversary without revealing the hidden
  volume, and the hidden volume sits inside a deniable backend (for example a
  VeraCrypt hidden volume). Encryption is not provided by NAILS; see
  [backends.md](backends.md).
- **Amnesic decoy.** The base system keeps no durable record of the hidden
  session: volatile journald, no classic syslog or audit daemon, no persistent
  crash dumps. NAILS enforces the load-bearing parts at pre-flight and fails
  closed otherwise; [decoy-requirements.md](decoy-requirements.md) has the full
  list and how to satisfy it per platform.
- **No swap or hibernation.** Memory pages from the hidden session must never be
  written to a decoy disk.
- **Volatile journald.** The journal lives in RAM only, so the window before
  `/var` is overlaid (see [Residual channels](#residual-channels)) never reaches
  disk.
- **Trusted root.** The NAILS binary, its configuration and the hidden flake on
  the hidden volume are intact. NAILS runs as root and performs no runtime
  self-integrity check.
- **Clean teardown.** The operator deactivates (or runs `nails emergency`) and
  powers off before the device is seized, and the hidden backend is closed.

## Out of scope

NAILS does not defend against:

- live compromise of a running system, including while the hidden session is
  active;
- memory forensics during or shortly after use, including cold-boot attacks;
- hardware implants, firmware compromise, or physical surveillance and
  keylogging;
- side channels such as timing, power or electromagnetic analysis;
- coercion and other threats outside the software boundary;
- **network-provider logs**: anything an ISP, Wi-Fi operator, VPN provider or
  other network observer records about the host's traffic;
- **remote-service records**: anything a server, cloud service or peer device
  holds about what the hidden session did (accounts, sync state, mail, messages,
  access logs);
- correlation through the network identifiers the hidden session shares with
  the decoy (see the next section);
- operator mistakes such as skipping deactivation or leaving the backend
  mounted.

## What the hidden environment shares with the decoy

The overlay isolates **writes to the on-disk filesystem**. It does not give the
hidden environment a separate machine, account or online identity, and hidden
services are not separate from decoy services: they run on the same kernel, in
the same init, next to whatever the decoy keeps running.

- **Account and home.** In the default `shared-home` persona the hidden session
  runs as the decoy user, in the decoy home, merged read-write through the
  `/home` overlay. The decoy's browser profiles, SSH/GPG keys,
  password-manager state and history are live in the hidden session. The
  opt-in `fresh-home` persona bind-mounts a clean home from the hidden volume
  instead, so the decoy home is not visible; see
  [Persona modes](configuration.md#persona-modes) and the
  [operator guide](operator-guide.md#shared-decoy-account-and-persona-modes).
  A separate hidden account does not exist yet.
- **Inherited system and user units.** Decoy system services keep running, and
  in `shared-home` the hidden session also inherits the decoy account's
  autostart entries, enabled user services and timers, lingering and
  display-manager autologin. `nails check` and the activation confirmation
  inventory them, and `[persona] mask_inherited` can stop autostart entries and
  user units from running in the hidden session. Lingering and autologin are
  reported, not masked.
- **Network identity.** The overlay does not change machine-id, hostname, MAC
  addresses or NetworkManager profiles (including VPN autoconnect);
  `clean_stale_network_config` preserves only DNS. An optional hidden
  network-identity configuration (random MAC, distinct hostname; VPN
  autoconnect disabled per profile) can be applied in the hidden NixOS
  generation or as a NetworkManager drop-in. It is opt-in and takes effect only
  when the hidden switch runs before the session restarts.
- **Remote state, never rolled back.** Deactivation discards the overlay upper
  directories and nothing else. Anything the hidden session sent through a
  shared account, token or sync client lives on the remote, and a decoy sync
  client can pull it back onto the decoy disk after deactivation. Masking
  changes what runs; it never reaches the remote side. See
  [Remote state and sync clients](operator-guide.md#remote-state-and-sync-clients).

## Invariant

**No hidden-mode enabler may persist on the decoy.** A boot entry, initramfs
hook, config file or EFI NVRAM variable that enables the hidden mode is itself
evidence, even when the hidden data stays encrypted. Everything NAILS needs to
start a hidden session lives on the hidden volume, and the decoy carries no hook
that knows about it.

For the bootloader this means: activating and then deactivating the hidden
environment must not change any boot entry, ESP file or EFI NVRAM variable
relative to a plain reboot. None of these is captured by the overlay, so a
change there could not be rolled back by unmounting.

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

## Residual channels

The overlay cannot cover these. Each is either bounded by an assumption above or
documented as a known gap:

- **The journal window before `/var` is overlaid.** Between `sudo nails
  activate` and the moment the `/var` overlay mounts, journald records the sudo
  command line, transient unit names and mount events on the decoy. Volatile
  journald keeps this in RAM.
- **The sudo log.** sudo records the invoking user and the command (including
  the binary path on the hidden volume) through journald, syslog or
  `/var/log/sudo.log`. NAILS cannot suppress it without tampering with sudo; an
  amnesic decoy and a neutral binary path are the mitigation. See
  [The sudo-log exposure](decoy-requirements.md#the-sudo-log-exposure-and-its-mitigation).
- **Decoy activation at deactivation time.** When the reboot command fails, the
  fallback runs the decoy generation's `switch-to-configuration test` on the
  real system, which restarts decoy services and writes to the decoy journal.
  This remains a channel until that fallback is removed.
- **EFI NVRAM, RTC and firmware-backed pstore.** These are not filesystem writes
  and are not overlaid. The invariant above keeps NAILS from writing NVRAM, but
  other software in the session can.
- **Memory.** RAM holds hidden-session data until power-off. Emergency drops the
  page cache, which does not zero memory; only a power-off clears it.

## Answer to "cannot trust the OS"

A common argument, made for example by the Shufflecake authors, is that hiding
a whole operating system by customising it to avoid leaks is hopeless: every
application, daemon and indexer may write somewhere, and auditing them one by
one never ends.

NAILS does not tune individual applications. It redirects **every write outside
pseudo filesystems at the mount layer**: the overlays cover the writable decoy
trees, so whatever program writes there — known or unknown — writes into an
upper directory on the hidden volume, which disappears from the decoy when the
overlays are unmounted. The question "which application leaks?" becomes "which
writes bypass the mount layer?", and that set is small and enumerable: the
residual channels listed above. Residual risk is limited to those channels and
to the shared state in the previous section, which the overlay does not claim to
isolate.

## Known residual changes

**Status: under investigation.**

On a NixOS decoy, `/var/lib/nixos` holds the declarative account bookkeeping
(`declarative-users`, `declarative-groups`, `uid-map`, `gid-map`,
`auto-subuid-map`). The one residual change seen in evaluation was a rewrite of
these files under `/persist/var/lib/nixos` across a hidden session. That
evaluation could not say whether NAILS caused it, because there was no control
run and the comparison was by mtime rather than by contents.

A disk-forensic E2E test on the impermanent decoy profile
(`nix/e2e-tests/tests/nixos/34-var-lib-nixos-drift.nix`), where only
`/persist/var/lib/nixos` survives a power-off, is designed to settle it. It
snapshots that tree by content hash and compares three runs:

- **Control** — a plain reboot with no hidden session. The decoy's own
  boot-time `update-users-groups` and `switch-to-configuration` rewrite the
  declarative-account and id-map files on every boot, so this churn is expected
  to be ordinary boot noise. It is the baseline every other run is measured
  against.
- **Standard deactivation** and **emergency deactivation** — a hidden session is
  activated with `/var` overlaid, so the hidden `switch-to-configuration` writes
  its user state into the overlay upper on the hidden volume, not onto the decoy.
  After teardown the persisted `/var/lib/nixos` must show no change beyond the
  control set.

To make containment falsifiable, the hidden configuration declares a canary user
and group (`hiddencanary`, uid/gid 64123) that exist nowhere in the decoy. The
test proves the canary is live during the hidden session and then asserts its
name and id appear on **no** persisted or regenerated decoy state — not in
`/persist/var/lib/nixos`, `/etc/passwd`, `/etc/group`, or the journal — after both
deactivation modes. A leak means the overlay is not covering the `/var/lib/nixos`
bind submount and the hidden account reached the decoy disk; that is a
containment failure to fix in the overlay handling for `/var/lib/nixos`
(evaluating `userborn`/`systemd-sysusers`), never to document away.

The drift stays "under investigation" until that test has run on a Nix host
(`nix build .#checks.x86_64-linux.var-lib-nixos-drift`) and its result is
recorded here.

## Evaluation scope

The forensic claims rest on this configuration:

- a NixOS decoy with a **tmpfs root** and only `/persist` (plus the Nix store)
  on disk;
- **no swap**, and volatile journald;
- a **VeraCrypt hidden volume** with ext4 inside, opened with
  `cryptsetup open --type tcrypt --tcrypt-hidden`, as the hidden backend;
- **dead-disk analysis** of the powered-off decoy disk image.

That full configuration was evaluated manually, once. The automated E2E
disk-image checks cover only NixOS VMs with a **LUKS2/ext4** hidden backend
(one nightly backend test images a VeraCrypt volume but has not yet been
validated on a Nix host). Debian and Ubuntu decoys, other backends and
filesystems, and physical hardware are not covered by disk-image checks; see
[backends.md](backends.md) for the per-backend status. Claims outside this scope
are unverified.
