# Changelog

All notable changes to NAILS (NixOS Anti-forensics Isolation & Layering System) are documented in
this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and the project
uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for commit history.

Each release is one annotated `v*` tag: a single workflow builds, rebuilds, tests and attests it
and drafts the GitHub release, which a maintainer then publishes (see `RELEASING.md`). The section
of this changelog for that version becomes the release notes word for word, and
`docs/verify-release.md` explains how to verify the assets.

## [Unreleased]

### Added

- `check` warns when the installed cryptsetup cannot open a VeraCrypt volume whose header key is
  derived with Argon2id (the "Argon2" entry added in VeraCrypt 1.26.29), keyed on the version
  `cryptsetup --version` reports. No released cryptsetup opens such a volume, and nothing outside
  the encrypted header reveals the algorithm, so it advises making both the outer and the hidden
  VeraCrypt volume with PBKDF2.

### Changed

- Discards (TRIM) reaching the hidden volume now refuse activation instead of only warning:
  forwarding TRIM to the physical device leaves a readable map of used and free blocks, where a
  deniable volume should look like uniform random data, and writing an outer volume with discards
  on can destroy a hidden volume inside it. A LUKS2 mapping with runtime or stored discards is
  included, and a RAM-only zram device is excepted. The refusal names no device-mapper node.
- A derivative of a supported distribution — one whose os-release `ID_LIKE` names `debian` or
  `ubuntu`, such as Linux Mint — now runs with a warning that NAILS has not tested it, instead of
  being accepted silently. Fedora, Arch and their known derivatives, Enterprise Linux rebuilds
  (RHEL, CentOS, AlmaLinux, Rocky, Oracle) and SteamOS are each refused with a reason that names
  them and says NAILS has not yet validated them.
- A host that boots from a sealed composefs image is now refused even when it does not set
  `/run/ostree-booted`, recognised by its kernel command line or the composefs runtime directory.
  NAILS cannot overlay an immutable system.

### Fixed

- The whole-root session overlay pins its feature options (`index=off`, `metacopy=off`,
  `redirect_dir=nofollow`) on every host, matching the pre-flight capability probe. On a kernel
  that turns these on by default (such as Arch's), the hidden overlay could keep an index, copy up
  only a file's metadata, or follow a redirect, so data could stay in the lower layer after a
  rollback and the overlay no longer behaved as NAILS's forensic guarantees assume.
- The `decoy-persistence` check judges journald's journal by the running systemd's built-in default
  when no configuration sets `Storage=`: below systemd 259 the default is still `auto`, but from 259
  (Ubuntu 26.04) it is `persistent`, so a decoy that keeps no explicit setting now counts as
  persistent and is refused, where it was read as volatile before. The `journal.storage` credential
  (systemd 257 and later) is read when no configuration file sets `Storage=`, and a systemd whose
  version cannot be read is treated as persistent.
- The journald, logind and systemd-coredump configuration is read line by line for UTF-8, as systemd
  reads it: a comment or other line that is not valid UTF-8 (a Latin-1 comment, say) no longer makes
  the whole file unreadable, so a `Storage=persistent` below such a line is still seen instead of the
  decoy reading as amnesic.
- A btrfs decoy root is accepted only when the mounted root is a real subvolume (its mount root
  equals its `subvol=`). A bind mount of a plain folder on a btrfs filesystem is now refused before
  activation, naming the folder, instead of passing the pre-flight check and then failing the
  way-back mount.
- A decoy mount point that is a symlink (for example `/home` linking to `var/home`, as on
  ostree-based systems) is resolved to its real path inside the decoy root. NAILS now decides, mounts
  and masks the filesystem where the decoy really keeps it (`var-home.mount`, not `home.mount`), and
  fresh-home mode creates the home at that real path instead of a directory where the decoy has a
  symlink.

## [0.3.0-rc.3] - 2026-10-20

### Changed

- The release binary is built with Rust 1.99.1; 0.3.0-rc.2 was built with 1.93.0.
- A release run boots every NixOS VM test on the tagged commit. Until now it took a test whose
  derivation had passed in an earlier run from the project's binary cache, without booting it.
- NAILS's automated VM tests cover Debian 13 and Ubuntu 24.04, and Ubuntu 26.04 is a supported target checked by hand (its automated image is still to be added). A later release, such as Ubuntu
  26.10 (released on 2026-10-15), still runs, but `init`, `check` and `activate` now warn that
  NAILS has not been tested on it; 0.3.0-rc.2 accepted every release from Debian 13 and Ubuntu
  24.04 on without a word. `check` names the detected host in a new `platform` row, which carries
  that warning.

### Fixed

- The attach gate and the storage checks resolve an `/etc/fstab` or `/etc/crypttab` entry that
  names its device by a tag (`LABEL=`, `UUID=`, `PARTLABEL=`, `PARTUUID=`) whose value holds a
  space, a slash or another character udev encodes in the link it makes for the tag, or is in
  single quotes. Such an entry named a path that no link has, and a value starting with a slash
  named that path itself.
- A command no longer hangs on a mount table that names one mount ID twice, as a read of
  `/proc/self/mountinfo` can while a mount is replaced: the lookup of the mount at a path went
  round in a circle for ever.
- A `utab` line with an empty value is skipped, as libmount skips it, instead of surviving a
  switch under its mount ID.
- The `decoy-persistence` and `sleep-policy` checks read the journald, logind and
  systemd-coredump configuration as systemd reads it: a line also ends at a carriage return or a
  NUL byte, a section name with a control character, a quote or a backslash stops the reading of
  that file and of every file after it, and a byte order mark is dropped from the first line that
  starts with one, not only from the first line. Assignments that systemd never applies counted,
  so a check could pass or fail on a setting the daemon does not use.
- `nails rehearse scan --offline` finds the UTF-16 form of the canary in a sparse disk image also
  when it ends where a hole starts; it reported such a canary as not found.
- `nails verify --disk` no longer wraps round the block numbers of a GPT whose byte offsets do not
  fit in 64 bits, which let a corrupt or crafted table place a partition, the free space or the
  partition entries anywhere on the disk.
- The refusal of a Debian or Ubuntu host below the minimum release, or whose release cannot be
  read, names the minimum as the distribution writes it, `Debian 13` and `Ubuntu 24.04`, instead of
  `Debian 13.0` and `Ubuntu 24.4`.
- `nails check` could report a host ready that `activate` then refused with exit 8, such as Fedora,
  Arch or a Debian host without the merged `/usr`. Its new `platform` row fails there, with the
  reason `activate` gives.

### Security

- The way back no longer leaves a login or boot record on the decoy that an ordinary power cycle
  never writes. On Debian with wtmpdb the boot writer named the boot row `soft-reboot` when the
  service manager reported a soft-reboot; on a service manager that keeps the userspace start time
  across a soft-reboot (systemd 255 and earlier, as on Ubuntu 24.04) the classic-`wtmp` boot record
  carried the decoy's first boot time, so the file held a boot stamped before the shutdown that
  precedes it. The way back now keeps the wtmpdb boot writer from recording `soft-reboot` and
  corrects a backdated `wtmp` boot record to the time the decoy came back, without masking either
  writer, so no shutdown row goes missing and the decoy's login and boot records read as one clean
  power cycle. The process numbers of the getty and login records written after the way back still
  continue from the decoy's boot, a weaker tell a later release will address.
  **Until you run a build with this fix**, end Debian 13 and Ubuntu 24.04 sessions with
  `nails deactivate --poweroff` (or `nails emergency --poweroff`): a power-off has no way back, so
  none of these records are written.
- The hidden session masks a decoy swap or mount under the unit name systemd gives it also when its
  `/etc/fstab` entry names the device by a tag whose value holds a character udev encodes in its
  link or is in single quotes (`LABEL=swap\040space`), or has a path with a `.` component or `..`
  right after the leading `/` (`/dev/disk/by-id/./x`, `/mnt/./backup`). NAILS masked a name systemd
  never generates and left the real unit free, so the hidden session could swap onto a decoy disk or
  mount a decoy filesystem. A decoy filesystem overlaid at such a mount point now keeps its hidden
  layers under the simplified name, the name of its unit (`<hidden-root>/root/mounts/mnt-backup` for
  `/mnt/./backup`, where 0.3.0-rc.2 used `mnt-.-backup`): rename the directory while NAILS is
  inactive, or the hidden files in it stay out of view.
- A release can be verified without a GitHub account. It carries its three attestations as
  Sigstore bundles (`provenance.sigstore.json`, `sbom.sigstore.json`, `vex.sigstore.json`), which
  cosign 3.1.3 or later checks against the downloaded files, also on a computer without a network
  connection; `docs/verify-release.md` shows how. The release workflow runs the same check before
  it drafts the release.

### Known issues

- On Ubuntu 26.04, chrony (time sync) and CUPS (printing) fail after the switch into the hidden
  session: AppArmor blocks their messages to systemd and to the journal, whose sockets were set up
  before the switch. Other services that AppArmor confines may fail the same way. In the hidden
  session the clock is not synchronized and printing times out, and after the way back the decoy
  lists chrony as failed until its next full reboot, which hints that a soft-reboot happened.
  Reboot fully after a session to clear it. The fault lies outside NAILS: a plain
  `systemctl soft-reboot` into another root, without NAILS, breaks chrony the same way.

## [0.3.0-rc.2] - 2026-10-16

NAILS 0.3.0 replaces the per-directory live overlays of 0.2 with one design: the hidden session is
an overlay over the whole decoy root, entered and left with `systemctl soft-reboot`.
Debian 13 or newer, Ubuntu 24.04 or newer and, provisionally, their derivatives join NixOS as
decoys.

0.3.0-rc.1 was tagged but never published: its release run stopped at the SBOM attestation.

### Upgrade notes

Upgrade only while NAILS is inactive: end a 0.2 session with its own `nails deactivate` (a reboot
ends it too) before replacing the binary. This release breaks compatibility with earlier state,
config and CLI surfaces; there are no compatibility shims.

- The decoy needs systemd 254 or newer. The hidden root lives under `<hidden-root>/root/`
  (among them `upper`, `work` and `mounts`); the uppers of the 0.2 per-directory overlays
  (`<hidden-root>/<name>`, `<hidden-root>/.work`) are not read. Move what you need into a hidden
  session and delete them. On NixOS the hidden hardware configuration now lives in
  `<hidden-root>/root/upper/etc/nixos/`; run `nails init` again to place it.
- On NixOS, a decoy whose `/etc/nixos` is a flake needs a hidden flake. 0.2 built that flake through
  its overlay of `/etc`; 0.3 refuses to build the decoy's own flake (`nixos-build-target`,
  `--no-preflight` included), also when `nixos_flake` or `--nixos-flake` names it
  (`/etc/nixos#host`, the form 0.2's examples used, `path:/etc/nixos`, `git+file:///etc/nixos`,
  `path:/etc?dir=nixos` or a link to it) and when `<hidden-root>/nixos` is a link to it, because the
  build would read only the decoy's files and leave out the hidden module and the hidden hardware
  configuration. Write a self-contained flake in `<hidden-root>/nixos` that imports the hidden
  module (`<hidden-root>/config/nixos/configuration.nix`) and reads none of the decoy's files, write
  and lock it inside a hidden session (`activate --overlay-only` enters one), never on the decoy,
  and build it there with `nixos-rebuild build --flake <hidden-root>/nixos#<host> --impure`,
  `<host>` being the decoy's hostname; `nixos_flake` names such a flake elsewhere.
- The hidden root must be a volume of its own. NAILS now refuses a root that 0.2 accepted: a folder
  (no mount point), a btrfs subvolume or bind of a folder of a filesystem the decoy uses, a logical
  volume in the decoy's volume group, an image file on a decoy filesystem, and an overlay, FUSE,
  network or ZFS filesystem. Move the hidden volume to a device of its own (see "Where setup
  happens" in the operator guide). An unprivileged `check` or `status` on a distribution whose
  `/etc/crypttab` only root can read gets `storage_unjudged` and logs to stderr only; run it with
  `sudo`.
- Configuration moves from `config/nails.yaml` (YAML) to strict `config/nails.toml` (TOML) next to
  the binary. 0.3 never reads `config/nails.yaml` and does not warn about it: an unconverted setup
  runs with the defaults. Convert each key by hand: `hidden_volume_path` is now `hidden_volume_root`
  (leave it unset to derive it from the binary's location), unknown keys are rejected, and the keys
  listed under "Removed" must be deleted. `nails init` writes a documented template and
  `nails config show --example` prints every key.
- Invoke the binary from the hidden volume by full path (`sudo "$ROOT/nails" …`); nails is never on
  the decoy `PATH`. `activate --flake` is now `--nixos-flake`, `status -v` is now
  `status --details`, `--plain` and `--no-color` are replaced by `--ascii` and
  `--color auto|always|never`, and `--no-logs` by `--no-log-file`; see "Removed" for the flags
  that are gone.
- `activate` and `deactivate` now ask for confirmation, and without a terminal they refuse with
  exit 2 (`needs_confirmation`); 0.2 skipped the prompt unless `--interactive` was given. Add `-y`
  to every script, keybinding or unit that runs them; `emergency` never prompts.
- Exit codes and JSON output changed. JSON output carries `schema_version = 1`; scripts that
  parsed the old output must be updated against the exit-code table in `nails --help` and the
  schemas under `docs/schemas/`.
- The on-disk state schema changed. 0.3 cannot verify a `state.json` that 0.2 wrote: `status`
  reports the state as unknown and `activate` refuses (exit 6) until you delete the file, from a
  clean inactive system; do not hand-edit it. `nails recover` removes what an interrupted activation
  left.

### Added

- The whole-root session. `nails activate` builds one overlay over the whole decoy root at
  `/run/nextroot` (the decoy root read-only as the lower, `<hidden-root>/root/upper` as the upper),
  applies a fixed policy to every other decoy filesystem (the ESP and `/boot` bound read-only, other
  mounted local filesystems overlaid with an upper under `<hidden-root>/root/mounts/`, swap,
  unmounted disks, network filesystems and disk-backed overlay entries masked), binds `/run` and the
  hidden volume into it, writes the session plan with a RAM copy of the binary and configuration to
  `/run/overlay-runtime`, and soft-reboots. An `/etc/fstab` that cannot be read refuses the entry.
  Every mount below `/run/nextroot` is private from the moment it exists, so none of them propagates
  into the decoy's own mounts; only the next root's own mount stays shared until the switch, so that
  the mount namespaces made before the entry (logind's, a sandboxed service's) see the next root and
  lose it again on a rollback. The policy's mount points and the decoy filesystems the session
  carries for the way back are placed as the hidden root resolves their paths, so an absolute link
  on the way (a `/home` linked elsewhere) never takes them onto the decoy disk. The boot-loader
  units that would write to the read-only ESP and `/boot` at every start
  (`systemd-boot-random-seed`, `grub-common`, `grub-initrd-fallback`) are masked in the hidden
  session only. Every process of the hidden session starts inside the overlay. Activation logs you
  out after a confirmation (`-y` skips it) and, as its last step, kills the decoy's interactive
  shells, so a shell that saves history on exit never writes the activation command (the
  `incremental-history-flush` check warns about shells that save after every command).
- On NixOS the hidden system is built into the next root's store (`nix build --store /run/nextroot`,
  the evaluation cache on the hidden volume), activated chrooted, and entered by repointing
  `/run/current-system` after every decoy unit has stopped: one soft-reboot, no bootloader install,
  no system profile change. It is built from the first of: a flake given with `--nixos-flake` or
  `nixos_flake`, a flake in `<hidden-root>/nixos`, and the legacy configuration (the decoy's
  `/etc/nixos` with the hidden hardware configuration, which imports the hidden module
  `<hidden-root>/config/nixos/configuration.nix`). A flake has the hidden module only if it imports
  it, and a decoy whose own `/etc/nixos` is a flake is refused (`nixos-build-target`,
  `--no-preflight` included) until a hidden flake is given; naming that flake with `--nixos-flake`
  or `nixos_flake` as a local path or a `path:`, `git+file:` or `file:` reference, also with a query
  (`?ref=main`), a `dir` parameter (`path:/etc?dir=nixos`) or through a link, or a
  `<hidden-root>/nixos` that is a link to it, is refused the same way. Inside the hidden session
  `nixos-rebuild test` applies changes: plain for the legacy configuration, and with
  `--flake <hidden-root>/nixos#<host> --impure` for a hidden flake, `<host>` being the decoy's
  hostname (on a flake decoy a plain `nixos-rebuild test` builds the decoy's own flake, without the
  hidden module). `--overlay-only` enters with the decoy's own system plus the hidden `/etc` and
  home; `check` says that no hidden system is built, and `activate` then names none. The paths of
  the hidden system's closure that still come from the decoy store are copied onto the hidden
  volume, so a decoy that garbage-collects or rebuilds between sessions does not break the hidden
  system. On Debian and Ubuntu the hidden configuration is the upper's `/etc`.
- The switch in both directions runs from the RAM copy (`ExecStart=` of
  `systemd-soft-reboot.service`) and acts only on an armed plan. On the way back it deletes the
  runtime journal, which the decoy's journald and the hidden one write alike, so a volatile decoy's
  journal starts again at the return, without the decoy's own records from before the session;
  scrubs the top of `/run` (two levels deep, three below `/run/systemd`) of what else the decoy did
  not leave there when it stopped for the entry, such as a PID file that the hidden session's copy
  of a decoy service wrote again; puts the decoy's name-server records below `/run/resolvconf` back
  as the decoy left them, so the hidden session's name servers and search domains (a VPN's, say) do
  not reach `/etc/resolv.conf` on the decoy disk; removes the session's drop-ins by name, leaving
  the decoy's own; resets units the session left failed; and, once the hidden units have stopped,
  gives the decoy's libmount `utab` lines back under the new mount IDs of the mounts the way back
  restores, without the hidden session's lines, and writes journald's kmsg cursor so the decoy
  journal imports no hidden kernel record. Each switch keeps only the `utab` lines whose mount it
  carries, by the line's mount ID or, for a line without one, by its path, source and root, and
  writes the file as libmount does (a new file renamed over the old one, under libmount's lock): the
  kernel hands the IDs of the mounts a switch leaves behind to later mounts, and a stale line would
  lend its options to one of those or to a new mount at its path; an `x-initrd.mount` lent that way
  could hang the next soft-reboot or power-off. After a session the decoy has its mounts back as it
  had them when the entry began: before the decoy's userspace starts, the way back makes again every
  mount it can take from the decoy root or a filesystem the session carried, in the decoy's order
  and with each mount's own options (NixOS's read-only bind over a store on the root filesystem, a
  mount stacked under a carried one, a RAM filesystem the initrd mounted), each with its `utab` line
  under its new mount ID, so those that the decoy's initrd marked `x-initrd.mount` are left to the
  final unmount at its next shutdown, as after a boot; a decoy line that names no mount the way back
  makes again is not given back. `activate` warns about a decoy mount the way back cannot make again
  where the session carries its filesystem, and about one that a plain soft-reboot keeps (NixOS's
  `/etc` overlay). Where the session itself puts a decoy filesystem behind an automount in place
  (`x-systemd.automount`, often the ESP), it masks that automount, and the way back leaves the
  automount to the decoy's start. Every way back to the
  decoy (the return, an emergency, an entry rolled back or recovered, a leftover next root disarmed
  at a reboot) also writes back the kernel's module loader, hotplug and firmware paths, which every
  entry records before anything runs and which a NixOS activation in the session points at the
  hidden store, and removes the session's unit masks. The session's drop-ins and runtime units are
  readable by all, so PID 1 logs no warning that names them as world-inaccessible. The session keeps
  working with `blk-availability.service` (Debian, Ubuntu), Ubuntu 26.04's D-Bus units and NixOS
  static addresses (`networking.interfaces`), whose stop would otherwise unmount the hidden volume,
  stall the login screen or drop the network.
- `nails deactivate` runs in the hidden session and soft-reboots back to the plain decoy after a
  confirmation (`-y` skips it); `--poweroff` powers off instead. The hidden volume is unmounted and
  its device-mapper stack closed by the switch itself, so dm-crypt wipes the master key from RAM; a
  backend that is not device-mapper based is unmounted but not closed.
- `nails emergency` acts at once, before argument parsing, configuration and logging: in the hidden
  session it prepares the way back, marks the backend for closing, enqueues the soft-reboot with
  PID 1 and kills every hidden cgroup (`cgroup.kill`); the machine returns to the decoy's login
  screen (NAILS logs nobody in, but a display manager set to log an account in automatically logs it
  in again, as at boot). `--countdown <SECS>` waits first with a Ctrl+C hint, `--poweroff` and
  `--reboot` replace the soft-reboot back, and a way back that cannot be prepared powers off. The
  result names the action and any fallback, the cgroups and processes killed, the timed phases and
  any mount left behind; an emergency that leaves a mount behind, or can only ask the kernel to
  power off, exits 7. On the decoy, it removes what an interrupted activation left and enqueues a
  requested `--poweroff` or `--reboot` right after; when it enqueues none, it also reloads PID 1,
  which would otherwise keep the removed drop-ins and masks loaded, and makes `/run` `noexec` again
  where the decoy had it so.
- `nails recover` removes an interrupted activation's leftovers on the decoy (`/run/nextroot`,
  `/run/overlay-runtime`, the session's drop-ins and unit masks), gives the kernel back the decoy's
  helper paths, closes the hidden backend where nothing uses it and resets the state. Like a
  rollback and an emergency on the decoy, it also removes the copies of the next root's mounts that
  every mount namespace made before the activation received (logind's, a sandboxed service's).
- `nails check` (alias `doctor`, and what `activate --dry-run` runs): a read-only readiness report
  built from the same pre-flight registry as activation, with each check's result and fix, the
  effective configuration, the decision for every decoy filesystem and the persona mode. It writes
  nothing, supports `--json` and exits 4 when a check fails.
- The attach gate: `init`, `activate`, `check`, `deactivate`, `reset-upper`, `rehearse plant` and
  the log and state writers accept only a hidden root that is a mounted volume of its own, before
  anything is written or probed. They refuse a folder, a second filesystem mounted over the root
  and, outside the session, storage the decoy uses (per its mount table, `/etc/fstab`,
  `/etc/crypttab` and sysfs); in the session only the volume the session started from is accepted.
  A refusal is one neutral message with exit 4 and a code (`not_separate_volume`, `root_covered`,
  `storage_unjudged`) that names no storage tool or device, and `--no-preflight` does not skip it.
  `--allow-decoy-storage` (`init`, `activate`, `check`) turns a refusal of decoy storage into a
  warning for storage the operator knows the decoy does not use; `status` shows the choice. Run as
  root, the gate reads `/etc/fstab` and `/etc/crypttab` without updating their access time.
- New pre-flight checks: `systemd-version`, `soft-reboot-units` (prints the module an older nixpkgs
  needs), `decoy-root` (refuses a tmpfs, ZFS or overlay decoy root), `session-state`,
  `fstab-policy`, `mount-namespace` (activation must share PID 1's mount namespace),
  `upper-fs-capability` (the hidden filesystem can host an overlay upper), `host-tools` (names any
  missing tool and its package), `backend-entries` (refuses a decoy crypttab or fstab line that
  opens or mounts the hidden volume), `decoy-persistence` (refuses a persistent journal or an active
  rsyslog, syslog-ng or auditd unless `accept_persistent_decoy` or `--accept-persistent-decoy` is
  set; warns about atime, crash-dump channels, sudo's own log files and the NixOS auto-upgrade
  timer, and passes systemd-coredump only when it has both `Storage=none` and `ProcessSizeMax=0`),
  and the warn-only `backend-detect` (discard, file container timestamps, copy-on-write hosts),
  `binary-location`, `inherited-autostart`, `incremental-history-flush`, `sleep-policy` (a lid or
  idle setting that would suspend the session, or a closed lid set to `ignore`, which leaves the
  session running and unlocked) and `residue-catalog`, and the informational `memory-wipe`
  (`init_on_free=1`). Failures end with one ordered list of fixes, and checks that depend on a
  failed one are skipped with a reason.
- Disks during the session (`[session_mounts]`): the session watcher raises a neutral desktop alert
  for every read-write mount of a disk outside the hidden volume and for a disk mounted over the
  hidden root or one of its parents, which `status` also names (`hidden_root_covered_by`); nothing
  NAILS writes reaches such a cover. Opt-in `read_only` makes every disk the session does not use
  read-only at the block layer until the way back. The alerts go to the account logged in on the
  machine's own screen and run as that account, since a desktop session bus admits no other (the
  child drops root's groups and ids before it starts), through `notify-send` or, where it is
  missing, `busctl`. Each alert runs in a session of its own with `no_new_privs` set, waits at most
  10 s for the notification daemon, and is sent from a thread of its own, so a daemon that never
  answers holds up no probe, no other alert and no emergency.
- The backend watcher (`[backend_watch]`) alerts when the hidden backend fails mid-session and,
  only when opted in, runs the emergency after a debounce.
- `[sleep_policy]` (`warn` by default, `block` or `teardown`): `block` holds sleep and idle block
  inhibitors, and the lid switch's when a closed lid would sleep; `teardown` powers off through the
  emergency before the machine sleeps.
- Persona options (`[persona]`): `mode = "fresh-home"` gives the operator an empty home in the upper
  instead of the decoy home, and `mask_inherited` lists inherited decoy autostart entries and user
  units to hide from the hidden session (`["*"]` hides all; empty by default), also one the
  inventory does not list: a name with a unit suffix as a user unit, any other as an autostart
  entry. The masks are written as the hidden root resolves their paths, so an absolute link on the
  way (a `/home` linked elsewhere, a `~/.config` linked to a dotfiles directory) never takes them
  onto the decoy disk. An optional NixOS module and NetworkManager drop-in give the hidden session
  its own MAC addresses and hostname; the way back can leave the random MAC address on the decoy's
  device, and the hostname on a decoy without `/etc/hostname`, so end a session that used them with
  `deactivate --poweroff` (or `emergency --poweroff`).
- Inherited decoy state: `nails check` and the `inherited-autostart` check report what the hidden
  session would inherit and needs review: autostart entries and user units in the decoy home,
  system-wide ones that are not part of the desktop or the distribution, lingering, display-manager
  autologin, and every entry on a documented list of known trace writers (sync, backup, messaging,
  mail and account clients, phone links). The desktop's and the distribution's own components are
  counted, not reported, and an entry `mask_inherited` names counts as handled. Autologin has a
  remedy of its own: turn it off for the hidden session only; it stays listed while the decoy keeps
  it. On NixOS the autostart directories of the system and user profiles are read too. `nails check`
  names a `mask_inherited` name that matches nothing, says on a line of its own when the hidden
  session starts in the decoy home (`shared-home`), and in JSON gives every entry its origin and
  status.
- `nails rehearse`: `plant` puts a random canary into a hidden session, and after the way back
  `scan` searches the raw decoy devices (or disk images with `--offline`) for it; `status` and
  `reset` follow the rehearsal. A scan is refused only inside the session the canary was planted
  in, which `plant` records by the session's entry time, so it runs on the decoy after a plain
  `nails deactivate` on every systemd version. The result lists the channels the canary could not
  be planted in (the notification, when no desktop session could show it) as not tested. The scan
  exits 0 when the canary is not found, 11 when it is and 9 when a device could not be read in
  full.
- `nails verify --offline --root <mount>` scans a mounted decoy image, and `--examiner` reports the
  setup traces an examiner looks for (encryption headers, containers, crypttab lines of every
  TrueCrypt and VeraCrypt kind, LVM archives, tooling and history), grouped by what they suggest;
  `--disk <device>` adds partition-level checks. A residue catalog names every class of trace a
  session or its setup can leave, with its mitigation; `verify` and the `residue-catalog` check run
  its probes, and the residue tables in the docs are generated from it.
- `nails activate` writes a read-only decoy residue report under `<hidden-root>/reports/` before
  the switch and prints a one-line summary: no known residue, or how many warnings and critical
  findings the report holds.
- `nails config path|show|validate`: `show` prints every effective value and its source
  (default, file, cli, derived), `--example` prints every key, and `validate` checks a file
  strictly.
- `nails reset-upper <PATH>` deletes a path's hidden copy from the upper, so the decoy's own files
  show through again (for example after a decoy update); it is refused in the hidden session.
- `nails completions <shell>`, a man page (`nails.1`), a Markdown CLI reference (`docs/cli.md`),
  JSON schemas under `docs/schemas/`, and EXAMPLES and an exit-code table in `--help`. The release
  archive ships the man page, the CLI reference, the operator guide and the threat model.
- `nails status` reports the live session from the mount table and the session plan (posture
  `decoy`, `active`, `transitioning`, `degraded` or `unknown`), the policy for every decoy
  filesystem, whether the decoy keeps a persistent log store, the persona mode and how long the last
  activation took, as `activate` printed it. It shows times in local time with their UTC offset;
  the JSON keeps UTC. An interrupted entry exits 7 and points at `nails recover`; a record that
  still says active after a power loss is named as such, and `nails recover` resets it.
- Ctrl+C (SIGINT) or SIGTERM cancels an activation at its next step up to the soft-reboot, during
  the residue baseline, the pre-flight checks and the hidden system's store copy too, and removes
  everything it built (exit 130); at the confirmation prompt it ends the prompt at once. A cancel
  reads "Activation cancelled; nothing was changed.", as an answer of n does (exit 1), and
  `activate --json` gives it the status `cancelled`. An answer of n at the `deactivate` and
  `reset-upper` prompts prints the same kind of notice ("Deactivation cancelled; nothing was
  changed.", "Reset cancelled; nothing was removed.") and exits 1; their JSON is the error envelope
  with the code `cancelled`. The hidden system's activation runs in a process group of its own,
  which a Ctrl+C on the terminal does not reach, and finishes first. SIGHUP no longer aborts a
  running command, and NAILS lowers its own OOM score.
- NAILS disables its own core dumps before parsing its arguments, so a crash cannot write its
  memory to the decoy.
- Documentation: an operator guide organised by where each step runs, with a recovery runbook,
  `docs/threat-model.md`, `docs/configuration.md`, `docs/backends.md`,
  `docs/decoy-requirements.md`, `docs/architecture.md`, `docs/distribution.md` and
  `docs/verify-release.md`.

### Changed

- Configuration is strict TOML: unknown keys are rejected with a did-you-mean hint, most keys of the
  old live-overlay design say they were removed, configured paths are validated when the file is
  loaded (relative, `..`, symlinked or out-of-root paths are rejected), and a missing or invalid
  `--config` file exits 3. So does a configuration the command cannot read: `init` writes it
  readable by root only, and a run without root then names the full `sudo` line to use, every
  argument included, in the text and as the hint of the JSON error. Without a config file,
  `activate` says before its confirmation that it uses the built-in defaults, under `-q` too.
- One stable machine interface: a typed JSON envelope (`schema_version`, `command`, `ok`, and `data`
  or `error`; `activate --json` prints a progress line and then its result, one JSON object per
  line, and every log line goes to stderr) and one exit-code table for every command (pre-flight
  refusals 4, not run as root 5, untrusted state 6, degraded or interrupted 7, unsupported host 8,
  completed with warnings 9, `verify` warnings and critical findings 10 and 11, cancelled 130).
  `activate --json` lists the boot-loader units in `masked_units`, as `status --json` does.
- Output flags (`-c`, `-v`/`-q`, `--color`, `--ascii`, `--json`, `--no-log-file`) are global. Colour
  is never used on piped output and honours `NO_COLOR` and `CLICOLOR_FORCE`; console lines no longer
  carry a timestamp. At the default verbosity the console is compact: a log event prints its
  message, a warning or error its mark, message and details, and routine events (each passed check,
  the store and staging steps) go to the log file only; `-v` and `-vv` show the full records. Counts
  on the console take the singular for one and the plural otherwise (`1 residue channel is live`,
  `4 catalog probes`).
- `activate`, `deactivate`, `emergency` and `recover` refuse to run without root before writing
  anything, with exit 5 and the full `sudo` line to use, every argument included.
- `nails init` checks the target, the attach gate first, before writing anything, supports `--json`,
  `--hardware-config` and `--no-hardware-config`, reports each item as created or already present,
  and ends with numbered next steps that keep editing off the decoy (prepare `nails.toml` on another
  machine, or as `nails.toml.new` in a hidden session), then `check` and `activate`. On Debian and
  Ubuntu the root overlay's upper is made by the first activation, with the decoy root's mode and
  owner; `storage-readiness` counts that as part of its pass.
- The swap check classifies each device: RAM-only zram passes, swap on dm-crypt with a random key
  warns, and disk or file swap, fixed-key encrypted swap and hibernation are refused. A hidden
  NixOS hardware configuration that NAILS seeds has the decoy's `swapDevices` and `resumeDevice`
  commented out.
- The disk-space check is one floor (`minimum_space_mb`, 500 MB); `rebuild_space_mb` (4096 MB) is
  checked before a hidden NixOS build.
- `nails verify` names the checks it ran and the areas it did not, reports session leftovers, and
  counts only warnings and critical findings in its header. Inside the hidden session it tells the
  session's own files from traces on the decoy: its runtime files, the mounted hidden volume and its
  state make one note, and a NAILS path that the hidden layer holds (on NixOS, the module link
  `nails init` stages) is a note that points to `verify --offline --root` instead of advice to
  delete it. On the decoy, the runtime directory of an interrupted activation is reported once, as
  critical, with `nails recover` as its fix; a read-only disk rule that an unfinished way back left
  says to power off or to remove it as root, and the fixed `/run` paths of an earlier release say to
  power off. The memory note no longer suggests a cold boot: it says to power off (in the hidden
  session, `nails deactivate --poweroff`) and to leave the machine off for a few minutes. `--deep`
  also searches the journal for the tool, the configuration file, `cryptsetup` and the hidden volume
  path, and names sudo's records of your own commands as such: notes while the journal is in RAM,
  warnings when it keeps files on disk. Artifact paths are probed without following links, so a
  leaked link is found even where its target does not resolve.
- On NixOS the hidden `hardware-configuration.nix` wraps the original (kept as
  `hardware-configuration.base.nix`) instead of patching it, a `nix-instantiate --parse` check
  rejects an unparseable configuration, and the hidden NixOS module forces
  `system.autoUpgrade.enable = false`. The base-configuration check (`suspicious-nails-reference`)
  reads every `.nix` file under `/etc/nixos`, following strings, `with` and `let … in` and reading
  comments as code, and refuses a line that names the hidden environment: the hidden volume's mount
  point or device as a whole path (`/mnt/data2` is not `/mnt/data`) and the units systemd names
  after them, in both spellings of an escaped name; what the volume is stored on, unless the decoy's
  own volumes sit on it too: the partition or disk and an image file behind a loop device by their
  paths, every link udev made for them or for the volume's own device (`/dev/disk/by-id`, `by-path`,
  `by-partlabel`, `by-uuid`, `by-label` and the LVM path `/dev/<vg>/<lv>` among them), the
  partition, LUKS and filesystem uuids, and the labels as `LABEL=`, `PARTLABEL=` or a `fileSystems`
  or `swapDevices` entry's `label`; its mapping name where a line opens the volume: a
  `boot.initrd.luks.devices` or `clevis.devices` entry, in nested blocks and in a block commented
  out line by line whose lines are indented at least as deep as its first, the `name` of such an
  entry, `encrypted.label`, crypttab text, `systemd-cryptsetup@<name>.service`, or a word after
  `cryptsetup` and a verb that opens, closes or asks about a mapping (`open`, `create`, `close`,
  `status` and the like), up to the end of the command, continued lines, comments and prose
  included; or NAILS itself. Ordinary configuration passes: the mapping name as an ordinary word
  (`description = "Back up user data"` with the mapping `data`, `cryptsetup` next to it in a package
  list or in prose that puts none of those verbs between `cryptsetup` and the name, or the comment
  `nixos-generate-config` writes above `system.stateVersion`), the decoy's own mapping whose name
  merely ends like the hidden one, and the word `hidden` and options such as `services.plausible`,
  which 0.2 refused. The check does not follow a mapping defined through a `let` binding,
  `lib.listToAttrs` or an interpolated name, and does not know the storage's kernel name without
  `/dev/` (as a udev rule writes it), `/dev/dm-<n>`, `/dev/block/<major>:<minor>` or a path written
  with a doubled slash. A refusal names the file, the line and the text, why it counts and what to
  do; with no `.nix` file under `/etc/nixos`, the check says it inspected nothing. Only `.nix` files
  are read: keep the other files in `/etc/nixos`, and its history where it is a git repository, free
  of the hidden volume too.
- Unsupported hosts are refused before any write, with exit 8: Debian before 13, Ubuntu before
  24.04, non-merged-`/usr` Debian-family layouts, ostree or image-based systems, systems without
  systemd, and distributions not yet validated (Fedora, Arch). Hosts with systemd older than 254
  fail the `systemd-version` check (exit 4). Derivatives whose `ID_LIKE` names debian or ubuntu are
  accepted provisionally.
- A corrupt or unreadable state file is reported as an unknown state: `status` shows it and
  `activate` refuses, instead of treating it as inactive.
- `nails --help` now describes the tool as "Run a hidden session on a decoy Linux system". Sources
  carry SPDX headers, and `REUSE.toml`, `NOTICE` and DCO sign-off guidance are added.
- Vulnerabilities are reported through GitHub private vulnerability reporting first, with
  `security@nails.run` as the fallback; conduct reports go to `contact@nails.run`.
- Releases come from one tag-triggered workflow that checks the tag against the version,
  `Cargo.lock` and this changelog, builds from source, rebuilds on a fresh runner, runs the full
  E2E suite, attests the assets and an SBOM, and drafts the release with this section as its
  notes. `docs/verify-release.md` explains how to verify the assets.
- Development: the library is split into crates along the session's boundaries, unsafe
  code is denied outside scoped, commented sites, the toolchain is pinned in
  `rust-toolchain.toml` (1.93.0), the flake pins nixos-unstable of 2026-10-11, and a `justfile` is
  the single source of local and CI commands. The VM tests cover the session on NixOS, Debian 13
  and Ubuntu 24.04, with host-side checks of the decoy disk image.
- CI: one required `gate` check per pull request, E2E VM tests on GitHub-hosted runners (affected
  tests per pull request, the full suite on `main` and nightly), scheduled advisory, stress,
  mutation and benchmark jobs, and dependency checks through cargo-deny only.

### Removed

- The per-directory live overlays (`/etc`, `/home`, `/var`, … on the running decoy) and everything
  that served them: process detection, restart and kill, the display-manager restart, the
  overlay pivot, the shell-history cleaner, the shell prompt marker and terminal colour scheme, and
  the desktop notifications after activation with their XDG autostart entry.
- The `notify-dispatch` command; the `activate` flags `--no-clear-history`, `--kill-session`,
  `--no-kill-session`, `--accept-pivot-risks`, `--no-pivot` and `--interactive`;
  `deactivate --no-clear-history`; `emergency --no-countdown` (emergency now acts at once); and the
  per-command `--plain` and `--no-color` flags and the global `--no-logs`.
- The configuration keys `overlays`, `overlay_mode`, `overlay_exclusions`,
  `overlay_exclusions_remove`, `extended_overlays` and the ephemeral overlays, `clear_history`,
  `color_scheme`, `preflight_checks`, `default_verbosity`, `color_output`, `verify_on_deactivate`,
  `milestone_tips`, `max_log_size_mb` and `retention_days`.
- The XOR string obfuscation: the binary is identifiable, and the documentation says so.
- `docs/USER-SECURITY-GUIDE.md` and `docs/vulnerability-handling.md`, replaced by the operator
  guide, the threat model and `SECURITY.md`.

### Fixed

- On NixOS, `activate`, `deactivate` and `emergency` work when a systemd unit starts them (a panic
  key, `systemd-run`): the Nix tools are found in the root-owned system directories when the
  caller's `PATH` lacks them, and a legacy build without `NIX_PATH` takes `nixpkgs` from root's
  `nixos` channel.
- Pre-flight results are reported once and honour `--quiet` and `--json`.
- Updated dependencies to clear the RUSTSEC advisories that affect the shipped binary (anyhow,
  crossbeam-epoch) and restored the Nix release build
  ([#54](https://github.com/WitteShadovv/nails/pull/54)).

### Security

- Nothing NAILS writes reaches the decoy: the state file, its lock, logs, reports and staged
  configuration are written only onto an attached hidden root, through `openat2` beneath it, so a
  planted symlink or `..` cannot redirect them; log files are created mode 0600, and a panic goes
  to the hidden-root log, not stderr.
- Commands NAILS starts run from a cleared environment with a fixed, root-owned `PATH`, so a
  caller's `PATH` or `NIX_*` cannot steer which binaries a root child runs.
- The release binary carries no test hook: test-only code compiles only under a non-default
  `test-hooks` feature.
- The release binary links the musl of the pinned nixpkgs (1.2.6, with nixpkgs' patches for
  CVE-2026-6042 and CVE-2026-40200) instead of the musl 1.2.5 that ships with the Rust toolchain,
  so the musl the release SBOM names is the one in the binary. The build fails if its linker map
  shows `libc.a` or one of musl's crt files from anywhere else.
- The release binary no longer refers to the Rust toolchain that built it, so installing the
  `nails` package through Nix no longer keeps the toolchain (about 2.6 GB) alive.
- The release SBOM records the CVEs that nixpkgs patches musl against as backported fixes in the
  musl component's `pedigree` and gives musl its CPE. A new attested release asset,
  `musl.openvex.json`, marks those CVEs as fixed; scan with
  `grype sbom:sbom.cdx.json --vex musl.openvex.json`.
- The way back keeps the network state the hidden session set up: its links, addresses, routes and
  VPN tunnels stay up in the decoy until power-off, the decoy's NetworkManager records a link it
  adopts, with the time, in `/var/lib/NetworkManager/timestamps` as soon as the decoy starts, the
  random MAC address of the network-identity snippet can stay on the decoy's device, and so can the
  hidden hostname on a decoy without `/etc/hostname`. Take down the connections and tunnels you
  brought up and delete the links you created before deactivating, or end with
  `deactivate --poweroff`; end a session that used the network-identity snippet with
  `deactivate --poweroff` (or `emergency --poweroff`).

## [0.2.0] - 2026-05-08

### Changed

- Bumped the Rust workspace version to `0.2.0`.
- Hardened release publication around immutable tag-based workflows: exact stable tags are
  verification-only, stable publication is deliberate/manual, and prerelease publication is tied to
  suffixed prerelease tags.
- Refined release workflow permissions and repository targeting so GitHub release automation works
  reliably under repository rulesets.

### Fixed

- Created `state.json` during `nails init` and preflight when needed, preventing init/preflight
  flows from missing expected state metadata.
- Fixed release workflow regressions after the immutable-release restructuring.

## [0.1.0] - 2026-04-27

### Added

- Established the Rust workspace split between `nails-cli` and `nails-core`, including shared
  workspace metadata, custom error types, a filesystem abstraction for testing, and the initial
  quality-gate infrastructure.
- Implemented the core lifecycle model: typed state transitions, state-file serialization,
  checksummed state metadata, RAII state guards, and the `NailsManager` orchestration layer.
- Added the preflight validation system with checks for hidden storage readiness, swap exposure,
  available space, overlay directories, current state, NixOS configuration, symlink support, and
  selected flake build targets.
- Implemented activation support for OverlayFS-based hidden sessions, NixOS configuration overlays,
  deterministic mount ordering, reverse-order rollback, process/session handling, display-manager
  restart behavior, and NixOS build/switch integration.
- Added support for flake-based activation via `--flake`, config-fingerprint fast paths,
  missing-only build paths, automatic overlay strategy selection, `/var` overlays, optional `/boot`
  pivoting, and bind-mounted fallbacks for overlay-incompatible targets.
- Implemented deactivation and emergency cleanup flows, including standard reboot-based cleanup,
  emergency no-reboot cleanup, force-unmount fallback behavior, cleanup reporting, and post-cleanup
  verification hooks.
- Added user-facing commands and output for status reporting, verification scans, emergency
  deactivation, progress indicators, verbosity controls, no-color handling, desktop notifications,
  and notification dispatch.
- Added shell integration and forensic-safety support, including prompt/alias management,
  in-memory and on-disk history cleanup, automatic terminal color-scheme switching, structured
  logging, sanitized log paths, and timestamp-based log rotation.
- Added Nix-based end-to-end validation infrastructure covering the basic workflow, emergency
  deactivation, forensic cleanliness, snapshot diffs, and performance scenarios.
- Added reproducible Nix release packaging for the canonical Linux artifact, checksum generation,
  SBOM/supply-chain checks, dependency auditing, coverage gates, and release-path verification.
- Added public project documentation and governance files, including release reproducibility
  guidance, CI documentation, support and security policies, issue templates, code of conduct,
  roadmap updates, and public README guidance.

### Changed

- Migrated the project surface from early prototype planning into a Rust-first implementation with a
  focused CLI crate and domain-oriented core library.
- Refactored the CLI and core library into focused modules for activation, deactivation, cleanup,
  config, filesystem access, logging, manager orchestration, NixOS integration, overlays,
  preflight checks, shell integration, state, status, and verification.
- Reworked CI from the initial pipeline into consolidated, cached workflows using `cargo-llvm-cov`,
  pinned tooling, reusable release/reproducibility jobs, and trusted full E2E validation.
- Replaced deprecated `serde_yaml` usage with `serde-saphyr` and refreshed Rust/GitHub Actions
  dependencies, including `thiserror`, `colored`, `signal-hook`, and Node.js 24-compatible actions.
- Aligned public documentation with the current alpha threat model, release process, support scope,
  NAILS OS separation, artifact format, and AI-assisted development disclosure.

### Removed

- Removed the legacy Python implementation after the Rust migration became the maintained code path.

### Fixed

- Hardened activation and deactivation around partial overlays, same-device submounts, overlay
  permission mismatches, display-manager restart timing, NixOS generation switching, fast-path
  activation, and deactivation base-configuration checks.
- Hardened hidden configuration and hardware-configuration handling to fail earlier and avoid unsafe
  or ambiguous activation states.
- Improved forensic cleanup by addressing shell-history persistence, alias stdout leakage,
  cleanup/log formatting, temporary-file cleanup, and post-deactivation artifact checks.
- Stabilized E2E and unit coverage by serializing fragile switch-to-configuration tests, moving real
  filesystem tests into test-only paths, expanding activation/deactivation guard coverage, and
  bringing measured coverage above the documented threshold.
- Fixed release and CI regressions around workflow permissions, reproducibility comparisons,
  GitHub CLI repository targeting, artifact naming, release tag handling, cargo-sbom output format,
  Dependabot configuration, and pre-commit coverage parity.

### Security

- Added comprehensive shell-history protection and cleanup verification for forensic-safety goals.
- Added SBOM generation, dependency/security audit workflows, cargo-geiger integration, and public
  vulnerability-handling documentation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for public contribution guidance.

[Unreleased]: https://github.com/WitteShadovv/nails/compare/v0.3.0-rc.3...HEAD
[0.3.0-rc.3]: https://github.com/WitteShadovv/nails/compare/v0.3.0-rc.2...v0.3.0-rc.3
[0.3.0-rc.2]: https://github.com/WitteShadovv/nails/compare/v0.2.0...v0.3.0-rc.2
[0.2.0]: https://github.com/WitteShadovv/nails/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/WitteShadovv/nails/releases/tag/v0.1.0
