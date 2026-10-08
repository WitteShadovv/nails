# Configuration reference

nails reads one strict TOML file, `nails.toml`. This page lists every key it
accepts. What the hidden session covers is not configured: it is always the
whole decoy root, plus a fixed policy for every other decoy filesystem (see
[What the session covers](#what-the-session-covers)).

## Platform support

nails runs on NixOS (full, with a declarative hidden configuration) and on the
Debian family with the same whole-root session (Debian 13+, Ubuntu 24.04+;
`ID_LIKE=debian` derivatives are accepted provisionally without a release
gate). Every host needs systemd 254 or newer for `systemctl soft-reboot`, so
Debian 12 and Ubuntu 22.04 are refused. Non-merged-`/usr` layouts, other
distributions, ostree/image-based hosts and non-systemd hosts are refused with a
documented message. On the Debian family there is no declarative layer: the
`nixos_*` keys below are inert and the hidden configuration is whatever the
upper's `/etc` holds. See the
[platform support matrix](../README.md#requirements) for the full table.

## Where the file lives

- By default nails reads `config/nails.toml` next to its own binary, after
  resolving symlinks. A binary at `/mnt/data/nails`, or a symlink to
  it, reads `/mnt/data/config/nails.toml`, so the configuration
  always travels with the binary on the hidden volume.
- `--config PATH` reads any TOML file instead. A file named by `--config` must
  exist; a missing file at the default location means "use the defaults".
- `nails init <root>` writes a commented starter file with every assignment
  commented out.
- Activation copies the effective configuration, with the binary, into RAM
  under `/run/overlay-runtime`. The runtime units of the hidden session (the
  backend watcher and the sleep guard) read that copy.

## Strict parsing

Every key is optional: an empty file is a valid configuration that uses the
defaults below. Unknown keys at any level, values of the wrong type and TOML
syntax errors are rejected with a one-line message that names the file, the
line and column, and for a misspelt key the closest valid key. A typo never
falls back to a default without a word. The keys of the earlier per-directory
overlay mode, listed under "Removed" in the [changelog](../CHANGELOG.md), are
rejected the same way.

On an invalid file, `activate`, `check`, `status`, `verify`, `rehearse`,
`reset-upper` and `nails config` exit with status 3. `deactivate` and `recover`
never refuse: they log one warning and carry on with defaults derived from the
binary location (`recover` uses the RAM copy under `/run/overlay-runtime` when
it can). `emergency` reads no configuration at all.

| Command | Purpose |
|---|---|
| `nails config path` | Print the resolved file and whether it exists |
| `nails config show` | Print every effective value and its source: `default`, `file`, `cli` or `derived` |
| `nails config show --example` | Print a commented example that lists every key |
| `nails config validate [PATH]` | Check a file strictly without using it |

`path`, `show` and `validate` also accept `--json`.

### Path rules

Every path is checked when the file is loaded, before anything is mounted.
A path that breaks a rule is rejected with one line that names the file, the
key and the rule, for example
`invalid config /mnt/data/config/nails.toml: hidden_volume_root = "/mnt/data,b": must not contain ','`.

- Every path is absolute, with no `.` or `..` segment and no newline.
- `hidden_volume_root` contains no `,` or `:`: the root overlay's upper and
  work directories are derived from it, and overlay mount options use those
  characters as separators. Spaces are fine.
- `hidden_volume_root` is not `/`.
- `state_file_path` and `log_path` lie inside `hidden_volume_root`.
- No existing directory on the way to `hidden_volume_root`, or to a path
  inside it, is a symlink: a symlink could send hidden data to the decoy disk.
  Configure the resolved path instead.

## Keys

Nested keys are written with dots: `persona.mode` is the `mode` key of the
`[persona]` table.

<!-- BEGIN config-keys -->
| Key | Type | Default | Effect |
|---|---|---|---|
| `hidden_volume_root` | path | derived from the binary location | Root of the hidden volume; the hidden root's layers (`root/upper`, `root/work`, `root/mounts`, `root/cache`), the state file and logs live under it. Unset, it is the directory holding the `nails` binary (symlinks resolved). nails writes nothing under it until a separate volume is mounted there. Leave it unset so the file keeps working when the volume is mounted somewhere else. See [Path rules](#path-rules). |
| `state_file_path` | path | `<hidden_volume_root>/state.json` | Activation state file. Must lie inside `hidden_volume_root`. |
| `log_path` | path | `<hidden_volume_root>/logs` | Directory of `nails.log`. Must lie inside `hidden_volume_root`. `--no-log-file` turns file logging off for one run. |
| `minimum_space_mb` | integer (MB) | `500` | Base free-space floor for the hidden volume. The pre-flight check fails below this value (no warn band); `activate --no-preflight` skips the check. |
| `rebuild_space_mb` | integer (MB) | `4096` | Free-space floor for building a hidden NixOS system into the hidden root's store (NixOS). A full build writes the store delta into the upper, often several GB. The hidden system's closure is then copied onto the hidden volume (once, the whole closure at the first entry); that copy is checked against the free space separately. |
| `show_opsec_reminders` | boolean | `true` | Show reminders in `nails status` once the hidden environment has been active for 6, 12 and 24 hours. |
| `nixos_flake` | string (flake reference) | unset | Flake of the hidden NixOS system, for example `/mnt/data/nixos#my-host`; it is built into the hidden root's store before the soft-reboot. Unset, the legacy hidden configuration is built (the decoy's `/etc/nixos` plus the hidden hardware configuration in the upper). `activate --nixos-flake` overrides it. |
| `accept_persistent_decoy` | boolean | `false` | Accept a persistent decoy posture instead of refusing activation. When `false` (the default), activation fails closed if the decoy keeps a persistent journald journal on disk or runs an active rsyslog/syslog-ng/auditd: what the decoy logs while it shuts down for the soft-reboot, and while it starts again afterwards, would survive on its disk. Overridden by `--accept-persistent-decoy`. See [decoy-requirements.md](decoy-requirements.md). |
| `persona.mask_inherited` | list of entry names, or `["*"]` | `[]` | Inherited decoy autostart entries and user units to hide from the hidden session. Each value is a name as `nails check` lists it: the `.desktop` stem for an autostart entry, or the full unit name for a user unit. `["*"]` names every maskable inherited entry. Lingering and autologin are reported but not masked. See [Inherited decoy state](#inherited-decoy-state). |
| `persona.mode` | `"shared-home"` or `"fresh-home"` | `"shared-home"` | How the hidden session relates to the decoy account. `shared-home` starts it from the decoy home (the root overlay's lower), so the decoy's accounts, keys and app profiles are live. `fresh-home` gives the operator an empty home, created in the upper at the first entry. See [Persona modes](#persona-modes). |
| `backend_watch.auto_emergency` | boolean | `false` | Opt into an automatic emergency when the hidden backend fails. When `false` (the default) the watcher is alert-only, so a transient I/O stall can never end the session; when `true`, the emergency runs on its own, returning to the decoy, only after the failure outlasts `backend_watch.debounce_secs`. See [Backend watcher](#backend-watcher). |
| `backend_watch.debounce_secs` | integer (seconds) | `15` | How long a failure must persist before an opted-in automatic emergency fires. Ignored unless `backend_watch.auto_emergency` is `true`. |
| `backend_watch.enabled` | boolean | `true` | Run the backend watcher as a runtime unit of the hidden session. The watcher polls the hidden backend and alerts you when it fails. With `false` and `session_mounts.alert` and `session_mounts.read_only` both `false`, no watcher runs. See [Backend watcher](#backend-watcher). |
| `backend_watch.poll_interval_secs` | integer (seconds) | `5` | Seconds between the watcher's probes of the hidden backend. |
| `session_mounts.alert` | boolean | `true` | Alert when a disk outside the hidden volume is mounted read-write during the hidden session (a USB drive udisks automounts, a manual `mount`). The session watcher raises the alert, and runs for it even with `backend_watch.enabled = false`. See [Disks mounted during the session](#disks-mounted-during-the-session). |
| `session_mounts.read_only` | boolean | `false` | Opt-in: make every disk the hidden session does not use read-only at the block layer for the session, the disks present at entry and every disk attached during it, so a mount comes up read-only and writes fail. The way back makes them writable again. See [Disks mounted during the session](#disks-mounted-during-the-session). |
| `sleep_policy.mode` | `"warn"`, `"block"` or `"teardown"` | `"warn"` | What to do about system sleep (suspend/hibernate) during a session. Suspending keeps the whole session — the overlay, the open dm-crypt mapper and the master key — resident in RAM. `warn` only surfaces a pre-flight warning when the host would suspend an active session. `block` holds a sleep/idle inhibitor for the life of the session so the host cannot suspend. `teardown` holds a sleep *delay* inhibitor and powers the machine off when it is about to sleep, within logind's `InhibitDelayMaxSec` window. Also set the decoy's logind lid switch to `ignore`/`lock`. See [Sleep policy](#sleep-policy). |
<!-- END config-keys -->

The Key and Default columns are generated from the code, and
`nails-core/tests/config_reference.rs` fails when this page and the code
disagree. After adding or changing a key, regenerate them with
`NAILS_REGEN_CONFIG_DOCS=1 cargo test -p nails-core --test config_reference`
and describe any new row.

## What the session covers

There is nothing to choose here. Activation builds one overlay over the whole
decoy root, with the upper at `<hidden_volume_root>/root/upper` and the work
directory at `<hidden_volume_root>/root/work`, and soft-reboots into it. Every
directory on the root filesystem is covered, including `/usr`, `/var`, `/nix`
and `/tmp` when they are part of it; there are no exclusions.

Every other filesystem the hidden systemd would mount from the decoy's fstab
gets a fixed decision before the switch:

| Decoy fstab entry | In the hidden session |
|---|---|
| `/` | the root overlay itself |
| `/boot`, `/boot/efi`, `/efi` (the ESP and boot partitions) | bound read-only |
| a local filesystem mounted read-only in the decoy | bound read-only |
| any other local filesystem mounted in the decoy (a separate `/home`, `/var` or `/nix`) | an overlay with its upper at `<hidden_volume_root>/root/mounts/<systemd-escaped path>/upper` |
| swap | masked: never activated |
| a local filesystem not mounted now but mounted at boot | masked, with its automount |
| a network filesystem | masked: the hidden session would write to the server |
| a VM host share (9p, virtiofs) or an overlay entry mounted in the decoy | an overlay with its upper on the hidden volume |
| an overlay entry not mounted now, its upper on a disk | masked |
| an overlay entry not mounted now with its upper in RAM, or a VM host share not mounted now | left to the hidden systemd |
| a `noauto` entry without an automount | left alone: never mounted |
| RAM and kernel filesystems | left to the hidden systemd (nothing reaches a disk) |
| the hidden volume, or a path inside it | bound at its own path |

Masks are runtime masks in `/run`, gone with the session. `nails check` prints
the decision for every entry (the `fstab-policy` check). A decoy partition you
mount by hand inside the hidden session is outside this policy and is written
directly.

The hidden volume must be a mount point of its own (the `hidden-volume`
pre-flight check refuses a plain directory), because everything nails writes
there would otherwise land on the decoy disk. The decoy root must be a disk
filesystem that can be mounted again by its device for the way back (the
`decoy-root` check refuses a tmpfs, ZFS or overlay root).

## Persona modes

The hidden root's lower is the decoy root, so by default the hidden session
starts as the decoy user, with the decoy home: every account, credential store
and application profile set up in the decoy home is visible and usable in the
hidden session. Changes go to the upper, so the decoy home on disk is not
modified. `persona.mode` names how the hidden session relates to that decoy
account:

- `shared-home` (default): the hidden session works with the decoy home, so
  logging in there gives it the decoy's browser profiles, SSH and GPG keys,
  password-manager state and shell history. This is a deliberate trade-off — it
  keeps a single, consistent login. `nails check` prints the persona mode,
  `nails status --json` reports it, and the `inherited-autostart` pre-flight
  warning lists what the decoy account brings in.
- `fresh-home`: at the first entry, activation creates the operator's home in
  the upper as an opaque directory, so nothing of the decoy home shows through.
  It stays the hidden home at every later entry. The operator is the account
  that ran `sudo`, so activation must run through `sudo`.

Test the mode you choose on your own machine before trusting it.

A third model, `separate-user` — a fixed-UID hidden account distinct from the
decoy user — is planned for a later release. It is not an accepted value yet;
`persona.mode` accepts only `shared-home` and `fresh-home`.

## Inherited decoy state

The hidden session inherits whatever the decoy starts: enabled system services,
autostart entries (`~/.config/autostart` and `/etc/xdg/autostart`), enabled
systemd user services and timers, lingering, and display-manager autologin.
Sync, cloud, messaging and account clients configured in the decoy therefore run
under the decoy identity in the hidden session and can reach remote servers and
your other devices.

`nails check` lists this inherited state and flags names that look like
remote-linked clients (a name-only heuristic; it makes no claim about signed-in
state). Activation shows the same summary in its pre-flight output (the
`inherited-autostart` warning).

`persona.mask_inherited` lists entries to hide from the hidden session, or the
single value `"*"` for every maskable entry:

```toml
[persona]
mask_inherited = ["dropbox", "syncthing.service"]
```

At each entry, activation writes a `Hidden=true` override (an autostart entry)
or a `/dev/null` mask (a user unit) for every named entry into the operator's
home in the next root, so the mask lands in the upper only. You can also
disable an entry from inside the hidden session (`systemctl --user
mask <unit>`, or remove or override the autostart file): the change lands in the
upper, so it affects the hidden session only. Lingering and autologin are
decoy settings — disable them on the decoy itself if they matter.

Masking hides what *runs*; it does not roll back remote or account state. Shared
accounts, tokens and sync history remain shared and are never undone. Correlation
through shared network identifiers (machine-id, hostname, MAC, NetworkManager
profiles) is out of scope for the overlay; see the
[threat model](threat-model.md#what-the-hidden-environment-shares-with-the-decoy)
and the [operator guide](operator-guide.md#shared-network-identifiers) for the
optional hidden network-identity snippet.

## Backend watcher

The binary and the configuration live on the hidden volume, and in the hidden
session so does the whole root's upper. If that volume fails or is pulled
mid-session, the session starts failing in confusing ways and the binary on it
may no longer run — exactly when it is needed most. Activation guards against
this in two ways.

First, it copies the running binary and the effective configuration into RAM, in
a private directory on `/run` (`/run/overlay-runtime`), next to the session plan.
`/run` is carried into the hidden session, so if the hidden volume is gone you
can still run `sudo /run/overlay-runtime/control emergency`; emergency needs
nothing from the hidden volume.

Second, when `backend_watch.enabled` is `true` (the default), the watcher runs
from that copy as a runtime unit of the hidden session, under a neutral name. It
probes the hidden backend every `backend_watch.poll_interval_secs` seconds and
raises a desktop alert the moment a probe fails, so an unresponsive volume is
explained instead of showing up only as unrelated application errors.

The watcher is **alert-only by default**: a transient I/O stall must never be able
to end a live session on its own. The automatic emergency is strictly opt-in —
set `backend_watch.auto_emergency = true` — and even then it fires only after the
failure has persisted for `backend_watch.debounce_secs`, so a brief hiccup that
recovers is reported but never acted on. The automatic emergency returns to the
decoy like `nails emergency`.

## Disks mounted during the session

The fstab policy at entry covers every filesystem the decoy knows about (see
[What the session covers](#what-the-session-covers)). A disk the hidden session
mounts itself is not covered: a USB drive udisks automounts, a decoy partition
the policy masked and you mount by hand, a Windows partition. It is a real disk,
and a read-write mount of it takes the hidden session's writes.

- **Alert** (`session_mounts.alert`, on by default). The session watcher checks
  the mount table every `backend_watch.poll_interval_secs` seconds and raises a
  desktop alert ("Disk mounted with write access") once for every read-write
  mount of a block device outside the hidden volume. The session's own mounts
  never alert: the root and the decoy filesystems are overlays, the ESP is a
  read-only bind, and the carried decoy filesystems are inside the hidden
  volume. A mount made inside another mount namespace (a service with private
  mounts) is not in the watcher's table.
- **Read-only** (`session_mounts.read_only`, opt-in). Every disk the session
  does not use is made read-only at the block layer for the session. The kernel
  then refuses a read-write mount: `mount` falls back to read-only with a
  warning, udisks mounts it read-only, `mount -o rw` fails, and a write through
  the device node fails. Nothing a mount itself writes (a journal replay, a
  mount count) reaches the disk either. A udev rule that only the hidden
  session's udevd loads applies this to every disk and partition the moment it
  appears, before udisks hears of it, and the hidden boot applies it to the
  disks present at entry; the watcher checks all disks on every poll as a
  fallback. The decoy root's disk, the hidden backend and everything it sits
  on, the ESP and the decoy filesystems the session carries stay writable, as
  do virtual devices (loop, device mapper, zram). The way back, `deactivate` and
  `emergency` alike, makes exactly the disks the session set read-only writable
  again before the switch, so the decoy finds them as it left them.
- **The way back.** `nails deactivate` unmounts every disk mounted during the
  session before it soft-reboots (a busy one is detached; the soft-reboot ends
  its users), so the decoy can mount it again normally. After an emergency, the
  soft-reboot's own shutdown unmounts them.

**Limits.** A root user in the hidden session can always mount a disk: setting
it writable again (`blockdev --setrw`) and mounting it is a deliberate act, and
the alert still fires for the read-write mount. The block-layer flag does not
stop writes through a filesystem already mounted read-write before the flag was
set (the watcher's fallback can be a poll late); the udev rule is not, which is
why it is the first line. A disk that is part of the session (the one the hidden
volume or the decoy root lives on) stays writable as a whole device.

## Sleep policy

Suspending or hibernating during a session leaves the whole hidden environment —
the overlay, the open dm-crypt mapper and the master key — resident in RAM, and
on resume the session is still live. logind's defaults make this the normal
case: `HandleLidSwitch` defaults to `suspend`, and desktops add idle
auto-suspend.

The `sleep-policy` pre-flight check resolves `logind.conf` the way systemd
does (the main file from `/etc`, `/run`, `/usr/local/lib` or `/usr/lib`, then
every `logind.conf.d/*.conf` drop-in by file name, `/etc` shadowing the others)
and **warns** (never blocks) when the effective
lid-switch or idle settings would suspend an active session. Fix the host
first: set the decoy's logind lid switch to `ignore` or `lock` and disable
desktop auto-suspend (see [decoy-requirements.md](decoy-requirements.md)). The
hidden session starts from the decoy's `/etc`, so it inherits the fix unless the
hidden configuration changes it.

`sleep_policy.mode` adds a runtime backstop: a sleep guard that runs from the RAM
copy as a runtime unit of the hidden session (the same mechanism as the backend
watcher) and holds a logind inhibitor for the life of the session:

- `warn` (default) — pre-flight warning only; nothing runs at runtime.
- `block` — hold a sleep/idle **block** inhibitor, so logind refuses to suspend
  or idle-sleep while the session is up. A suspend blocked with the lid shut can
  overheat a laptop, so still fix the lid switch.
- `teardown` — hold a sleep **delay** inhibitor and, on the host's
  `PrepareForSleep` signal, power the machine off within logind's
  `InhibitDelayMaxSec` window (default 5s) instead of letting it sleep with the
  session in RAM.

The inhibitor appears in `systemd-inhibit --list` under neutral, non-product
names, and nothing is written to the decoy disk.

## Closing the backend

There is nothing to configure. `deactivate` and `emergency` always mark the
hidden backend's device-mapper stack for deferred removal before the
soft-reboot; the switch back releases the last reference (the overlay that held
the hidden volume), and the kernel removes the mapping and wipes the master key
then. A loop device set up with autoclear detaches with it. A backend that is not
device-mapper based is unmounted by the switch but not closed; close it yourself
from the decoy, or power off.

Device-removal kernel messages reach the ring buffer and, on a persistent
journal, the decoy journal. Powering off is still the only way to clear all
kernel and RAM residue.
