# Configuration reference

nails reads one strict TOML file, `nails.toml`. This page lists every key it
accepts. What the hidden session covers is not configured: it is always the
whole decoy root, plus a fixed policy for every other decoy filesystem (see
[What the session covers](#what-the-session-covers)).

## Platform support

nails runs on NixOS (full, with a declarative hidden configuration) and on the
Debian family with the same whole-root session (Debian 13, Ubuntu 24.04 and
26.04; a later Debian or Ubuntu release runs with a warning that nails has not
been tested on it, and `ID_LIKE=debian` derivatives are accepted provisionally
without a release gate, unless their `ID_LIKE` also names Fedora, RHEL, CentOS
or Arch). Every host needs systemd 254 or newer for
`systemctl soft-reboot`, so Debian 12 and Ubuntu 22.04 are refused.
Non-merged-`/usr` layouts, other distributions, ostree/image-based hosts and
non-systemd hosts are refused with a documented message. On the Debian family
there is no declarative layer: the `nixos_*` keys below are inert and the hidden
configuration is whatever the upper's `/etc` holds. See the
[platform support matrix](../README.md#requirements) for the full table.

## Where the file lives

- By default nails reads `config/nails.toml` next to its own binary, after
  resolving symlinks. A binary at `/mnt/data/nails`, or a symlink to
  it, reads `/mnt/data/config/nails.toml`, so the configuration
  always travels with the binary on the hidden volume.
- `--config PATH` reads any TOML file instead. A file named by `--config` must
  exist; a missing file at the default location means "use the defaults", and
  `activate` says so before it asks for confirmation, since every opt-in
  protection then keeps its default.
- `nails init <root>` writes a commented starter file with every assignment
  commented out. `nails config set` changes it in place
  ([Changing settings](#changing-settings)).
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
`discard` and `nails config` exit with status 3. `deactivate` and `recover`
never refuse: they log one warning and carry on with defaults derived from the
binary location (`recover` uses the RAM copy under `/run/overlay-runtime` when
it can). `emergency` reads no configuration at all.

`nails init` writes the file readable by root only. A command run without root
that cannot read it exits with status 3 too, and names the full line to run
instead (`sudo /mnt/data/nails status`), in its text and on a line of its own
in the `message` of its JSON error.

| Command | Purpose |
|---|---|
| `nails config path` | Print the resolved file and whether it exists |
| `nails config show` | Print every effective value and its source: `default`, `file`, `cli` or `derived` |
| `nails config show --example` | Print a commented example that lists every key |
| `nails config validate [PATH]` | Check a file strictly without using it |
| `nails config set KEY VALUE...` | Set one key, keeping the file's comments and every other key |
| `nails config unset KEY...` | Remove keys, so their defaults apply |

Every `config` subcommand also accepts `--json`.

### Changing settings

`nails config set` and `nails config unset` change the file in place, so no
editor touches it. Run them inside a hidden session, as root
(`sudo /mnt/data/nails config set persona.mode fresh-home`); on the decoy the
command line would land in the decoy's journal.

- A key is written as the [Keys](#keys) table names it: `persona.mode` is the
  `mode` key of `[persona]`. `set` takes one value: `true` or `false`, a whole
  number, a path or a string as it is, without TOML quotes. A list
  (`persona.mask_inherited`) takes one value per entry. A key or a value the
  key does not take is refused before the file is read (exit 2).
- Only the named keys change. The file's comments, its order and every other
  key stay as they were; a value already set as asked is not rewritten, and
  then nothing is written at all. A new key goes after the keys of its table,
  or into a new table at the end, below the comments that end the file, such
  as the template `init` writes. A removed key's comments stay in the file.
- The changed file is checked as `config validate` checks one before it is
  written: a file that would not be valid after the change is not written
  (exit 3), and a change that makes a file valid again is. A file that is not
  TOML at all is refused whatever the change.
- The file is replaced at once: the new text goes to a new file in the same
  directory, with the old file's owner and mode (a new file is root's alone),
  is flushed, and is renamed over the old one. Two changes at the same time
  do not lose one another: each waits for the other, up to ten seconds.
  Ctrl+C or a SIGTERM stops a change until the rename (exit 130), and the new
  file is removed again; after the rename the change is reported as made.
- A setting is written only on the volume the running `nails` lies on: the
  directory it runs from must pass the
  [attach gate](threat-model.md#the-attach-gate) and hold the NAILS layout,
  and the file, the configuration beside the binary or a `--config` file, must
  lie beneath that directory with no link and no other filesystem on the way,
  which the kernel checks as it opens the path. A `--config` file anywhere
  else, the decoy's included, a link at the file or on the way to it, a file
  with a second name (a hard link), and a filesystem mounted inside the volume
  are refused (exit 4), and nothing is read or written.
- While a hidden session runs, while an activation is entering one and
  while an interrupted entry is left behind, `hidden_volume_root` and
  `state_file_path` point only where the session recorded them when it began
  (exit 4): the way back to the decoy and `recover` read the session's state
  there. A change that points them back there is written, so a file changed
  by hand can be put right. Make any other such change on another machine,
  with the hidden volume mounted there. The session's backend watcher and
  sleep guard read the copy of the configuration activation made, so a
  change reaches them at the next activation.

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
| `hidden_volume_root` | path | derived from the binary location | Root of the hidden volume; the hidden root's layers (`root/upper`, `root/work`, `root/mounts`, `root/cache`), the state file and logs live under it. Unset, it is the directory holding the `nails` binary (symlinks resolved). nails writes nothing under it until a volume of its own is mounted there: not a folder, not a subvolume or bind mount of a filesystem the computer uses, and not a volume inside its storage (see [the attach gate](threat-model.md#the-attach-gate)). Leave it unset so the file keeps working when the volume is mounted somewhere else. See [Path rules](#path-rules). |
| `state_file_path` | path | `<hidden_volume_root>/state.json` | Activation state file. Must lie inside `hidden_volume_root`. |
| `log_path` | path | `<hidden_volume_root>/logs` | Directory of `nails.log`. Must lie inside `hidden_volume_root`. `--no-log-file` turns file logging off for one run. |
| `minimum_space_mb` | integer (MB) | `500` | Base free-space floor for the hidden volume. The pre-flight check fails below this value (no warn band). |
| `rebuild_space_mb` | integer (MB) | `4096` | Free-space floor for building a hidden NixOS system into the hidden root's store (NixOS). A full build writes the store delta into the upper, often several GB. The hidden system's closure is then copied onto the hidden volume (once, the whole closure at the first entry); that copy is checked against the free space separately. |
| `show_opsec_reminders` | boolean | `true` | Show reminders in `nails status` once the hidden environment has been active for 6, 12 and 24 hours. |
| `nixos_flake` | string (flake reference) | unset | Flake of the hidden NixOS system, for example `/mnt/data/nixos#my-host`; it is built into the hidden root's store before the soft-reboot. Unset, activation takes the first of: a flake in `<hidden_volume_root>/nixos`, built for this machine's hostname; the decoy's own flake in `/etc/nixos`, which it refuses, because a hidden system built from the decoy's files would lack the hidden module and the hidden hardware configuration; the legacy hidden configuration, the decoy's `/etc/nixos/configuration.nix` with the hidden hardware configuration in the upper, which imports the hidden module `<hidden_volume_root>/config/nixos/configuration.nix`. A flake includes the hidden module only if it imports it. Write and lock a hidden flake inside a hidden session, never on the decoy, and keep it self-contained: one that imports `/etc/nixos/configuration.nix` reads the decoy's files and its hardware configuration, swap included (see the [operator guide](operator-guide.md#how-it-works)). `nails check` names the choice under "NixOS profile". `activate --nixos-flake` overrides it. Naming the decoy's own flake or a directory below it here or with `--nixos-flake` (`/etc/nixos#host`, `path:/etc/nixos`, `git+file:///etc/nixos`, `git+file:///etc/nixos/.git`, `hg+file:///etc/nixos`, `path:/etc?dir=nixos`, the percent-encoded `path:/etc/%6Eixos`, a link to it or a bind mount of it) is refused the same way, and so is `<hidden_volume_root>/nixos` when it is the decoy's flake or a directory below it through a link or a bind mount. Besides a local path or URL, only a plain remote reference (`github:owner/repo`, `git+https://example.org/repo`) passes: a local URL with an authority (`git+file://../../etc/nixos`) and any other reference Nix may read as a path relative to the working directory (`a_b:x`), and a registry alias (`flake:nixos-config`, or a name alone), are refused too, whatever they name. A git directory of its own that holds the decoy's flake (`git+file:///var/lib/cfg.git`) is not recognised. |
| `persona.mask_inherited` | list of entry names, or `["*"]` | `[]` | Inherited decoy autostart entries and user units to hide from the hidden session. Each value is a name as `nails check` lists it: the `.desktop` stem for an autostart entry, or the full unit name for a user unit. `["*"]` names every maskable inherited entry. A name `nails check` does not list is masked too, as a user unit when it ends in a unit suffix and as an autostart entry otherwise; a value with a `/` is refused. Lingering and autologin are reported but not masked. See [Inherited decoy state](#inherited-decoy-state). |
| `persona.mode` | `"shared-home"` or `"fresh-home"` | `"shared-home"` | How the hidden session relates to the decoy account. `shared-home` starts it from the decoy home (the root overlay's lower), so the decoy's accounts, keys and app profiles are live. `fresh-home` gives the operator an empty home, created in the upper at the first entry. See [Persona modes](#persona-modes). |
| `backend_watch.auto_emergency` | boolean | `false` | Opt into an automatic emergency when the hidden backend fails. When `false` (the default) the watcher is alert-only, so a transient I/O stall can never end the session; when `true`, the emergency runs on its own, returning to the decoy, only after the failure outlasts `backend_watch.debounce_secs`. See [Backend watcher](#backend-watcher). |
| `backend_watch.debounce_secs` | integer (seconds) | `15` | How long a failure must persist before an opted-in automatic emergency fires. Ignored unless `backend_watch.auto_emergency` is `true`. |
| `backend_watch.enabled` | boolean | `true` | Run the backend watcher as a runtime unit of the hidden session. The watcher polls the hidden backend and alerts you when it fails. With `false` and `session_mounts.alert` and `session_mounts.read_only` both `false`, no watcher runs. See [Backend watcher](#backend-watcher). |
| `backend_watch.poll_interval_secs` | integer (seconds) | `5` | Seconds between the watcher's probes of the hidden backend. |
| `session_mounts.alert` | boolean | `true` | Alert when a disk outside the hidden volume is mounted read-write during the hidden session (a USB drive udisks automounts, a manual `mount`). The session watcher raises the alert, and runs for it even with `backend_watch.enabled = false`. See [Disks mounted during the session](#disks-mounted-during-the-session). |
| `session_mounts.read_only` | boolean | `false` | Opt-in: make every disk the hidden session does not use read-only at the block layer for the session, the disks present at entry and every disk attached during it, so a mount comes up read-only and writes fail. The way back makes them writable again. See [Disks mounted during the session](#disks-mounted-during-the-session). |
| `sleep_policy.mode` | `"warn"`, `"block"` or `"teardown"` | `"warn"` | What to do about system sleep (suspend/hibernate) during a session. Suspending keeps the whole session — the overlay, the open dm-crypt mapper and the master key — resident in RAM. `warn` only surfaces a pre-flight warning when the host would suspend an active session. `block` holds sleep and idle block inhibitors for the life of the session so the host cannot suspend, and takes the lid switch from logind when a closed lid would sleep. `teardown` holds a sleep *delay* inhibitor and powers the machine off when it is about to sleep, within logind's `InhibitDelayMaxSec` window. Also set the decoy's logind lid switch to `lock`. See [Sleep policy](#sleep-policy). |
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

An entry behind an automount (`x-systemd.automount`, often the ESP) that is
bound read-only or overlaid keeps its automount masked: the hidden systemd
would find the mount point taken and fail the automount, and with it
`local-fs.target`, which would start the hidden session in emergency mode.
Masks are runtime masks in `/run`, gone with the session. systemd's GPT
auto-generator, which would mount partitions the fstab does not list, is masked
the same way. `nails check` prints the decision for every entry (the
`fstab-policy` check). A decoy partition you mount by hand inside the hidden
session is outside this policy and is written directly.

A mount point the fstab names through a symlink (a `/home` that links to
`var/home`) is decided, mounted and masked at its real path, the way systemd
resolves it: `var-home.mount` and `var-home.automount`, not `home.mount`.
`nails check` resolves each entry in the decoy root. Activation also resolves
it in the hidden session's root, where a symlink a session changed can lead
elsewhere, and decides the entry at that path too, which is `home.mount` once a
session replaced the link with a directory. The hidden systemd finds the entry
masked or in place there as well. A path that a link leads into the hidden
volume is masked, not bound with the volume: the entry still names a decoy
filesystem, which the hidden systemd would otherwise mount inside the hidden
volume.

The hidden volume must be storage of its own, because everything nails writes
there would otherwise land on the decoy disk. The attach gate refuses a plain
directory, a btrfs subvolume or bind mount of a filesystem the decoy uses, a
volume stacked on the decoy's storage, an image file on a decoy filesystem, a
filesystem that shows no disk it stores its data on (an overlay, FUSE, a network
filesystem or a ZFS dataset), and a root with a second filesystem mounted over
it; it runs before `init`, `activate` and `check` write or probe anything.
`--allow-decoy-storage` turns the refusal of
the decoy's storage into a warning; a folder is always refused (see [the attach
gate](threat-model.md#the-attach-gate)). The decoy root must be a disk
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
  keeps a single, consistent login. `nails check` says so on a line of its own
  under "Inherited decoy state", `nails status --json` reports the mode, and the
  `inherited-autostart` pre-flight warning lists the autostart entries and user
  services of the decoy home that need review (see
  [Inherited decoy state](#inherited-decoy-state)).
- `fresh-home`: at the first entry, activation creates the operator's home in
  the upper as an opaque directory, so nothing of the decoy home shows through.
  It stays the hidden home at every later entry. The operator is the account
  that ran `sudo`, so activation must run through `sudo`. Activation makes the
  home, and each directory missing on the way to it, only through directories
  of that upper and never follows a symbolic link there. A hidden session may
  have replaced `/home`, or a directory below it on the way to the home, with
  a link (to `/var/home`, say), and the link could lead the new home onto the
  decoy disk: activation is then refused, makes nothing, and names the link.
  Delete it from the upper on the hidden volume and activate again.

Test the mode you choose on your own machine before trusting it.

A third model, `separate-user` — a fixed-UID hidden account distinct from the
decoy user — is planned for a later release. It is not an accepted value yet;
`persona.mode` accepts only `shared-home` and `fresh-home`.

## Inherited decoy state

The hidden session inherits whatever the decoy starts: enabled system services,
autostart entries, enabled systemd user services and timers, lingering, and
display-manager autologin. Sync, cloud, messaging and account clients configured
in the decoy therefore run under the decoy identity in the hidden session and
can reach remote servers and your other devices.

NAILS reads the autostart entries a desktop session starts: those in
`~/.config/autostart` and `/etc/xdg/autostart`, and on NixOS also the
`etc/xdg/autostart` of each profile NixOS adds to the search path
(`~/.nix-profile`, `~/.local/state/nix/profile`,
`/etc/profiles/per-user/<user>`, `/nix/var/nix/profiles/default` and
`/run/current-system/sw`, where the desktop's own entries live). When several
directories hold a file of the same name, the first one in that order decides,
as it does for the desktop, and a `Hidden=true` there hides the entry. Only
regular files count, once their links are followed, as for systemd's autostart
generator: a directory, FIFO, socket or device there is skipped unread, and so
is a link to nothing, so a file of the same name in a later directory decides.
User services and timers are those enabled in `~/.config/systemd/user` and
`/etc/systemd/user`. What lives in the home carries over only in `shared-home`;
the rest carries over in both modes. On NixOS with a hidden configuration, the
system-wide entries come from that configuration, which normally imports the
decoy's.

Autologin is read from each display manager's own files, in the order the
display manager reads them and with its own parser, so a later file that names
another account or empties the setting counts as it does there:

- GDM: `AutomaticLoginEnable` and `AutomaticLogin` in the `[daemon]` group of
  `/etc/gdm/custom.conf`, `/etc/gdm3/custom.conf` (Ubuntu) or
  `/etc/gdm3/daemon.conf` (Debian).
- SDDM: `User=` under `[Autologin]` in the files of
  `/usr/lib/sddm/sddm.conf.d`, then of `/etc/sddm.conf.d`, then
  `/etc/sddm.conf`.
- Plasma Login Manager: `User=` under `[Autologin]`, or under the first seat's
  `[Autologin][seat0]`, in the files of
  `/usr/lib/plasmalogin/plasmalogin.conf.d`, then of `/etc/plasmalogin.conf.d`,
  then `/etc/plasmalogin.conf`.
- LightDM: `autologin-user=` in `[Seat:*]` (`[SeatDefaults]` in older files)
  and in the `[Seat:…]` groups that match the first seat, in the `*.conf` files
  of `lightdm/lightdm.conf.d` below `/usr/share`, `/usr/local/share`,
  `/etc/xdg` and `/etc`, then in `/etc/lightdm/lightdm.conf`.

Only regular files are read: a FIFO, socket or device in one of these places
is skipped, so reading it can neither block nor go on without end.

Where the files leave the account in doubt, it is listed:

- SDDM and Plasma Login Manager sort the files of a directory by the
  collation of the locale they run in, which the files do not tell: with ICU
  `kde_settings.conf` comes before `kde-autologin.conf`, in the C locale after
  it. The files are read in each order a collation may give, and the account
  any of them ends with is listed. Names that first differ in a digit, such as
  `10-a.conf` and `20-b.conf`, sort the same everywhere.
- A line the display manager may read two ways: SDDM on Qt 5 reads a line
  only up to a NUL, on Qt 6 to its end; and GLib judges a key's language tag
  beyond ASCII by Unicode tables of its own, so GDM and LightDM may read on
  past such a line or stop there.
- A Plasma Login Manager setting translated for a language, which the
  language it runs in decides, or expanded from the environment.
- The KDE Frameworks release Plasma Login Manager 6.7 runs on, 6.26 or
  later: before 6.29 KConfig keeps the settings of drop-ins differently, so
  that a later drop-in's `User=` wins over a deletion marked immutable
  (`User[$id]`). The files are read both ways.
- GDM turned on without naming an account, which is listed as you.

In these cases the list may name an autologin that does not happen, rather
than leave out one that does. Some it can leave out: only the first seat,
`seat0`, is judged; a file that is not valid UTF-8 is skipped, although the
display managers read it; GDM's timed login (`TimedLoginEnable`, `TimedLogin`
and `TimedLoginDelay` in `[daemon]`), with which the login screen logs the
account in once the delay has passed, at every switch as well, is not read;
GDM's runtime configuration in `/run` (`/run/gdm/custom.conf` upstream), which
GDM reads before its own file, is not read; and no display manager but these
four is read.

`nails check` lists the inherited entries that need review, and the
`inherited-autostart` pre-flight check warns about them; activation shows the
same warning. They are:

- everything in the home, and every system-wide entry that is not a known
  component of the desktop or the distribution: those were added by you or by
  third-party software, such as a Dropbox or Syncthing client or your own
  scripts;
- lingering and autologin;
- every entry on a short list of known trace writers, whoever installed it:
  clients that carry data, or the fact that the machine is running, off the
  machine. They are sync and cloud storage clients (Dropbox, Nextcloud,
  ownCloud, Syncthing, MEGA, Insync, OneDrive, rclone), backup tools (Déjà Dup,
  Pika Backup, Vorta, Back In Time), messaging and meeting clients (Telegram,
  Signal, Slack, Discord, Element, Keybase, Zoom, Teams), mail, calendar and
  account clients (Thunderbird, Evolution, Geary, GNOME Online Accounts, KDE
  Accounts) and phone links (KDE Connect, GSConnect, Valent). `nails check`
  tags them remote-linked.

The components the desktop or the distribution ships itself are not reported:
the settings daemons and session services of GNOME, KDE Plasma, Xfce, MATE,
Cinnamon, LXQt and Budgie, the keyring, PipeWire, D-Bus, the GnuPG and SSH
agents, input methods, the screen reader's speech service, NixOS's own user
units and update notifiers. Masking them would break or degrade the hidden
desktop. `nails check` counts them, and `nails check --json` lists
every entry with its `origin` (`desktop` or `added`) and its `status`
(`ignored`, `masked` or `review`). Both lists match names only: they make no
claim about what an entry does or whether a client is signed in.

`persona.mask_inherited` lists entries to hide from the hidden session, or the
single value `"*"` for every maskable entry:

```toml
[persona]
mask_inherited = ["dropbox", "syncthing.service"]
```

At each entry, activation writes a `Hidden=true` override (an autostart entry)
or a `/dev/null` mask (a user unit) for every named entry into the operator's
home in the next root, so the mask lands in the upper only. A masked entry
counts as handled: `nails check` shows it as masked and it no longer warns. A
name that matches no inherited entry `nails check` lists, such as an entry in a
directory NAILS does not read, is masked as well: as a user unit when it ends in
a unit suffix such as `.service` or `.timer`, and as an autostart entry
otherwise. `nails check` names those names, so a typo does not go unnoticed. You
can also disable an entry from inside the hidden session (`systemctl --user
mask <unit>`, or remove or override the autostart file): the change lands in the
upper, so it affects the hidden session only. Lingering is a decoy setting —
disable it on the decoy itself if it matters. A display manager set to log an
account in automatically logs it in again at every switch, as at boot (Plasma
Login Manager 6.7 and later, on systemd 256 and later, only with
`Relogin=true`); the operator guide says how to
[turn that off for the hidden session only](operator-guide.md#inherited-autostart-services-and-autologin).

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

The watcher's alerts go to the account logged in on the machine's own screen
(the active session of its first seat), and they run as that account, because a
desktop session bus admits no other: through `notify-send`, or `busctl` where
`notify-send` is not installed. While nobody is logged in there, no alert can be
shown.

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
  mounts) is not in the watcher's table. A disk mounted over the hidden root
  itself, or over one of its parents, always raises its own alert ("Disk
  mounted over a folder in use") instead, whatever this setting, while the
  watcher runs.
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
does (the main file from `/etc`, `/run`, `/usr/local/lib` or `/usr/lib` on
systemd 256 and later and from `/etc` alone before, then every
`logind.conf.d/*.conf` drop-in by file name, `/etc` shadowing the others)
and **warns** (never blocks) when the effective lid-switch or idle settings
would suspend an active session, and when a closed lid is set to `ignore` (on
battery, or on external power), which keeps the session running and unlocked
behind the lid. Fix the host first: set the decoy's logind lid switch to `lock`
and disable desktop auto-suspend (see
[decoy-requirements.md](decoy-requirements.md)). The hidden session starts from
the decoy's `/etc`, so it inherits the fix unless the hidden configuration
changes it.

`sleep_policy.mode` adds a runtime backstop: a sleep guard that runs from the RAM
copy as a runtime unit of the hidden session (the same mechanism as the backend
watcher) and holds logind inhibitors for the life of the session:

- `warn` (default) — pre-flight warning only; nothing runs at runtime, and a
  closed lid or an idle timeout suspends the session as logind is configured to.
- `block` — hold a `sleep:idle` **block** inhibitor, so logind refuses a
  suspend that is asked for (a sleep key, a desktop's or a user's suspend) or
  that an idle timeout would start. logind ignores that inhibitor for the lid
  switch by default (`LidSwitchIgnoreInhibited=yes`), so when the session's
  logind would sleep on a closed lid, the guard also takes a
  `handle-lid-switch` **block** inhibitor, which logind always honours: a
  closed lid then does nothing at all, neither suspend nor lock the screen. A
  lid switch set to `lock`, `ignore` or `poweroff` is left to logind and keeps
  working, unless NAILS cannot read logind's configuration the way logind does
  (a drop-in that is no regular file, or a file it cannot read): the guard then
  takes the lid switch too. A laptop kept running with the lid shut can
  overheat, so still set the lid switch to `lock`. Both inhibitors are released
  together at the way back.
- `teardown` — hold a sleep **delay** inhibitor and, on the host's
  `PrepareForSleep` signal, power the machine off within logind's
  `InhibitDelayMaxSec` window (default 5s) instead of letting it sleep with the
  session in RAM. logind honours delay inhibitors for every sleep, so this
  covers a closed lid too.

The `session-sleep-guard` VM test closes a virtual lid in a hidden session in
each mode. The inhibitors appear in `systemd-inhibit --list` under neutral,
non-product names, and nothing is written to the decoy disk.

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
