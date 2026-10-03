# Configuration reference

nails reads one strict TOML file, `nails.toml`. This page lists every key it
accepts and explains how the overlay keys decide what the hidden environment
protects.

## Where the file lives

- By default nails reads `config/nails.toml` next to its own binary, after
  resolving symlinks. A binary at `/mnt/data/nails`, or a symlink to
  it, reads `/mnt/data/config/nails.toml`, so the configuration
  always travels with the binary on the hidden volume.
- `--config PATH` reads any TOML file instead. A file named by `--config` must
  exist; a missing file at the default location means "use the defaults".
- `nails init <root>` writes a commented starter file with every assignment
  commented out.

## Strict parsing

Every key is optional: an empty file is a valid configuration that uses the
defaults below. Unknown keys at any level, values of the wrong type and TOML
syntax errors are rejected with a one-line message that names the file, the
line and column, and for a misspelt key the closest valid key. A typo never
falls back to a default without a word.

On an invalid file, `activate`, `status`, `verify`, `notify-dispatch` and
`nails config` exit with status 3. `emergency` and `deactivate` never refuse:
they log one warning and carry on with defaults derived from the binary
location.

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
`invalid config /mnt/data/config/nails.toml: overlays[0].upper = "/mnt/data/a,b": must not contain ','`.

- Every path is absolute, with no `.` or `..` segment and no newline.
- `hidden_volume_root` and the `overlays[]` paths contain no `,` or `:`:
  overlay mount options use them as separators. Spaces are fine.
- `hidden_volume_root` is not `/` and does not lie inside an
  `overlays[].target`.
- `state_file_path`, `log_path`, `overlays[].upper` and `overlays[].work` lie
  inside `hidden_volume_root`.
- No existing directory on the way to `hidden_volume_root`, or to a path
  inside it, is a symlink: a symlink could send hidden data to the decoy disk.
  Configure the resolved path instead.

## Keys

Nested keys are written with dots: `color_scheme.hidden.background` is the
`background` key of the `[color_scheme.hidden]` table, and `overlays[].name`
is the `name` key of each `[[overlays]]` table.

<!-- BEGIN config-keys -->
| Key | Type | Default | Effect |
|---|---|---|---|
| `hidden_volume_root` | path | derived from the binary location | Root of the hidden volume; overlay layers, the state file and logs live under it. Unset, it is the directory holding the `nails` binary (symlinks resolved). nails writes nothing under it until a separate volume is mounted there. Leave it unset so the file keeps working when the volume is mounted somewhere else. See [Path rules](#path-rules). |
| `state_file_path` | path | `<hidden_volume_root>/state.json` | Activation state file. Must lie inside `hidden_volume_root`. |
| `log_path` | path | `<hidden_volume_root>/logs` | Directory of `nails.log`. Must lie inside `hidden_volume_root`. `--no-log-file` turns file logging off for one run. |
| `overlay_mode` | `"auto"` or `"explicit"` | `"auto"` | How overlay targets are chosen; see [Overlay semantics](#overlay-semantics). |
| `overlay_exclusions` | array of paths | `[]` | Auto mode: top-level directories to leave out in addition to the [default exclusions](#default-exclusions). Writes under them reach the decoy disk, so excluding a load-bearing directory is refused unless `allow_leaky_exclusions` lists it. |
| `overlay_exclusions_remove` | array of paths | `[]` | Auto mode: default exclusions to overlay anyway. It cannot lift the [safety floor](#safety-floor). |
| `allow_leaky_exclusions` | array of paths | `[]` | Auto mode: load-bearing directories that `overlay_exclusions` may exclude anyway. Without an entry here, excluding one is refused; see the [safety floor](#safety-floor). Writes under them reach the decoy disk. |
| `overlays` | array of tables | `[]` | Explicit mode: one `[[overlays]]` table per overlay. Ignored in auto mode; explicit mode without any table refuses to activate. |
| `overlays[].lower` | path | required | Read-only lower layer, normally the same directory as `target`. |
| `overlays[].name` | string | required | Human-readable label for the overlay. |
| `overlays[].target` | path | required | Mount point. A tree the platform keeps read-only or never overlays (for example `/usr` on an FHS host) is refused. |
| `overlays[].upper` | path | required | Writable upper layer, where everything the hidden session writes under `target` ends up. Must lie inside `hidden_volume_root`. |
| `overlays[].work` | path | required | overlayfs work directory, on the same filesystem as `upper`. Must lie inside `hidden_volume_root`. |
| `minimum_space_mb` | integer (MB) | `500` | Free space the hidden volume needs. The pre-flight check warns below this value and blocks activation below half of it; `activate --no-preflight` skips the check. |
| `clear_history` | boolean | `true` | Clear shell history files during deactivation. `--no-clear-history` on `activate` or `deactivate` turns it off for that run; emergency teardown always clears them. |
| `show_opsec_reminders` | boolean | `true` | Show reminders in `nails status` once the hidden environment has been active for 6, 12 and 24 hours. |
| `prompt_label` | string | `""` | Text prepended to the shell prompt while the hidden environment is active. Empty shows nothing; any label is visible on screen and in screenshots. |
| `nixos_flake` | string (flake reference) | unset | Flake passed to `nixos-rebuild --flake` for the hidden system, for example `/mnt/data/nixos#my-host`. Unset, the flake is discovered automatically. `activate --flake` overrides it. |
| `risky_services` | `"restart"` or `"skip"` | unset | What to do with risky services (NetworkManager, dbus-daemon, the audio server) still referencing a target at activation: `restart` them, or `skip` and leave them running as reported survivors. Unset, activation restarts them when the session is killed and prompts on a terminal otherwise, and a non-interactive run that keeps the session must choose. `activate --risky-services` overrides it. |
| `color_scheme.decoy.reset` | boolean | `true` | Reset the terminal colours when returning to the decoy environment. |
| `color_scheme.enabled` | boolean | `true` | Change the terminal colours while the hidden environment is active. Like `prompt_label`, the change is visible on screen and in screenshots. |
| `color_scheme.hidden.background` | string (colour) | `"#1a1a2e"` | Terminal background while the hidden environment is active, as an OSC colour such as `#rrggbb`. Not validated; terminals ignore values they do not understand. |
| `color_scheme.hidden.foreground` | string (colour) | `"#e0e0e0"` | Terminal foreground while the hidden environment is active, in the same format as `background`. |
| `persona.mask_inherited` | list of entry names, or `["*"]` | `[]` | Inherited decoy autostart entries and user units to hide from the hidden session. Each value is a name as `nails check` lists it: the `.desktop` stem for an autostart entry, or the full unit name for a user unit. `["*"]` masks every maskable inherited entry. Masks are written after the overlays mount and before the session restarts, so they take effect for the hidden session only and vanish on deactivation. Lingering and autologin are reported but not masked. See [Inherited decoy state](#inherited-decoy-state). |
| `persona.mode` | `"shared-home"` or `"fresh-home"` | `"shared-home"` | How the hidden session relates to the decoy account. `shared-home` runs it in the decoy home (merged read-write through the `/home` overlay), so the decoy's accounts, keys and app profiles are live; activation warns while it is in effect. `fresh-home` bind-mounts a clean, empty home from the hidden volume over the operator's home, so the decoy home contents are not visible. See [Persona modes](#persona-modes). |
<!-- END config-keys -->

The Key and Default columns are generated from the code, and
`nails-core/tests/config_reference.rs` fails when this page and the code
disagree. After adding or changing a key, regenerate them with
`NAILS_REGEN_CONFIG_DOCS=1 cargo test -p nails-core --test config_reference`
and describe any new row.

## Overlay semantics

### Auto mode

Auto mode is the default. At activation nails lists the entries directly under
`/` and overlays every directory that is not excluded. The effective exclusion
list is the [default exclusions](#default-exclusions), plus the active
platform's base-OS trees, plus `overlay_exclusions`, minus
`overlay_exclusions_remove`. Symlinks and files at the top level are skipped; on
merged-`/usr` distributions this already skips `/bin`, `/lib`, `/lib64` and
`/sbin`. Which base-OS trees are left out of overlay is platform data, not a
config default: on an FHS host (Debian/Ubuntu) `/usr` and the real-directory
core binary roots are excluded and kept read-only for the session instead (see
the [safety floor](#safety-floor)); on NixOS `/bin` and `/usr` are overlaid, so
the hidden `switch-to-configuration` rewrites of `/bin/sh` and `/usr/bin/env`
land in the overlay upper rather than on the decoy disk.

Each target `/<name>` gets its upper layer at `<hidden_volume_root>/<name>`
and its work directory at `<hidden_volume_root>/.work/<name>`, both created
when missing. Because the list is computed at every activation, a top-level
directory added after the configuration was written is protected too. If any
target cannot be overlaid, activation fails. The `[[overlays]]` tables are
ignored.

Some targets get extra handling. A target on a filesystem that overlayfs
cannot use as a lower layer (vfat, exFAT or NTFS, typically `/boot`) is copied
into RAM and the copy is overlaid. Before `/nix` is overlaid, the Nix daemon is
stopped, and it is started again afterwards.

Everything the hidden session writes under an excluded directory goes straight
to the decoy system's disk. Only exclude directories that the hidden session
does not write to, or whose contents never reach a disk.

### Explicit mode

With `overlay_mode = "explicit"`, nails mounts exactly the `[[overlays]]`
tables and ignores the exclusion keys. Explicit mode with no tables refuses to
activate, because it would protect nothing. Writes to any directory that has
no table reach the decoy disk, so auto mode is the safer choice.

### Default exclusions

<!-- BEGIN default-exclusions -->
| Path | Why it is excluded |
|---|---|
| `/proc` | Kernel process and sysctl interface (procfs). The kernel generates it; it cannot be overlaid and holds nothing on disk. |
| `/sys` | Kernel device and driver interface (sysfs). The kernel generates it; it cannot be overlaid and holds nothing on disk. |
| `/dev` | Device nodes, kept in memory by the kernel and udev (devtmpfs). |
| `/run` | Runtime state on a tmpfs that running services depend on. It is lost at shutdown, so writes never reach a disk. |
| `/mnt` | Holds the hidden volume's default mount point, `/mnt/data`. Overlaying it would stack an overlay on the volume that stores the overlay layers. |
| `/lost+found` | Recovery directory used by `fsck`; empty in normal use. |
<!-- END default-exclusions -->

### Safety floor

Some limits hold whatever the configuration says:

- The base OS stays read-only while hidden is active. Each platform's overlay
  policy decides how: on an FHS host (Debian/Ubuntu) the decoy root and `/usr`
  (plus any non-merged `/bin`, `/sbin`, `/lib*`) are bind-remounted read-only
  for the session, so a stray write — a package payload, a `/usr/local` change,
  a new top-level directory — is refused with `EROFS` instead of reaching the
  decoy disk, and write access is returned on deactivation and emergency
  teardown. On NixOS `/bin` and `/usr` are overlaid instead, so the hidden
  switch's rewrites stay off the decoy. Either way, auto mode drops these trees
  even when `overlay_exclusions_remove` lists them, and explicit mode refuses to
  activate with a read-only or never-overlaid tree as a target. Activation is
  refused outright if any base-OS tree would be left writable and non-overlaid.
- `/proc`, `/sys`, `/dev` and `/run` can be removed from the exclusions, but
  nails logs a warning when they are. They are kernel-managed or in-memory
  filesystems: overlaying them fails or breaks running services, and they hold
  nothing that reaches a disk.
- No overlay target may be equal to or above the hidden volume root, the
  state file, the log directory or the running `nails` binary, in either mode
  and with symlinks resolved. overlayfs does not carry other mounts into the
  overlay, so a hidden volume mounted at VeraCrypt's `/media/veracrypt1` or
  udisks2's `/media/<user>/<label>` would vanish under an overlay of `/media`,
  and the layers and the state file would end up inside the overlay. Such a
  configuration is refused before anything is mounted or any session is
  killed, also with `--no-preflight`, for example: `hidden root
  /media/veracrypt1 is under overlay target /media; mount it under /mnt or
  /run/media, or add /media to overlay_exclusions`. `/mnt` and `/run` are
  excluded by default, and excluding `/media` is allowed. A binary on the
  target's own filesystem, such as one in the Nix store under an overlaid
  `/nix`, stays visible and is accepted.
- In auto mode, `/home`, `/root`, `/etc`, `/var`, `/nix`, `/srv`, `/opt`, and
  `/tmp` unless it is a tmpfs, are load-bearing: the hidden session writes to
  them, so excluding one would send those writes to the decoy disk. Loading the
  configuration refuses such an exclusion, and the `overlay-targets` pre-flight
  check (which can see whether `/tmp` is a tmpfs) refuses it again before
  activation. List the directory in `allow_leaky_exclusions` to accept the leak
  deliberately; the check then warns on every activation.
- The hidden volume root must be a mount point of its own (the
  `hidden-volume` pre-flight check refuses a plain directory), because
  everything nails writes there would otherwise land on the decoy disk.
## Persona modes

By default the hidden session runs as the decoy user, in the decoy home. The
`/home` overlay merges the decoy home read-write, and `/home` is deliberately
not excluded, so every account, credential store and application profile set up
in the decoy home is live in the hidden session. `persona.mode` chooses how the
hidden session relates to that decoy account.

- `shared-home` (default): the legacy shared-account model. The hidden session
  works in the decoy home, so logging in there gives it the decoy's browser
  profiles, SSH and GPG keys, password-manager state and shell history. This is
  a deliberate trade-off — it keeps a single, consistent login — so activation
  prints a warning while it is in effect, and `nails status` and `nails check`
  report it.
- `fresh-home`: once the `/home` overlay is mounted, a fresh, empty directory on
  the hidden volume (`<hidden_volume_root>/persona/home`) is bind-mounted over
  the operator's home. It is a plain bind with no decoy lower, so the decoy home
  contents are not visible and the hidden session starts from a clean home;
  everything it writes there lands on the hidden volume and is torn down with the
  other hidden mounts on deactivation. The directory persists on the hidden
  volume between sessions, so the hidden persona keeps its own state.

A third model, `separate-user` — a fixed-UID hidden account distinct from the
decoy user — is planned for a later release. It needs the hidden NixOS
generation switched before login rather than at activation time, so it is not an
accepted value yet; `persona.mode` accepts only `shared-home` and `fresh-home`.

## Inherited decoy state

In `shared-home` mode the hidden session inherits whatever the decoy account
starts on login: autostart entries (`~/.config/autostart` and
`/etc/xdg/autostart`), enabled systemd user services and timers, lingering, and
display-manager autologin. Sync, cloud, messaging and account clients configured
in the decoy therefore run under the decoy identity in the hidden session and can
reach remote servers and your other devices.

`nails check` lists this inherited state and flags names that look like
remote-linked clients (a name-only heuristic; it makes no claim about signed-in
state). The same summary appears in the activation confirmation.

`persona.mask_inherited` hides specific inherited entries from the hidden session.
List the entry names to mask, or the single value `"*"` to mask every maskable
entry:

```toml
[persona]
mask_inherited = ["dropbox", "syncthing.service"]
```

Autostart entries are masked with a `Hidden=true` override and user units with a
`/dev/null` mask, both written through the merged home after the overlays mount
and before the session restarts, so they land only in the hidden overlay and are
gone on deactivation. Lingering and autologin are reported but cannot be masked
this way — disable them on the decoy itself if they matter.

Masking hides what *runs*; it does not roll back remote or account state. Shared
accounts, tokens and sync history remain shared and are never undone. Correlation
through shared network identifiers (machine-id, hostname, MAC, NetworkManager
profiles) is out of scope for the overlay; see the user security guide for the
optional hidden network-identity snippet.
