# Configuration reference

nails reads one strict TOML file, `nails.toml`. This page lists every key it
accepts and explains how the overlay keys decide what the hidden environment
protects.

## Where the file lives

- By default nails reads `config/nails.toml` next to its own binary, after
  resolving symlinks. A binary at `/mnt/hidden-volume/nails`, or a symlink to
  it, reads `/mnt/hidden-volume/config/nails.toml`, so the configuration
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
`invalid config /mnt/hidden-volume/config/nails.toml: overlays[0].upper = "/mnt/hidden-volume/a,b": must not contain ','`.

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
| `hidden_volume_root` | path | derived from the binary location | Root of the hidden volume; overlay layers, the state file and logs live under it. Unset, it is the directory holding the `nails` binary (symlinks resolved), or `/mnt/hidden-volume` when the binary runs from a build directory or the Nix store. Leave it unset so the file keeps working when the volume is mounted somewhere else. See [Path rules](#path-rules). |
| `state_file_path` | path | `<hidden_volume_root>/state.json` | Activation state file. Must lie inside `hidden_volume_root`. |
| `log_path` | path | `<hidden_volume_root>/logs` | Directory of `nails.log`. Must lie inside `hidden_volume_root`. `--no-log-file` turns file logging off for one run. |
| `overlay_mode` | `"auto"` or `"explicit"` | `"auto"` | How overlay targets are chosen; see [Overlay semantics](#overlay-semantics). |
| `overlay_exclusions` | array of paths | `[]` | Auto mode: top-level directories to leave out in addition to the [default exclusions](#default-exclusions). Writes under them reach the decoy disk. |
| `overlay_exclusions_remove` | array of paths | `[]` | Auto mode: default exclusions to overlay anyway. It cannot lift the [safety floor](#safety-floor). |
| `overlays` | array of tables | `[]` | Explicit mode: one `[[overlays]]` table per overlay. Ignored in auto mode; explicit mode without any table refuses to activate. |
| `overlays[].lower` | path | required | Read-only lower layer, normally the same directory as `target`. |
| `overlays[].name` | string | required | Human-readable label for the overlay. |
| `overlays[].target` | path | required | Mount point. `/bin` and `/usr` are refused. |
| `overlays[].upper` | path | required | Writable upper layer, where everything the hidden session writes under `target` ends up. Must lie inside `hidden_volume_root`. |
| `overlays[].work` | path | required | overlayfs work directory, on the same filesystem as `upper`. Must lie inside `hidden_volume_root`. |
| `minimum_space_mb` | integer (MB) | `500` | Free space the hidden volume needs. The pre-flight check warns below this value and blocks activation below half of it; `activate --no-preflight` skips the check. |
| `clear_history` | boolean | `true` | Clear shell history files during deactivation. `--no-clear-history` on `activate` or `deactivate` turns it off for that run; emergency teardown always clears them. |
| `show_opsec_reminders` | boolean | `true` | Show reminders in `nails status` once the hidden environment has been active for 6, 12 and 24 hours. |
| `prompt_label` | string | `""` | Text prepended to the shell prompt while the hidden environment is active. Empty shows nothing; any label is visible on screen and in screenshots. |
| `nixos_flake` | string (flake reference) | unset | Flake passed to `nixos-rebuild --flake` for the hidden system, for example `/mnt/hidden-volume/nixos#my-host`. Unset, the flake is discovered automatically. `activate --flake` overrides it. |
| `risky_services` | `"restart"` or `"skip"` | unset | What to do with risky services (NetworkManager, dbus-daemon, the audio server) still referencing a target at activation: `restart` them, or `skip` and leave them running as reported survivors. Unset, activation restarts them when the session is killed and prompts on a terminal otherwise, and a non-interactive run that keeps the session must choose. `activate --risky-services` overrides it. |
| `color_scheme.decoy.reset` | boolean | `true` | Reset the terminal colours when returning to the decoy environment. |
| `color_scheme.enabled` | boolean | `true` | Change the terminal colours while the hidden environment is active. Like `prompt_label`, the change is visible on screen and in screenshots. |
| `color_scheme.hidden.background` | string (colour) | `"#1a1a2e"` | Terminal background while the hidden environment is active, as an OSC colour such as `#rrggbb`. Not validated; terminals ignore values they do not understand. |
| `color_scheme.hidden.foreground` | string (colour) | `"#e0e0e0"` | Terminal foreground while the hidden environment is active, in the same format as `background`. |
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
list is the [default exclusions](#default-exclusions), plus
`overlay_exclusions`, minus `overlay_exclusions_remove`. Symlinks and files at
the top level are skipped; on merged-`/usr` distributions this already skips
`/bin`, `/lib`, `/lib64` and `/sbin`.

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
| `/mnt` | Holds the hidden volume's default mount point, `/mnt/hidden-volume`. Overlaying it would stack an overlay on the volume that stores the overlay layers. |
| `/bin` | Holds the shell (`/bin/sh`), or is a symlink to `/usr/bin`. Part of the [safety floor](#safety-floor). |
| `/usr` | System programs and libraries. Part of the [safety floor](#safety-floor). Software the hidden session installs into `/usr` is written to the decoy disk. |
| `/lib` | Shared libraries and the dynamic loader, or a symlink to `/usr/lib`. System files, not session data. |
| `/lib64` | The 64-bit dynamic loader, or a symlink to `/usr/lib64`. System files, not session data. |
| `/sbin` | System administration programs, or a symlink to `/usr/sbin`. System files, not session data. |
| `/lost+found` | Recovery directory used by `fsck`; empty in normal use. |
<!-- END default-exclusions -->

### Safety floor

Some limits hold whatever the configuration says:

- `/bin` and `/usr` are never overlaid. Auto mode drops them even when
  `overlay_exclusions_remove` lists them, and explicit mode refuses to activate
  with either as a target. Hiding the shell and core programs while activation
  runs would leave the system unusable.
- `/proc`, `/sys`, `/dev` and `/run` can be removed from the exclusions, but
  nails logs a warning when they are. They are kernel-managed or in-memory
  filesystems: overlaying them fails or breaks running services, and they hold
  nothing that reaches a disk.
- An explicit overlay whose target contains the hidden volume is rejected: it
  would cover the very layers it writes to. In auto mode, keep the hidden
  volume under an excluded directory such as `/mnt`.
