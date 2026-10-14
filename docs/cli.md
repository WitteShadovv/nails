# Command-Line Help for `nails`

This document contains the help content for the `nails` command-line program.

**Command Overview:**

* [`nails`↴](#nails)
* [`nails activate`↴](#nails-activate)
* [`nails deactivate`↴](#nails-deactivate)
* [`nails emergency`↴](#nails-emergency)
* [`nails recover`↴](#nails-recover)
* [`nails status`↴](#nails-status)
* [`nails verify`↴](#nails-verify)
* [`nails rehearse`↴](#nails-rehearse)
* [`nails rehearse plant`↴](#nails-rehearse-plant)
* [`nails rehearse scan`↴](#nails-rehearse-scan)
* [`nails rehearse status`↴](#nails-rehearse-status)
* [`nails rehearse reset`↴](#nails-rehearse-reset)
* [`nails check`↴](#nails-check)
* [`nails init`↴](#nails-init)
* [`nails reset-upper`↴](#nails-reset-upper)
* [`nails config`↴](#nails-config)
* [`nails config path`↴](#nails-config-path)
* [`nails config show`↴](#nails-config-show)
* [`nails config validate`↴](#nails-config-validate)
* [`nails completions`↴](#nails-completions)

## `nails`

Run a hidden session on a decoy Linux system.

NAILS runs a hidden session on a decoy system: one OverlayFS over the whole
decoy root, with every change kept on the hidden volume, entered and left with
`systemctl soft-reboot` (systemd 254 or newer). The binary and its
configuration live on the hidden volume, so you run it by its
full path from the mounted volume (e.g. `sudo /mnt/data/nails status`),
never from a copy on the decoy disk.

The workflow has four steps:
  1. Open and mount the hidden backend (e.g. unlock the LUKS/VeraCrypt volume).
  2. `init <root>` once, to lay out the hidden volume.
  3. `activate` to soft-reboot into the hidden session. You are logged out;
     the hidden session starts at its own login screen.
  4. `deactivate` to soft-reboot back to the plain decoy, or `emergency` to
     kill the hidden session at once and return (or power off). If an
     activation was interrupted, `recover` removes what it left behind.

**Usage:** `nails [OPTIONS] <COMMAND>`

EXAMPLES:
  # Run by full path from the mounted backend, never from a decoy copy.
  sudo /mnt/data/nails init /mnt/data   Lay out the hidden volume (once)
  sudo /mnt/data/nails activate         Soft-reboot into the hidden session
  /mnt/data/nails status --json         Machine-readable state and uptime
  sudo /mnt/data/nails deactivate       Soft-reboot back to the decoy
  sudo /mnt/data/nails emergency        Kill the hidden session and return now
  source <(/mnt/data/nails completions bash)   Load completions in the session

EXIT STATUS:
  0    success
  1    the operation failed
  2    command-line usage error
  3    the configuration file or environment was unusable
  4    a pre-flight check refused the operation
  5    the operation needs privileges it did not have
  6    the on-disk state could not be trusted
  7    a degraded or interrupted session, or an incomplete cleanup
  8    the host is not one NAILS can operate on
  9    completed, but with a warning the caller should act on
  10   verify found warnings
  11   verify found critical artifacts, or rehearse scan found its canary
  130  cancelled by a signal (SIGINT/SIGTERM)

###### **Subcommands:**

* `activate` — Soft-reboot into the hidden session (whole-root overlay on the hidden volume)
* `deactivate` — Soft-reboot from the hidden session back to the plain decoy
* `emergency` — Kill the hidden session at once and soft-reboot back to the decoy (or power off)
* `recover` — Remove what an interrupted activation left in /run
* `status` — Show the session, security posture and hidden volume
* `verify` — Check for known NAILS traces (evidence, not proof)
* `rehearse` — Rehearse: plant a canary in a hidden session, then scan the raw decoy for it
* `check` — Check readiness to activate without making any changes (alias: doctor)
* `init` — Initialize NAILS directory structure on a hidden volume
* `reset-upper` — Delete a path's hidden copy from the hidden root's upper
* `config` — Inspect and check the configuration file (nails.toml)
* `completions` — Print a shell completion script on stdout (for `source <(...)`)

###### **Options:**

* `-c`, `--config <PATH>` — Path to the configuration file (overrides binary-relative discovery)
* `-v`, `--verbose` — More diagnostics on stderr: -v for debug, -vv for trace
* `-q`, `--quiet` — Print only errors and the final result
* `--color <WHEN>` — When to use colour

  Default value: `auto`

  Possible values:
  - `auto`:
    Colour a stream only when it is a terminal, TERM is not `dumb` and NO_COLOR is unset or empty
  - `always`:
    Always colour, even when piped
  - `never`:
    Never colour

* `--ascii` — Use ASCII markers instead of Unicode symbols and box drawing
* `--json` — Print machine-readable JSON on stdout
* `--no-log-file` — Do not write the log file on the hidden volume (diagnostics still go to stderr)



## `nails activate`

Soft-reboot into the hidden session (whole-root overlay on the hidden volume)

**Usage:** `nails activate [OPTIONS]`

WHAT HAPPENS:
  Activation builds one overlay over the whole decoy root at /run/nextroot,
  with every change stored on the hidden volume, and soft-reboots into it
  (systemd 254 or newer). Every program is closed and you are logged out; the
  hidden session starts at its own login screen. Nothing of the hidden session
  can reach the decoy disk: the ESP is read-only, other decoy filesystems are
  overlaid, and decoy swap is never used.

EXAMPLES:
  nails activate                      Enter the hidden session
  nails activate --overlay-only       Enter with the decoy's own system (NixOS)
  nails activate --dry-run            Preview without changing anything

###### **Options:**

* `--no-preflight` — Skip pre-flight checks (DANGEROUS - expert use only)
* `-y`, `--yes` — Proceed without the confirmation prompt

   Without this flag activation prompts on a terminal and refuses to run without one, because it logs you out.
* `--nixos-flake <FLAKE_REF>` — NixOS: the hidden configuration as a flake reference <path>#<host>

   The hidden system is built from it into the hidden root's store before the soft-reboot. Supports attribute selection after the `#`.
* `--dry-run` — Preview activation steps without making changes
* `--overlay-only` — NixOS: enter with the decoy's own system, without building the hidden configuration (the hidden /etc and home still apply)
* `--accept-persistent-decoy` — Accept a persistent decoy posture instead of refusing activation

   By default activation refuses a host that keeps forensic traces on the decoy disk: a persistent systemd-journald journal, or an active rsyslog/syslog-ng/auditd. What the decoy logs while it shuts down for the soft-reboot, and while it starts again afterwards, would survive on the decoy disk. This flag accepts that risk (and overrides `accept_persistent_decoy` in `nails.toml`).
* `--allow-unmounted` — Use a hidden root that this computer's own storage seems to hold

   By default activation refuses a root that this computer's own storage holds (a subvolume or a bind mount of one of its filesystems, a volume inside its storage, an image file on it): everything the session writes there lands on this computer's disk. Use this flag only for storage you know this computer does not use, such as a disk its fstab lists but never mounts. It turns those refusals into a warning, adds a line to the logout confirmation and records the choice for `status`. A folder that is no mount point, a root with a second filesystem mounted over it, storage that cannot be judged, and a decoy entry that opens the volume are still refused.



## `nails deactivate`

Soft-reboot from the hidden session back to the plain decoy

**Usage:** `nails deactivate [OPTIONS]`

WHAT HAPPENS:
  In the hidden session, deactivation mounts the decoy root at /run/nextroot,
  marks the hidden volume for closing and soft-reboots: every hidden program
  is stopped in order, /run is scrubbed of the hidden session, and the decoy
  starts again at its own login screen. The hidden volume is unmounted and
  its encryption mapping closed by the switch itself.

EXAMPLES:
  nails deactivate                    Soft-reboot back to the decoy
  nails deactivate --poweroff         Power off instead
  nails deactivate -y                 Skip the confirmation prompt

###### **Options:**

* `-y`, `--yes` — Proceed without the confirmation prompt

   Deactivation ends the hidden session. Without this flag it prompts on a terminal and refuses to run without one.
* `--poweroff` — Power the machine off instead of returning to the decoy.

   Powering off lets RAM decay; leave the machine off for a few minutes before handing it over.



## `nails emergency`

Kill the hidden session at once and soft-reboot back to the decoy (or power off)

**Usage:** `nails emergency [OPTIONS]`

WHAT HAPPENS:
  In the hidden session: the decoy root is mounted at /run/nextroot, the
  hidden volume is marked for closing, the soft-reboot is enqueued and every
  hidden program is killed at once. The machine returns to the plain decoy,
  which shows its normal login screen; log in with the decoy password. With
  --poweroff the machine powers off instead. On the decoy, emergency removes
  what an interrupted activation left in /run.

EXAMPLES:
  nails emergency                     Kill the hidden session and return now
  nails emergency --countdown 5       Wait 5s (Ctrl+C to abort), then act
  nails emergency --poweroff          Kill the hidden session and power off
  nails emergency --reboot            Kill the hidden session and reboot fully

###### **Options:**

* `--countdown <SECS>` — Wait this many seconds before acting, printing a Ctrl+C abort hint.

   Omitted (the default) acts immediately. The wait is never affected by `--quiet` or `--json`, so output flags never change the timing.
* `--poweroff` — Power the machine off instead of returning to the decoy, whatever the outcome. RAM decays: the strongest answer to a seizure. Leave the machine off for a few minutes. Mutually exclusive with `--reboot`
* `--reboot` — Reboot fully (firmware and bootloader) instead of the soft-reboot back.

   A warm reboot does not clear RAM. Prefer `--poweroff` when RAM residue matters. Mutually exclusive with `--poweroff`.



## `nails recover`

Remove what an interrupted activation left in /run

**Usage:** `nails recover`

EXAMPLES:
  nails recover                       Remove an interrupted activation's leftovers



## `nails status`

Show the session, security posture and hidden volume

**Usage:** `nails status [OPTIONS]`

EXAMPLES:
  nails status                        Show the current state and uptime
  nails status --details              Add resolved paths and overlay details
  nails status --json                 Emit a machine-readable envelope

###### **Options:**

* `--details` — Show resolved paths and overlay mount details



## `nails verify`

Check for known NAILS traces (evidence, not proof)

**Usage:** `nails verify [OPTIONS]`

EXAMPLES:
  nails verify                        Scan the live host for NAILS artifacts
  nails verify --deep                 Slower, more thorough scan
  nails verify --offline --root /mnt  Scan a mounted decoy image
  nails verify --offline --root /mnt --examiner --disk /dev/sdb
                                      Add the examiner's view of setup traces

###### **Options:**

* `--deep` — Perform deep scan (slower, more thorough)
* `--offline` — Scan a read-only mounted decoy image or partition instead of the live host. Requires `--root`; live checks (processes, mounts, block devices) are skipped and every path is read from under the image root
* `--root <MOUNT>` — Root of the mounted decoy image to scan in `--offline` mode
* `--examiner` — Also report setup traces an examiner looks for (encryption headers, containers, crypttab, LVM archives, tooling and history), grouped by what they suggest. Reports only; changes nothing. Needs `--offline`
* `--disk <DEVICE>` — The raw disk or disk image behind `--root`, read-only, for the partition-level examiner checks (LUKS headers, random-looking space)



## `nails rehearse`

Rehearse: plant a canary in a hidden session, then scan the raw decoy for it

**Usage:** `nails rehearse [COMMAND]`

STEPS:
  1. In an active hidden session:     nails rehearse plant
  2. Deactivate as usual, then on the decoy unlock and mount the hidden volume
  3. From the decoy, or a later session: nails rehearse scan
  Then `nails rehearse reset` removes the rehearsal from the hidden volume.

EXAMPLES:
  nails rehearse                      Show where the rehearsal stands
  nails rehearse plant --user alice   Plant the canary for alice's session
  nails rehearse scan                 Scan the mounted decoy devices
  nails rehearse scan --offline --image decoy.raw
                                      Scan a disk image instead

The scan exits 0 when no canary is found, 11 when one is, and 9 when a device
could not be scanned completely.

###### **Subcommands:**

* `plant` — Step 1, in an active hidden session: plant a random canary in the session's files, log, a process, recent files and a notification
* `scan` — Step 3, after deactivating: scan the raw decoy devices for the canary
* `status` — Show where the rehearsal stands and the next step
* `reset` — Remove the rehearsal state and its planted files from the hidden volume



## `nails rehearse plant`

Step 1, in an active hidden session: plant a random canary in the session's files, log, a process, recent files and a notification

**Usage:** `nails rehearse plant [OPTIONS]`

###### **Options:**

* `--user <NAME>` — The operator whose home, recent files and notifications are used (default: the user who ran sudo)



## `nails rehearse scan`

Step 3, after deactivating: scan the raw decoy devices for the canary

**Usage:** `nails rehearse scan [OPTIONS]`

###### **Options:**

* `--device <DEVICE>` — Scan this block device instead of the mounted decoy devices (repeatable)
* `--offline` — Scan disk images or devices given with --image, not this machine's mounts
* `--image <IMAGE>` — An image or device to scan in --offline mode (repeatable)
* `--token-file <FILE>` — Read the canary token from this file instead of the hidden volume's rehearsal state (--offline only)
* `--allow-same-boot` — Scan even in the session the canary was planted in (proves little: the session's writes may not have reached the disk yet)
* `--max-bytes <BYTES>` — Stop each device after this many bytes



## `nails rehearse status`

Show where the rehearsal stands and the next step

**Usage:** `nails rehearse status`



## `nails rehearse reset`

Remove the rehearsal state and its planted files from the hidden volume

**Usage:** `nails rehearse reset`



## `nails check`

Check readiness to activate without making any changes (alias: doctor)

**Usage:** `nails check [OPTIONS]`

EXAMPLES:
  nails check                         Report readiness to activate
  nails doctor                        Same, via the alias
  nails check --overlay-only          Skip the hidden NixOS build checks

###### **Options:**

* `--overlay-only` — Check as for `activate --overlay-only` (skip the hidden NixOS build checks)
* `--nixos-flake <FLAKE_REF>` — NixOS layer: check a specific flake reference as <path>#<host> (e.g. /etc/nixos#myhost)
* `--accept-persistent-decoy` — Report a persistent decoy posture as a warning instead of a failure

   Mirrors `activate --accept-persistent-decoy` so `check`/`--dry-run` reflects what activation would do.
* `--allow-unmounted` — Report a hidden root on this computer's own storage as a warning

   Mirrors `activate --allow-unmounted`: a root this computer's own storage seems to hold then warns instead of failing. A folder that is no mount point, a covered root and storage that cannot be judged still fail.



## `nails init`

Initialize NAILS directory structure on a hidden volume

**Usage:** `nails init [OPTIONS] <PATH>`

EXAMPLES:
  nails init /mnt/data                Lay out the hidden volume at /mnt/data
  nails init /mnt/data --no-hardware-config   Skip the hidden NixOS layout

###### **Arguments:**

* `<PATH>` — Path to the mounted hidden volume to initialize

###### **Options:**

* `--allow-unmounted` — Initialize a volume that this computer's own storage seems to hold

   By default `init` refuses a target that this computer's own storage holds (a subvolume or a bind mount of one of its filesystems, a volume inside its storage, an image file on it), because writing the NAILS layout there leaves an identifying tree on this computer's disk. Use this flag only for storage you know this computer does not use; it turns those refusals into a warning. A folder that is no mount point, a target with a second filesystem mounted over it, and one whose storage cannot be judged are still refused.
* `--hardware-config <PATH>` — Base hardware configuration to seed the hidden NixOS layout from

   Overrides the default `/etc/nixos/hardware-configuration.nix`. On a non-NixOS host the layout is skipped unless this is given.
* `--no-hardware-config` — Do not create the hidden NixOS layout at all



## `nails reset-upper`

Delete a path's hidden copy from the hidden root's upper

**Usage:** `nails reset-upper [OPTIONS] <TARGET>`

EXAMPLES:
  nails reset-upper /home             Delete the hidden copy of /home
  nails reset-upper /nix -y           Delete the hidden /nix without prompting

###### **Arguments:**

* `<TARGET>` — Path whose hidden copy to delete (e.g. /home, /etc, /nix); the decoy's own files show through again

###### **Options:**

* `-y`, `--yes` — Proceed without the confirmation prompt

   Without this flag reset-upper lists what it would delete and confirms on a terminal, refusing to run without one.



## `nails config`

Inspect and check the configuration file (nails.toml)

**Usage:** `nails config <COMMAND>`

EXAMPLES:
  nails config path                   Print the resolved config file path
  nails config show                   Print the effective configuration
  nails config show --example         Print a commented example config
  nails config validate ./nails.toml  Strictly check a config file

###### **Subcommands:**

* `path` — Print the resolved configuration file path and whether it exists
* `show` — Print the effective configuration and where each value comes from
* `validate` — Check a configuration file strictly (syntax, types, unknown keys)



## `nails config path`

Print the resolved configuration file path and whether it exists

**Usage:** `nails config path`



## `nails config show`

Print the effective configuration and where each value comes from

**Usage:** `nails config show [OPTIONS]`

###### **Options:**

* `--example` — Print a commented example configuration instead (not with --json)
* `--nixos-flake <FLAKE_REF>` — Preview the effect of `activate --nixos-flake FLAKE_REF`



## `nails config validate`

Check a configuration file strictly (syntax, types, unknown keys)

**Usage:** `nails config validate [PATH]`

###### **Arguments:**

* `<PATH>` — File to check (default: the resolved configuration file)



## `nails completions`

Print a shell completion script on stdout (for `source <(...)`)

**Usage:** `nails completions <SHELL>`

EXAMPLES:
  source <(nails completions bash)    Load completions in the current shell
  nails completions zsh               Print the zsh completion script
  nails completions fish              Print the fish completion script

The script is written to stdout only; nothing is installed, so running this from
the hidden session leaves no completion file on the decoy.

###### **Arguments:**

* `<SHELL>` — Shell to generate a completion script for

  Possible values: `bash`, `elvish`, `fish`, `powershell`, `zsh`




<hr/>

<small><i>
    This document was generated automatically by
    <a href="https://crates.io/crates/clap-markdown"><code>clap-markdown</code></a>.
</i></small>
## Exit status

Every command shares one set of exit codes.

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | The operation failed |
| 2 | Command-line usage error |
| 3 | The configuration file or environment was unusable |
| 4 | A pre-flight check refused the operation |
| 5 | The operation needs privileges it did not have |
| 6 | The on-disk state could not be trusted |
| 7 | A degraded or interrupted session, or an incomplete cleanup; `nails status` names the fix (usually `nails recover`) |
| 8 | The host is not one NAILS can operate on |
| 9 | Completed, but with a warning the caller should act on |
| 10 | `verify` found warnings |
| 11 | `verify` found critical artifacts, or `rehearse scan` found its canary |
| 130 | Cancelled by a signal (SIGINT/SIGTERM) |

Notable per-command codes: `verify` returns 0/10/11 for secure/warning/critical;
`rehearse scan` returns 0 when the canary is not found, 11 when it is, and 9
when a device could not be scanned completely;
`status` returns 7 on a degraded posture and 6 on an untrusted state file; every
mutating command returns 5 when run without root.
