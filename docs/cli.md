# Command-Line Help for `nails`

This document contains the help content for the `nails` command-line program.

**Command Overview:**

* [`nails`↴](#nails)
* [`nails activate`↴](#nails-activate)
* [`nails deactivate`↴](#nails-deactivate)
* [`nails reapply`↴](#nails-reapply)
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

Overlay environment manager.

NAILS layers a hidden environment over a decoy system using OverlayFS. The
binary and its configuration live on the hidden volume, so you run it by its
full path from the mounted volume (e.g. `sudo /mnt/data/nails status`), never
from a copy on the decoy disk.

The workflow has four steps:
  1. Open and mount the hidden backend (e.g. unlock the LUKS/VeraCrypt volume).
  2. `init <root>` once, to lay out the hidden volume.
  3. `activate` to mount the overlays and apply the platform layer.
  4. `deactivate` to return to the decoy and reboot, or `emergency` to tear
     everything down now. If a run is interrupted and the system is stuck,
     `recover` reconciles the state and finishes the teardown.

**Usage:** `nails [OPTIONS] <COMMAND>`

EXAMPLES:
  # Run by full path from the mounted backend, never from a decoy copy.
  sudo /mnt/data/nails init /mnt/data   Lay out the hidden volume (once)
  sudo /mnt/data/nails activate         Mount the overlays and apply the layer
  /mnt/data/nails status --json         Machine-readable state and uptime
  sudo /mnt/data/nails deactivate       Restore the decoy and reboot
  sudo /mnt/data/nails emergency        Tear everything down immediately
  source <(/mnt/data/nails completions bash)   Load completions in the session

EXIT STATUS:
  0    success
  1    the operation failed
  2    command-line usage error
  3    the configuration file or environment was unusable
  4    a pre-flight check refused the operation
  5    the operation needs privileges it did not have
  6    the on-disk state could not be trusted
  7    the system is degraded or a reboot is required to finish
  8    the host is not one NAILS can operate on
  9    completed, but with a warning the caller should act on
  10   verify found warnings
  11   verify found critical artifacts, or rehearse scan found its canary
  130  cancelled by a signal (SIGINT/SIGTERM)

###### **Subcommands:**

* `activate` — Activate the hidden environment (mount overlays and apply the platform layer)
* `deactivate` — Deactivate and reboot into the decoy state (unmount + cleanup + reboot)
* `reapply` — Reapply the hidden configuration layer while active (platforms with a layer only)
* `emergency` — Emergency teardown: detach overlays immediately, nothing written to the decoy
* `recover` — Reconcile a stuck state and finish an interrupted or degraded teardown
* `status` — Show current status and uptime
* `verify` — Verify system is clean of NAILS artifacts
* `rehearse` — Rehearse: plant a canary in a hidden session, then scan the raw decoy for it
* `check` — Check readiness to activate without making any changes (alias: doctor)
* `init` — Initialize NAILS directory structure on a hidden volume
* `reset-upper` — Delete a target's persistent overlay upper on the hidden volume
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

Activate the hidden environment (mount overlays and apply the platform layer)

**Usage:** `nails activate [OPTIONS]`

EXAMPLES:
  nails activate                      Mount the overlays and apply the layer
  nails activate --session keep       Keep the current graphical session
  nails activate --overlay-only       Mount overlays, skip the platform layer
  nails activate --dry-run            Preview without changing anything

###### **Options:**

* `--no-preflight` — Skip pre-flight checks (DANGEROUS - expert use only)
* `--session <POLICY>` — What to do with the graphical session (default: kill)

  Default value: `kill`

  Possible values:
  - `kill`:
    Terminate the graphical session before mounting (the secure default)
  - `keep`:
    Keep the current session running (mounts only what can be overlaid live)

* `--pivot <POLICY>` — How to handle a volume that needs a pivot mount (default: refuse)

  Default value: `refuse`

  Possible values:
  - `refuse`:
    Abort rather than fall back to a pivot mount (the secure default)
  - `allow`:
    Fall back to a pivot mount without asking (degraded security)
  - `ask`:
    Prompt on a terminal before falling back to a pivot mount; refuse without one

* `-y`, `--yes` — Proceed without confirmation prompts

   Without this flag activation prompts on a terminal and refuses to run without one, so it never ends a graphical session unattended.
* `--nixos-flake <FLAKE_REF>` — NixOS layer: flake reference as <path>#<host> (e.g. /etc/nixos#myhost)

   Only applies on NixOS. When set, this value is passed directly to `nixos-rebuild --flake` instead of auto-detecting the flake path. Supports attribute selection after the `#`.
* `--dry-run` — Preview activation steps without making changes
* `--overlay-only` — Mount overlays only, skip the platform configuration layer
* `--risky-services <POLICY>` — What to do with risky services still referencing a target (overrides the `risky_services` config key)

   Unset: restart when the session is killed, prompt on a terminal otherwise, and refuse a non-interactive run that keeps the session.

  Possible values:
  - `restart`:
    Restart them so they no longer reference the decoy
  - `skip`:
    Leave them running; they are reported as surviving writers

* `--terminate-processes` — Signal non-service processes (shells, editors, scripts) holding a target instead of aborting

   Off by default: a process with no systemd unit can only be stopped by signal, so activation never signals one and aborts before mounting, listing them. This flag ends them anyway.
* `--accept-persistent-decoy` — Accept a persistent decoy posture instead of refusing activation

   By default activation refuses a host that keeps forensic traces on the decoy disk: a persistent systemd-journald journal, or an active rsyslog/syslog-ng/auditd. Records those sinks write before the overlays are mounted survive deactivation and reboot. This flag accepts that risk (and overrides `accept_persistent_decoy` in `nails.toml`).



## `nails deactivate`

Deactivate and reboot into the decoy state (unmount + cleanup + reboot)

**Usage:** `nails deactivate [OPTIONS]`

EXAMPLES:
  nails deactivate                    Restore the decoy and reboot
  nails deactivate --poweroff         Restore the decoy and power off
  nails deactivate -y                 Skip the confirmation prompt

###### **Options:**

* `--no-clear-history` — Skip shell history cleanup

   By default, deactivation removes all 'nails' commands from shell history. Use this flag to preserve history (not recommended for forensic safety).
* `-y`, `--yes` — Proceed without the confirmation prompt

   Deactivation restores the decoy configuration and reboots. Without this flag it prompts on a terminal and refuses to run without one.
* `--poweroff` — Power the machine off instead of rebooting once the decoy is restored.

   A warm reboot does not clear RAM: DRAM keeps its contents across a reset unless the firmware honours the TCG memory-overwrite request (MOR), and setting MOR writes EFI NVRAM. Powering off lets the memory decay; leave the machine off for a few minutes before handing it over.



## `nails reapply`

Reapply the hidden configuration layer while active (platforms with a layer only)

**Usage:** `nails reapply`

EXAMPLES:
  nails reapply                       Rebuild and switch the hidden config



## `nails emergency`

Emergency teardown: detach overlays immediately, nothing written to the decoy

**Usage:** `nails emergency [OPTIONS]`

EXAMPLES:
  nails emergency                     Tear everything down immediately
  nails emergency --countdown 5       Wait 5s (Ctrl+C to abort), then tear down
  nails emergency --poweroff          Tear down, then power the machine off
  nails emergency --reboot            Tear down, then reboot into the decoy

###### **Options:**

* `--countdown <SECS>` — Wait this many seconds before tearing down, printing a Ctrl+C abort hint.

   Omitted (the default) tears down immediately. The wait is never affected by `--quiet` or `--json`, so output flags never change the timing.
* `--poweroff` — Power the machine off after the teardown attempt, whatever its outcome.

   Powering off lets RAM decay, the only complete remedy for residue the teardown cannot remove; it runs even when a mount could not be removed. Leave the machine off for a few minutes. Mutually exclusive with `--reboot`.
* `--reboot` — Reboot into the decoy after the teardown attempt, whatever its outcome.

   A warm reboot does not clear RAM: DRAM keeps its contents across a reset unless the firmware honours the TCG memory-overwrite request (MOR), and setting MOR writes EFI NVRAM. Prefer `--poweroff` when RAM residue matters. Mutually exclusive with `--poweroff`.
* `--lock-backend` — Close the encrypted backend after the teardown attempt: lazy-unmount the hidden root and mark its device-mapper stack for deferred removal, wiping the master key from kernel memory when the last reference drops.

   Forces the close for this run regardless of the `[emergency] lock_backend` config key. Without it (and without the key) the hidden filesystem stays mounted and readable after the emergency, and the printed sequence closes it by hand.



## `nails recover`

Reconcile a stuck state and finish an interrupted or degraded teardown

**Usage:** `nails recover`

EXAMPLES:
  nails recover                       Reconcile a stuck state and finish teardown



## `nails status`

Show current status and uptime

**Usage:** `nails status [OPTIONS]`

EXAMPLES:
  nails status                        Show the current state and uptime
  nails status --details              Add resolved paths and overlay details
  nails status --json                 Emit a machine-readable envelope

###### **Options:**

* `--details` — Show resolved paths and overlay mount details



## `nails verify`

Verify system is clean of NAILS artifacts

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
  2. Deactivate as usual (it reboots), then unlock and mount the hidden volume
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
* `--allow-same-boot` — Scan even in the boot the canary was planted in (proves little: the session's writes may not have reached the disk yet)
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
  nails check --overlay-only          Skip the platform-layer checks

###### **Options:**

* `--overlay-only` — Check as for an overlay-only activation (skip the platform-layer checks)
* `--nixos-flake <FLAKE_REF>` — NixOS layer: check a specific flake reference as <path>#<host> (e.g. /etc/nixos#myhost)
* `--accept-persistent-decoy` — Report a persistent decoy posture as a warning instead of a failure

   Mirrors `activate --accept-persistent-decoy` so `check`/`--dry-run` reflects what activation would do.



## `nails init`

Initialize NAILS directory structure on a hidden volume

**Usage:** `nails init [OPTIONS] <PATH>`

EXAMPLES:
  nails init /mnt/data                Lay out the hidden volume at /mnt/data
  nails init /mnt/data --no-hardware-config   Skip the hidden NixOS layout

###### **Arguments:**

* `<PATH>` — Path to the mounted hidden volume to initialize

###### **Options:**

* `--allow-unmounted` — Initialize a path that is not a mounted volume of its own

   By default `init` refuses a target that shares a device with `/`, because writing the NAILS layout onto the decoy disk is exactly the mistake that leaves an identifying tree where the real volume later hides it. Pass this for a directory-style backend that is deliberately not a separate mount.
* `--hardware-config <PATH>` — Base hardware configuration to seed the hidden NixOS layout from

   Overrides the default `/etc/nixos/hardware-configuration.nix`. On a non-NixOS host the layout is skipped unless this is given.
* `--no-hardware-config` — Do not create the hidden NixOS layout at all



## `nails reset-upper`

Delete a target's persistent overlay upper on the hidden volume

**Usage:** `nails reset-upper [OPTIONS] <TARGET>`

EXAMPLES:
  nails reset-upper /home             Delete the persistent /home upper
  nails reset-upper /nix -y           Delete the /nix upper without prompting

###### **Arguments:**

* `<TARGET>` — Overlay target whose persistent upper to delete (e.g. /home, /etc, /nix)

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
* `--no-clear-history` — Preview the effect of `deactivate --no-clear-history`



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
| 7 | The system is degraded or a reboot is required to finish |
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
