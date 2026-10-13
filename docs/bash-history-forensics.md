# Shell history forensics

This page explains, at a technical level, where a shell can leave a record of
what was typed in a hidden session, why naive deletion is not enough against a
forensic examiner, and how NAILS neutralises each surface. It is the companion
reference for the operator-facing steps in
[operator-guide.md](./operator-guide.md#shell-history); read that guide first for
the day-to-day rules, and use this page to understand the mechanics behind them.
Decoy-side history hardening (environment, symlinks, boot-time enforcement) is
something you configure on the decoy itself; it lives in
[decoy-requirements.md](./decoy-requirements.md#shell-history-hardening).

The threat NAILS defends against is an examiner who images the decoy disk after
the hidden session is gone. The goal is simple: no command typed inside the
hidden overlay may survive on the decoy's real filesystem.

## Where shell history persists

A single interactive command can be recorded in several independent places. A
history-protection scheme is only as strong as the surface it forgets about.

| Surface | Example location | Notes |
|---------|------------------|-------|
| Per-user history file | `~/.bash_history`, `~/.zsh_history` | Written on normal shell exit or on explicit `history -a`/`history -w`. |
| Root history file | `/root/.bash_history` | Same mechanism, separate file. |
| In-memory buffer | bash process memory | Flushed to the history file on exit or `SIGHUP`; recoverable from `/proc/<pid>/mem` while the process lives. |
| Systemd journal | `journalctl _UID=<uid>` | Session and (where configured) command logging that outlives the shell. |
| Audit log | `auditd` / `/var/log/audit/` | `execve` records when audit rules are active. |
| Process accounting | `/var/log/account/pacct` | Per-command accounting when `acct` is enabled. |
| TTY / script capture | `script`, `ttyrec`, session recorders | Captures the full terminal stream. |

In the hidden session the whole root is an overlay whose upper is on the hidden
volume, so a history file written there lands on the hidden volume, never on the
decoy disk. The risk is in the **decoy** shells around the session: the shell
you unlock the volume and run `nails activate` from, and a decoy shell that
flushes its buffer when the session starts.

## How NAILS neutralises each surface

NAILS's own runtime defence is narrow and honest. It does **not** set history
environment variables, symlink history files to the null device, or install a
boot-time enforcement unit — that hardening is decoy configuration you apply
yourself (see
[decoy-requirements.md](./decoy-requirements.md#shell-history-hardening)). What
NAILS does at runtime is:

1. **Keep hidden writes off the decoy.** Every process of the hidden session
   runs inside the root overlay, so its history files land in the upper on the
   hidden volume. When the session ends, the orderly shutdown stops its shells
   while the overlay is still the root, so their final flush lands there too.
2. **Kill the decoy's shells before entry.** Stopping a login session sends its
   shells `SIGHUP`, on which bash writes its history. Right before it starts the
   soft-reboot, `nails activate` therefore sends `SIGKILL` to the decoy's
   interactive shells, yours included, so none of them writes the activation
   command to a history file on the decoy (see [the flush race](#the-flush-race)).
   `nails emergency` kills shells the same way before it starts the way back or
   the power-off.
3. **Make no write to decoy history.** NAILS never edits or reads a history file
   on the decoy: an access would itself leave a fresh timestamp. Decoy-history
   hygiene is decoy configuration and the operator's pre-activation routine.
4. **Warn on incremental flushing.** A preflight check warns when the shell you
   run NAILS from flushes history after every command
   (`INC_APPEND_HISTORY`/`SHARE_HISTORY`, or `history -a` in bash
   `PROMPT_COMMAND`), because such a shell writes the unlock/mount commands to
   disk before teardown can help.

Journal, audit and accounting surfaces are host-policy concerns: NAILS does not
enable them, and an operator who turns them on must account for them separately.

## Why deletion alone is not enough

An examiner does not rely on the current contents of a file. The following
survive an ordinary `rm` or an in-place overwrite on many systems:

- **Unlinked-but-open data** - a deleted history file whose inode is still open
  remains fully readable until the last handle closes.
- **Filesystem journals** - ext4, XFS and others may retain recently written
  blocks (including old history contents) in the journal after the visible file
  is gone.
- **Copy-on-write snapshots** - on btrfs/ZFS a snapshot keeps the pre-deletion
  version regardless of what happens to the live file.
- **Slack space and unallocated blocks** - overwriting a file does not scrub the
  blocks a shorter replacement no longer uses.
- **SSD wear-levelling / TRIM timing** - the flash controller may keep old copies
  the filesystem believes are overwritten.

This is why NAILS keeps hidden writes on the overlay upper instead of writing and
then deleting on the decoy: there is nothing on the real disk to recover, so
there is nothing for these mechanisms to preserve.

## The flush race

The one window where a typed command can reach the decoy disk is a decoy shell
that is still alive when its session ends:

```
nails activate typed in a decoy shell
    -> held in bash's in-memory buffer
    -> the soft-reboot stops the decoy's login sessions
    -> the shell receives SIGHUP
    -> bash flushes the buffer to the decoy's ~/.bash_history
```

`nails activate` closes this window by killing the decoy's interactive shells
with `SIGKILL` as its last step before the soft-reboot, so no exit trap or
flush runs. Your terminal closes at that point; what activation printed up to
then is already on it. A shell that flushes after every command
(`INC_APPEND_HISTORY`, `SHARE_HISTORY` or `history -a` in `PROMPT_COMMAND`) has
already written the command before any of this, which is why the pre-flight
check warns about it and why the decoy commands belong in a shell with history
off (`set +o history`).

Inside the hidden session there is no such window: the shells stop before the
switch back, while the overlay is still the root.

## Verifying on the decoy

After a session, back on the decoy system:

```bash
# Both should be empty (or contain only decoy commands).
cat ~/.bash_history
cat /root/.bash_history

# Confirm the protective settings are still in place.
echo "$HISTFILE $HISTSIZE $HISTFILESIZE"
```

If either history file holds hidden-session commands, treat the decoy as
compromised and follow the recovery guidance in the operator guide.

## See also

- [operator-guide.md](./operator-guide.md#shell-history) - operator steps before
  and during a session.
- [decoy-requirements.md](./decoy-requirements.md#shell-history-hardening) -
  decoy-side history hardening you configure yourself.
