# Shell History Forensics in NAILS

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

NAILS layers the hidden environment over the decoy with OverlayFS, so writes
made inside the session land on the hidden upper, not the decoy lower. The risk
is not the overlay itself but the moments around it: a buffer that flushes after
the overlay is gone, or a history file that already exists on the real disk.

## How NAILS neutralises each surface

NAILS's own runtime defence is narrow and honest. It does **not** set history
environment variables, symlink history files to the null device, or install a
boot-time enforcement unit — that hardening is decoy configuration you apply
yourself (see
[decoy-requirements.md](./decoy-requirements.md#shell-history-hardening)). What
NAILS does at runtime is:

1. **Keep hidden writes off the decoy.** The session runs over an OverlayFS
   upper, so a history file written inside the session lands on the hidden
   volume, not the decoy lower.
2. **Kill shells before the unmount.** Both standard and emergency teardown
   SIGKILL every interactive shell (including root's) before the overlays come
   down, so none runs an exit trap or flushes its in-memory buffer to the decoy
   (see [the flush race](#the-flush-race)). Standard deactivation then reboots.
3. **Make no post-unmount write.** Editing, or even reading, a history file on
   the decoy after unmount is itself a deactivation-time artifact (a fresh
   timestamp at the moment of teardown), so no teardown makes such an access.
   Decoy-history hygiene belongs to the pre-activation cleanup.
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

The one window where a hidden command can reach the decoy is the gap between the
overlay unmount and the shell's exit:

```
command typed in hidden session
    -> held in bash's in-memory buffer
    -> overlay unmounts, real decoy filesystem reappears
    -> shell exits or receives SIGHUP
    -> bash flushes the buffer to the REAL ~/.bash_history
```

NAILS closes this window by killing shell processes before the unmount:

- **Both standard and emergency deactivation** send `SIGKILL` to every
  interactive shell first, so none runs an exit trap or flushes its buffer.
  Standard deactivation additionally reboots once teardown completes.

The operator's part is to not manually exit a shell once deactivation has begun,
and to confirm the history files are empty after returning to the decoy.

## Verifying on the decoy

After deactivation, back on the decoy system:

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

- [operator-guide.md](./operator-guide.md#shell-history) - operator steps and the
  deactivation workflow.
- [decoy-requirements.md](./decoy-requirements.md#shell-history-hardening) -
  decoy-side history hardening you configure yourself.
