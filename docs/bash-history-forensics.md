# Shell History Forensics in NAILS

This page explains, at a technical level, where a shell can leave a record of
what was typed in a hidden session, why naive deletion is not enough against a
forensic examiner, and how NAILS neutralises each surface. It is the companion
reference for the operator-facing steps in
[USER-SECURITY-GUIDE.md](./USER-SECURITY-GUIDE.md#shell-history-protection); read
that guide first for the day-to-day rules, and use this page to understand the
mechanics behind them.

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
| TTY / script capture | `script`, `ttyrec`, agent recorders | Captures the full terminal stream. |

NAILS layers the hidden environment over the decoy with OverlayFS, so writes
made inside the session land on the hidden upper, not the decoy lower. The risk
is not the overlay itself but the moments around it: a buffer that flushes after
the overlay is gone, or a history file that already exists on the real disk.

## How NAILS neutralises each surface

The operator guide describes this as a five-layer defence; the mechanics are:

1. **Environment** - `HISTFILE=/dev/null`, `HISTSIZE=0`, `HISTFILESIZE=0` are set
   so an interactive shell has nowhere and nothing to write.
2. **Shell options** - `set +o history` and `shopt -u histappend` stop recording
   and append-on-exit inside the session.
3. **Filesystem redirection** - `~/.bash_history` and `~/.zsh_history` are
   symlinked to `/dev/null`, so even a shell that ignores the environment writes
   into the null device.
4. **Boot-time enforcement** - a systemd unit truncates any regular history file
   and re-creates the symlinks early in boot, before an interactive login can
   repopulate them.
5. **Deactivation cleanup** - shell processes are terminated *before* the overlay
   unmounts to defeat the flush race (see below), and real-disk history files are
   truncated after the overlay is removed.

Journal, audit and accounting surfaces are host-policy concerns: NAILS does not
enable them, and an operator who turns them on must account for them separately.
The guide's "What You Should NOT Do" table lists the actions that defeat these
layers.

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

- **Emergency deactivation** sends `SIGKILL` first, so no flush can run.
- **Standard deactivation** relies on a reboot to terminate the processes.

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

- [USER-SECURITY-GUIDE.md](./USER-SECURITY-GUIDE.md#shell-history-protection) -
  operator steps, the "What You Should NOT Do" table, and deactivation workflow.
