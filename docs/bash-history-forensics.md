# Bash History Forensics and Anti-Forensics

## Table of Contents
1. [History Persistence Locations](#1-history-persistence-locations)
2. [Environment Variables](#2-environment-variables)
3. [Disabling History](#3-disabling-history)
4. [Best Practices for History Protection](#4-best-practices-for-history-protection)
5. [Forensic Recovery Techniques](#5-forensic-recovery-techniques)
6. [Race Conditions and Timing](#6-race-conditions-and-timing)

---

## 1. History Persistence Locations

### 1.1 Primary History File

**Default Location:** `~/.bash_history`

```bash
# View current history file location
echo $HISTFILE

# Default for regular users
/home/<username>/.bash_history

# Default for root
/root/.bash_history
```

The history file is written when:
- Shell exits normally (not killed with SIGKILL)
- `history -a` is explicitly called (append)
- `history -w` is explicitly called (write/overwrite)

### 1.2 In-Memory History

Commands are stored in memory during the shell session:

```bash
# View current in-memory history
history

# The in-memory list is separate from HISTFILE
# It syncs to disk on shell exit or explicit flush
```

**Key Points:**
- Memory history survives until shell termination
- Can be dumped from `/proc/<pid>/mem` if you have privileges
- Killing bash with `kill -9` prevents history flush to disk

### 1.3 Systemd Journal

Modern Linux systems log shell sessions through systemd:

```bash
# View journal entries for user sessions
journalctl _UID=$(id -u) --since "1 hour ago"

# View all login/logout events
journalctl _COMM=login
journalctl _COMM=sshd

# View specific user's session commands (if session logging enabled)
journalctl _SYSTEMD_USER_UNIT=*.scope

# Journal is stored in:
/var/log/journal/<machine-id>/
/run/log/journal/<machine-id>/  # volatile
```

### 1.4 Audit Logs (auditd)

If auditd is configured to log shell commands:

```bash
# Audit log locations
/var/log/audit/audit.log
/var/log/audit/audit.log.1  # rotated logs

# Example audit rule to capture all execve calls
# In /etc/audit/rules.d/audit.rules:
-a always,exit -F arch=b64 -S execve -k commands
-a always,exit -F arch=b32 -S execve -k commands

# Search audit logs
ausearch -k commands
ausearch -x bash
aureport -x --summary
```

### 1.5 Process Accounting

If enabled, records all executed commands:

```bash
# Process accounting files
/var/account/pacct       # Binary log of all commands
/var/log/wtmp            # Login records
/var/log/btmp            # Failed login attempts
/var/log/lastlog         # Last login info

# View process accounting
lastcomm                 # Show recent commands
sa                       # Summary of commands
ac                       # Connect time accounting

# Enable process accounting
accton /var/account/pacct
```

### 1.6 Script/TTY Recording

Sessions may be recorded via `script`:

```bash
# Common recording locations
/var/log/script/
/var/log/session/
~/typescript             # Default script output
~/.script_logs/

# Check if script is running
ps aux | grep script
pstree -p | grep script
```

### 1.7 Other Persistence Locations

```bash
# Syslog (may contain session info)
/var/log/syslog
/var/log/messages
/var/log/auth.log        # SSH/sudo commands
/var/log/secure          # RHEL/CentOS

# User-specific locations
~/.bash_history          # Primary
~/.history               # Legacy/other shells
~/.sh_history            # ksh history
~/.zsh_history           # If user uses zsh
~/.local/share/fish/fish_history  # fish shell

# Backup locations (created by editors/systems)
~/.bash_history.bak
~/.bash_history~
~/.bash_history.old

# Temporary files (may contain command data)
/tmp/
/var/tmp/
/dev/shm/                # RAM-based tmpfs

# Core dumps (may contain memory with history)
/var/crash/
/var/lib/systemd/coredump/
./core

# Swap space
/swapfile
/dev/<swap_partition>
```

---

## 2. Environment Variables

### 2.1 Core History Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HISTFILE` | `~/.bash_history` | File where history is saved |
| `HISTSIZE` | 500 | Max commands in memory |
| `HISTFILESIZE` | 500 (or HISTSIZE) | Max lines in history file |
| `HISTCONTROL` | (empty) | Controls what's saved |
| `HISTIGNORE` | (empty) | Patterns to exclude |
| `HISTTIMEFORMAT` | (empty) | Timestamp format |

### 2.2 HISTFILE

```bash
# Set custom history file
export HISTFILE=/path/to/custom/history

# Disable history file (prevents disk writes)
export HISTFILE=/dev/null
# OR
unset HISTFILE
# OR
export HISTFILE=""
```

### 2.3 HISTSIZE

```bash
# Number of commands kept in memory
export HISTSIZE=1000      # Keep 1000 commands in memory
export HISTSIZE=0         # Disable in-memory history
export HISTSIZE=-1        # Unlimited (bash 4.3+)
```

### 2.4 HISTFILESIZE

```bash
# Max lines in history file
export HISTFILESIZE=2000   # Keep 2000 lines in file
export HISTFILESIZE=0      # Truncate file to zero on exit
export HISTFILESIZE=-1     # Unlimited (bash 4.3+)
```

### 2.5 HISTCONTROL

```bash
# Options (colon-separated)
export HISTCONTROL=ignorespace      # Ignore commands starting with space
export HISTCONTROL=ignoredups       # Ignore consecutive duplicates
export HISTCONTROL=ignoreboth       # Both of above
export HISTCONTROL=erasedups        # Remove ALL duplicates from history

# Combined
export HISTCONTROL=ignorespace:erasedups
```

**Using ignorespace:**
```bash
# This command will NOT be recorded (note leading space)
 sensitive-command --password=secret

# This WILL be recorded
sensitive-command --password=secret
```

### 2.6 HISTIGNORE

```bash
# Patterns to ignore (colon-separated)
export HISTIGNORE="ls:cd:pwd:exit:clear"

# Ignore commands matching patterns
export HISTIGNORE="ls*:cd*:pwd:exit:history*"

# Ignore everything (nuclear option)
export HISTIGNORE="*"

# Use & to match previous command (duplicate detection)
export HISTIGNORE="&"

# Complex example
export HISTIGNORE="ls*:cd*:pwd:exit:history:clear: *:export *PASS*:*password*"
```

### 2.7 HISTTIMEFORMAT

```bash
# Enable timestamps (forensically valuable)
export HISTTIMEFORMAT="%F %T "    # 2024-01-15 14:30:00
export HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S "

# This creates entries like:
# #1705330200
# ls -la
```

### 2.8 Other Relevant Variables

```bash
# histchars - Characters for history expansion
histchars='!^#'   # Default: ! for expansion, ^ for quick sub, # for comment

# PROMPT_COMMAND - Runs before each prompt (can be used for history tricks)
PROMPT_COMMAND='history -a'  # Append after each command
```

---

## 3. Disabling History

### 3.1 Temporary Disable (Current Session)

```bash
# Method 1: Disable history recording
set +o history
# ... commands not recorded ...
set -o history

# Method 2: Unset HISTFILE
unset HISTFILE

# Method 3: Point to /dev/null
HISTFILE=/dev/null

# Method 4: Set sizes to 0
HISTSIZE=0
HISTFILESIZE=0
```

### 3.2 Permanent Disable (User-Level)

Add to `~/.bashrc`:

```bash
# Option 1: Unset everything
unset HISTFILE
unset HISTSIZE
unset HISTFILESIZE
set +o history

# Option 2: Redirect to null
export HISTFILE=/dev/null
export HISTSIZE=0
export HISTFILESIZE=0

# Option 3: Complete disable
HISTSIZE=0
HISTFILESIZE=0
shopt -u histappend
set +o history
```

### 3.3 System-Wide Disable

Add to `/etc/profile` or `/etc/bash.bashrc`:

```bash
# System-wide history disable
export HISTFILE=/dev/null
export HISTSIZE=0
export HISTFILESIZE=0
```

### 3.4 Selective Command Exclusion

```bash
# In ~/.bashrc
export HISTCONTROL=ignorespace

# Then prefix sensitive commands with space
 mysql -u root -pMyPassword
 export AWS_SECRET_KEY=xxx
 curl -u user:password https://api.example.com
```

### 3.5 Disable at Shell Invocation

```bash
# Start bash without history
bash --norc --noprofile
HISTFILE=/dev/null bash
bash -c 'unset HISTFILE; exec bash'

# Interactive shell without history
env -i TERM=$TERM HOME=$HOME bash --norc
```

---

## 4. Best Practices for History Protection

### 4.1 Secure Deletion Methods

#### Standard rm (INSECURE)

```bash
# Does NOT securely delete - data recoverable
rm ~/.bash_history
```

**Why rm is insufficient:**
- Only removes directory entry
- File blocks remain on disk
- Data recoverable with forensic tools
- Journaling filesystems may have copies

#### shred (Better)

```bash
# Basic shred
shred -u ~/.bash_history

# Comprehensive shred
shred -v -f -z -n 10 -u ~/.bash_history
# -v: verbose
# -f: force (change permissions if needed)
# -z: add final zero pass to hide shredding
# -n 10: 10 overwrite passes
# -u: unlink (delete) after

# Shred with specific size
shred -s $(stat -c%s ~/.bash_history) -u ~/.bash_history
```

**shred limitations:**
- Ineffective on journaling filesystems (ext3/4, XFS, etc.)
- Ineffective on copy-on-write filesystems (ZFS, Btrfs)
- Ineffective on SSDs with wear leveling
- Ineffective on RAID arrays
- May not work on network filesystems

#### wipe (Most Thorough for HDDs)

```bash
# Install wipe
apt install wipe  # Debian/Ubuntu
yum install wipe  # RHEL/CentOS

# Secure wipe
wipe -f -s -q ~/.bash_history
# -f: force
# -s: silent
# -q: quick mode

# Paranoid wipe
wipe -f -i -l2 -x4 -p4 ~/.bash_history
# -i: verbose
# -l2: level 2 (more thorough)
# -x4: 4 random passes
# -p4: 4 pattern passes
```

#### srm (Secure Remove)

```bash
# Simple secure delete
srm ~/.bash_history

# With options
srm -sz ~/.bash_history
# -s: simple mode (1 pass)
# -z: zero fill
```

#### dd Method

```bash
# Overwrite file with zeros
dd if=/dev/zero of=~/.bash_history bs=1 count=$(stat -c%s ~/.bash_history) conv=notrunc
sync
rm ~/.bash_history

# Overwrite with random data
dd if=/dev/urandom of=~/.bash_history bs=1 count=$(stat -c%s ~/.bash_history) conv=notrunc
sync
rm ~/.bash_history
```

### 4.2 Memory Considerations

```bash
# Clear bash's internal history
history -c          # Clear in-memory history
history -w          # Write empty history to file

# Proper sequence for memory cleanup
history -c && history -w

# Force memory pages to be cleared (requires root)
echo 3 > /proc/sys/vm/drop_caches

# Kill bash to prevent memory dump
# WARNING: This will terminate your session
kill -9 $$
```

### 4.3 Timing of Cleanup

#### Before Sensitive Operations

```bash
# Pre-operation cleanup
history -c
unset HISTFILE
set +o history

# Perform sensitive operations
sensitive_command

# If you want to re-enable
set -o history
HISTFILE=~/.bash_history
```

#### After Sensitive Operations

```bash
# Post-operation cleanup
history -d $(history 1 | awk '{print $1}')  # Delete last command
# OR
history -c && history -w  # Clear all
```

#### On Shell Exit

Add to `~/.bash_logout`:

```bash
# Secure cleanup on logout
history -c
shred -f -u -z ~/.bash_history 2>/dev/null
unset HISTFILE
```

### 4.4 Complete Cleanup Script

```bash
#!/bin/bash
# comprehensive-history-cleanup.sh

# Clear in-memory history
history -c

# Secure delete history files
for histfile in ~/.bash_history ~/.history ~/.sh_history; do
    if [ -f "$histfile" ]; then
        shred -f -z -n 3 -u "$histfile" 2>/dev/null
    fi
done

# Remove any backups
rm -f ~/.bash_history~ ~/.bash_history.bak ~/.bash_history.old 2>/dev/null

# Symlink to /dev/null to prevent recreation
ln -sf /dev/null ~/.bash_history

# Clear related files
> ~/.lesshst      # less history
> ~/.viminfo      # vim history
> ~/.python_history
> ~/.mysql_history
> ~/.psql_history
> ~/.sqlite_history
> ~/.node_repl_history

# Clear bash memory
unset HISTFILE HISTSIZE HISTFILESIZE
set +o history

# Notify
echo "History cleanup complete"
```

---

## 5. Forensic Recovery Techniques

### 5.1 Artifacts Surviving Standard Deletion (rm)

#### Filesystem Level Recovery

```bash
# ext3/ext4 journal recovery
debugfs /dev/sda1
# logdump -i <inode>

# Using extundelete
extundelete /dev/sda1 --restore-file /home/user/.bash_history

# Using photorec
photorec /dev/sda1

# Using testdisk
testdisk /dev/sda1

# Strings search on raw device
strings /dev/sda1 | grep -E "^(ls|cd|cat|rm|sudo)" > recovered_commands.txt
```

#### Memory Analysis

```bash
# Dump process memory (requires root)
gcore -o bash_dump $(pgrep -u $USER bash)

# Search memory dump
strings bash_dump.* | grep -E "^(ls|cd|cat|rm|sudo)"

# Volatility (for full memory dumps)
volatility -f memory.dump --profile=LinuxProfile linux_bash
```

### 5.2 Artifacts Surviving Secure Deletion

Even with secure deletion, artifacts may exist in:

1. **Filesystem Journal**
```bash
# Journal may contain file metadata and partial content
# ext4 journal location
dumpe2fs /dev/sda1 | grep -i journal

# XFS journal
xfs_logprint /dev/sda1
```

2. **Swap Space**
```bash
# Search swap for history
strings /dev/sda2 | grep -E "^[a-z]+\s" | head -100  # Assuming sda2 is swap

# Or swapfile
strings /swapfile | grep -E "bash_history|HISTFILE"
```

3. **Core Dumps**
```bash
# If bash crashed with history in memory
strings /var/crash/core.bash.* 2>/dev/null
strings /var/lib/systemd/coredump/* 2>/dev/null
```

4. **Terminal Scrollback**
```bash
# Terminal emulators may store scrollback
~/.local/share/konsole/
~/.config/xfce4/terminal/
# Screen/tmux scrollback buffers
```

5. **Backup Systems**
```bash
# Timeshift, rsync backups, etc.
/timeshift/snapshots/*/localhost/home/*/.bash_history
/.snapshots/*/snapshot/home/*/.bash_history  # Btrfs
```

### 5.3 Journaling Filesystem Considerations

| Filesystem | Journal Behavior | Deletion Recovery Difficulty |
|------------|------------------|------------------------------|
| ext2 | No journal | Low (easy recovery) |
| ext3 | Metadata journal | Medium |
| ext4 | Metadata + optional data journal | Medium-High |
| XFS | Metadata journal | Medium |
| ZFS | Copy-on-write | Very High (snapshots) |
| Btrfs | Copy-on-write | Very High (snapshots) |

#### ext4 with Full Journaling

```bash
# Check journal mode
tune2fs -l /dev/sda1 | grep "Filesystem features"

# data=journal mode journals file content too
# Recovery possible from journal

# Disable for sensitive operations (not recommended)
mount -o remount,data=writeback /mount/point
```

#### Btrfs/ZFS Snapshots

```bash
# Btrfs - check for snapshots
btrfs subvolume list /
btrfs subvolume snapshot list /

# ZFS - check for snapshots
zfs list -t snapshot

# These may contain old versions of history files!
```

### 5.4 Complete Forensic Recovery Checklist

Locations investigators will check:

```
[ ] ~/.bash_history (and .history, .sh_history, etc.)
[ ] /root/.bash_history
[ ] /home/*/.bash_history
[ ] /var/log/audit/audit.log (if auditd enabled)
[ ] /var/log/auth.log, /var/log/secure (sudo commands)
[ ] /var/account/pacct (process accounting)
[ ] Systemd journal (/var/log/journal/)
[ ] Filesystem slack space
[ ] Unallocated disk blocks
[ ] Swap space
[ ] Memory dumps/core files
[ ] Backup files (~/.bash_history~, .bak, .old)
[ ] Editor backup files (vim .swp, emacs ~)
[ ] Filesystem journal
[ ] ZFS/Btrfs snapshots
[ ] Network backup servers
[ ] Terminal emulator logs/scrollback
[ ] Screen/tmux session files
[ ] Cloud sync (Dropbox, etc.)
[ ] VM snapshots
[ ] SSD wear-leveling reserved blocks
```

---

## 6. Race Conditions and Timing

### 6.1 History Flush Race Condition

```bash
# Race condition: History is flushed on shell exit
# If you delete history THEN exit, the in-memory history overwrites

# WRONG (history gets written back):
rm ~/.bash_history
exit

# CORRECT (prevents write):
unset HISTFILE
rm ~/.bash_history
exit

# OR
history -c
unset HISTFILE
rm ~/.bash_history
exit
```

### 6.2 histappend Race Condition

```bash
# If histappend is set, multiple shells append on exit
shopt -s histappend

# Race condition: Shell A reads history, Shell B writes
# Solution: Immediate append
PROMPT_COMMAND='history -a'

# But this means every command is immediately written!
```

### 6.3 Multiple Shell Sessions

```bash
# Problem: Multiple shells = multiple in-memory histories
# Each will write on exit, potentially different content

# Check for other bash processes
pgrep -u $USER bash

# Each needs HISTFILE unset before their exit
# Or kill them all simultaneously
pkill -9 -u $USER bash  # WARNING: Terminates all your shells
```

### 6.4 Timing Attack on History Deletion

```bash
# Attacker can monitor for history file changes
inotifywait -m ~/.bash_history

# Defense: Delete and symlink atomically
HISTFILE=/dev/null
history -c
rm -f ~/.bash_history && ln -s /dev/null ~/.bash_history
```

### 6.5 SIGHUP vs SIGKILL Behavior

```bash
# Normal exit (history written)
exit
logout
# Shell receives SIGHUP, writes history

# Kill without history write
kill -9 $$  # SIGKILL - no history written
kill -9 $(pgrep -u $USER bash)

# But be aware: SIGKILL leaves memory state intact
# Memory can potentially be dumped
```

---

## Appendix A: Quick Reference Commands

### Disable History for Current Session
```bash
set +o history && unset HISTFILE
```

### Delete Last N Commands
```bash
for i in {1..5}; do history -d $(history 1 | awk '{print $1}'); done
```

### Secure Single-Session Shell
```bash
bash --norc --noprofile -c 'unset HISTFILE; exec bash --norc'
```

### Emergency Cleanup
```bash
history -c && unset HISTFILE && shred -u ~/.bash_history 2>/dev/null; kill -9 $$
```

### Check Current History Settings
```bash
echo "HISTFILE=$HISTFILE HISTSIZE=$HISTSIZE HISTFILESIZE=$HISTFILESIZE HISTCONTROL=$HISTCONTROL"
set -o | grep history
shopt | grep hist
```

---

## Appendix B: Defense-in-Depth Recommendations

1. **Layered approach**: Disable at shell level AND filesystem level
2. **Use encrypted filesystems**: LUKS, VeraCrypt for sensitive systems
3. **Consider full-disk encryption**: Protects against offline analysis
4. **Regular secure deletion**: Don't let history accumulate
5. **Audit your audit logs**: Know what's logging your commands
6. **Test your cleanup**: Verify deletion actually worked
7. **Consider RAM-based home**: tmpfs for truly ephemeral sessions
8. **Network considerations**: SSH sessions may be logged server-side

---

*Document Version: 1.0*
*Last Updated: 2024*
*For educational and authorized security testing purposes only*
