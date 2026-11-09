# Decoy requirements: making the base system amnesic

NAILS hides a session behind a decoy system by running it inside one overlay of
the whole decoy root, entered and left with `systemctl soft-reboot`, so the
hidden session's writes land on the hidden volume instead of the decoy disk.
That guarantee only holds if the decoy itself keeps **no durable record** of the
hidden session. The decoy runs before the soft-reboot into the hidden session
and again after the way back: a decoy that writes logs, audit records, crash
dumps or swap to its own disk records the activation command, its own shutdown
and start under one boot ID, and anything it imports from the kernel ring
buffer.

The decoy also has to be one the session can enter and leave:

- **systemd 254 or newer** with `soft-reboot.target` and
  `systemd-soft-reboot.service` installed (`systemd-version`,
  `soft-reboot-units`). Debian 13, Ubuntu 24.04, Ubuntu 26.04 and current
  NixOS qualify; Debian 12 and Ubuntu 22.04 are refused. On an older systemd
  `nails check` names how to upgrade the host the way its distribution
  documents it: Debian by its release notes, Ubuntu with `do-release-upgrade`,
  Fedora with `dnf system-upgrade`, Arch, EndeavourOS, CachyOS and Manjaro
  with a full `pacman -Syu`, and NixOS by moving the decoy's nixpkgs to a
  current release. Nobara, Ultramarine and a Debian derivative NAILS runs on
  are pointed at a release built on a tested one, upgraded as each documents.
  Any other host is shown the platforms NAILS supports.
  A later Debian or Ubuntu release runs with a warning that NAILS has not been
  tested on it (`platform`). A NixOS decoy on a nixpkgs that does not install
  the two units needs the module `nails check` prints (and so does a hidden
  NixOS configuration, or the session could not leave).
- **A decoy root on a block device** (`decoy-root`): ext4, xfs, btrfs (including
  a subvolume) or f2fs. The way back mounts it again by device, so a tmpfs root
  (impermanence), an overlay root (overlayroot, bilibop-lockfs) and ZFS are
  refused.
- **The tools NAILS runs** (`host-tools`): `systemctl` and `loginctl`
  (systemd), `ip` (iproute2), `dmsetup` when the hidden volume is on
  device-mapper (dm-crypt, LUKS or a VeraCrypt mapping) or its backend cannot be
  read, and on NixOS `nix`. The way back deletes the links a session made and
  sets hardware addresses back with `ip`, and closes the hidden volume's mapping
  with `dmsetup`. Without them it would leave both behind, so activation is
  refused while one is missing; `nails check` names it and the package that
  provides it.
- **The tools the way back runs where they are installed**
  (`network-tools`): `nft` (nftables), with which activation lists the
  decoy's own firewall tables and the way back deletes the ones a session
  added, and, on a machine with a Wi-Fi interface, `iw`, with which the way
  back deletes a Wi-Fi interface a session added on one of the decoy's radios
  (a monitor or access point interface, or the one iwd makes in place of the
  decoy's). Without `nft` every nftables table a session adds stays on the
  decoy until power-off: root lists it with `nft list tables`, a table's name
  can name the VPN that made it, and a VPN app's table that blocks all traffic
  outside its tunnel keeps the decoy offline. Without `iw` such a Wi-Fi
  interface makes the way back power off instead of returning, as does every
  link, MAC address, policy-routing rule or nftables table it sets out to undo
  that is still the session's afterwards (the network settings and the
  hostname do not count). A decoy that runs iwd needs `iw`: a session that
  runs iwd as well ends in a power-off without it, as iwd makes its own
  interface in place of the decoy's by default when it starts.
  `nails check` and activation warn and name the package to install; they do
  not refuse, since a stock NixOS decoy has no `nft`. NAILS looks for both
  where the way back does, never in `PATH`: in `/run/current-system/sw/bin`
  (on NixOS, the decoy's system), `/usr/bin`, `/bin`, `/usr/sbin` and
  `/sbin`.
- **SELinux labels on the hidden volume**, where the host may run SELinux:
  where the mount table (`/proc/self/mounts`) lists a selinuxfs, where it
  cannot be read while `/sys/fs/selinux` exists or `/etc/selinux/config` sets
  `SELINUX=` or `SELINUXTYPE=`, and where NAILS cannot detect the host. A policy sees a directory without a
  label as `unlabeled_t`, which confined services may not even look up. So at
  every activation NAILS copies onto these directories on the hidden volume
  the SELinux label of the decoy directory each stands for: the root of each
  upper, which becomes the hidden `/` or the root of a decoy filesystem the
  session overlays (a separate `/home`, say), and each directory the upper
  holds below it on the way to your home, the whole way in the `fresh-home`
  persona, which makes your home there. It reads the decoy's labels without
  changing anything on the decoy, not even an access time, and writes each one
  before the overlay over that upper is mounted. It copies no label onto any
  other directory it makes on the hidden volume (see the
  [threat model](threat-model.md#what-the-hidden-environment-shares-with-the-decoy)).
  A label it cannot copy refuses the activation, which is undone. So on such a
  host:
  - the hidden volume's filesystem must store `security.selinux` attributes,
    as ext4, xfs and btrfs do, and the policy must let NAILS write them there.
    A `context=` mount option lets NAILS write none, since it gives every file
    of the mount one label, so mount the hidden volume without that option;
  - the decoy's `/` and the root of each decoy filesystem the session
    overlays must carry labels;
  - whatever the upper holds on the way to your home must be a directory,
    not a link or a file, and its counterpart on the decoy must exist and
    carry a label. In the `fresh-home` persona your account therefore needs a
    home on the decoy. In the `shared-home` persona the same holds for a home
    of yours that the upper holds and the decoy lacks, such as one a refused
    `fresh-home` activation leaves behind or a hidden session makes: every
    activation you run is refused until the decoy has that home or it is
    removed from the upper (the refusal names its path there).

  Elsewhere a label is copied only where the decoy has one, so a decoy
  without labels gets the hidden root it got before. That includes a host
  whose mount table lists no selinuxfs while it keeps an empty
  `/sys/fs/selinux`, or an `/etc/selinux/config` that sets `SELINUX=` or
  `SELINUXTYPE=` as SELinux packages installed once leave it: no selinuxfs
  shows a policy there. Of these hosts, the `lsm-status` check lets only one
  whose kernel does not run SELinux go on, such as one that keeps the
  configuration of packages installed once, and there the activation says in
  one line that SELinux is configured but selinuxfs is not mounted. A kernel
  makes `/sys/fs/selinux` only where it started SELinux at boot, so where an
  empty one is left SELinux runs in the kernel, and `lsm-status` refuses the
  host (see [Fail closed](#fail-closed-activation-is-refused)).
  `nails check` tests part of this with the same rule
  (`upper-fs-capability`): it copies the label of the decoy's `/` onto the
  upper of its trial overlay on the hidden volume and, where the labels are
  required, reads it back, so a hidden filesystem that cannot store the
  label, a policy that denies the relabel and a decoy `/` without a label
  fail the check as they refuse the activation. The roots of the other decoy
  filesystems the session overlays and the way to your home are not tested
  before activation.

This document lists what an amnesic decoy must look like, what NAILS enforces at
pre-flight, and how to satisfy each requirement on the supported platforms. The
[residue catalog](#residue-catalog) at the end lists every class of trace in one
place, with the check that warns about it, the check that detects it and the VM
test that asserts it.

## What NAILS enforces

The `decoy-persistence` pre-flight check inspects the decoy before any state is
written. It performs **no writes** — it never rotates or vacuums the decoy's own
logs, because destroying the decoy's log history is itself a deniability tell.

### Fail closed (activation is refused)

<!-- residue-catalog:begin fail-closed -->
| Finding | Why it matters |
|---|---|
| [Persistent systemd journal](#fail-closed-activation-is-refused) | The decoy journal records the sudo command line (including the hidden-root binary path) before the soft-reboot, and the decoy's own shutdown and start around each transition. |
| [Classic syslog daemon](#fail-closed-activation-is-refused) | A syslog daemon (rsyslog, syslog-ng, a syslogd, metalog or socklog) writes every logged line to /var/log on the decoy disk, outside the journal. |
| [Audit daemon log](#fail-closed-activation-is-refused) | auditd records executed commands and file access in /var/log/audit, independent of journald. An enabled auditd that does not run starts again when the decoy starts after the way back, unless its unit is masked or the kernel command line keeps it from starting (audit=0). |
| [Armed kdump](#fail-closed-activation-is-refused) | If the kernel crashes during a hidden session, kdump's crash kernel mounts the decoy root by its device, outside the session's overlay, and writes a dump of kernel memory (which can hold the hidden volume's key) and the session's kernel log to /var/crash on the decoy disk. |
| [unattended-upgrades set to install at shutdown](#unattended-upgrades) | With Unattended-Upgrade::InstallOnShutdown on, unattended-upgrades' shutdown helper takes a switch through logind for a shutdown: at activation it installs the pending updates on the decoy disk and logs that run there, so the decoy keeps the record of a shutdown at the time of the switch, and its packages change. At the way back with nails deactivate the hidden session's own copy installs them into the session's overlay. |
| [tuned's log file](#tuned-firewalld-and-abrt) | tuned started with its log option, -l, which Fedora's tuned.service passes, or with -d, writes its log to /var/log/tuned on the decoy disk: it logs when it stops for the switch and when it starts again after the way back, each line with the time, so the decoy keeps both times, as a syslog daemon's log would. tuned-ppd with -l, which Fedora's tuned-ppd.service passes, logs there the power profiles it sets and the holds it releases, around a switch too. Without them both log to their standard error, which a unit or a hand start can send to a file as well, and a unit to a journal namespace that the decoy keeps on its disk. |
<!-- residue-catalog:end fail-closed -->

Override these per run with `--allow-persistent-decoy` on `activate`/`check`,
only if you understand and
accept that what the decoy logs around each soft-reboot may survive on the
decoy disk, that tuned logs its stop and start around each switch there, that
a kernel crash during the session can leave a dump of its memory there, and
that unattended-upgrades set to install at shutdown installs the pending
updates on the decoy disk at activation and logs that run there (see
[tuned, firewalld and ABRT](#tuned-firewalld-and-abrt) and
[Unattended upgrades](#unattended-upgrades)).

auditd counts while it runs, as a unit or a process, and also while its unit
is enabled although it does not run, since the service manager starts it again
when the decoy starts after the way back, and while a timer, path or socket
unit that is enabled or active starts it, which can start it then too: the
refusal names that unit. Such an auditd does not count
where the manager cannot start it: where its unit is masked in any unit
directory (`systemctl mask --runtime` masks it in `/run`, which the way back
keeps), where no unit file is left, or where a `ConditionKernelCommandLine=`
of its unit fails on the kernel's command line, which a soft-reboot keeps:
every audit package NAILS knows ships `!audit=0` and `!audit=off` there, so a
kernel booted with `audit=0` starts no auditd. Its unit refuses a plain
`systemctl stop` on Fedora and Arch (`RefuseManualStop=yes`, as upstream ships
it, which the Fedora 44 and Arch probes record), so there `systemctl stop` and
`systemctl disable --now` leave it running. Turn it off for good, without a
reboot, the same way on Debian, Ubuntu, Fedora and Arch:

```bash
sudo systemctl disable auditd.service
sudo systemctl mask auditd.service
sudo auditctl --signal stop
```

`auditctl --signal stop` asks the daemon itself to stop (audit 3.1.1 and newer,
which every supported release ships). On NixOS set `security.auditd.enable =
false` in the decoy configuration, run `sudo auditctl --signal stop` while
`auditctl` is still installed, and rebuild.

The `unattended-upgrade-run` check refuses too, and no flag lifts its refusal:
while a daily unattended-upgrade run is in progress, the switch would make
unattended-upgrades' shutdown helper stop it and write
`Unattended-upgrade in progress during shutdown` to its log on the decoy disk,
and while `apt-daily.service` runs before its download takes the lock, the
helper does the same if the download run takes the lock between NAILS's last
look and the helper's first. Try again in a few minutes, once the run has
ended (see [Unattended upgrades](#unattended-upgrades)).

The `locate-database` check refuses as well, and no flag lifts its refusal:
an updatedb that runs now, or that a timer, a path unit, an enabled service or
a cron job it reads starts, and that does not skip the hidden volume would
write the name of every file on the volume into the decoy's locate database
(see [The locate database](#the-locate-database), which also names what it
does not read).

The `hidden-volume` check refuses too, and no flag lifts that refusal either,
while the hidden volume's filesystem is mounted at another place in the
decoy's mount table as well, as a desktop that mounts drives by itself can
mount it once the volume is unlocked (see
[Attaching the drive](#attaching-the-drive), which also says what the check
leaves out).

The `lsm-status` check names the Linux Security Modules the kernel runs, from
`/sys/kernel/security/lsm`, and judges SELinux where it runs; no flag lifts its
refusals. A host where SELinux does not run passes: AppArmor, Landlock and
Yama change nothing it judges. Where SELinux runs, the check reads the mode
from `/sys/fs/selinux/enforce`, `SELINUX=` and `SELINUXTYPE=` from
`/etc/selinux/config` the way libselinux reads them, when that file last
changed, and the SELinux context of the `nails` process from
`/proc/self/attr/current`, and it refuses:

- an `/etc/selinux/config` that names a policy other than `targeted`, as
  untested. The name is compared in its case, since it names the directory
  the policy is loaded from. The kernel does not know that name, so a file
  that names `targeted` but changed after the boot (its change time, to the
  second, is not before the boot time in `/proc/stat`) is refused too, as is
  one that is a symbolic link or whose change time or the boot time cannot
  be read: SELinux may run another policy than the one it names. A reboot
  loads the one it names;
- a context without a level, or whose level has a sensitivity other than
  `s0`, whatever the file names: every context of Fedora's targeted policy
  has a level, and `s0` is its one sensitivity. A multi-level (MLS) policy
  gives others;
- a host whose kernel runs SELinux without a policy: the `nails` process is
  labelled `kernel`, as every process is until a policy is loaded.
  `SELINUX=disabled` leaves such a host where the kernel started SELinux at
  boot, since a running kernel cannot turn SELinux off (Linux 6.4 and later):
  no policy is loaded, selinuxfs is unmounted and an empty `/sys/fs/selinux`
  is left. NAILS is untested there. The check says to start the kernel with
  `selinux=0` on its command line;
- a `nails` process in a domain other than `unconfined_t`, which a login
  whose SELinux user is `unconfined_u` runs in and `sudo` keeps, or
  `unconfined_service_t`;
- a fact among these that cannot be read;
- for now, every host where SELinux runs: NAILS does not yet choose the
  SELinux domain of the processes systemd starts from its copy in `/run`
  (the transition step at each switch, the watcher and the sleep guard of
  the hidden session, and the boot-record steps after the way back), nor
  that of the hidden session's disk guard, which udev runs itself from the
  rule NAILS installs there, so nothing shows that they run unconfined. The
  check judges the two apart: what NAILS sets on systemd's side does not
  reach what udev runs.

Where it refuses nothing, it warns when SELinux is permissive, or runs in
another mode than `/etc/selinux/config` sets. Where the kernel's list of
active modules cannot be read, a mounted selinuxfs or an SELinux context of
the `nails` process means SELinux runs. Without either, `/sys/fs/selinux` or
an `/etc/selinux/config` that sets a mode or names a policy is refused
without deciding: a kernel makes `/sys/fs/selinux` only where it started
SELinux at boot, but a mount over `/sys` can hide it too, so the check does
not rule SELinux out because it is missing.

kdump counts as armed when `/sys/kernel/kexec_crash_loaded` reads `1` (a crash
kernel is loaded), or when `kdump-tools.service` (Ubuntu, Debian) or
`kdump.service` (Fedora) is enabled or active. The soft-reboot into the hidden
session starts the decoy's enabled units, so an enabled unit that was stopped
before activation, with no crash kernel loaded, starts again there and loads
it. An active unit counts too, because the check cannot tell whether it is
still loading the crash kernel. A unit is enabled when a link to it sits in a
`.wants`, `.requires` or `.upholds` directory of any directory the service
manager loads units from (`/etc/systemd/system.control`,
`/run/systemd/system.control`, `/run/systemd/transient`, the generator
directories, `/etc/systemd/system`, `/run/systemd/system`, their `.attached`
siblings, `/usr/local/lib/systemd/system`, `/usr/lib/systemd/system` and
`/lib/systemd/system`), or when a `systemd.wants=` on the kernel command line
names it, for which systemd-debug-generator links it again each time the
service manager starts, unless a link to `/dev/null` in `/etc/systemd/system`
masks it. If the
kernel crashes during a hidden session, the crash kernel mounts the decoy root
by its device, outside the session's overlay, and writes a dump of kernel
memory, which can hold the hidden volume's encryption key and the names of the
files the session used, and the session's kernel log to `/var/crash` on the
decoy disk. Ubuntu arms kdump-tools by default from 24.10, so 26.04 among them.
Disarm it on the decoy with `sudo systemctl disable --now kdump-tools`
(Fedora: `sudo systemctl disable --now kdump`). When `kexec_crash_loaded`
cannot be looked up or read, or holds anything but `0` or `1`, NAILS cannot
tell and refuses as if kdump were armed, and so it does when it cannot tell
whether one of the units is enabled or active, because a lookup that would
show it fails or would mount an automount point that nothing is mounted on
yet, or the mount table, which shows where such a point is, cannot be read.
A kernel without that file has no crash kernel support, so nothing can
be loaded. `nails status` shows an armed kdump on the decoy, and one NAILS
cannot tell about with the reason (`decoy_kdump_armed` in `--json` is true
for both).

NAILS reads journald's `Storage=` the way journald does. The main
`journald.conf` and every `journald.conf.d/*.conf` drop-in come first. From
systemd 256 the main file is the first one in `/etc`, `/run`, `/usr/local/lib`
or `/usr/lib/systemd`, while earlier releases read `/etc/systemd/journald.conf`
alone, and NAILS looks where the running release looks; when it cannot read
the release, a main file outside `/etc` that changes the result counts as
persistent. systemd stops reading these files at the first line that is not
valid UTF-8, unless
it is a comment, so a setting below that line or in a later drop-in counts for
nothing. Keep these files in UTF-8. When no file sets `Storage=`, the
`journal.storage` credential decides, from systemd 256 on. journald accepts
only the exact bytes, so write it with `printf volatile`, not `echo volatile`,
which adds a newline. Failing both, the built-in default applies: `auto` below
systemd 259, which persists when `/var/log/journal` exists on disk, and from
259 `persistent`, or the default the distribution's own
`/usr/lib/systemd/journald.conf` documents. A systemd whose version cannot be
read counts as persistent. Where `auto` decides and NAILS cannot look up
`/var/log/journal` for another reason than that it is not there (no
permission, an I/O error, an automount point on the way that nothing is
mounted on yet), the journal counts as persistent too.

Keep every main file and drop-in a regular file. systemd lists a drop-in by
its name alone, so a directory or a link to `/dev/null` with a drop-in's name
shadows the drop-in of that name below it, and the systemd releases do not read
such an entry alike: from systemd 260 a directory or a device there leaves the
whole configuration unread, the main file included. NAILS counts such a
configuration, one with a file it cannot read or look up, and one with a
drop-in directory it may not list or that lies behind an automount point that
nothing is mounted on yet, as persistent whatever release runs, and names the
entry: journald reads these files when it starts,
and an update can bring 260 before it next does, at the latest when the decoy
starts again after the way back. To mask a vendor
drop-in, put an empty file of its name in `/etc/systemd/journald.conf.d/`. The
same goes for logind's and systemd-coredump's configuration: `sleep-policy`
then warns that the host may suspend an active session, and
`decoy-persistence` that core dumps may reach the disk.

NAILS reads the credential from the copy journald received, in
`/run/credentials/systemd-journald.service/`, which only root can read. An
unprivileged `nails check` or `nails status` cannot read it, so there the
built-in default decides, and a journal that only the credential makes
volatile can count as persistent. Run them with sudo.

### Warn (surfaced, never blocking)

- **atime policy** — a root mounted without `noatime`/`relatime` records read
  access, leaving an atime trail on the decoy.
- **Crash-dump channels** — a disk `kernel.core_pattern`, one that hands core
  dumps to a handler other than systemd-coredump (by a pipe, `|program`, or
  the kernel's coredump socket, `@socket`), systemd-coredump with
  any setting other than `Storage=none` together with `ProcessSizeMax=0`, or
  registered pstore records. Each can persist process or
  kernel memory (which may contain hidden-session data) to the decoy disk or
  firmware-backed storage. NAILS does not judge what another handler keeps:
  Ubuntu's apport, which Ubuntu's images run, logs the path and the command
  line of each crashing program to `/var/log/apport.log`. Only the kernel
  default, `core`, which writes into the crashing program's working directory
  as far as its core limit lets it, an empty pattern and a pipe to a program
  that only discards the dumps, `/bin/false` or `/bin/true` (or the same in
  `/usr/bin`), pass without a warning; stopping apport
  (`sudo systemctl disable --now apport.service`) sets the pattern back to
  `core`. `kernel.core_pattern=|/bin/false`, which Kicksecure sets, keeps no
  core and no record of the crash: it keeps core dumps off the decoy disk
  without systemd-coredump. systemd-coredump writes every core it
  processes to `/var/lib/systemd/coredump` first, so `Storage=none` alone
  still puts each one on the decoy disk for as long as it takes;
  `ProcessSizeMax=0` stops the processing, and with both set it only logs that
  a program crashed. Keep systemd-coredump running with those two settings
  rather than turning it off: without it, and without a pattern that discards
  the dumps, the kernel writes a `core` file into the crashing program's
  working directory. A unit that systemd-coredump
  starts for each crash warns too, whatever those settings say: it can read
  the crash from the journal. That is one `systemd-coredump@.service` names
  in `OnSuccess=` or `OnFailure=`, a service it names in `Wants=`,
  `Requires=`, `BindsTo=` or `Upholds=`, or one linked into its `.wants`,
  `.requires` or `.upholds` directories, as KDE's DrKonqi links its
  `drkonqi-coredump-processor@.service`. Ubuntu's apport package adds one,
  `apport-coredump-hook@.service`, which runs where systemd-coredump takes the
  crashes: it logs the path and the command line of each crashing program to
  `/var/log/apport.log`, with the time, and, for a program a package
  installed, writes a report of the crash to `/var/crash`, whether
  `apport.service` runs or not; mask it
  (`sudo systemctl mask apport-coredump-hook@.service`). An `apport.service`
  that is stopped but still enabled warns as well, while the pattern does not
  name apport: it sets the pattern to its pipe again when the decoy starts
  after the way back. So does a pattern that a `sysctl.d` file sets, which
  systemd-sysctl applies again then, where it differs from the pattern in
  force now. An armed kdump, which reaches past the session entirely, is
  refused (see above).
- **Maintenance timers** (NixOS) — `nixos-upgrade.timer`, which rebuilds the
  decoy on its own schedule (and can touch EFI NVRAM). The generated hidden
  module force-disables `system.autoUpgrade`, but with `--overlay-only`, or
  with a hidden flake that does not import that module, the decoy's own timer
  runs in the hidden session.
- **sudo's own logs** — `Defaults logfile=` in `/etc/sudoers` or
  `/etc/sudoers.d/*` writes every sudo command line to a file, and I/O logging
  (`log_input`, `log_output`, the `log_stdin`/`log_ttyout`/... flags, or the
  `LOG_INPUT:`/`LOG_OUTPUT:` command tags, stored under `iolog_dir`) records
  whole terminal sessions, keystrokes and output included. Both write to the
  decoy disk, outside the journal. A sudoers file behind an automount point
  that nothing is mounted on yet is not read, and the check names the point.
- **sssd** — sssd in use on the decoy: one of its units or daemons running,
  its Kerberos ticket cache listening on its socket, or one of nine state
  files it writes under `/var/lib/sss`. Where NAILS cannot look up a place
  that would show it, it warns that it cannot tell whether sssd is in use,
  and names the place. NAILS is not tested on a decoy joined
  to a domain, whose domain controller records the hidden session's logins;
  see [Decoys joined to a domain](#decoys-joined-to-a-domain).
- **unattended-upgrades in a hidden session** — the hidden session's own copy
  of unattended-upgrades' shutdown helper set to install at shutdown: the
  decoy's helper is stopped while the decoy or the session's overlay enables
  it and nothing masks it as the session sees it, so the session starts it,
  or the session's overlay turns the setting on. At the way back it installs
  the pending updates into the session's overlay on the hidden volume. It
  warns too where NAILS cannot tell what the session reads, as for a link
  among apt's files; see [Unattended upgrades](#unattended-upgrades).
- **unattended-upgrades without python3-gi** — the decoy's shutdown helper
  enabled while python3-gi is missing: each time it starts it writes two
  WARNING lines to its log on the decoy disk, so every way back adds a pair
  dated at the switch (`apt install python3-gi`); see
  [Unattended upgrades](#unattended-upgrades).
- **firewalld logging to a file** — firewalld's default log target appends its
  warnings and errors to `/var/log/firewalld`, so what it logs when it stops
  or starts around a switch stays on the decoy disk with the time; see
  [tuned, firewalld and ABRT](#tuned-firewalld-and-abrt).
- **ABRT** — ABRT in use on the decoy keeps crash reports in
  `/var/spool/abrt`; see [tuned, firewalld and ABRT](#tuned-firewalld-and-abrt).

The `residue-catalog` pre-flight check adds the channels the catalog probes by
path: a populated LVM metadata archive, udisks2 state, and the session-time
stamps described below. It warns or notes them and never blocks. A probe path
it cannot look up for another reason than that it is not there, one behind an
automount point that nothing is mounted on yet among them, is one it cannot
tell about: it warns for it, also where it would only note what it finds
there.

The `decoy-nix-trace` check warns when a decoy that is not NixOS holds what a
Nix install leaves behind, and never blocks either (see
[Nix on the decoy](#nix-on-the-decoy)).

### tuned, firewalld and ABRT

These daemons write to the decoy disk as their own settings say, so
`decoy-persistence` reads how each starts: its unit file with every drop-in,
as the service manager loads them, those of the unit's aliases included (the
links `systemctl enable` makes from `Alias=`, as
`dbus-org.fedoraproject.FirewallD1.service` for firewalld), and the commands
of its `ExecStart=`, split as systemd splits them, with the variables the unit
sets itself (`Environment=`, and the files `EnvironmentFile=` names, read as
systemd reads them). It reads the program's own options as the program does.
Where a daemon logs to its standard output or standard error, the unit's
`StandardOutput=` and `StandardError=` say where that goes, as systemd reads
them: `journal`, `syslog` and `kmsg`, alone or with `+console`, send the
stream to the journal, and `tty` to the terminal `TTYPath=` names,
`/dev/console` unless it names one. A standard output left to `inherit` or
not set takes the service manager's default, which NAILS takes for the
journal, systemd's own default, wherever `StandardInput=` is not a terminal,
`socket` or a named descriptor (`fd:`); after a terminal input it goes to
that terminal. Where it is the journal, or the daemon logs to syslog, the journal
namespace its unit sets with `LogNamespace=` decides, or, for a running
daemon, the one its mount table shows: that namespace's journald instance
reads `journald@<namespace>.conf` and its drop-ins, never `journald.conf`,
and keeps the journal on the decoy disk, in
`/var/log/journal/<machine-id>.<namespace>`, unless they set another
`Storage=`, so a namespace that persists counts as a log file, however
volatile the decoy's own journal is. A program can also connect a running
daemon's stream to a namespace's socket itself, as `systemd-cat
--namespace=` does, with no mount that shows it, so a socket on that stream
counts as NAILS cannot tell while PID 1's socket table lists a socket of a
namespace that persists (see below). To keep a namespace's journal off the
disk, set `Storage=volatile` in the `[Journal]` section of
`/etc/systemd/journald@<namespace>.conf`, then run
`sudo systemctl restart systemd-journald@<namespace>.service`, or drop the
unit's `LogNamespace=`, then run `sudo systemctl daemon-reload` and restart
the unit. On NixOS set the file through
`environment.etc."systemd/journald@<namespace>.conf".text`, or drop
`LogNamespace` from the unit's `serviceConfig`, in the decoy configuration,
then run `sudo nixos-rebuild switch` and
`sudo systemctl restart systemd-journald@<namespace>.service`. What the
namespace kept before stays in `/var/log/journal/<machine-id>.<namespace>`.
Where NAILS cannot tell whether a namespace keeps its journal on the disk,
the refusal and the warning give that namespace's fix as well, and where a
unit names its namespace with a specifier, which NAILS does not expand, they
say to name it without one or drop it. NAILS does not judge the namespaces
of other units for what those units log. A unit counts when the service manager
can start it: it is enabled (a link in a `.wants`, `.requires` or `.upholds`
directory of any directory the service manager loads units from, or a
`systemd.wants=` on the kernel command line, as for kdump above) or active, or
a timer, path or socket unit that is enabled or active starts it, and it is not
masked. A timer or a path starts the first `Unit=` systemd takes, a socket its
last `Service=`, and either, without one, the service of its own name. In those
values NAILS expands the specifiers systemd takes from the trigger's own name,
`%n`, `%N`, `%p`, `%i` and `%j`, and `%%`, with the name of the trigger's unit
file, as systemd expands them for a trigger it loads by that name, so Arch's
`gpg-agent-ssh@etc-pacman.d-gnupg.socket` starts
`gpg-agent@etc-pacman.d-gnupg.service`. systemd expands a unit file's own
values with the name it first loads the trigger under, so for a trigger enabled
through a link named after one of its aliases, `%n`, `%N`, `%p` and `%j` come
from that alias, which NAILS does not follow; no stock unit is enabled that
way. systemd ignores a value with `%P`, `%I`, `%J`, `%f` or another letter it
does not expand there, and so does NAILS. A value with a specifier systemd
fills in from the host, such as `%H` or `%m`, counts as a trigger that may
start each daemon whose unit name the rest of the value fits, and what it would
start without that value, which NAILS cannot tell about. A process counts as it
runs, by its name (`comm`), or, run through its interpreter as in
`python3 /usr/sbin/tuned`, by the script Python runs, its options read from its
command line, so a daemon started by hand, or one still running with the
options its unit had before a change, is seen as well. NixOS's wrapper runs
tuned as `.tuned-wrapped`, which counts as tuned. Fedora 44 enables all three
by preset wherever their packages are installed; the Cloud image the Fedora 44
probe boots has none of them.

- **tuned** refuses activation, as a syslog daemon does, and
  `--allow-persistent-decoy` turns that into a warning for one run. tuned
  started with its log option, `-l` (`--log`), or with `-d`, writes its log to
  `/var/log/tuned/tuned.log`, or to the file the option names: it logs when it
  stops for the switch and when it starts again after the way back, each line
  with the time, so the decoy disk keeps both times. Fedora's `tuned.service`
  runs `/usr/sbin/tuned -l -P`. tuned-ppd, which serves the power profiles of
  desktops through tuned, writes its log with `-l` to
  `/var/log/tuned/tuned-ppd.log`, and Fedora's `tuned-ppd.service` passes it:
  not a line at each stop and start, but the power profiles it sets and the
  holds it adds or releases, around a switch too, each with the time.
  Without `-l` and `-d` both log every line to their standard error, which
  counts as a log file where it leads to one: where the unit's
  `StandardError=` names a file (`file:`, `append:`, `truncate:`), or, left
  to systemd's default, `inherit`, where `StandardOutput=` does, for one
  unit or, through `service.d`, for every service; or where a running
  process has a file as its standard error, as one started by hand with
  `2>file` or `nohup` has. Only root may follow another user's descriptors,
  so an unprivileged `nails check` cannot tell where a running tuned's
  standard error goes and refuses: run it with sudo. tuned also counts when
  it is neither enabled nor active but tuned-ppd is installed and not masked:
  D-Bus starts tuned-ppd whenever a program asks for power profiles, and its
  unit needs tuned's. So `systemctl disable` is not enough while tuned-ppd is
  installed. Make tuned log to the journal with a drop-in for each unit, then
  restart them:

  ```ini
  # /etc/systemd/system/tuned.service.d/50-journal.conf
  [Service]
  ExecStart=
  ExecStart=/usr/sbin/tuned -P
  StandardError=journal
  ```

  ```ini
  # /etc/systemd/system/tuned-ppd.service.d/50-journal.conf
  [Service]
  ExecStart=
  ExecStart=/usr/sbin/tuned-ppd
  StandardError=journal
  ```

  ```bash
  sudo systemctl daemon-reload
  sudo systemctl restart tuned.service tuned-ppd.service
  ```

  Or mask both (`sudo systemctl mask --now tuned.service tuned-ppd.service`),
  which takes the power profiles from the desktop. Any log file counts, one in
  a RAM filesystem included. The log stops growing, but what tuned logged
  before stays in `/var/log/tuned`. tuned also rewrites its state files in
  `/etc/tuned` each time it starts, as other daemons rewrite theirs, which
  these settings do not change. On NixOS disable `services.tuned`, or clear
  `systemd.services.tuned`'s `ExecStart=` (and `tuned-ppd`'s) in the decoy
  configuration and set it again without `-l`, with `StandardError=` set to
  `journal`.
- **firewalld** warns. With its default log target, `mixed`, it appends its
  warnings and errors to `/var/log/firewalld`, and every message it logs with
  `--debug`; the target `file` appends every message it logs there,
  `--log-file` names another file, `syslog` sends them to the journal, and
  `console` writes them to its standard output, which Fedora's and Debian's
  units send to `/dev/null`. Fedora's unit runs
  `/usr/bin/firewalld --nofork --nopid $FIREWALLD_ARGS` and reads
  `FIREWALLD_ARGS` from `/etc/sysconfig/firewalld`. Make it log to the journal
  there:

  ```bash
  # /etc/sysconfig/firewalld
  FIREWALLD_ARGS=--log-target=syslog
  ```

  then `sudo systemctl restart firewalld.service`. Debian's unit runs
  `/usr/sbin/firewalld --nofork --nopid` and reads no such variable: clear
  `ExecStart=` in a drop-in and set it again with `--log-target=syslog`, then
  restart it.
  On NixOS set `services.firewalld.extraArgs = [ "--log-target=syslog" ];`,
  from which the configuration writes `/etc/sysconfig/firewalld`, rebuild, then
  restart it. NAILS takes `mixed`, the default of firewalld's upstream build
  and of Fedora's, unless the command line says otherwise, and cannot tell, so
  it warns, where the unit names a variable it does not set itself.
- **ABRT** warns while it is in use: `abrtd.service`, which every other ABRT
  unit needs, is enabled or active and runs `abrtd`, or an `abrtd` process
  runs. ABRT keeps crash reports in its dump location, `/var/spool/abrt`
  unless `DumpLocation` in `/etc/abrt/abrt.conf` names another, made from the
  core dumps systemd-coredump keeps of the programs packages install (it drops
  those of other programs, NAILS's own among them, unless `ProcessUnpackaged`
  is on), from the kernel oops messages in the journal and, each time it
  starts, from the crash records pstore holds, a kernel crash of the hidden
  session among them. So a crash on the decoy around a switch, dated then, or
  such a crash record lands there. Turn it off with
  `sudo systemctl disable --now abrtd.service`.

What NAILS cannot read of these, a unit file or drop-in directory it cannot
read, a command or option it does not follow, a program that runs the daemon in
turn (as `logsave` or `script` does, which can copy what it logs into a file of
their own), a variable the unit does not set, a standard stream it cannot
follow (a pipe, a pseudo-terminal, or a descriptor a socket unit passes, among
them), a journal namespace whose configuration it cannot read, a drop-in name
that two aliases of a unit hold in files that give the unit's section
differently, where the name of its unit file holds no drop-in of that name
(systemd reads the drop-ins of the unit file's name first, so one of those
shadows one of an alias, but takes the aliases in an order of its own), counts
against the decoy: tuned is refused as if it logged to a file, and firewalld
and ABRT warn. A timer, path or socket unit counts for a daemon only where what
it starts is the daemon's own unit name: one whose `Unit=` or `Service=` names
the daemon by an alias, as firewalld's
`dbus-org.fedoraproject.FirewallD1.service` or an `Alias=` link of auditd or
tuned, is not counted. A log to a device that keeps nothing it is given, as
`/dev/null`, the console, a virtual console (`/dev/tty<n>`) or a serial line
(`/dev/ttyS<n>`), is no file. A pseudo-terminal (`/dev/pts/<n>`), or the
controlling terminal (`/dev/tty`), which may be one, counts as a pipe does: the
program that holds its other side may copy all it shows into a file, as
`script` does into its typescript, `screen -L` into its log or `tmux pipe-pane`
into a command. Another device NAILS does not judge counts so too. Whether a
unit is enabled or active NAILS reads from the links and markers systemd
leaves, without following them, and from the kernel command line. Of the
`SystemdOptions` EFI variable it reads only the copy the service manager made
under `/run/systemd/efivars` when it last started, so a `systemd.wants=` that
`bootctl systemd-efi-options` adds to the variable later is missed, though on
systemd 255 to 257, booted by UEFI without Secure Boot, the way back reads the
variable again and starts that unit. A unit whose link or marker NAILS cannot
look up, as an unprivileged `nails check` cannot in a directory only root may
look into, counts as one that starts, wherever its commands would make the
daemon log to a file or NAILS cannot tell whether they would; a unit directory
NAILS cannot list at all hides the links in it. A socket on a running daemon's
standard output or standard error counts as one to the decoy's own journal,
which the journal's own check judges, where PID 1's socket table,
`/proc/1/net/unix`, lists it as a connected local stream socket bound to no
path, as the service manager connects one to the journal, and lists no socket
of a journal namespace that persists, or whose configuration NAILS cannot read.
While it lists one, the socket counts as NAILS cannot tell, and the fix is that
namespace's. A namespace's journald reads its configuration only when it
starts, so where `journald@<namespace>.conf` or a drop-in was changed to keep
the journal off the disk without the restart the fix names, NAILS counts the
namespace as one that does not persist while its journald still writes to
`/var/log/journal/<machine-id>.<namespace>`. A socket the table lists
otherwise, or not at all, as one of another network namespace or a network
socket, counts as NAILS cannot tell, and so does a table NAILS cannot read. The
table does not show what holds the other end of a socket, so one of that kind
whose other end a program other than journald holds, as the other end of a
socket pair, counts as one to the journal, though that program may copy what it
reads into a file. A unit that another unit pulls in with `Wants=` or
`Requires=` in its own file is not followed, tuned-ppd's need of tuned aside,
and a unit of another name that runs one of these programs is seen only by its
process, while it runs. Where `/proc` is mounted with `hidepid=1`, a process an
unprivileged `nails check` cannot read counts against the decoy wherever the
daemon's unit is installed; with `hidepid=2` it does not see other users'
processes at all. Activation, which runs as root, sees them all.

## Package updates

Update the system on the decoy. Hidden sessions run the decoy's programs and
see its updates until a hidden session installs, updates or removes a package
itself: from then on hidden sessions keep a record of their own of what is
installed, which a later update of the decoy does not reach (dpkg's and rpm's
whole record, pacman's entries of the packages they changed). The
`package-drift` check warns, and never refuses, when that record no longer
follows the decoy's, and activation shows the warning before it asks to log
you out. [Package changes in hidden
sessions](operator-guide.md#package-changes-in-hidden-sessions) says what
drifts for dpkg, pacman and rpm, and how to bring hidden sessions back in line.

## Suspend and the lid switch

Suspend and hibernate are not a filesystem concern, so they sit outside the
overlay model, but they are a direct hazard: suspending while a session is active
leaves the whole hidden environment — the root overlay, the open dm-crypt
mapper and the master key — resident in RAM behind the hidden session's lock
screen. The decoy is not running at all, and whoever unlocks that screen is in
the live hidden session. logind's defaults make this the normal
case: `HandleLidSwitch` defaults to `suspend`, `HandleLidSwitchExternalPower`
takes `HandleLidSwitch`'s value unless it is set, and desktops add their own
idle auto-suspend.

The `sleep-policy` pre-flight check parses `/etc/systemd/logind.conf` and its
`logind.conf.d/*.conf` drop-ins and warns (never blocks) when the effective lid
or idle settings would suspend an active session, and when a closed lid is set
to `ignore` (on battery, or on external power), which leaves the session running
and unlocked behind the lid.

Set the decoy's lid switch so a closed lid does not suspend. Use `lock` (lock the
screen, stay running): `ignore` also keeps the host awake but leaves the screen
unlocked behind a closed lid. Add a drop-in rather than editing the main file:

```ini
# /etc/systemd/logind.conf.d/10-lid.conf
[Login]
HandleLidSwitch=lock
HandleLidSwitchExternalPower=lock
HandleLidSwitchDocked=ignore
IdleAction=ignore
```

On NixOS, set it declaratively in the **decoy** configuration (a drop-in on the
decoy, not the hidden module):

```nix
services.logind.settings.Login = {
  HandleLidSwitch = "lock";
  HandleLidSwitchExternalPower = "lock";
  HandleLidSwitchDocked = "ignore";
  IdleAction = "ignore";
};
```

Also disable any desktop-level auto-suspend (GNOME/KDE power settings), which
logind does not govern.

For defence in depth, set `sleep_policy.mode` in `nails.toml`. `block` holds
sleep and idle block inhibitors for the life of the session so the host cannot suspend while
active. logind ignores sleep inhibitors for the lid switch by default
(`LidSwitchIgnoreInhibited=yes`), so when a closed lid would sleep, `block` also
takes the lid switch from logind (a `handle-lid-switch` inhibitor): the closed lid
then does nothing, and does not lock the screen either. `teardown` holds a sleep
*delay* inhibitor, which logind honours for the lid too, and powers the machine
off when the host is about to sleep, within logind's `InhibitDelayMaxSec` window
(default 5s). Both run as runtime units of the hidden session. The inhibitors are
a runtime backstop — still set the lid switch to `lock` above, since a laptop kept
running with the lid shut can overheat and `block` leaves a lid that locks to
logind.

## Satisfying the requirements per platform

### NixOS

- **Soft-reboot units**: until nixpkgs installs `soft-reboot.target` and
  `systemd-soft-reboot.service`, declare them as `nails check` shows
  (`systemd.units`); the hidden configuration needs them too.
- **A disk-backed root**: a tmpfs root (`nixos-impermanence` on `/`) is refused.
  Keep the root on disk; a wiped-on-boot `/var` or `/home` on its own tmpfs is
  fine (the hidden session mounts a fresh tmpfs there, in RAM).
- **Volatile journald**: `services.journald.storage = "volatile";`.
- **No classic syslog / audit**: do not enable `services.rsyslogd`,
  `services.syslog-ng`, `services.syslogd` or `security.auditd` / the audit
  framework on the decoy. To turn a running auditd off, set
  `security.auditd.enable = false`, run `sudo auditctl --signal stop` and
  rebuild.
- **tuned without its log file**: leave `services.tuned` disabled, or clear
  `systemd.services.tuned`'s `ExecStart=` and set it again without `-l`, with
  `StandardError=` set to `journal` (see
  [tuned, firewalld and ABRT](#tuned-firewalld-and-abrt)).
- **firewalld logging to the journal**: with `services.firewalld` enabled, set
  `services.firewalld.extraArgs = [ "--log-target=syslog" ];`.
- **noatime**: add `"noatime"` to the root filesystem's mount options.
- **The locate database skips the hidden volume** (`locate-database`): leave
  `services.locate` disabled, or for a volume mounted below `/mnt` add
  `services.locate.prunePaths = lib.mkOptionDefault [ "/mnt" ];` (see
  [The locate database](#the-locate-database)).
- **Core dumps kept off the disk**:
  `systemd.coredump.settings.Coredump = { Storage = "none"; ProcessSizeMax = 0; };`.
- **No swap / hibernation**: leave `swapDevices` empty and do not configure
  `boot.resumeDevice` or a resume kernel parameter.
- **nftables, and iw on a machine with Wi-Fi** (`network-tools`):
  `environment.systemPackages = [ pkgs.nftables pkgs.iw ];`, so the way back
  can delete the firewall tables and Wi-Fi interfaces a session adds.
  `networking.nftables.enable` installs `nft` as well, and moves the decoy's
  firewall to nftables.
- **Nothing in `/etc/nixos` names the hidden environment**. The
  `suspicious-nails-reference` check reads every `.nix` file there and refuses
  activation with the file, the line and the text it found, in comments as in
  code, when a line holds:
  - the hidden volume's mount point as a whole path (`/mnt/data`, also
    `/mnt/data/nixos`, but not `/mnt/data2`), or the units systemd names after
    it (`mnt-data.mount`, `mnt-data.automount`);
  - its device as a whole path (`/dev/mapper/data`,
    `/dev/disk/by-id/dm-name-data`, the `/dev/disk/by-id/dm-uuid-CRYPT-…-data`
    link of a mapping called `data`), or the unit systemd names after it
    (`dev-mapper-data.device`);
  - what it is stored on, unless the decoy's own volumes sit on it too: its
    device paths, its kernel names, every link udev made for it, its uuids
    and its labels. NAILS reads the layers below the mount from the kernel
    and their names from udev: the partition or disk as a whole path
    (`/dev/sdb2`), the mapping below a logical volume, the image file behind
    a loop device; the kernel's name of each of these layers and of the
    hidden volume's own device, alone as a udev rule writes it
    (`KERNEL=="sdb2"`, but not `sdb20`) or as its device node (`/dev/dm-0`),
    and its `/dev/block/<major>:<minor>` link (`/dev/block/8:18`);
    every link udev made for one of these layers or for the hidden volume's
    own device, among them each `/dev/disk/by-id`, `by-path`, `by-partlabel`,
    `by-partuuid`, `by-diskseq`, `by-uuid` and `by-label` name and the LVM
    path `/dev/<vg>/<lv>`; their uuids (the partition's, the LUKS header's
    and the filesystem's own, as in `UUID=<uuid>` or a `luks-<uuid>` name);
    and their labels written as a tag (`LABEL=`, `PARTLABEL=`) or as the
    `label` of a `fileSystems` or `swapDevices` entry;
  - its mapping name where a line opens the volume: a
    `boot.initrd.luks.devices` or `boot.initrd.clevis.devices` entry
    (`luks.devices.data`, `luks.devices."data"`, `data = { … }` inside
    `luks.devices = { … }` or a `lib.mkForce`, `lib.mkMerge`, `with` or
    `let … in` value of it, `devices.data` inside `luks = { … }`, the same in
    fully nested blocks, or `inherit data;`), also in a block commented out
    line by line whose lines are indented at least as deep as its first; the
    `name` of such an entry or of one in the old list form
    (`luks.devices = [ { name = "data"; … } ]`);
    `fileSystems.<path>.encrypted.label`; `systemd-cryptsetup@data.service`;
    a crypttab line, at the start of a line or of a string, that starts with
    the name (`data UUID=… none luks`, `data /var/lib/vault.img none luks`);
    or a word after `cryptsetup` (or `systemd-cryptsetup`) and one of the
    verbs that open, close or ask about a mapping: `open`, `create`, `close`,
    `remove`, `status`, `resize`, `refresh`, `luksSuspend`, `luksResume`, the
    `luks`, `plain`, `tcrypt`, `loopaes`, `bitlk` and `fvault2` forms of
    `Open` and `Close` (`luksOpen`, `plainClose`, …), and
    `systemd-cryptsetup`'s `attach` and `detach`. Every word after such a
    verb that is not part of a path counts, up to the end of the command: a
    `;`, `|`, `&` or `#`, or the end of a line that is not continued with
    `\`. A comment or prose counts the same as a script:
    `cryptsetup open /dev/sdb2 data` and
    `# use cryptsetup open for the data volume` are both refused;
  - text NAILS writes during a session, or the word `nails`.

  A unit name with a character systemd escapes counts in both spellings: with
  one backslash, as a comment or an indented `''…''` string holds it
  (`mnt-my\x2ddata.mount` for `/mnt/my-data`), and with two, as a
  double-quoted string must write it (`"mnt-my\\x2ddata.mount"`). A path
  counts however many slashes separate its parts: `/mnt//data` and
  `/dev/mapper//data` are refused as `/mnt/data` and `/dev/mapper/data` are,
  while `/srv//mnt/data`, which is `/srv/mnt/data`, passes. A path counts
  behind the prefixes systemd allows before one too, where they start the
  value (`EnvironmentFile=-/mnt/data/app.env`, `ExecStart=+/mnt/data/bin/app`),
  but not where such a prefix is part of another path (`/srv/-/mnt/data`).

  A kernel name counts as the kernel gives it while the check runs. The
  numbers of `dm-<n>` and `loop<n>` are handed out as the devices appear, so
  a line that names a device of the decoy that way (`/dev/dm-1`) is refused
  while the hidden volume's storage holds that number. Name the decoy's own
  devices by their uuid or label instead.

  Ordinary configuration passes. The mapping name as an ordinary word passes
  (`description = "Back up user data"`, `cryptsetup` next to it in a package
  list, or in prose that puts none of those verbs between `cryptsetup` and
  the name, such as `# cryptsetup keeps the data safe`, or the comment
  `nixos-generate-config` writes above `system.stateVersion`), and so do a
  directory such as `/var/lib/postgresql/data`, the decoy's own mapping whose
  name merely ends like the hidden one (`user-data` beside `data`), another
  device's kernel name (`sdb20` beside `sdb2`, `/dev/dm-1` beside
  `/dev/dm-0`), the word `hidden` and options such as `services.plausible`.

  The check reads text; it does not evaluate Nix. It does not follow a
  mapping defined through a `let` binding, `lib.listToAttrs` or an
  interpolated name (`luks.devices.${"data"}`), nor a path written with a
  `.` or `..` component or relative to the file (`/mnt/./data`,
  `../../mnt/data`), and it does not know these names of the storage: the
  units systemd names after its device nodes and links (`dev-sdb2.device`,
  `dev-dm\x2d0.device`), and its `<major>:<minor>` outside `/dev/block/`
  (`8:18` in a device-mapper table). Keep such lines out of `/etc/nixos`
  yourself; an entry defined in one of these ways still counts by its device
  when that is written in one of the forms above. Run
  `nixos-generate-config` only while the hidden volume is closed: it writes
  an entry for every mounted filesystem.

  The check reads `.nix` files only. Keep the other files in `/etc/nixos`
  (notes, scripts, a README) free of these names too, and, where
  `/etc/nixos` is a git repository, as a flake often is, its history: a line
  removed from a file stays in the commit that added it.

### Ubuntu

- **Ubuntu 24.04 or 26.04** (systemd 255+). A later release runs with a
  warning that NAILS has not been tested on it. `overlayroot` is not supported:
  an overlay root cannot be mounted again for the way back.
- **Ubuntu 26.04: reboot fully after a session.** In the hidden session chrony
  (time sync) and CUPS (printing) fail: AppArmor blocks their messages to
  systemd and to the journal, whose sockets were set up before the switch, so
  the clock is not synchronized and printing times out. After the way back the
  decoy lists chrony as failed until its next full reboot, which hints that a
  soft-reboot happened. A plain `systemctl soft-reboot` into another root,
  without NAILS, breaks chrony the same way. The distribution tests boot Ubuntu
  26.04 and expect chrony to fail in the hidden session and after the way back,
  so they show when a newer image fixes it. Their image has no CUPS, so the
  printing half rests on a check by hand. They also require the warning that
  `nails check` gives on 26.04 to name chrony and CUPS until each is shown
  fixed.
- **Volatile journald**: set `Storage=volatile` under `[Journal]` in
  `/etc/systemd/journald.conf`, or in a drop-in such as
  `/etc/systemd/journald.conf.d/50-volatile.conf`. NAILS resolves the main
  file and every `journald.conf.d/*.conf` drop-in the way systemd does, so a
  drop-in that sets `Storage=persistent` is caught too.
- Remove or disable `rsyslog` and any other syslog daemon if installed, and
  turn `auditd` off for good if installed (`systemctl disable` and
  `systemctl mask auditd.service`, then `auditctl --signal stop`; see
  [Fail closed](#fail-closed-activation-is-refused)).
- Leave unattended-upgrades' `Unattended-Upgrade::InstallOnShutdown` off, or
  set it to `false`. With it on, the decoy's shutdown helper installs the
  pending updates on the decoy disk at every activation, as at every shutdown,
  and `decoy-persistence` refuses it (see
  [Unattended upgrades](#unattended-upgrades)). Where the helper is enabled,
  install python3-gi (`apt install python3-gi`), without which it writes two
  lines to its log on the decoy disk at every way back.
- Turn apport off (`sudo systemctl disable --now apport.service`), which sets
  `kernel.core_pattern` back to `core`: Ubuntu's images run it, and it logs the
  path and the command line of each crashing program to `/var/log/apport.log`
  on the decoy disk, which `decoy-persistence` warns of.
- If `systemd-coredump` is installed, set `Storage=none` and `ProcessSizeMax=0`
  under `[Coredump]` in a drop-in such as
  `/etc/systemd/coredump.conf.d/50-discard.conf`, and mask the hook apport
  adds to it (`sudo systemctl mask apport-coredump-hook@.service`), which
  reads each crash from the journal whatever those settings say.
- Mount the root with `noatime`; disable swap and hibernation.
- With plocate installed, add the directory the hidden volume is mounted in to
  `PRUNEPATHS` in `/etc/updatedb.conf`, or mask and stop
  `plocate-updatedb.timer` (`sudo systemctl mask --now`)
  (`locate-database`; see [The locate database](#the-locate-database)).
- Keep `nftables` installed, and `iw` on a machine with Wi-Fi
  (`apt install nftables iw`), so the way back can delete the firewall tables
  and Wi-Fi interfaces a session adds (`network-tools`).
- Install Nix inside a hidden session, not on the decoy (`decoy-nix-trace`;
  see [Nix on the decoy](#nix-on-the-decoy)).

### Debian

- **Debian 13** (systemd 257+). A later release runs with a warning that NAILS
  has not been tested on it. `bilibop-lockfs` and other RAM-overlay roots are
  not supported: the way back mounts the decoy root by device.
- **Volatile journald**: `Storage=volatile` in `journald.conf` or a
  `journald.conf.d/*.conf` drop-in.
- Remove or disable the syslog daemon (`rsyslog`, `syslog-ng`,
  `inetutils-syslogd`, `busybox-syslogd`, `sysklogd`), and turn `auditd` off
  for good (`systemctl disable` and `systemctl mask auditd.service`, then
  `auditctl --signal stop`).
- Leave unattended-upgrades' `Unattended-Upgrade::InstallOnShutdown` off, or
  set it to `false`. With it on, the decoy's shutdown helper installs the
  pending updates on the decoy disk at every activation, as at every shutdown,
  and `decoy-persistence` refuses it (see
  [Unattended upgrades](#unattended-upgrades)). Where the helper is enabled,
  install python3-gi (`apt install python3-gi`), without which it writes two
  lines to its log on the decoy disk at every way back.
- With `systemd-coredump` installed, `Storage=none` and `ProcessSizeMax=0` in a
  `coredump.conf.d/*.conf` drop-in.
- `noatime`; no swap; no hibernation.
- With plocate installed, the directory the hidden volume is mounted in in
  `PRUNEPATHS` of `/etc/updatedb.conf`, or `plocate-updatedb.timer` masked and
  stopped (`locate-database`; see
  [The locate database](#the-locate-database)).
- `nftables`, and `iw` on a machine with Wi-Fi (`apt install nftables iw`), so
  the way back can delete the firewall tables and Wi-Fi interfaces a session
  adds (`network-tools`).
- Nix, if you use it, installed inside a hidden session, not on the decoy
  (`decoy-nix-trace`; see [Nix on the decoy](#nix-on-the-decoy)).

## The sudo-log exposure and its mitigation

Running `sudo nails …` is itself a sensitive event: sudo logs the invoking user,
the target command and its full path through its configured log channel
(journald, syslog, or `/var/log/sudo.log`). On a persistent decoy that record
names the hidden-root binary path; `nails activate` runs on the decoy, before
the soft-reboot into the overlay.

**Mitigation**: run NAILS on an amnesic decoy (volatile journald, no syslog,
no sudo `logfile` or I/O logging in sudoers) so the sudo record is never durably
written, and keep the binary at a neutral path
on the hidden volume. NAILS cannot suppress sudo's own logging without tampering
with the decoy, which would itself be a tell.

### What the decoy journal keeps

The decoy journal logs the window around each soft-reboot: the sudo line of the
activation, the hidden build's progress and the decoy's own shutdown before the
switch, and its start after the way back, all under one boot ID. Where those
records end up depends on the journal:

- **Persistent** (allowed with `--allow-persistent-decoy`): they are on the
  decoy disk and stay there, with a gap where the hidden session ran.
- **Volatile** (the amnesic setup): they are in RAM, in the runtime journal
  below `/run/log/journal`, which the hidden session's journald writes to as
  well. The way back deletes that journal whole, the decoy's own records from
  before the session included, so the decoy journal starts at the return: it
  holds neither the activation nor anything the decoy logged earlier, nor any
  of the kernel's boot messages, because the kernel-message cursor that keeps
  the hidden session's kernel records out is set past them too. `uptime` and
  `dmesg` still go back to the boot, so until the machine is powered off,
  anyone with a shell can see that the journal starts long after the boot.
  Power off after the session.

## Shell history hardening

Hidden-session history never reaches the decoy: every hidden shell runs inside
the overlay and writes its history file into the upper. On the decoy,
`nails activate` SIGKILLs the decoy's interactive shells, the newest first,
right before it asks logind for the switch, keeps killing every interactive
shell opened while logind holds the switch back (within about a tenth of a
second after it starts, too soon to have anything to save), and kills them once more when
PID 1 holds the switch's job, so a shell that saves history on exit (bash on
SIGHUP) never writes the activation command, unless a terminal multiplexer
hangs it up itself (see **Terminal multiplexers** below and
[bash-history-forensics.md](bash-history-forensics.md)). NAILS does
**not** configure the decoy's own shells, and a shell that writes each command
line to its history file as it runs has written it before any kill: zsh with
`INC_APPEND_HISTORY`, `SHARE_HISTORY` or `INC_APPEND_HISTORY_TIME` or an
`fc -A`, `fc -W` or `fc -p` in a hook, bash with `history -a` or `history -w` in
`PROMPT_COMMAND`, and fish outside private mode. The `incremental-history-flush` check warns about the settings it can
see (see [Shell history](operator-guide.md#shell-history)). If you type on the decoy — and the
pre-activation unlock and mount commands must be typed there — harden the decoy's
history yourself so an interactive shell has nowhere to write:

- **Environment.** Set `HISTSIZE=0` and `HISTFILESIZE=0`, and point the history
  file at the null device, in the decoy's shell profile so a login shell keeps no
  on-disk history.
- **Shell options.** Disable history recording (`set +o history`) and append mode
  (`shopt -u histappend`) for sessions where you unlock the volume.
- **Filesystem redirection.** Symlink `~/.bash_history` and `~/.zsh_history` to
  the null device so even a shell that ignores the environment writes nowhere.
- **Boot-time enforcement.** A systemd unit that truncates any regular history
  file and re-creates the symlinks early in boot closes the gap before the first
  interactive login.
- **A shell NAILS knows.** Activation kills only the shells it knows by the
  name of their process (bash, zsh, fish, dash, the Korn and C shells, yash,
  nu, elvish and xonsh; [bash-history-forensics.md](bash-history-forensics.md#the-flush-race)
  lists every name). Type the decoy commands in one of them, started under its
  own name, and with its history off: the kill keeps a shell from writing
  what it still holds when it ends, not what it writes as each command runs,
  as ksh93, nu (by default) and elvish do and the other Korn shells and yash
  can.
- **No write after every command.** Turn off zsh's `INC_APPEND_HISTORY`,
  `SHARE_HISTORY` and `INC_APPEND_HISTORY_TIME` (NixOS's `programs.zsh` sets
  `SHARE_HISTORY` by default, through `programs.zsh.setOptions`, Home
  Manager's `programs.zsh` through `history.share`, which is on by default,
  and so does Oh My Zsh), keep `fc -A`, `fc -W` and `fc -p`, and a write to
  any file but a device, out of zsh's hooks (`$TTY` counts as any file, as
  your files may change what it holds: write to `/dev/tty` instead; and a
  write to a device too where your files define a global alias) and
  `history -a` and
  `history -w` out of bash's `PROMPT_COMMAND`, and type the decoy commands in
  fish only as `fish --private`. For zsh, the check counts any mention of the
  three options in a file zsh reads as on, an `unsetopt` too, as no reading of
  the files can show that a turn-off holds: leave them out of every startup file
  (on NixOS, out of `programs.zsh.setOptions`), or type the decoy commands in a
  zsh started as `zsh -f`, which reads no startup file but `/etc/zshenv` (and on
  NixOS `/etc/zshenv.local`). Start that zsh after your last change to its
  startup files, and on NixOS after the rebuild: zsh keeps what it read as it
  started, so the check warns for the zsh you type into when a file it reads
  or looks for, a link or a directory on the way to it changed after that zsh
  started (an edit, `rm ~/.zshrc`, a rebuild, or any program that makes or
  removes a file in your home). As zsh reads a history file that holds lines
  at its start, it makes and removes a lock file beside it unless
  `HIST_FCNTL_LOCK` is on,
  so with the history file in your home or `ZDOTDIR` turn that option on, as
  NixOS does by default, or keep the history file in a directory of its own:
  else the check warns for a zsh however new it is. With NixOS's
  `programs.zsh`, `SHARE_HISTORY` taken out of `programs.zsh.setOptions`
  (`HIST_FCNTL_LOCK` kept there) and `programs.zsh.enableCompletion` (or just
  `programs.zsh.enableGlobalCompInit`) turned off, a zsh you start after the
  rebuild and type `nails activate` into passes with the files
  `programs.zsh` generates: the check knows the lines
  NixOS generates there as they are written, and follows `promptinit` into
  zsh's own directory and the Nix profiles. It warns wherever your files
  autoload `compinit`, as NixOS's `/etc/zshrc` does with
  `programs.zsh.enableCompletion` on, the default, and nearly every `.zshrc`
  does: zsh's own completion functions run what programs print as code as you
  complete a word, and the programs and settings that may change what they
  print cannot all be listed (`tar` with a `LANGUAGE` that names a message
  catalog of yours, `bash` with a `BASH_ENV`).
  An option that adds lines to those files (`enableBashCompletion`,
  `autosuggestions`, `syntaxHighlighting`) can make it warn again, and so can
  an alias, a `TRAP...` function, a `trap`, `ARGV0` or a variable of the
  dynamic loader (`LD_...`) in your `.zshenv` or in
  `programs.zsh.shellInit` or `interactiveShellInit`, which run before the
  line of `/etc/zshrc` that runs `dircolors` and may change what it runs, an
  `ARGV0` or a variable of the dynamic loader (`LD_...`) in the environment you
  start the shell from, arithmetic in your files that names a parameter that
  holds no number (`(( i++ ))` before `i` is set in it), a global alias your
  files use or one named like an operator (`alias -g '>'=...`), any global alias
  where a hook writes to a device, an `alias` word an expansion, brace
  expansion or a glob may make a flag of (`alias $g`, `alias {-g,-g}`), a
  `bindkey` word with a glob or a brace outside quotes, or an expansion there
  that may make several words of it (`bindkey ^[[A up-line-or-search` written
  without quotes, `bindkey $k`), `compctl`, an alias
  named like a reserved word of the code's structure (`alias do=...`),
  a builtin's word brace expansion or a glob may make a flag or a name of
  (`setopt {-m,...}`, `functions {-c,f} preexec`), a `histchars` your files set,
  `RC_QUOTES`, `IGNORE_BRACES` or `IGNORE_CLOSE_BRACES` where a function's `}`
  follows a command's words, a `typeset -m`, which sets every parameter its
  pattern matches, an `unset -m` whose pattern may match one the check reads
  (`ZDOTDIR`, `HOME` and the like), a word of a builtin that sets or takes
  away a parameter where an expansion, brace expansion or a glob may make its
  options or the name (`private -$o x`, `typeset {a,b}=x`, `print "$x"`, which
  `print -r -- "$x"` is not), an attribute that changes what `ZDOTDIR` or
  `XDG_CONFIG_HOME` expands to or keeps a later assignment from setting it
  (`typeset -l`, `readonly`, `typeset -a XDG_CONFIG_HOME`), an
  `XDG_CONFIG_HOME` set otherwise than by an assignment or an `unset`
  (`read`, `+=`), a `ZDOTDIR` or `XDG_CONFIG_HOME` whose `~` a quote or a
  backslash keeps (`ZDOTDIR="~/.zd"`), a function or an alias named like a
  builtin that sets one (`alias export=:`, `unset() { ... }`) or a `disable`
  of one, an `autoload -X`, `ALIAS_FUNC_DEF` where an alias shares a
  function's
  name, a prompt with code where `PROMPT_SUBST` (or `PROMPT_VARS`) may be on, a
  `NULLCMD` or `READNULLCMD` of any value in the environment you start the shell
  from, a `TMOUT`, `PERIOD` or `REPORTTIME` (and the like) that is no number,
  which zsh reads as arithmetic each time it uses it, in your files or in that
  environment, or tied to another name (`typeset -T TMOUT tmout`), a `TMOUT`
  above 0 there, with which zsh ends by itself at a prompt left waiting and
  writes its history then (start the shell you type in without it,
  `env -u TMOUT zsh -f`), a hook that may end the shell, which writes its
  history as it ends (`exit`, in a `$(...)` too, `exec`, `kill -HUP $$`), a
  builtin's name a hook runs as an outside program (after `command` or a
  `disable` of it, or of a module zsh does not load, as `stat`), a file your
  files source by a path with a modifier on `$HOME` (`source $HOME:a/x`), a
  file your startup files write before zsh reads it (at any point, for one a
  hook or another function reads), a function
  or an alias named `sudo`, `doas`, `run0`, `pkexec`, `su` or `nails` (or the
  path you start `nails` by) that writes a file or hands a program a word an
  expansion makes (`nails() { sudo /mnt/data/nails "$@" }`; one that only runs
  its own name through `command`, as `sudo() { command sudo "$@" }`, passes),
  one named `run-help`, `which-command`, `man` or `run-help-...` that does
  so, which zsh runs with the line you type as you press Alt-h or Alt-?, or
  named like a widget a key runs them by (`.run-help`, a name `zle -A` gives
  one), and a global alias named like a word of the NAILS commands you type
  (`activate`, `--yes`) or like one of those commands.
  For any other zsh than one from the Nix store, and when the check finds no
  shell you typed into, it cannot tell where zsh finds a function your files
  autoload (`promptinit` too), a doubt. With Home Manager's `programs.zsh`,
  only `zsh -f` passes the check, as it names the options in `.zshrc` whether
  it turns them on or off. A history tool that records each command itself,
  such as atuin, writes as the command runs too. No kill takes back what such
  a shell has written.
- **Terminal multiplexers.** Leave off the options that end a session when its
  last client goes: tmux's `destroy-unattached` and `exit-unattached`,
  screen's `autodetach off` and zellij's `on_force_close "quit"`. Activation
  kills the shells the newest first, so no hangup the kernel sends as one dies
  reaches a shell still alive, but such a multiplexer hangs up the shells in
  its panes itself, older ones among them, as the shell that ran its last
  client dies, and one of them can write its history first.

If the decoy's home is on a wiped-on-boot tmpfs, the history file is discarded
at power-off anyway, so these steps are defence in depth. In the decoy shell you
unlock from, do **not** re-enable history recording or run
`history -a`/`history -w` (in zsh `fc -A`/`fc -W`): each of those writes the
commands you typed to the decoy disk. (Inside the hidden session, history lands in the upper.)

## Writes that bypass the overlays

The root overlay covers only the root filesystem. The hidden systemd reads the
decoy's fstab (or the one the hidden `/etc` holds in its place, such as a hidden
NixOS generation's) and would mount every other decoy filesystem **directly and
read-write**, and activate decoy swap. Before the switch the `fstab-policy`
decides each entry, and activation puts the decision in place inside the next
root:

| Entry | In the hidden session |
| --- | --- |
| `/boot`, `/boot/efi`, `/efi` (ESP, boot partitions), and filesystems mounted read-only | read-only bind |
| other mounted local filesystems (a separate `/home`, `/var`, `/srv`), mounted VM host shares and overlays | overlay, upper at `<hidden>/root/mounts/<unit name>/upper` |
| swap | kept off: never activated |
| local filesystems not mounted now but mounted at boot, network filesystems, overlay entries not mounted now with an upper on a disk | kept unmounted: not available in the hidden session |
| tmpfs and kernel filesystems, `noauto` entries | left alone |
| any entry at or below the hidden root, the hidden volume's own line, a `noauto` one and a tmpfs included | refused: the hidden session could mount it over the hidden volume or inside it |

So the decoy's fstab must mount nothing at or below the hidden root: mount the
hidden volume where the decoy mounts nothing (see
[What the session covers](configuration.md#what-the-session-covers)). In the
fstab the hidden `/etc` holds in place of the decoy's, an activation without a
build keeps such a line off with a warning instead, so the session entered to
remove it still starts.

A unit kept off is masked in `/run`, or skipped where a boot target requires it
(an entry without `nofail`): a mask there would leave `local-fs.target`,
`remote-fs.target` or `swap.target` unreached in the hidden session, and with
it every unit only that target pulls in. A skipped unit, and the fsck, makefs
and other units it pulls in that act on its disk, gets a runtime drop-in whose
start condition never holds. A skipped mount still waits for its device, so an
entry whose device is not there when you activate is masked, and `check` and
`activate` warn that the target will not be reached: attach the device, or give
the entry `nofail` (see
[What the session covers](configuration.md#what-the-session-covers)).

systemd's GPT auto-generator mounts the partitions it finds by their type on
the root filesystem's disk (`/home`, `/srv`, `/var`, the ESP) and turns on a
swap partition, where the fstab does not cover them. The policy never decides
on those, so the generator is masked in the hidden session. On the root overlay
it finds no disk; the mask is a defence in depth for a decoy where it would find
one all the same: one whose separate `/usr` is mounted read-only. The policy
binds that `/usr` read-only into the hidden root, and with `/` on no disk the
generator takes the disk of `/usr`.

The decoy's own mount, swap and automount units that a boot target links in
its `.wants` or `.requires` directory outside the fstab (a NixOS
`systemd.mounts` unit wanted by `local-fs.target`, a `.mount` unit enabled for
`multi-user.target`, a mount the kernel command line names) get the decision
an fstab line with the same source, type and options would get, and the ESP
the GPT auto-generator mounted in the decoy is bound read-only into the hidden
root. zram-generator's swap is left to the hidden systemd as RAM-only swap
while its zram device has no backing device, and kept off like disk swap when
it has one; NAILS does not read zram-generator's configuration (see
[What the session covers](configuration.md#what-the-session-covers)).

Any other mount outside the fstab is not carried into the hidden session: an
automounted USB drive, a disk mounted by hand, a mount unit that only another
unit pulls in (by `Requires=`, `Wants=` or `RequiresMountsFor=`, or from a
service's `.wants` directory). The hidden session can mount it again itself,
as the hidden systemd does for such a unit at its start, and then writes to it
directly. The session watcher alerts on every such read-write mount, one below
the hidden root included, and `[session_mounts] read_only` makes every disk the
session does not use read-only for the session, including disks attached during
it; `nails deactivate` unmounts them before the way back (see
[Disks mounted during the session](configuration.md#disks-mounted-during-the-session)).
None of that holds for a disk mounted below `<hidden-root>/root`, where NAILS
keeps its layers and every mount counts as the session's own: mount nothing
there.
`verify` cannot tell what a session wrote there, but
[`nails rehearse`](operator-guide.md#rehearsing-before-you-rely-on-it) scans
every mounted disk for its canary.

In the `fresh-home` persona activation itself writes into an upper, before
the overlay over it is mounted: it makes your home there at the first entry,
with the directories missing on the way to it. These writes pass through no
overlay, so activation looks up and makes each of those directories inside
the upper without following a symbolic link. A hidden session that replaced
`/home`, or a directory below it on the way to your home, with a link (to
`/var/home`, say, or a relative one) would otherwise have the new home made
wherever the link leads, which can be the decoy disk. While such a link
stands there, activation is refused and makes nothing (see
[Persona modes](configuration.md#persona-modes)).

## Pending offline updates

Desktop updaters that use PackageKit, such as GNOME Software, and
`dnf system-upgrade` can stage an update to be installed offline: they link
`/system-update` (or `/etc/system-update`) to it. At the next start of the
service manager, `systemd-system-update-generator` sees the link and starts
`system-update.target` instead of the default target, where the updater
deletes the link, installs the update and reboots.

A soft-reboot starts the service manager again, and its generators run in the
new root as at a boot. A link the hidden root shows would turn the start of the
hidden session into the update: the decoy's updater would install it into the
upper on the hidden volume and then reboot or power off the machine, so the
session ends without its way back. That run deletes the link only in the upper,
so the decoy keeps its own and installs the update itself at its next boot.

So activation is refused while a link is staged (`pending-offline-update`),
on the decoy or in the root overlay's upper. A dangling link counts; a link a
session deleted (a whiteout in the upper) does not. Install or cancel a pending
update on the decoy before you activate. A link a hidden session staged stays
in the upper: the way back is a soft-reboot into the decoy root, which does not
show the upper, so the decoy starts as usual, and the next activation is
refused until `nails discard` deletes the link, as the refusal says.

The check runs before activation prepares the hidden root, so it does not see
an update staged after it and before the service manager starts again in the
hidden root. On every family that window spans the setup of the hidden root and
the soft-reboot, which stops the decoy's services before it switches. On NixOS,
unless activation runs with `--overlay-only`, it also spans the build of the
hidden system, the copy of its closure onto the hidden volume and its
activation, which can take minutes.

## Unattended upgrades

unattended-upgrades (Debian, Ubuntu) runs a shutdown helper,
`unattended-upgrades.service`, that waits for logind's shutdown signal.
Activation sends that signal, as `systemctl soft-reboot` does, and so does the
way back with `nails deactivate`; `deactivate --poweroff` and `emergency` ask
PID 1 directly and send none. The helper does not ask what kind of shutdown
comes. At activation two things then reach the decoy disk.

**A daily run in progress.** When the signal comes while a run of
unattended-upgrade holds its lock, `/run/unattended-upgrades.lock`, the helper
sends the run SIGTERM and writes
`Unattended-upgrade in progress during shutdown` to
`/var/log/unattended-upgrades/unattended-upgrades-shutdown.log`, and the run
writes that it stops to `unattended-upgrades.log`, whatever
`Unattended-Upgrade::InstallOnShutdown` says. A run holds the lock while it
plans, downloads and between its install steps, but APT blocks shutdown only
while dpkg runs, so `shutdown-inhibitors` does not see it.
`apt-daily-upgrade.service` starts the daily run (its timer fires once a day,
in the hour after 6:00, and after a boot that missed it). `apt-daily.service`
runs `apt-get update` and then, with unattended-upgrades installed,
`unattended-upgrade --download-only`, which takes the same lock: a switch made
while it runs meets that lock if the download run takes it between NAILS's
last look and the helper's first look for it, a moment with python3-gi and up
to 3 seconds after the signal without it. The `unattended-upgrade-run` check
refuses while `apt-daily-upgrade.service` or `apt-daily.service` is active or
a process holds the lock, and activation looks again right before it asks
logind for the switch. No flag lifts it: try again in a few minutes, once the
run has ended
(`systemctl status apt-daily.service apt-daily-upgrade.service`). It asks the
kernel whether a lock is held on the lock file itself (`fcntl` `F_GETLK`): it
opens the file read-only, which changes none of its times, takes no lock and
reads nothing. The kernel's list of all locks, `/proc/locks`, would not do:
the kernel prints it a page at a time, and a lock released between two pages
makes it skip another, a held one included. unattended-upgrade makes the lock
file with mode 0640, so only root can open it: a `nails check` run without
sudo cannot tell wherever the file exists, which is after any run since the
boot, and says to run it as root; activation runs as root. When NAILS cannot
ask, it refuses as well, and so it does when the lock file is anything but a
plain file: the helper opens it without following a link, so it cannot open a
link, a directory or a socket there and takes that for a held lock, and NAILS
refuses any other kind of file there too, as one it does not judge. A lookup
of the lock file, or of a daily run's unit, that fails for another reason than
that nothing is there leaves NAILS unable to tell, and it refuses, and so does
a lookup `check` does not make because it would mount an automount point that
nothing is mounted on yet, as below a `/var` an automounter mounts: the
refusal names the point and says to mount it. Without the mount table, which
shows where such a point is, `check` looks nothing up and refuses, and says to
run it where `/proc` is mounted and readable.

**An install at shutdown.** With `Unattended-Upgrade::InstallOnShutdown` on,
the helper reads apt's configuration again on the signal and runs an install
of the pending updates its settings allow: at activation on the decoy disk,
the overlays already mounted on it, and it logs that run there. With
python3-gi installed the helper holds the switch back while the install runs;
without it the helper polls for the signal and exits right after it starts the
install, which then runs on into the switch. At the way back with
`nails deactivate` the hidden session's own copy of the helper installs them
into the session's overlay. `decoy-persistence` refuses while the decoy's
helper runs with the setting on, and where NAILS cannot tell whether it runs,
and `--allow-persistent-decoy` turns that into a warning for one run. It
reads the setting as apt reads it: first the
file the helper's `APT_CONFIG` names, if it runs with one, then each file of
`/etc/apt/apt.conf.d` that apt reads, in apt's order (a name with an
extension other than `.conf`, such as `.bak` or `.dpkg-old`, one starting with
a dot, one with other characters than letters, digits, `_`, `-`, `:` and `.`,
one ending with a dot, and what is not a file are skipped, as apt skips them),
then `/etc/apt/apt.conf`, with apt's syntax, the last setting winning. A file
or a directory of them NAILS cannot look up or read, a line NAILS does not
read the way apt does (one longer than 4000 bytes, or with a NUL byte in it),
an `#include`, and a `Dir` or `RootDir` setting, which move the files apt
reads, leave the setting unknown,
and `decoy-persistence` refuses that as if it were on. So does an
`#x-apt-configure-index`: apt loads an index of its options there, which
NAILS does not read, and stops reading the file with only a warning when it
cannot load it, so what follows in that file, a line apt would refuse
included, may never count. So do
a file name and a value of the setting with a byte beyond ASCII: apt runs in
the system's locale, which decides whether it takes such a byte for a letter
of a file name it reads (`é` in ISO-8859-1, but not in a UTF-8 locale) and
how it compares a value with its words for true and false (`İ` in ISO-8859-9
lowercases to `i`, so `WİTH` reads as `with`), so NAILS cannot tell what apt
makes of it.

A file apt refuses is refused as well, and `--allow-persistent-decoy` lifts
that with the rest, but the refusal says what happens then: at every
activation the decoy's helper reads apt's configuration again, finds that file
refused and installs nothing, but writes two ERROR lines, `Apt returned an
error thus shutdown mode is disabled` and apt's message. They go to its log on
the decoy disk, `/var/log/unattended-upgrades/unattended-upgrades-shutdown.log`,
or to the journal if the helper started with the file already refused, as it
then logs there for its whole run. The refusal names the file and the line to
fix.

The helper's unit sets no `APT_CONFIG`, but PID 1's environment, a drop-in of
the unit or `systemctl set-environment` can give it one, and apt then reads
the file it names before every other. NAILS reads that one variable from the
environment of the running helper's processes, those its unit's cgroup lists
(`/proc/<pid>/environ`, which only root can read), keeps nothing else of it,
and reads the file first as apt does. It cannot tell, and refuses, when that
environment cannot be read, when the file cannot be read, when the variable
names a relative path or one with `..`, and when the processes run with
different values. A `nails check` or `nails status` run without sudo cannot
read the environment, which the kernel refuses to all but root, or hides as if
the process were gone where `/proc` is mounted with `hidepid=invisible` or
`hidepid=ptraceable`, so check refuses on every decoy whose helper runs and
says to run it as root, and status says that NAILS cannot tell without root.
Run them with sudo. Where the decoy's helper runs, the hidden session's own
copy is read with the same file, the one the running helper's own environment
names: what the unit's files and PID 1's environment gave that helper when it
started. A drop-in of the unit, PID 1's environment or `DefaultEnvironment=`
changed since then can give the session's copy another `APT_CONFIG` or none,
which NAILS does not follow, as with a stopped helper. With the decoy's
helper stopped, no running process shows `APT_CONFIG`, so NAILS reads the
session's copy without one: a variable that a drop-in of the unit or PID 1's
environment would give it is not followed there.

Set it to `false` rather than deleting the line: the helper reads the files
when it starts and again on the signal, keeping what it read first, so a line
deleted after it started stays in effect until `unattended-upgrades.service`
restarts or the machine reboots, while an explicit `false`, or a `#clear` of
it, wins on the signal. So when no file sets the setting and apt's
configuration changed after the helper started (one of the files apt reads,
`/etc/apt`, where `apt.conf` lies, `/etc/apt/apt.conf.d`, where a deleted part
shows, or the directory that holds the file `APT_CONFIG` names, where one
swapped into place shows), `decoy-persistence` cannot tell whether the running
helper still holds a `true`, and refuses that as well,
`--allow-persistent-decoy` lifting it like the rest. It compares their change
time, which neither `touch -d` nor dpkg sets back as they set a file's
modification time, with the helper's start: the earlier of systemd's
invocation marker of `unattended-upgrades.service` and the start of each of
its processes, so that a step of the clock either way after the start leaves
one of them early enough. A change in the second the helper started counts, as
a filesystem may keep change times to the second. A symbolic link among those
files or on the way to them, whose target's change NAILS does not follow,
counts as a change, and so does a link among the files of
`/etc/apt/apt.conf.d` or at `/etc/apt/apt.conf` that leads to no file now: apt
skips it on the signal, while the helper may still hold what it read through
it at its start. A directory higher up swapped into place, such as `/etc`, or
the parent of the directory that holds the file `APT_CONFIG` names, replaces
the files below it without changing their change times or those of the
directories NAILS compares, so NAILS does not see it. This also refuses a
decoy after an update of a package that ships a file of `/etc/apt/apt.conf.d`,
until the helper restarts: set the setting to `false` once, or reboot. What
the helper read first also decides which files it reads on the signal: after a
`Dir` or `RootDir` line that moved them was removed, it still reads the files
that line named, which NAILS does not read, so where a file NAILS reads sets
the setting, the one the helper reads need not be the same. Restart the helper
or reboot after removing such a line.

Without python3-gi, which unattended-upgrades only suggests and Debian 13's
cloud image does not install, the helper cannot wait for logind's signal: each
time it starts, it writes two WARNING lines to its log on the decoy disk,
`Unable to monitor PrepareForShutdown() signal, polling instead.` and that
python3-gi would let it wait. The decoy starts its enabled helper again at
every way back, so each way back adds a pair, dated at the switch.
`decoy-persistence` warns while the decoy's helper is enabled and
`/usr/lib/python3/dist-packages/gi/__init__.py`, which python3-gi installs, is
missing: install it (`apt install python3-gi`). Where NAILS cannot tell whether
the helper is enabled, or whether that file is there, it warns that it cannot
tell.

When only the hidden session would install, `decoy-persistence` warns and does
not refuse: the decoy's helper is stopped but the session starts its own copy,
because the decoy or the session's overlay enables it and nothing masks it as
the session sees it, or the session's overlay turns the setting on. It reads
what the session sees: the decoy's files with the root overlay's upper on top.
It counts anything the overlay holds in the place of the decoy's mask but
another link to `/dev/null`, a unit file of the session's own included, as
unmasking the helper. A directory the upper holds may be one a session deleted
and made again, below which the decoy's files no longer show; NAILS does not
read that mark, so it reads such a directory both ways and warns if either
turns the setting on. A link among apt's files, or on the way to them,
resolves in the session through the overlay, which NAILS does not follow, so
it warns that it cannot tell. Where apt refuses a file the session reads, the
warning says what the session's copy does: it starts with the file refused, so
it logs to the session's journal for its whole run, and at the way back it
installs nothing while apt still refuses the file, but a session that fixes
the file has it read the setting again then. Set the setting to `false`, or
end the session with `nails deactivate --poweroff`.

As for kdump, the window's launcher stays usable with the setting on, and
`nails status` does not call the decoy persistent for it. Like kdump it has a
line of its own in `nails status` on the decoy wherever `decoy-persistence`
refuses it, which names the cause: that unattended-upgrades installs at
shutdown, that apt refuses a file of its configuration, so that the helper
installs nothing but writes its two ERROR lines, or that NAILS cannot tell
that it does not install (`decoy_installs_at_shutdown` in `--json` is true for
each). A `nails status` run without sudo cannot read the running helper's
environment either: its line says that NAILS cannot tell without root, and
names the command that can, and the `--json` flag is true there even where a
run as root finds nothing. Run it with sudo.

The distribution test `<image>-apt-shutdown` shows these on Debian 13, Ubuntu
24.04 and Ubuntu 26.04: on the stock decoy both rows pass, with the setting
off as `apt-config` reads it too, but Debian 13, which has no python3-gi,
warns of the helper's lines, which its way back then writes; a daily run held
with its lock taken makes `check` and `activate` refuse and leaves no line on
the decoy disk, while a plain `systemctl soft-reboot` during the same run
writes the helper's line there; so does `apt-daily.service` held before its
download takes the lock, where the control is a plain soft-reboot with the
helper paused (SIGSTOP) until the download run holds the lock, the order of
the race; with the setting on, as `apt-config` reads it, `check` and
`activate` refuse and `status --json` says so, and with
`--allow-persistent-decoy` the decoy's helper logs its shutdown-mode run at
the switch; with the decoy's helper stopped but enabled, `check` only warns
and the session's copy logs its shutdown-mode run into the upper at the way
back; with the line deleted after the helper started, `apt-config` reads the
setting off but `check` refuses, and with the override the helper logs its
shutdown-mode run all the same; and with a file apt refuses while the helper
holds the setting on, `check` refuses and `status --json` says so, with the
override the helper logs its two ERROR lines on the decoy disk and no
shutdown-mode run, and restarted with the file refused it logs to the journal
of its own invocation instead.

## Decoys joined to a domain

A decoy joined to a domain (Active Directory or FreeIPA, through sssd) checks
logins and account lookups with the domain controller. The controller keeps
its own records of them, with their times: the hidden session's logins reach it
as the decoy's do, and nothing NAILS does on this computer reaches those
records. sssd also keeps caches of the domain's accounts and credentials under
`/var/lib/sss` and logs under `/var/log/sssd`. In the hidden session these
writes land in the upper on the hidden volume. The decoy's own sssd, stopped
before the switch and started again after the way back, logs both under
`/var/log/sssd` on the decoy disk by default, as at any shutdown and boot.

NAILS is not tested on decoys joined to a domain, and no VM test runs a domain
controller. `nails check` and activation warn (`decoy-persistence`) while sssd
is in use on the decoy:

- one of its service units is active, or one of its daemons runs (`sssd`, or
  a responder or back end named `sssd_<name>`);
- its Kerberos ticket cache may listen: the socket file
  `/run/.heim_org.h5l.kcm-socket` (`sssd-kcm.socket`) is in place, and PID 1's
  socket table, `/proc/1/net/unix`, lists a socket listening on it in either
  of two reads, cannot be read, or does not begin with the header the kernel
  writes. That table lists the sockets of the network namespace systemd runs
  in, whichever one `nails check` runs in. It is read twice because it is no
  snapshot: the kernel writes it a page at a time, and a socket closed between
  two pages can make one read skip a line. Where `/proc` hides other users'
  processes from an unprivileged `nails check`, the table cannot be read, and
  the warning says that `nails check` run with sudo can tell. That socket is
  where every ticket cache of the KCM kind listens, Heimdal's among them, so
  it does not count either on a decoy that is not NixOS where no unit file of
  `sssd-kcm.socket` can be in `/etc/systemd/system.control`,
  `/run/systemd/system.control`, `/run/systemd/transient`,
  `/run/systemd/generator.early`, `/etc/systemd/system`,
  `/etc/systemd/system.attached`, `/run/systemd/system`,
  `/run/systemd/system.attached`, `/run/systemd/generator`,
  `/usr/local/lib/systemd/system`, `/usr/lib/systemd/system`,
  `/lib/systemd/system` or `/run/systemd/generator.late`, and a process whose
  name (`comm`) is `kcm` runs as root in PID 1's mount namespace, as Heimdal's
  KCM daemon does. A directory a link leads to, or one a lookup on the way to
  fails, can hold one, since the check follows no link: so on a merged `/usr`,
  where `/lib` is a link, and on NixOS a socket something listens on always
  counts. Any process can take that name, so root is read from the real and
  effective user on the `Uid:` line of its status, and a root process in a
  container without a user namespace of its own runs in a mount namespace
  other than PID 1's. A socket file that the table shows nothing listening on,
  which a stopped socket leaves until the next boot, does not count;
- `/var/lib/sss` holds one of nine files sssd writes when it runs: its two
  configuration databases (`db/config.ldb`, `db/config_kcm.ldb`), the four
  memory caches of its NSS responder (`mc/passwd`, `mc/group`,
  `mc/initgroups`, `mc/sid`), the database of its Kerberos ticket cache
  (`secrets/secrets.ldb`) and the sockets of its NSS and PAM responders
  (`pipes/nss`, `pipes/pam`). Only root can see some of them, so run
  `nails check` with sudo to see them all.

The probes read file metadata and `/proc`, `/run` and `/sys`, never a file or
a directory listing on the decoy disk, so no access time there changes. That is
also why the check looks for those nine files by name: sssd keeps more under
`/var/lib/sss`, such as the cache of each domain, named after the domain, and
finding those would take a listing of its directories. Fedora 44 Cloud enables
`sssd-kcm.socket` by default, so a decoy made from it warns even when it is not
joined to a domain.

Use a decoy that is not joined to a domain. Where nothing on the decoy needs
sssd, disable it, then delete the nine state files the warning looks for:

```bash
sudo systemctl disable --now sssd.service
sudo systemctl disable --now sssd-kcm.socket
sudo rm -f /var/lib/sss/db/config.ldb /var/lib/sss/db/config_kcm.ldb \
  /var/lib/sss/mc/passwd /var/lib/sss/mc/group /var/lib/sss/mc/initgroups \
  /var/lib/sss/mc/sid /var/lib/sss/secrets/secrets.ldb \
  /var/lib/sss/pipes/nss /var/lib/sss/pipes/pam
```

Skip the second command where `sssd-kcm.socket` does not exist: Debian and
Ubuntu install it only with the `sssd-kcm` package. Keep the two commands
apart: systemd before 257 refuses a `disable` that names a unit it does not
have and leaves every unit as it was. On NixOS the configuration owns the
units, so `systemctl disable` cannot change them: set `services.sssd.enable`
and `services.sssd.kcm` to `false` and run `nixos-rebuild switch` in place of
the two `systemctl` commands.

Stopping sssd leaves those of the nine it wrote in place until they are deleted,
and each of them keeps the warning, so the warning names the ones it finds and
the `rm` that deletes them. The socket file stays in `/run` until the next boot,
but once `sssd-kcm.socket` is stopped, PID 1's socket table shows nothing
listening on it and it no longer counts, so nothing here deletes it. Where that
table cannot be read, the socket file counts until the next boot. Another daemon
listening on that socket, such as Heimdal's `kcm`, keeps it counting unless the
check rules sssd's unit out as above. The rest of sssd's state under
`/var/lib/sss`, such as the cache of each domain, neither keeps the warning nor
goes with that `rm`: the warning can clear while it is still on the decoy disk.
Deleting the nine files once sssd is stopped is safe: sssd builds its
configuration databases again from `sssd.conf` at every start, and makes its
memory caches, its sockets and an empty ticket database anew. What is lost is
the Kerberos tickets its ticket cache kept, which nothing reaches while
`sssd-kcm` is off. On Fedora, turning `sssd-kcm` off also turns off the ticket
cache that `kinit` uses by default.

## The locate database

updatedb, the indexer behind `locate` (plocate, mlocate, and NixOS's
`services.locate`), walks the whole tree and writes the name of every file it
finds into the locate database on the decoy disk:
`/var/lib/plocate/plocate.db`, `/var/lib/mlocate/mlocate.db`, or
`/var/cache/locatedb` on NixOS. A run while the hidden volume is mounted on the
decoy, before activation or after the way back, writes every name on the
volume there, where `locate` lists it. plocate's and NixOS's timers run daily
with `Persistent=true`, which catches a missed run up right after boot, when
the volume is unlocked for a session. Fedora installs and enables plocate by
default. The default `PRUNEPATHS` of Debian 13, Ubuntu 26.04, Fedora 44 and
NixOS do not skip `/mnt`; Arch Linux's does.

The `locate-database` check refuses activation while an updatedb that runs now,
or that a timer, a path unit, an enabled service or a cron job it reads (below)
starts, does not skip the hidden volume, whatever flags the run is given. It
warns instead, and does not refuse, where it cannot tell: an
`/etc/updatedb.conf` it cannot read, or one that updatedb refuses and stops
on; a command or option it does not follow; findutils' updatedb, whose prune
options it does not read; a unit directory, crontab, cron script,
`/etc/passwd` or process it cannot read, or a `/proc` that hides processes
from it; a timer it cannot ask the system manager about, or one whose `Unit=`
has a specifier the host fills in (below). An unprivileged
`nails check` cannot read root's crontab or a cron directory only root may
list, so run it with sudo. It also warns when updatedb is installed but only a person starts it
and does not skip the volume. When every run skips it, the check passes and
names the rule that does.

What it reads:

- **Services.** A service runs updatedb when a command of its `[Service]`
  section (`ExecStart=`, `ExecStartPre=`, `ExecStartPost=`, `ExecCondition=`,
  `ExecReload=`, `ExecStop=`, `ExecStopPost=`) runs a program named `updatedb`
  or `updatedb.*`, or passes such a word to the program it runs (`nice`,
  `flock`, `sh -c updatedb`). Only a plain path counts as such a word: the
  whole script of `sh -c '…'`, or any word with a blank, a quote, `;`, `|`,
  `&` or `$` in it, is a script NAILS cannot tell about, however it ends. It
  runs now when the system manager shows it active. It is scheduled when a
  timer or path unit starts it (its first `Unit=` systemd takes, or the service
  of its own name, with the specifiers of the timer's own name expanded from
  the name of its unit file, see
  [tuned, firewalld and ABRT](#tuned-firewalld-and-abrt); one whose `Unit=` has
  a specifier the host fills in, such as `%H`, is a timer NAILS cannot tell
  about where the name of a unit on the disk fits the rest of the value) that
  is enabled, or that the system manager runs as `systemctl list-units` shows
  it: one started with `systemctl start`, an instance of a template, a
  transient one as `systemd-run --on-calendar` makes it in
  `/run/systemd/transient`, and one masked, or whose file is gone, since it
  started (systemd leaves no file that says a timer runs, and the file of a
  transient one may stay a while after it stops); and when it is enabled
  itself: an entry for it in a `.wants`, `.requires` or `.upholds` directory,
  as `systemctl enable` and `systemctl add-wants` make. Such a service runs
  again at the soft-reboot back to the decoy. Where NAILS cannot ask the system
  manager, a transient trigger whose file is there counts, and one that is not
  enabled may run all the same, which warns. Units are read from every
  directory systemd loads them from (`/etc/systemd/system.control`,
  `/run/systemd/system.control`, `/run/systemd/transient`, the generator
  directories, `/etc/systemd/system`, `/run/systemd/system`, their `.attached`
  siblings, `/usr/local/lib/systemd/system`, `/usr/lib/systemd/system` and
  `/lib/systemd/system`), with the drop-ins of the unit, of its template, of
  its name's prefixes and of its aliases, read as for
  [tuned, firewalld and ABRT](#tuned-firewalld-and-abrt), and an instance is
  read from its template. Users' managers count too: the units in each home
  `/etc/passwd` names, in the other directories of `/home` and in the other
  numbers of `/run/user` (`~/.config/systemd/user`,
  `~/.local/share/systemd/user`, `/run/user/<uid>/systemd/…`), and those every
  user shares (`/etc/systemd/user`, `/usr/lib/systemd/user` and the others). Of
  a user's timers only an enabled or a transient one counts: NAILS asks no
  user's manager what it runs. `plocate-updatedb.service`,
  `mlocate-updatedb.service` and `update-locatedb.service` with nothing
  starting them are ones a person starts. A unit file that is empty or a link
  to `/dev/null` masks its unit.
- **Cron.** `/etc/crontab`, the files of `/etc/cron.d`, root's and the users'
  crontabs (`/var/spool/cron/crontabs`, `/var/spool/cron`), `/etc/anacrontab`,
  and the scripts of `/etc/cron.hourly`, `daily`, `weekly` and `monthly`. A
  crontab line is a job when it starts with its schedule, after the `-` with
  which cronie (Fedora, Arch) runs a job it does not log; its command ends at
  the first `%` no backslash escapes, and cron feeds the rest to it as input,
  each further `%` a newline, which a shell reads as a script: that is read as
  one too. anacron hands its command to the shell as it is. Comments and
  settings are no jobs. A
  command or script is read as the shell splits it: quotes and backslashes,
  commands split at `;`, `&`, `|`, `&&`, `||` and parentheses, comments,
  redirections, and the first `updatedb` word of a command as the program,
  whatever runs it. A command whose updatedb gets a word the shell expands (a
  variable, a backquoted command, a glob), or that names updatedb in a
  variable or in the script of `sh -c '…'`, is one NAILS cannot tell about: it
  does not follow variables. Debian's and Ubuntu's `/etc/cron.daily/plocate`
  ends at once where systemd runs, so it does not count while that test is its
  first command (after `set -e` and plain assignments).
- **Processes.** A process whose name or program is an updatedb runs now, one
  started by hand among them, and is judged by its own command line. One whose
  name is `updatedb` but whose program is a shell runs a script, such as
  findutils' updatedb, which NAILS does not read. A `/proc` NAILS cannot list,
  one that hides process 1 from it (mounted with `hidepid`), and processes it
  cannot read may hide an updatedb, which warns.
- **Programs.** An updatedb in `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`,
  `/usr/local` or NixOS's system profile is one a person starts.
- **What a run skips.** `/etc/updatedb.conf`, or the file `--config-file`
  names (plocate 1.1.24 and later, as Fedora 44, Arch and NixOS ship; a file it
  names that does not exist stops updatedb), read as plocate and mlocate read
  it (`PRUNEPATHS`, `PRUNENAMES`, `PRUNEFS`), with the options of the run's
  command line on top, read as updatedb's `getopt_long()` reads them (a unique
  prefix such as `--data`, a cluster such as `-vU/mnt/data`):
  `--prunepaths`, `--prunefs` and `--prunenames` replace the file's list,
  `--add-prunepaths` (`-e`), `--add-single-prunepath`, `--add-prunefs` and
  `--add-prunenames` add to it, and `--database-root` (`-U`) starts the scan
  in another directory. A relative path resolves from where updatedb runs: for
  a service without `WorkingDirectory=`, `/` under the system manager and the
  user's home under a user's, and a process's own working directory. A
  relative path in a cron job, in a unit every user's manager runs, or in a
  service that sets `WorkingDirectory=`, is one NAILS cannot tell about. An
  `ExecStart=` is read as systemd reads it, an escape systemd does not know
  keeping its backslash.
- **The volume.** The hidden root where its links lead, and every other mount
  of the filesystem mounted there. updatedb skips it when a `PRUNEPATHS` entry
  is exactly one of the directories from the scan root down to it (`/mnt` or
  `/mnt/data` skip `/mnt/data`, `/mnt/` skips nothing), when a `PRUNENAMES`
  entry is the name of one of them below the scan root, when a `PRUNEFS` entry
  is, in any ASCII case, the type of a filesystem mounted on the way below the
  scan root where the device changes, or when the scan starts elsewhere.
  `PRUNE_BIND_MOUNTS` does not count: a volume mounted from its device is no
  bind mount.

It does not see:

- a script that a service or a cron job runs by its name and that runs
  updatedb itself;
- a service another unit pulls in with `Wants=` or `Requires=` in its own
  file, or that a socket, a udev rule or a target starts;
- `at` and `batch` jobs, which it does not read;
- a user's timer started with `systemctl --user start` and not enabled, as no
  user's manager is asked what it runs, and a user's updatedb running now
  other than by its process.

The check writes nothing. It opens each file it reads with `O_NOATIME`, so run
as root it changes none of their access times (an unprivileged `nails check`
cannot ask for that, and the links a lookup follows still get theirs), and it
reads no file that a link leads onto the hidden volume. It runs `systemctl
list-units`, which does change the access time of `systemctl` and the libraries
it loads, at most once a day under the default `relatime`, as activation's own
`systemctl` calls do.

Make updatedb skip the directory the volume is mounted in long before you use
the volume again, since a change made just before a session dates it, and keep
the volume locked until then:

- On NixOS, leave `services.locate` disabled, or add the directory:

  ```nix
  services.locate.prunePaths = lib.mkOptionDefault [ "/mnt" ];
  ```

  `lib.mkOptionDefault` adds to the default list, and only while no other
  definition sets the option; a plain list replaces the default, and `/tmp`,
  `/nix/store` and the rest of it are then indexed. Where the configuration
  sets `services.locate.prunePaths` itself, the check sees a list other than
  the default and says to add `/mnt` to that list. Another definition joins it
  only at the same priority: a plain list joins a plain list, replaces one set
  with `lib.mkDefault` or `lib.mkOptionDefault`, and is dropped beside one set
  with `lib.mkForce`. A configuration that sets exactly the default list looks
  like none to the check, whose `lib.mkOptionDefault` line then does nothing:
  add `/mnt` to that list. The line names
  `/mnt`, not the mount point `/mnt/data`, so the `suspicious-nails-reference`
  check does not refuse it; a mount of the volume below its root is pruned
  with it. For a volume mounted right below `/`, leave `services.locate`
  disabled: an entry that skips it would name its mount point.
- On Debian, Ubuntu and Fedora, add the directory to `PRUNEPATHS` in
  `/etc/updatedb.conf`, or stop what starts updatedb: mask and stop the timer
  with `sudo systemctl mask --now plocate-updatedb.timer` (a mask alone leaves
  a running timer running), mask a service that is enabled itself, stop a
  transient timer, remove the cron job. The check names each one it finds.
  With the timer masked and `PRUNEPATHS` as it was, the check still warns,
  since a run by hand indexes the volume. A run that reads another file with
  `--config-file`, or replaces the list with its own options, needs the
  directory there.

The check cannot see a run that already happened. A database written while the
volume was mounted lists the volume's files until updatedb runs again with the
volume locked.

## Nix on the decoy

On every distribution but NixOS, install Nix inside a hidden session, never on
the decoy. Inside a session everything the installer and Nix write lands on the
hidden volume: the store under `/nix`, the installer's files in `/etc`, the
build users in the session's copy of `/etc/passwd`. A Nix installed on the
decoy writes to the decoy disk instead, and so does everything it installs or
builds there: each store path is named after its package and recorded in the
store's database, and the installer adds a daemon, build users and shell hooks
to the decoy's own files. On NixOS, Nix is the system's package manager, and
none of this applies.

The `decoy-nix-trace` check warns when a decoy that is not NixOS holds what a
Nix install leaves behind. It looks for:

- `/nix`, whatever it is: a directory, even an empty one, a file, or a link,
  even one to nothing;
- `nix-daemon.service` and `nix-daemon.socket` in `/etc/systemd/system`,
  `/usr/local/lib/systemd/system`, `/usr/lib/systemd/system` and
  `/lib/systemd/system`, a link to one in a `.wants`, `.requires` or
  `.upholds` directory of `/etc/systemd/system`, a drop-in directory for one
  there, and `/etc/tmpfiles.d/nix-daemon.conf`;
- `/etc/nix`, and a `nix` command in `/usr/bin`, where a distribution's
  package puts it, or in `/usr/local/bin`;
- the `nixbld` group in `/etc/group` and `/etc/gshadow`, and the build users
  in `/etc/passwd` and `/etc/shadow`: `nixbld` or `_nixbld` followed by a
  number, and in `/etc/passwd` any user whose group is `nixbld`. It looks in
  `/etc/group-`, `/etc/gshadow-`, `/etc/passwd-` and `/etc/shadow-` as well,
  the copy of each file that shadow-utils keeps as it was before its last
  change: after `userdel` and `groupdel` remove the build users and the group,
  these copies still name the group and the last user removed;
- the shell hooks: `/etc/profile.d/nix.sh` and `nix-daemon.sh`,
  `conf.d/nix.fish` in `/etc/fish`, `/usr/local/etc/fish`,
  `/opt/homebrew/etc/fish` and `/opt/local/etc/fish`, a line naming
  `/nix/var/nix/profiles/` or `.nix-profile/etc/profile.d/` in `/etc/bashrc`,
  `/etc/bash.bashrc`, `/etc/profile`, `/etc/zshrc` or `/etc/zsh/zshrc`, and the
  copy the installer keeps of each of these files but `/etc/profile`, and of
  `/etc/profile.d/nix.sh`, with `.backup-before-nix` added to its name;
- in `/root` and in each home `/etc/passwd` names: `.nix-profile`,
  `.nix-defexpr`, `.nix-channels`, `.local/state/nix`, `.local/share/nix`,
  `.cache/nix`, `.config/nix` and `.config/fish/conf.d/nix.fish`, and such a
  line in `.bash_profile`, `.bash_login`, `.profile`, `.bashrc`, `.zshenv` or
  `.zshrc`, where the single-user installer adds its hook.

It names each one it finds and never refuses, since the decoy may need Nix for
itself. Where it cannot look up a path or read a file, the warning says so, so
a decoy it could not see never passes: run `check` with sudo, which the shadow
files and their copies need in any case. On NixOS it passes. Inside a hidden
session it is skipped, because `/` shows the session's own files there, its own
Nix among them.

It does not look into a home that lies on the hidden volume, as `/etc/passwd`
names it or where its links lead.

The check writes nothing, and mounts nothing but in the one case below. It
opens each file it reads with `O_NOATIME`, so run as root it changes none of
their access times (an unprivileged `nails check` cannot ask for that, and the
links a lookup follows still get theirs), and it reads no file that a link
leads onto the hidden volume. As the other checks that look into the homes and `/usr/local` do, it
makes no lookup that would mount an automount point that nothing is mounted on
yet ([What `check` touches](operator-guide.md#what-check-touches)): the
warning names the path, or the home, and the automount point instead, and
once something is mounted there, the check looks it up. A name of an indirect
map, such as a home, whose mount expires while the check runs can be mounted
again by its own reading of the way there. Where it cannot read the mount table, it looks up
nothing and says so.

When it warns, use the decoy's Nix only for what the decoy itself needs, and
install the hidden session's software inside a hidden session. If the decoy
does not need Nix, remove it and the traces the check lists long before the
next session, as the uninstall steps of the installer you used describe. Nix's
own steps remove the build users and the group with `userdel` and `groupdel`,
which leave them in the copies `/etc/passwd-`, `/etc/shadow-`, `/etc/group-`
and `/etc/gshadow-`: the check names each copy until a later change to its file
replaces it, or you copy the file over it. What Nix wrote to the decoy disk
while it was there can stay readable after it is removed, in the filesystem's
journal and in unallocated blocks, as any deleted file can.

The check reads neither the store's database nor what the store holds, and it
does not look for a Nix installed anywhere else, such as a store at another
path or a `nix` binary in a user's own directories.

The distribution test `debian-13-nix-trace` shows both sides on Debian 13. It
installs Nix in a hidden session with Nix's multi-user installer, from the
contents of a release tarball that it builds as Nix builds its own, and uses it
to write to the store, through a build as a build user among other ways. After
the way back the check reports what it reported before the session, and an
image of the decoy's disk shows none of the marks the test looks for: the
session's store writes, the installer's files, the names of the store paths it
copies and three of the lines it writes. Installed the same way on the decoy,
Nix is named by the check, each path it looks for that the install left
included, and the image shows the store and those three lines
([details](../nix/e2e-tests/README.md#the-nix-scenario)).

## Session-time records

Some records do not hold what the session did, only that the machine was
running. An examiner compares them with the decoy's own logs, and unexplained
uptime points to use the decoy does not account for.

- **The timesyncd clock stamp.** `systemd-timesyncd` touches
  `/var/lib/systemd/timesync/clock` at each sync and at shutdown. The session's
  touches go to the upper, but the decoy's own shutdown before the session and
  its start after it stamp the decoy copy.
- **chrony's drift and clock files.** A decoy that runs chrony instead (the
  default on Fedora, and on Ubuntu installed since 25.10, 26.04 among them)
  rewrites its measured drift and real-time-clock offset under
  `/var/lib/chrony` periodically and at shutdown, which dates the decoy's runs
  the same way. A NixOS decoy runs it when `services.chrony` is enabled.
- **Persistent timer stamps.** Timers with `Persistent=true` record their last
  run under `/var/lib/systemd/timers`. Runs during the session land in the
  upper; at the next decoy boot, missed timers catch up at once, which dates the
  gap.
- **SMART power-on hours.** The drive counts the hours it is powered, in
  firmware. No software can change or hide this; a decoy that is used normally
  keeps its logged uptime plausible.

If `/var` is on a wiped-on-boot tmpfs, the first three are wiped at every boot
anyway. `verify` reports their timestamps as notes, so you can see what an
examiner would see.

## Attaching the drive

The routine is to attach the drive that holds the hidden volume, unlock the
volume from a terminal with `cryptsetup open`, mount it at the hidden root and
activate. A desktop that mounts drives by itself can mount the unlocked
filesystem a second time: gnome-shell through gvfs and udisks2, KDE Plasma's
Device Auto-Mount once it is turned on, and udiskie mount a new filesystem under
`/media/<user>/` on Debian and Ubuntu, and under `/run/media/<user>/` on most
other distributions, in a directory named after the filesystem's label or UUID.
While it is mounted there, the decoy's desktop reaches the hidden files. On
Debian and Ubuntu that directory is made on the decoy's root filesystem, and
its name can stay there after the directory is gone, in the filesystem's
journal or in the blocks of `/media/<user>`.

Whether a desktop mounts a mapping that `cryptsetup` opened, rather than one it
unlocked itself, depends on the desktop and its release, and is not verified
for GNOME or KDE Plasma. udiskie does: in the `routine-automount` VM test,
where it runs as a root service, it mounted the mapping that `cryptsetup`
opened on a USB stick at `/run/media/root/<UUID>` less than two seconds after
the mapping appeared, sooner than a person types the mount line. The test
records what udiskie does in each run.

NAILS cannot keep a desktop from doing this, and it changes no setting of the
decoy. Instead `check` and activation refuse, with no flag to lift it, while
the volume's filesystem is also mounted at another place in the decoy's mount
table, the one `findmnt` lists (`hidden-volume`, exit 4). Every mount of the
same filesystem there counts, a bind of a folder of it and another btrfs
subvolume of it included. A mount made in another mount namespace, such as a
container's, is not in that table and is not seen. The refusal names each
other mount point and how to unmount it, such as
`sudo umount /media/alice/data`, and for a mount that a later mount hides, the
mount over it, which has to go first. A bind of the volume at the hidden root
itself is no second mount, and neither is one below a next root mounted at
`/run/nextroot`, where an activation binds the volume (`session-state` refuses
while one is mounted).

A hidden root on a filesystem the decoy uses, accepted with
`--allow-decoy-storage`, is judged as well, with two kinds of mounts left out.
One is the decoy's own mounts of that filesystem: the one at `/`, and one that
a line of `/etc/fstab` makes. That is a line for that mount point that names
the mount's device (for a ZFS dataset, the dataset) and mounts what the mount
shows: the filesystem's top, or the btrfs subvolume its `subvol=` or
`subvolid=` names (with both, the one both name), as the mount table shows
that subvolume's path and id, but never a folder bound there by hand. Or it is
a bind line whose source lies on another of the decoy's own mounts of that
filesystem, and the mount shows that source's folder. A line whose
`subvolid=` is no number makes no mount of the decoy's, and neither does a
line with `subvolid=` for a mount whose id the mount table does not show. The
other is a mount that shows none of the root's folder,
such as NixOS's read-only bind of `/nix/store` beside a bind of a folder of
`/`, or another btrfs subvolume. So the `hidden-volume` check passes a bind of
a folder of `/`, or a subvolume of a filesystem the fstab mounts, with the
flag's warning, while a separate drive also mounted at `/srv` is refused with
`sudo umount /srv`. The `backend-entries` check lets be the decoy's own fstab
lines that its boot mounts at `/` or at a system folder for such a root's
filesystem: `/usr`, `/var`, `/home`, `/srv`, `/boot`, `/efi`, `/boot/efi`,
`/nix` and `/opt`, unless the hidden root is that folder or lies above it. So
`backend-entries` passes a bind of a folder of `/`, or a subvolume beside the
fstab's `/home`, as well. On NixOS, `suspicious-nails-reference` still refuses
such a root while the decoy's `/etc/nixos` names the device of its filesystem,
as the `hardware-configuration.nix` of most installs does for every filesystem
it lists. A line that names the device of that filesystem for any other
folder, such as `/pool`, `/var/log` or `/.snapshots`, still fails
`backend-entries`, since it may name the hidden drive's disk, and the check
says to put the hidden root on storage of its own instead.

A root is refused as well when a mount that no fstab line makes shows its
folder, such as a bind of a folder of a `/home` or `/srv` partition that
systemd-gpt-auto-generator mounts, of ostree's `/sysroot`, or of a ZFS dataset
that ZFS mounts by its mountpoint property. The refusal then first says not to
unmount a mount this computer makes by itself but to use a volume of its own
instead, and only then how to unmount one made by hand. Do not unmount such a
mount: once a `/home` or `/srv` partition that no fstab line names is no
longer mounted, nothing shows the check that a root on it lies on this
computer's storage.

Choose a hidden root that lies neither at nor below either place of a bind of
a folder. systemd makes the mounts shared, so a bind that it mounts from
fstab, or that a person makes later, can pass a mount made at or below one of
its two places on to the other: with `/persist/mnt` bound at `/mnt`, the
volume mounted at `/mnt/data` is also mounted at `/persist/mnt/data`, and with
`/persist/home` bound at `/home`, a volume mounted at `/persist/home` is also
mounted at `/home`. That copy is a second mount, and unmounting it unmounts the
root as well.

Turn the automatic mounting of removable media off long before the next use,
so that the change is not dated next to a session, and unlock the drive from a
terminal, not from the desktop's prompt or file manager, which leave udisks2
state behind (see [udisks2 state](#udisks2-state)). The settings, which are not
verified for every release:

- **GNOME:** `gsettings set org.gnome.desktop.media-handling automount false`,
  run as the desktop user.
- **KDE Plasma:** System Settings, Device Auto-Mount: leave the automatic
  mounting of removable media off (Plasma's own default), for all devices and
  for each device it lists, on login and on attach. The device notifier then
  only offers to mount the drive. Do not take the offer.
- **udiskie:** start it with `--no-automount`, or not at all.

## Setup traces an examiner looks for

An examiner looks for traces of the setup as well as of a session: the backend's
headers and tooling, configuration that opens encrypted storage, and history
that names a container. `nails verify --offline --root <image> --examiner`
reports these on a decoy image mounted so that nothing writes to its disk (see
[Verifying the decoy](operator-guide.md#verifying-the-decoy)), grouped by what
an examiner would conclude from them. It reports only and changes nothing.

### LVM metadata archives

LVM writes a copy of a volume group's metadata to `/etc/lvm/archive` before
every change and to `/etc/lvm/backup` after it, with the command line, host name
and time. Running `pvcreate`, `vgcreate` or `lvchange` on the hidden backend from
the decoy records a volume group the decoy does not use. Do not run LVM tools on
the hidden backend from the decoy, or set `archive = 0` and `backup = 0` in the
decoy's `/etc/lvm/lvm.conf` before you ever do.

### udisks2 state

Unlocking or mounting the backend through udisks (a file manager, GNOME Disks,
`udisksctl`) leaves per-drive state under `/var/lib/udisks2` and asks the
keyring to remember passphrases. Unlock and mount the backend with `cryptsetup`
and `mount` from a shell instead.

### crypttab and fstab

An entry in `/etc/crypttab` or `/etc/fstab` for the hidden backend (a tcrypt or
VeraCrypt mapping, a loop-mounted container, an unexplained mapper name) tells an
examiner where to look. The decoy's own full-disk encryption legitimately has an
entry; the hidden backend never should. Open it by hand each time.

The `backend-entries` pre-flight check enforces this for the mounted hidden
volume: `nails check` and activation fail while a crypttab line opens it or a
device it is stored on, while a crypttab line with `tcrypt-hidden` opens a
device on the hidden volume's drive or one that cannot be found, or while an
fstab line mounts it or a device below it, `noauto` lines included. A crypttab
line that opens only another volume on the same drive (a VeraCrypt outer volume
on another partition) warns. Remove such a line long before the next use, since
the decoy's configuration history can keep it. A line the decoy's own boot needs
(one that mounts its root or another of its filesystems or its swap, or opens a
device below one of them) cannot go: the hidden root then lies on the decoy's own
storage, and the check says to put it on storage of its own instead. The lines
only the hidden volume needs still go, and where both kinds are flagged the
check says both. If the check cannot read `/etc/crypttab` (some distributions
make it readable by root only), it fails and asks you to run the command with
sudo. `--allow-decoy-storage` covers only the decoy's own fstab lines that its
boot mounts at `/` or at a system folder for the filesystem it accepted the
hidden root on (see [Attaching the drive](#attaching-the-drive)).

### Encryption headers, high-entropy space and containers

The audit reads the raw disk when given `--disk` and reports:

- LUKS1 and LUKS2 headers at partition starts, in gaps and in the LUKS2
  secondary-header slots;
- gaps between partitions and space after the last one, sampled for entropy:
  random-looking bytes where a fresh disk holds zeros suggest a headerless
  encrypted volume;
- partitions with no known filesystem signature and high entropy;
- files larger than the threshold whose size is a multiple of 512, with no known
  header and high entropy: the TCHunt heuristic for TrueCrypt and VeraCrypt
  containers.

A VeraCrypt hidden volume inside an outer volume is indistinguishable from the
outer volume's free space; what stands out is the outer volume itself. Fill free
disk space with random data when the disk is set up so the encrypted region does
not stand out, and prefer a partition or whole device over a container file on
the decoy.

### Partition types systemd acts on

Unless the decoy masks it, systemd-gpt-auto-generator acts on the partitions
of one disk by their GPT type alone, at every boot: the disk it finds below
the decoy's root file system, one layer of devices down before systemd 259.1,
as from a LUKS volume to its partition, and every layer down from 259.1 on, as
through LVM on LUKS. There it mounts the first `/home`, `/srv`, `/var` or
`/var/tmp` partition without the no-auto flag at that folder when no fstab
line mounts the folder and the folder is empty (`/var` only with the uuid the
machine ID gives it), uses the first swap partition without that flag as swap
when no fstab line names a swap, and asks for the passphrase first when such a
partition is a LUKS volume. Ubuntu 24.04 and 26.04 mask it by default; Debian
13 and NixOS do not. Where it runs, a hidden volume on such a partition of
that disk can show itself at the decoy's next boot, and on any decoy and any
disk an examiner who reads the partition table sees a partition typed for a
use the decoy does not have. The `backend-partition-type` pre-flight check,
which reads no mask, refuses a partition of these types on a disk the decoy
boots from, whether or not the generator reads that disk, says whether it
does (or that it cannot tell, where sysfs does not list the devices below the
root file system), and gives the command that changes the type to the generic
Linux type, to run from a live system or where setup happens. With the no-auto
flag, a `/home`, `/srv`, `/var` or `/var/tmp` partition only warns, and a swap
partition is refused all the same (see [Partition type in
preflight](backends.md#partition-type-in-preflight)). A hidden volume on a
disk of its own, such as an external drive, is not affected.

### Backend tooling and history

VeraCrypt installed on a decoy, or a `cryptsetup` binary whose access time is
recent, says encrypted volumes were opened. VeraCrypt's `History.xml` and
`Favorite Volumes.xml`, a `recently-used.xbel` entry and a shell history line
running `cryptsetup` or `veracrypt` name the container and when it was used.
Disable VeraCrypt's history, harden the decoy shell history (see
[Shell history hardening](#shell-history-hardening)) and mount the decoy root
`noatime`.

## Residue catalog

Generated from the rows under `nails-forensics/src/residue_catalog/rows/`; do
not edit the tables by hand. A unit test fails when they drift; regenerate them with
`REGENERATE_CATALOG_DOCS=1 cargo test -p nails-forensics residue_catalog`.

A row with "none" in the pre-flight or verify column says why nothing at that
point checks the class; verify lists those classes among the areas it did not
check. A row with "none" in the VM-test column says why no VM test asserts it.

### Session residue

<!-- residue-catalog:begin session -->
| Class | Where | Platforms | Pre-flight | Verify | Mitigation | VM test |
|---|---|---|---|---|---|---|
| [Persistent systemd journal](#fail-closed-activation-is-refused) (`persistent-journal`) | `/var/log/journal` | all | `decoy-persistence` (refuses) | `journal-scan` | Set Storage=volatile under [Journal] in journald.conf or a journald.conf.d drop-in. | `decoy-persistence-preflight` |
| [Journal window around each soft-reboot](#what-the-decoy-journal-keeps) (`pre-entry-journal-window`) | journald records of `sudo nails activate`, the decoy shutdown before the soft-reboot and the decoy start after the way back | all | `decoy-persistence` (refuses) | `journal-scan` | Run on a volatile journal, so the window never reaches the decoy disk; keep the binary at a neutral path. | `decoy-journal-leak` |
| [Decoy journal reset by the way back](#what-the-decoy-journal-keeps) (`runtime-journal-reset`) | the runtime journal below /run/log/journal, which the decoy and the hidden journald write alike and the way back deletes | all | none: the scrub causes it, as the last step before the switch back | none: RAM only, gone at power-off | Power off after the session. | `session-lifecycle` |
| [Classic syslog daemon](#fail-closed-activation-is-refused) (`classic-syslog`) | `/var/log/syslog`, `/var/log/messages`, `/var/log/auth.log` | all | `decoy-persistence` (refuses) | `deep-scan-files` | Remove or disable the syslog daemon on the decoy. | `decoy-persistence-preflight` |
| [Audit daemon log](#fail-closed-activation-is-refused) (`auditd`) | `/var/log/audit` | all | `decoy-persistence` (refuses) | path probe (warn) | Turn auditd off for good, without a reboot: systemctl disable auditd.service and systemctl mask auditd.service, then auditctl --signal stop, which has the daemon stop itself (on Fedora and Arch its unit refuses a plain systemctl stop); on NixOS set security.auditd.enable = false, stop the daemon with auditctl --signal stop, then run nixos-rebuild switch. | `decoy-persistence-preflight` |
| [sudo log file](#the-sudo-log-exposure-and-its-mitigation) (`sudo-logfile`) | `/var/log/sudo.log` | all | `decoy-persistence` | path probe (warn) | Remove `Defaults logfile=` from sudoers and sudoers.d. | `examiner-audit` |
| [sudo I/O logging](#the-sudo-log-exposure-and-its-mitigation) (`sudo-io-log`) | `/var/log/sudo-io` | all | `decoy-persistence` | path probe (warn) | Remove every I/O logging option and tag from sudoers and sudoers.d. | `examiner-audit` |
| [Swap and hibernation](threat-model.md#assumptions) (`swap-hibernation`) | swap partitions and files, the hibernation image | all | `swap` (refuses) | `memory-swap` | No disk or file swap and no resume device; RAM-only zram is fine. | `preflight-swap` |
| [Crash dumps](#warn-surfaced-never-blocking) (`crash-dumps`) | `/var/lib/systemd/coredump`, `/var/crash` | all | `decoy-persistence` | path probe (warn) | Set systemd-coredump to Storage=none and ProcessSizeMax=0, and send other core dumps nowhere persistent: stop and disable a handler other than systemd-coredump, such as apport (systemctl disable --now apport.service), or discard the dumps with a kernel.core_pattern that pipes them to /bin/false, and mask a unit systemd-coredump starts for each crash, such as apport-coredump-hook@.service. | `examiner-audit` |
| [Armed kdump](#fail-closed-activation-is-refused) (`kdump`) | `/var/crash` | all | `decoy-persistence` (refuses) | none: the crash-dumps row probes /var/crash, where kdump writes its dumps | Disable kdump on the decoy (Ubuntu: kdump-tools, Fedora: kdump). | none: a VM test would have to reserve crash kernel memory and panic the guest kernel; the refusal is unit tested |
| [Locate database](#the-locate-database) (`locate-database`) | `/var/lib/plocate/plocate.db`, `/var/lib/mlocate/mlocate.db`, `/var/cache/locatedb` | all | `locate-database` (refuses) | path probe (info) | Make updatedb skip the directory the volume is mounted in (PRUNEPATHS in /etc/updatedb.conf, services.locate.prunePaths on NixOS), or stop what schedules it, long before the volume is next used. Activation refuses while an updatedb that runs now, or that a timer, path unit, enabled service or cron job the check reads starts, does not skip it; the docs name what the check does not read. | `locate-database` |
| [Shell history](#shell-history-hardening) (`shell-history`) | `~/.bash_history`, `~/.zsh_history` | all | `incremental-history-flush` | `deep-scan-history` | Harden the decoy shells' history and do not flush history during a session. | `session-emergency` |
| [Desktop recent-files lists](threat-model.md#what-the-hidden-environment-shares-with-the-decoy) (`desktop-recent-files`) | `~/.local/share/recently-used.xbel` | all | none: written by desktop applications during the session, into the upper on the hidden volume | `deep-scan-recent-files` | Hidden sessions write recent-file lists into the upper; never open hidden files from a decoy session. | `rehearse-canary` |
| [NAILS's own files and markers](threat-model.md#invariant) (`nails-artifacts`) | the paths and content markers listed in the artifact registry (nails-base/src/artifacts.rs) | all | `suspicious-nails-reference` (refuses) | `artifact-files` | Deactivate normally; `nails recover` finishes an interrupted teardown. | `verify-seeded-artifacts` |
| [NixOS account bookkeeping](threat-model.md#known-residual-changes) (`var-lib-nixos`) | `/var/lib/nixos` | NixOS | none: the decoy rewrites these files on every boot; only a control run tells noise from a leak | `platform-scanners` | Overlay /var; the drift test compares against a plain-reboot control. | `session-nixos-hidden-system` |
| [Decoy filesystems the hidden systemd would mount](#writes-that-bypass-the-overlays) (`decoy-filesystems`) | fstab entries of the hidden root, and the mount, swap and automount units its boot targets link outside the fstab: a separate /home or /var, the ESP, decoy swap, a second disk | all | `fstab-policy` (refuses) | none: verify cannot tell what a session wrote to another filesystem | NAILS binds the ESP and boot filesystems read-only, overlays other mounted decoy filesystems with an upper on the hidden volume, keeps swap and unmounted disks off (masked, or skipped where a boot target requires them, so that the target is still reached), refuses the activation for an entry at or below the hidden root, which the hidden systemd would mount over the hidden volume or inside it (in the fstab the hidden /etc holds in place of the decoy's, an activation without a build keeps such an entry off with a warning instead, so the session entered to remove it starts), decides the units the boot targets link outside the fstab the same way (a zram swap without a backing device stays on), and masks systemd's GPT auto-generator (which would mount partitions the fstab does not list) before the switch. | `soft-reboot-mechanics` |
| [Disks mounted during the hidden session](configuration.md#disks-mounted-during-the-session) (`session-disk-mounts`) | a USB drive udisks automounts, a decoy partition the policy masked mounted by hand, a Windows partition, a decoy mount unit that only another unit pulls in | all | none: the disk is mounted after activation | none: verify cannot tell what a session wrote to another disk | The session watcher alerts on every read-write disk mount that is not the session's own storage, which it tells by device (and by path below `<root>/root`, where NAILS keeps its layers), so a disk mounted elsewhere below the hidden root alerts too; `[session_mounts] read_only` makes every disk the session does not use read-only at the block layer for the session; deactivate unmounts them and the way back makes them writable again. | `session-disk-mounts` |
| [The hidden session's /run carried into the decoy](threat-model.md#residual-channels) (`run-carry-over`) | a soft-reboot carries /run: logind state, utmp, the runtime journal, utab lines, name-server records, stray files | all | none: the scrub runs as the last step before the switch back | `session-leftovers` | The transition step deletes the runtime journal and logind's session state whole, and whatever else the hidden session added two levels below /run (three below /run/systemd), judged against what the decoy left when it stopped for the entry; it puts the decoy's name-server records below /run/resolvconf back, gives the decoy's utab lines back to the mounts it restores, under their new mount IDs, and never touches sockets or /run/udev. | `session-lifecycle`, `session-emergency`, `session-dns-records` |
| [An interrupted entry's runtime files in /run](threat-model.md#residual-channels) (`interrupted-entry`) | an activation killed before the soft-reboot leaves /run/nextroot, the session plan and the transition drop-in | all | `session-state` (refuses) | `session-leftovers` | The transition drop-in is installed before the next root is populated, so an unarmed entry is disarmed by any soft-reboot; `nails recover` removes the leftovers. | `session-interrupted-entry` |
| [Hidden kernel records imported by the decoy journal](threat-model.md#residual-channels) (`kmsg-import`) | journald reads /dev/kmsg from its stored sequence number after every soft-reboot | all | `decoy-persistence` | `journal-scan` | The transition step writes the decoy journald's kmsg cursor past every hidden record; only PID 1's last lines follow it, whose final `Sending SIGKILL to PID N (<name>)` lines name each process of the hidden session still alive then, with the hidden filesystem's unmount line and, on a kernel that audits device-mapper changes (Fedora's does), the audit record of the hidden volume's dm-crypt teardown, and on Fedora 44 a device-mapper line that a device was left open. | `soft-reboot-mechanics` |
| [Network state the hidden session created or changed](operator-guide.md#how-it-works) (`network-state`) | a soft-reboot keeps the kernel's network state across the switch, so the links, addresses, routes, policy-routing rules, firewall tables and network settings the hidden session set up, and any MAC address or hostname it changed, are still live when the way back begins | all | none: the hidden session creates them after activation | none: a link the decoy adopted looks like one the decoy made itself | A deactivate or a plain emergency puts most of it back on its own. Stop VPN apps, containers and virtual machines in the session before you deactivate (wg-quick down, nmcli connection down, the app's own disconnect), keep nftables installed on the decoy so the way back sees the firewall tables, and end the session with `--poweroff` when none of its network state may reach the decoy. | `session-dns-records`, `session-nixos-hidden-system`, `session-mac-restore`, `session-wayback-poweroff` |
| [Soft-reboot counter and boot ID](threat-model.md#residual-channels) (`soft-reboot-counter`) | SoftRebootsCount (systemd 256 and newer) and the unchanged boot ID and uptime, readable with systemctl and journalctl | all | none: kernel and PID 1 state, not a file | none: RAM only, gone at power-off | Power off after the session; keep the decoy journal volatile. | `soft-reboot-mechanics` |
| [Login and boot records around a switch](threat-model.md#residual-channels) (`login-boot-records`) | the decoy's own writers record the way back in the login and boot records (classic wtmp, wtmpdb, and the getty and login records) | all | none: the records are written by the decoy's own units after the switch, not before it | none: the records are the decoy's own; verify reports the pieces the way back leaves in /run when their step never ran | The way back dates the decoy's start with the time of the switch, without masking either writer, so no row goes missing: the wtmpdb boot writer starts in a time namespace whose boot clock starts at the switch and itself writes the ordinary reboot row, and a backdated classic-wtmp boot record is corrected to that time, so the login and boot records read as one clean power cycle. Until the next power-off, anyone with a shell on the decoy sees the one-shot that did this in the journal and both units loaded from files that are gone in systemctl status. As its last step before the decoy starts, the way back also sets the kernel's process-number counter back: the entry records the number the decoy's boot gave its getty (else logind), the hidden session's own start shows how many numbers a start uses up to its copy of it, and the counter goes that many below. Where the getty is what it measures by, the decoy's getty gets about the number its own boot gave it, as far as the hidden start runs about as many processes up to its getty as the decoy's does. A getty or logind started more than a minute after the oldest process of its start that still runs, such as a getty started again after a logout, is passed over. When the getty is passed over, the measure goes by logind, or, without logind either, the counter goes to just below the lowest number the decoy's own userspace held at entry, and no test checks where the getty lands then. The decoy's other units are not measured. That step is best effort: where it cannot write the counter, deactivate warns before the switch and the numbers continue from the decoy's boot, and where it has neither a getty nor logind to measure by, deactivate warns as well; only ending the session with --poweroff, which has no way back, leaves none of them then. | none: asserted against a power cycle past five minutes of uptime by the cross-distro login- and boot-record test under nix/distro-tests (Debian 13 and Ubuntu 24.04), run on a KVM host outside the NixOS e2e suite; the process numbers of the getty and its records after the way back, in a first session and in a second one beside a unit every soft-reboot leaves running, are asserted against two fresh boots by the NixOS test session-fresh-pids |
| [The decoy's mounts made again by the way back](operator-guide.md#how-it-works) (`decoy-mount-table`) | the mount table after the way back: the decoy's mounts made again with new mount IDs and peer groups, its root and its initrd's mounts (the store bind) included; /run/credentials a mount of its own; the boot's mounts below /run gone | all | none: the mount table is kernel state; activation warns about a decoy mount the way back cannot make again at a place the session carries, and about one a plain soft-reboot keeps | none: RAM only, gone at power-off | The way back makes every decoy mount it can take from the decoy root or a filesystem the session carried again as the decoy had it when the entry began (its filesystem, the directory of it the mount shows, its place in a stack, its options), NixOS's read-only store bind included, and gives the decoy its utab lines back with them. Power off after the session. | `session-decoy-mount-table`, `session-emergency` |
| [EFI NVRAM, RTC and firmware pstore](threat-model.md#invariant) (`firmware-state`) | EFI variables, the real-time clock, firmware-backed pstore | all | none: not filesystem state, so nothing on the decoy root shows it | none: EFI variables and firmware storage are not part of a disk image | NAILS never writes NVRAM; avoid firmware tools inside the session. | `uefi-esp-nvram-invariant` |
| [Memory remanence](operator-guide.md#cold-boot-and-running-memory-attacks) (`ram-remanence`) | DRAM contents until power-off | all | `memory-wipe` | `memory-swap` | Power off (`--poweroff`) before handing the machine over; boot the decoy with init_on_free=1. | none: memory forensics is out of scope; no VM test images RAM |
| [timesyncd clock stamp](#session-time-records) (`timesync-clock`) | `/var/lib/systemd/timesync/clock` | all | path probe (info; a path it cannot look up warns) | path probe (info) | Session touches land in the upper; on a persistent decoy, use the decoy normally after a session so its own activity follows the stamp. | `examiner-audit` |
| [Persistent timer stamps](#session-time-records) (`timer-stamps`) | `/var/lib/systemd/timers` | all | path probe (info; a path it cannot look up warns) | path probe (info) | Session stamps land in the upper; expect catch-up runs at the next decoy boot. | `examiner-audit` |
| [SMART power-on hours](#session-time-records) (`smart-power-on-hours`) | the drive's own power-on-hours and power-cycle counters | all | none: not filesystem state, so nothing on the decoy root shows it | none: a disk image does not carry SMART counters | None in software; use the decoy normally so its logged uptime is plausible. | none: virtual disks have no SMART log |
| [SSD flash-translation-layer remnants](operator-guide.md#ssd-wear-levelling) (`ssd-ftl-remnants`) | remapped and over-provisioned flash blocks | all | none: not filesystem state, so nothing on the decoy root shows it | none: no host-side read reaches remapped flash cells, so `nails rehearse` cannot see them either | Full-disk encryption on the decoy, so remnants are ciphertext; no TRIM on a volume that holds a hidden volume. | none: virtual disks have no flash translation layer |
| [chrony clock drift and RTC records](#session-time-records) (`chrony-drift`) | `/var/lib/chrony` | all | path probe (info; a path it cannot look up warns) | path probe (info) | Session writes land in the upper; on a persistent decoy, use the decoy normally after a session so its own clock activity follows the stamp. | none: asserted on the Fedora and Arch decoys by the cross-distro forensic probe once their images boot; shares the session-time-records mitigation meanwhile |
| [NetworkManager connection records](operator-guide.md#how-it-works) (`networkmanager-connection-records`) | NetworkManager's per-connection timestamps and seen-BSSID lists under /var/lib/NetworkManager, and the saved profiles under /etc/NetworkManager/system-connections | all | none: the hidden session brings the connection up after activation, and the decoy records it only after the way back | none: a connection record the decoy wrote after adopting a session's link looks like one the decoy made itself | A deactivate or a plain emergency handles this with the network-state class above, deleting the session's links and in-memory profiles before the decoy's NetworkManager starts. Take down what that class leaves before you deactivate, or end the session with --poweroff. | none: session-dns-records asserts that the session's link and in-memory profile are gone after the way back; the raw-disk assertion of the connection record waits on a cross-distro control run |
| [Plymouth boot log](#session-time-records) (`plymouth-boot-log`) | `/var/log/boot.log` | all | none: the decoy writes it during the boot the way back performs, not before | path probe (info) | Keep /var/log out of the decoy's persistent storage, or expect boot.log to date the way back; power off after the session. | none: asserted on the Fedora and Arch decoys by the cross-distro forensic probe once their images boot |
| [Snapper timeline snapshots](#session-time-records) (`snapper-timeline`) | `/.snapshots`, `/var/lib/snapper` | all | path probe (info; a path it cannot look up warns) | path probe (info) | Keep the overlay upper on the hidden volume, which NAILS enforces, so a decoy snapshot never captures a session's writes; disable the snapper timeline timer on the decoy if you want no snapshot dating the machine's activity. | none: asserted on a btrfs decoy with snapper by the cross-distro forensic probe once those images boot |
| [Copy-on-write and compressed storage history](threat-model.md#residual-channels) (`btrfs-cow-history`) | old extents a copy-on-write filesystem keeps after data is overwritten or deleted, and compressed extents on btrfs, bcachefs, zfs or an f2fs mount with compression | all | none: a copy-on-write or compressed decoy is a property of the decoy's own storage, not a session write | none: a raw scan reads old copy-on-write extents but cannot read compressed ones, so `nails rehearse` reports a compressed or copy-on-write decoy as not checked rather than clean: a mounted one (a zfs dataset included) by its mount, an image or an unmounted device by its superblock, and a whole disk partition by partition, where an encrypted partition, or one on which no filesystem is identified, is not checked either | Full-disk encryption on the decoy keeps old extents as ciphertext; power off after the session. A rehearsal on a compressed or copy-on-write decoy is inconclusive by design, and `nails rehearse` says so rather than reporting it clean. | none: the compressed-storage verdict is unit-tested; a live rehearsal on a btrfs or f2fs decoy is a follow-up on hardware with those filesystems |
| [Fedora GRUB boot-success state](#session-time-records) (`grubenv-boot-success`) | `/boot/grub2/grubenv`, `/boot/efi/EFI/fedora/grubenv` | Fedora | none: Fedora's boot-success flag is written by the decoy's own boot after the switch; NAILS binds /boot and the ESP read-only during a session, so the session never writes it | path probe (info) | Power off after the session so the decoy's next boot is a plain one; the block is the decoy's own, written on the way back as on any boot. | none: asserted on the Fedora decoy by the cross-distro forensic probe once its image boots |
| [unattended-upgrades set to install at shutdown](#unattended-upgrades) (`unattended-upgrades-install-on-shutdown`) | `/var/log/unattended-upgrades`, `/var/log/apt`, `/var/log/dpkg.log` | Debian | `decoy-persistence` (refuses) | none: the logs and the packages are the decoy's own, as after any shutdown that installs updates | Activation refuses while the decoy's helper runs with the setting on, or with an apt configuration NAILS cannot read or follow, one apt refuses, or one that changed since the helper started while no file sets the setting, and --allow-persistent-decoy turns that into a warning for one run; it only warns when the hidden session alone would install. Leave the setting off, or set it to false. | none: asserted on Debian 13, Ubuntu 24.04 and Ubuntu 26.04 by the cross-distro unattended-upgrades scenario under nix/distro-tests, whose positive control is an activation with the override |
| [A daily unattended-upgrade run at the switch](#unattended-upgrades) (`unattended-upgrades-run-at-the-switch`) | `/var/log/unattended-upgrades` | Debian | `unattended-upgrade-run` (refuses) | none: the lines are the decoy's own logs, as after a shutdown during a daily run | Activation refuses while apt-daily-upgrade.service or apt-daily.service is active or a process holds /run/unattended-upgrades.lock, and looks again right before the switch; no flag lifts it. Try again in a few minutes, once the run has ended. | none: asserted on Debian 13, Ubuntu 24.04 and Ubuntu 26.04 by the cross-distro unattended-upgrades scenario under nix/distro-tests, whose positive control is a plain soft-reboot during the run |
| [unattended-upgrades' shutdown helper without python3-gi](#unattended-upgrades) (`unattended-upgrades-polling-without-python3-gi`) | `/var/log/unattended-upgrades/unattended-upgrades-shutdown.log` | Debian | `decoy-persistence` | none: the lines are the decoy's own log, as after any start of the helper | decoy-persistence warns while the decoy's helper is enabled and python3-gi is not installed. Install it: apt install python3-gi. | none: asserted on Debian 13 by the cross-distro unattended-upgrades scenario under nix/distro-tests, whose stock decoy warns of it and whose helper adds a pair at the way back |
| [tuned's log file](#tuned-firewalld-and-abrt) (`tuned-log`) | `/var/log/tuned` | all | `decoy-persistence` (refuses) | path probe (warn) | Activation refuses while tuned or tuned-ppd can start with a log file (enabled, active, started by a timer, path or socket that runs, or tuned-ppd installed, which D-Bus starts and which needs tuned) or runs with one, its standard error sent to a file or to a journal namespace the decoy keeps included, and --allow-persistent-decoy turns that into a warning for one run. Drop -l and -d from their ExecStart= in a drop-in that also sets StandardError=journal, then restart them, or mask them. Where they log to a journal namespace the decoy keeps, set Storage=volatile in its `journald@<namespace>.conf` and restart that namespace's journald, or drop the unit's LogNamespace=. | none: no VM test runs tuned: Fedora, whose units pass -l, is not admitted yet and its cloud image has no tuned; the refusal is unit tested on Fedora 44's own unit files |
| [firewalld's log file](#tuned-firewalld-and-abrt) (`firewalld-log`) | `/var/log/firewalld` | all | `decoy-persistence` | path probe (info) | decoy-persistence warns while firewalld is enabled, active or started by a timer, path or socket that runs, or runs, with a log file, a journal namespace the decoy keeps included. Make it log to the journal: add --log-target=syslog to FIREWALLD_ARGS where its unit reads that variable (/etc/sysconfig/firewalld on Fedora), to its ExecStart= in a drop-in where it does not (Debian), or to services.firewalld.extraArgs on NixOS, then restart it. Where it logs to a journal namespace the decoy keeps, set Storage=volatile in its `journald@<namespace>.conf` and restart that namespace's journald, or drop the unit's LogNamespace=. | none: no VM test runs firewalld: Fedora, which enables it, is not admitted yet and its cloud image has no firewalld; the warning is unit tested on Fedora 44's own unit and sysconfig file |
| [ABRT's crash reports](#tuned-firewalld-and-abrt) (`abrt-spool`) | `/var/spool/abrt` | all | `decoy-persistence` | path probe (warn) | decoy-persistence warns while ABRT is in use on the decoy. Turn it off: systemctl disable --now abrtd.service, which the other ABRT units need. | none: no VM test runs ABRT: Fedora, which enables it, is not admitted yet and its cloud image has no ABRT; the warning is unit tested on Fedora 44's own unit |
| [Pending offline update](#pending-offline-updates) (`pending-offline-update`) | systemd's offline updates: a /system-update or /etc/system-update link to a staged update makes the next start of the service manager, a soft-reboot's included, start system-update.target instead of the default target | all | `pending-offline-update` (refuses) | none: a link staged on the decoy is on the decoy disk, where a scan sees it, but it is the decoy's own state, not a trace of a session; a link a session staged sits in the upper on the hidden volume, where the next activation finds it and refuses | Activation refuses while a link is staged on the decoy or in the upper: install or cancel the decoy's pending update before activating, and delete a link a session staged with `nails discard`. | `preflight-checks` |
| [sssd and the domain controller's records](#decoys-joined-to-a-domain) (`sssd-domain-records`) | the domain controller's own records of the logins and account lookups sssd makes on a decoy joined to a domain, and sssd's caches under /var/lib/sss and logs under /var/log/sssd | all | `decoy-persistence` | none: the domain controller keeps its records on the controller, out of reach of any scan of this computer; what a scan of the decoy disk sees of sssd is the decoy's own, its caches under /var/lib/sss and the lines it logs under /var/log/sssd when it stops before the switch and starts after the way back, as at any shutdown and boot | NAILS is not tested on decoys joined to a domain; check and activation warn while sssd is in use on the decoy. Use a decoy that is not joined to a domain, and where nothing on it needs sssd, disable it. | none: no VM test runs a domain controller; the warning is unit-tested |
<!-- residue-catalog:end session -->

### Setup traces

<!-- residue-catalog:begin setup -->
| Class | Where | Platforms | Pre-flight | Verify | Mitigation | VM test |
|---|---|---|---|---|---|---|
| [LVM metadata archive and backup](#lvm-metadata-archives) (`lvm-metadata-archive`) | `/etc/lvm/archive`, `/etc/lvm/backup` | all | path probe (warn) | `examiner-lvm` | Never run LVM tools on the hidden backend from the decoy, or disable archive and backup in the decoy's lvm.conf first. | `examiner-audit` |
| [udisks2 state](#udisks2-state) (`udisks2-state`) | `/var/lib/udisks2` | all | path probe (warn) | path probe (warn) | Unlock and mount the backend with cryptsetup and mount from a shell, not through the desktop. | `examiner-audit` |
| [crypttab and fstab entries](#crypttab-and-fstab) (`crypttab-fstab`) | `/etc/crypttab`, `/etc/fstab` | all | `backend-entries` (refuses) | `examiner-config` | Never add the hidden backend to the decoy's crypttab or fstab; open it by hand each time. Activation refuses an entry that opens or mounts the hidden volume; the decoy's own entries are reviewed with verify --examiner. | `preflight-decoy-filesystem` |
| [LUKS headers on partitions](#encryption-headers-high-entropy-space-and-containers) (`luks-headers`) | LUKS1/LUKS2 signatures at partition starts, in gaps and in LUKS2 secondary-header slots | all | `backend-detect` | `examiner-disk` | Prefer a deniable backend (a VeraCrypt hidden volume) over a bare LUKS volume next to the decoy. | `examiner-audit` |
| [Partition types systemd acts on](#partition-types-systemd-acts-on) (`auto-discovered-partition-type`) | the GPT type of the hidden volume's partition on a disk the decoy boots from | all | `backend-partition-type` (refuses) | none: verify judges no partition type, and its examiner audit of a raw disk shows one only beside a trace it finds in that partition; the pre-flight check reads the table of the disk the hidden volume is on | Give the hidden volume's partition the generic Linux type from a live system or where setup happens, or keep the hidden volume on a disk of its own. | none: the check is unit tested on GPT images; no VM test boots a decoy from a disk with such a partition yet |
| [High-entropy unpartitioned space](#encryption-headers-high-entropy-space-and-containers) (`high-entropy-space`) | partition gaps, space after the last partition, partitions with no known signature | all | none: needs the raw disk, which verify --offline --examiner --disk reads | `examiner-disk` | Fill free space with random data when the disk is set up, so the hidden region does not stand out; explain it as wiped space. | `examiner-audit` |
| [Encrypted container candidates](#encryption-headers-high-entropy-space-and-containers) (`container-candidates`) | large files whose size is a multiple of 512, with no known header and high entropy | all | `backend-detect` | `examiner-containers` | Put the hidden volume on a whole device or partition rather than in a file on the decoy. | `examiner-audit` |
| [Encryption tooling and its access times](#backend-tooling-and-history) (`backend-tooling`) | `/usr/bin/veracrypt`, `/usr/sbin/cryptsetup`, `/sbin/cryptsetup` | all | none: the tools are part of the decoy install; their access times are what an examiner reads | `examiner-tooling` | Mount the decoy root noatime; run the backend tools from the separate machine or a live medium when you can. | `examiner-audit` |
| [History naming a container or unlock](#backend-tooling-and-history) (`container-history`) | `~/.local/share/recently-used.xbel`, `~/.config/VeraCrypt/History.xml`, `~/.config/VeraCrypt/Favorite Volumes.xml`, `~/.bash_history`, `~/.zsh_history` | all | `incremental-history-flush` | `examiner-history` | Disable VeraCrypt's history, harden the decoy shell history, and unlock from a shell that records nothing. | `examiner-audit` |
<!-- residue-catalog:end setup -->

## Out of scope

These sit outside the overlay model and NAILS does not attempt to manage them:

- **EFI / firmware variables** and **RTC** — writes here are not filesystem
  writes and are not overlaid.
- **Firmware-backed pstore** that survives a disk wipe (surfaced as a warning
  only).

See also [threat-model.md](threat-model.md) for the overall model and
[operator-guide.md](operator-guide.md) for operational guidance.
