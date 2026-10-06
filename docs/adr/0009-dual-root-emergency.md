# 9. Dual root on one seat: whole-root isolation with a non-disruptive emergency

- Status: proposed (research; a decision waits on the spike and the hardware matrix)
- Date: 2026-10-06 (risk assessment added 2026-10-07)
- Related: [ADR 0005](0005-live-overlay-vs-boot-time-overlay.md),
  [ADR 0008](0008-whole-root-soft-reboot.md), [threat model](../threat-model.md),
  [operator guide](../operator-guide.md#standard-vs-emergency-vs-recover)

## Context

ADR 0008 showed that a whole-root overlay entered by soft-reboot removes the
process heuristics and the silent missed-writer leak class (T-132). It also
showed the price: every process, including the desktop, runs inside the overlay,
so any emergency ends at a greeter or with the machine off (ADR 0008, §6).

The operator's ruling for emergency is binding:

1. Tear down quickly.
2. Never touch the display manager or the X server.
3. Never log the user out.
4. Nothing may look suspicious at first glance.
5. No writes to the decoy disk.

The operator also wants whole-root isolation if it can be had. This record looks
for a design that gives both.

### What today's emergency actually shows

Today's activation restarts the display manager so that the desktop logs in
again on top of the overlays (`session_guard.rs`, operator guide). Emergency
then spares the whole graphical session on purpose. The ruling holds to the
letter: no logout, display manager and X untouched. But the desktop that is left
on screen is the **hidden** session. Its windows, including any hidden
application that does not hold an overlay open, keep running on lazily detached
overlays, and the backend cannot be closed while they hold it
(`security/80-emergency-graphical.nix` asserts exactly that). So rule 4 is met
only if every open window happens to look harmless. The designs below are
measured against that baseline.

### How to read this record

- **[V-src]** verified in source code or man pages (links under Sources).
- **[V-web]** reported by upstream issue trackers or vendor documentation; not
  reproduced here.
- **[V-spike]** will be verified by the spike VM test once it has run. Its log is
  the evidence, and this record must be updated with the results.
- **[I]** inferred, not yet observed.

The spike is `nix/e2e-tests/tests/research/dual-root-vt-emergency.nix`; build it
with
`nix build .#legacyPackages.x86_64-linux.e2e.research-dual-root-vt-emergency -L`.
Run history on the KVM host:

- 50a9a26: stopped at the first root check. `readlink /proc/<pid>/root` prints
  `/` to a host reader for a process whose root is the root mount of another
  mount namespace, which is what `RootDirectory=` sets up; the hidden X socket
  had in fact appeared only in the upper. The spikes now compare device and
  inode of `/proc/<pid>/root/` with the overlay root.
- 6adc66c: the hidden X server is in the hidden root (device/inode check true).
  Stopped at the hidden logind session: `login -f` failed with "Authentication
  service cannot retrieve authentication info" (see the hidden-user mechanism
  below). Fixed in the next commit; not yet re-run.

A second spike, `nix/e2e-tests/tests/research/dual-root-risks.nix`
(`e2e.research-dual-root-risks`), probes the risks; see
[Risk assessment](#risk-assessment). It is independent of the first, so the two
fail separately. Its 6adc66c run reached the same `login -f` failure after R1
and R5a; those results are in the risk assessment.

## The core idea

Do not overlay the running decoy at all. Leave the decoy desktop running,
logged in, on its own virtual terminal. Start the hidden environment as a
**separate process tree whose root is a whole-root overlay** (lower = a
read-only bind of the decoy root, upper on the hidden volume), with its own
display server on another VT. Emergency is then:

1. switch the console back to the decoy VT, and
2. `cgroup.kill` the hidden process tree.

The user lands on a real decoy desktop that was never logged out and never
restarted. Because no decoy process ever runs inside the overlay, there is
nothing to classify, restart or spare. Every hidden process was started inside
the hidden root, so killing its cgroups removes all of them, and the overlay can
then be unmounted without a lazy detach.

This keeps ADR 0008's main property (no process heuristics, no missed-writer
class for processes) without soft-rebooting the decoy away.

## Mechanisms the designs rely on

**One seat, two VTs, two DRM masters.** The kernel VT layer arbitrates which
display server owns the screen. A display server that owns a VT in `VT_PROCESS`
mode is asked to release it on a switch. It drops DRM master, and the server on
the new VT takes DRM master. This is how Ctrl+Alt+F*n* and fast user switching
work [V-src: `drivers/tty/vt/vt_ioctl.c`; logind does the drop/set on behalf of
the sessions it controls]. Nothing in this protocol looks at mount namespaces:
DRM master, the VT and the input devices are kernel objects reached through
`/dev`, which the hidden root binds from the host [I; V-spike: hidden X on VT 8,
decoy X on its own VT, both alive, switch back works]. If the owner of a
`VT_PROCESS` VT has died, the kernel resets the VT to `VT_AUTO` and completes the
switch, so a killed hidden display server cannot block the return [V-src:
`vt_ioctl.c`, `reset_vc()` in the switch path].

**A logind session from inside another root.** logind identifies sessions by
PID and cgroup, not by mount namespace. A process in the hidden root that runs
PAM with `pam_systemd` (for example `login -f` or a hidden greeter) and reaches
the host system bus through a bind of `/run` gets a normal seat0 session with a
VT [I; V-spike: `login -f aux` inside the hidden root yields a seat0 session
whose leader's root is the overlay]. Because PAM then runs **inside** the hidden
root, its writes (lastlog2, wtmp) land in the upper. A unit with `PAMName=` does
**not** do this: systemd calls PAM before it sets up the mount namespace
[V-src: `exec_invoke()` calls `setup_pam()` before
`setup_delegated_namespaces()`], so the decoy's PAM stack would run against the
decoy disk. NixOS's `login` stack writes `/var/lib/lastlog/lastlog2.db`
[V-src: `programs/shadow.nix`, `updateWtmp = true`].

**A hidden user without touching `/etc/passwd`.** A JSON user record in
`/run/userdb/<name>.user` (plus a `<uid>.user` symlink) is resolved by
nss-systemd and libuserdb in-process, without `systemd-userdbd` [V-src:
`userdb.c` falls back to `dropin_user_record_by_*()`]. It lives in RAM. NixOS
puts `systemd` in `passwd`/`group` in `nsswitch.conf` by default [V-src];
Debian/Ubuntu need `libnss-systemd` installed [I: check the default install].
That is enough for logind, PID 1 and `user@.service`, but **not** for PAM in
the hidden root: NixOS's glibc reaches NSS modules only through nscd, and nscd
has no shadow database, so `getspnam()` of a userdb-only user fails and
pam_unix's account check returns `PAM_AUTHINFO_UNAVAIL` [V-spike 6adc66c:
"Authentication service cannot retrieve authentication info" from `login -f`].
The hidden root is the hidden system's own `/etc`, so the hidden user also gets
ordinary `passwd`/`group`/`shadow` entries there (locked password, no aging);
they land in the upper only. On distributions whose glibc loads nss-systemd
directly this is not needed, but it does no harm.

**The hidden user manager in the hidden root.** `user@<uid>.service` is started
by the host PID 1, so by default it would run on the decoy root, and with it the
session bus, PipeWire and the portals. A runtime drop-in in
`/run/systemd/system/user@<uid>.service.d/` with `RootDirectory=`,
`MountAPIVFS=yes`, `BindPaths=/run` moves it into the hidden root. The drop-in is
in RAM and goes away with a `daemon-reload` [V-src: `systemd.exec(5)`; explicit
binds override the API VFS defaults, `namespace.c` `apivfs_table`; V-spike:
the user manager's `/proc/<pid>/root` is the overlay].

**A different uid for the hidden user.** With the decoy's uid, the hidden session
would share `/run/user/<uid>`, the decoy's user manager, its session bus,
PipeWire, dconf, keyring, gvfs and tracker. All of those are decoy-rooted and
write to the decoy home. A separate uid gets separate instances of all of them,
started by the drop-in above in the hidden root. **Same uid is ruled out.**

**Emergency primitives.** `cgroup.kill` (Linux 5.14+) SIGKILLs a whole cgroup
subtree atomically, with no grace period and no hooks. `chvt` / `VT_ACTIVATE`
needs root, which NAILS has. Neither writes to any disk.

## Options

### A. Live overlays (today, baseline)

As described in the operator guide. Emergency keeps the desktop, but it is the
hidden desktop on detached overlays, the backend stays open, and spared
processes can write to the exposed decoy through absolute paths.

### B. Whole-root soft-reboot (ADR 0008)

The strongest isolation of the userspace options. Emergency E1–E3 ends at a
greeter, E4 powers off. It cannot meet rule 3 (ADR 0008, §6).

### C. Soft-reboot back, then autologin and session restore (candidate 3)

Emergency = soft-reboot to the decoy, then an immediate autologin into a decoy
desktop that restores a plausible set of applications.

- **Timing.** The whole soft-reboot grey-out (ADR 0008 estimates 5–20 s, 90 s
  worst case per stuck unit), plus the desktop start, plus the application
  restore. [I]
- **What an observer sees.** The screen goes to a text console, then a desktop
  starts from scratch: login sounds, the splash, panels drawing, applications
  reopening one by one. Anyone who was watching sees a session restart. That is
  a logout in everything but name, and it fails rule 4 for anyone looking at the
  screen.
- **Autologin is an enabler.** Autologin needs display-manager configuration.
  GDM reads it only from `/etc/gdm/custom.conf`; SDDM and LightDM read `/etc`
  too. Putting it on the decoy is a permanent enabler (ADR 0005's objection), and
  a decoy that autologins anyway weakens the decoy. A runtime-only override would
  need a bind mount over a decoy config file inside the soft-rebooted root.
  That is possible but per display manager. [I]
- **Session restore is not portable.** KDE restores sessions; GNOME has no
  general session restore; sway has none. Restored applications open in their
  default state, not where the operator left them. [I]
- **Traces.** `SoftRebootsCount` rises, and the decoy's boot-time writes happen
  during an emergency (ADR 0008, §5).

**Rejected.** It is slow, visibly a restart, and needs an enabler.

### D. Dual root, one seat, host logind (candidate 1, the recommended direction)

- The decoy desktop keeps running on its VT, untouched, logged in.
- NAILS builds the whole-root overlay at a runtime path (spike: `/run/aux/root`)
  and starts the hidden environment as host systemd units with `RootDirectory=`
  that overlay. The units sit in one slice (spike: `aux.slice`), and the hidden
  user's `user-<uid>.slice` is added to it.
- The hidden session is a real seat0 logind session for a separate uid,
  registered from inside the hidden root (PAM in the hidden root). The hidden
  compositor or X server runs on its own VT. Every logind-aware compositor works
  here, because the host logind is a full, ordinary logind. That includes GNOME
  Shell, KWin and sway through libseat's logind backend.
- Emergency: `chvt <decoy VT>`, then `cgroup.kill` on the hidden slices, then
  strict unmount and backend close.

**Isolation.** Hidden processes cannot open decoy paths: their `/` is the
overlay, and the decoy root is not mounted anywhere in their namespace. What is
left:

| Channel | Leak | Mitigation |
| --- | --- | --- |
| Shared **system** daemons over the host system bus: NetworkManager (`/etc/NetworkManager/system-connections`, `/var/lib/NetworkManager`), bluetoothd (`/var/lib/bluetooth`), CUPS (`/var/spool/cups`, `/var/cache/cups`), AccountsService (`/var/lib/AccountsService/users`), boltd, power-profiles-daemon, fwupd, PackageKit, udisks2 (mounts appear in the host namespace) | Writes on the **decoy disk** made on the hidden user's behalf. A seat0 session is "active", so polkit's `allow_active` lets it add Wi-Fi networks, pair devices and print | D+ below: give the hidden root a filtered system bus that forwards only `org.freedesktop.login1` (and what the compositor needs), and run its own instances of stateful daemons in the hidden root. Until then, list these daemons in the operator guide as residual channels |
| `/proc/<pid>/root` and `/proc/<pid>/cwd` of host processes | A **root** process in the hidden root can reach the decoy filesystem through `/proc/1/root` (same PID namespace). An unprivileged hidden user cannot (ptrace access check) [V-spike: both probes are logged] | A PID namespace for the hidden tree (`PrivatePIDs=`, systemd ≥ 257, or `unshare --pid`; not possible for `user@.service`, risk 4), `NoNewPrivileges=` on every hidden unit; keep hidden system services few |
| The host **journal** | stdout of hidden units, logind's "New session … of user aux", and the unit names reach the decoy's journald. On the required volatile journal that is RAM only [V-spike: the token stays off the raw disk] | Neutral unit names; `StandardOutput=null` or a hidden journald socket; scrub the volatile journal after teardown (emergency already does) |
| Shared `/run` | userdb records, drop-ins, `/run/user/<uid>`, utmp entries left after SIGKILL (no logout record) | Bind only the needed parts of `/run` (D+); remove what NAILS created at teardown; a private `/run/utmp` |
| Mount-namespace copies | A decoy service that creates its own mount namespace while the hidden root is mounted (an on-demand service with `PrivateTmp=` or `ProtectSystem=`) gets a private copy of the hidden mounts. It can see the hidden root, and its copy pins the hidden filesystem, so the backend cannot close [I; V-spike logs any such namespace] | Revised (risk 5): `CLONE_NEWNS` copies private and unbindable mounts too, so a private tmpfs does not prevent copies. Mount the hidden root only in a pinned mount namespace and start units with `systemd-run --root-directory=` (systemd 259) or an `nsenter` wrapper; keep the `nsenter -m umount` sweep at teardown as a backstop |
| `(sd-pam)` of `user@<uid>.service` | The PAM helper is forked before the unit's namespace is set up, so a hidden-uid process with the **decoy** root exists for the whole session. It only waits to call `pam_close_session()` [V-src: `exec_invoke()` order; V-spike logs it] | `cgroup.kill` never lets it reach the close; keep the decoy's `systemd-user` PAM stack free of writers (true on NixOS) |
| **Kernel** state | kmsg (overlay and dm-crypt messages), the VT history, the network identity (same netns, same MAC and IP) | As in ADR 0008; network identity is out of scope in the threat model |
| **Observer during the session** | `ps`, `loginctl` and `systemctl` on the decoy show the hidden processes and session while they run | Emergency removes them in under a second; nothing remains at first glance |

**Emergency behaviour.**

- **Time.** VT switch plus cgroup kill. Expected well under 1 s in a VM; on real
  hardware dominated by the modeset on VT switch (typically 0.1–1 s, longer on
  some NVIDIA setups) [I; V-spike measures `switch_ms`, `dead_ms` and
  `active_ms` from the trigger].
- **What an observer sees.** The screen flips to the decoy desktop exactly as it
  was left, the same as a Ctrl+Alt+F*n* switch. If the decoy screen locker kicked
  in while the hidden session ran (the decoy session was idle the whole time), a
  decoy lock screen appears. That is a lock, not a logout, and it looks like "I
  stepped away" [I]. NAILS can hold an idle inhibitor for the decoy session,
  where the desktop honours one, if the operator prefers no lock.
- **Rules.** 1 yes; 2 yes: the display manager and the decoy X server or
  compositor are never stopped, restarted or signalled; the VT switch is the
  ordinary VT protocol; 3 yes; 4 yes, and better than today because the hidden
  windows are gone; 5 yes: no write on the emergency path [V-spike: sector
  counter logged, raw-disk grep].
- **Bonus.** All hidden processes are dead, so the overlay unmounts strictly and
  the backend **can be closed** during emergency. Today it cannot in a graphical
  session.

**Feasibility on real hardware.**

- **Intel/AMD (Mesa, KMS):** VT switching between two DRM masters is routine.
  Low risk [I].
- **NVIDIA proprietary:** fast user switching works with `nvidia-drm.modeset=1`,
  but black-screen-after-VT-switch bugs keep being reported for Wayland
  compositors [V-web]. Medium to high risk; it must be on the hardware matrix.
  Option N is the fallback.
- **Decoy on Wayland or X11:** both are fine. A logind-controlled decoy
  compositor is paused and resumed by logind; a rootful X server handles the VT
  signals itself [I].
- **Hidden GNOME, KDE or sway:** all possible, because the host logind is real.
  GNOME needs its system-side helpers (AccountsService, NetworkManager, upower,
  geoclue) on the system bus, which is the shared-daemon channel above.

**Complexity and testability.** Medium. Everything is ordinary systemd: transient
units, runtime drop-ins, userdb drop-ins, cgroups. The NixOS test driver drives
graphical VMs and VTs; the spike covers the core in a single VM.

**Fit.** Works with systemd ≥ 250 (userdb drop-ins, `RootDirectory=`,
`BindPaths=`) and Linux ≥ 5.14 (`cgroup.kill`). That covers Debian bookworm,
Ubuntu jammy and every newer release, which is wider than soft-reboot (≥ 254).
`PrivatePIDs=` needs 257; older systems can use `unshare --pid`. On NixOS the
hidden toplevel's **user** environment works inside the root once the hidden
root gets its own `/run/current-system` (a private `/run` with selected host
binds instead of the whole host `/run`). The hidden toplevel's **system
services** are not booted (no hidden PID 1). They have to be run as host units
with `RootDirectory=` (portable-service style), or dropped. That is the main
NixOS gap.

### D+. Hardening track for D

These steps take D towards container-grade isolation without giving up the host
logind:

1. A PID namespace for the hidden tree (closes the `/proc/<pid>/root` path).
   Revised by the risk assessment (risk 4): `PrivatePIDs=` works for hidden
   system-style units (the session leader is being probed) but not for
   `user@.service`, so
   the step is `NoNewPrivileges=` everywhere plus `PrivatePIDs=` where possible.
2. A private `/run` in the hidden root with only the host system-bus socket, the
   logind state directories (`/run/systemd/{seats,sessions,users}`), `/run/udev`
   (read-only) and `/run/user/<uid>` bound in.
3. A filtered system bus for the hidden root (`xdg-dbus-proxy --filter
   --talk=org.freedesktop.login1 …` on a socket at the hidden root's
   `/run/dbus/system_bus_socket`), and hidden-root instances of the stateful
   daemons the hidden desktop needs. They are started by the host PID 1 as units
   with `RootDirectory=`, joined to the hidden namespaces with
   `JoinsNamespaceOf=`, and talk to a hidden dbus-daemon.
   Revised by the risk assessment (risk 2): hidden copies of daemons that own a
   bus name cannot share the host bus, and a hidden bus loses
   `org.freedesktop.login1`. The step becomes a runtime polkit rule, a D-Bus
   uid deny for bluez/fwupd, blocked CUPS, and optionally the proxy, applied
   after PAM has created the session.
4. Optionally a private network namespace. Wi-Fi moves with its `phy` (nspawn
   supports this since v256 [V-web]; plain `iw phy … set netns` works for units).
   The decoy then shows its network as disconnected until emergency returns the
   device, which happens automatically when the namespace dies [I].

Each step is independently testable. Step 3 is the large one.

### E. Hidden container: `systemd-nspawn --boot` on the overlay (candidate 2)

The hidden root boots its own PID 1 in a container: its own journald, D-Bus,
NetworkManager (with a moved NIC or `phy`) and PID namespace. The display comes
from bound `/dev/dri`, `/dev/input` and `/dev/tty<N>`.

- **Graphics are the blocker.** logind inside nspawn does not provide a
  graphical seat. Upstream labels it "not supported" (#35114), and the
  enhancement request is open (#36673) [V-web]. The workarounds are a rootful X
  server or seatd plus a wlroots compositor (sway, labwc, Hyprland). **GNOME
  cannot run** (mutter's native backend needs a logind session); Plasma on X11
  may work [I].
- **Isolation** is the strongest of the live options: own system tier, own PID
  namespace, own journal in the upper. What is left: kmsg, and the devices it
  shares.
- **Emergency** is the same as D (`chvt`, then kill the machine's scope).
- **NixOS fit** is good for the system side (`boot.isContainer` generations are
  first class) but means a container-flavoured hidden configuration. Debian roots
  boot under nspawn as they are.
- **Two VT owners without logind coordination** (container X or seatd on one VT,
  host logind on the others) rely on the bare kernel VT protocol only [I].

**Not chosen as the main path** while the operator wants GNOME/KDE. It stays the
answer for an X11/wlroots hidden desktop that wants full system isolation, and
D+ step 3 borrows its idea.

### N. Nested compositor inside the decoy session (found during research)

The hidden desktop runs as a fullscreen nested compositor window inside the
decoy session (cage, sway with the Wayland backend, `kwin_wayland --windowed`,
Xephyr). The nested compositor and all hidden clients run as the hidden uid in
the hidden root. The nested compositor gets the decoy's display socket as an fd.

- **Emergency:** `cgroup.kill`. The window vanishes and the decoy desktop is
  underneath. There is no VT switch and no modeset, so it takes tens of
  milliseconds [I]. Rules 1–5 hold.
- **GPU:** vendor-independent, because the nested compositor is an ordinary
  client and clients render through render nodes, which need no DRM master. This
  avoids the NVIDIA VT risk [I].
- **Isolation is weaker:** the decoy compositor (decoy-rooted, decoy uid) sees
  all hidden pixels and all hidden input. Decoy-side screenshot and screencast
  tools can capture it. Decoy input methods (IBus/Fcitx) see the keystrokes and
  may learn them into on-disk dictionaries. Decoy usage trackers record a window
  or application being in use for hours (GNOME's `application_state`, KDE's
  activity manager database): **decoy-disk writes during the session** [I].
- **Fit:** no system changes at all; same on NixOS and Debian.

**A fallback**, for hardware where D's VT handover is unreliable, with the
leaks above stated in the UX. Pin the nested window to a neutral application id.

### G. Two modes with honest emergency semantics (candidate 4)

Ship more than one session mode and say in the UX what each emergency does:

| Mode | Isolation | Emergency ends at |
| --- | --- | --- |
| `dual-root` (D, later D+) | Whole-root for every hidden process; shared system daemons until D+ | The decoy desktop, still logged in (meets the ruling) |
| `whole-root` (B, opt-in) | Whole-root for everything, decoy userspace stopped | A greeter, or power-off (does not meet rule 3) |
| `live-overlay` (A, legacy) | Directory overlays plus process heuristics | The hidden desktop on detached overlays |

`nails status` and `activate` should print the active mode's emergency
semantics in one line, for example "emergency: returns to the decoy desktop" or
"emergency: ends at the login screen".

### Other ideas considered

- **CRIU checkpoint/restore of the decoy session.** Impractical: CRIU cannot
  checkpoint processes holding DRM master or GPU contexts (its amdgpu and CUDA
  plugins cover compute, not display). It cannot save a compositor's connections
  to the kernel KMS state or the clients' Wayland/X sockets as a consistent
  graph. The image must be stored somewhere: on the decoy disk (a write) or the
  hidden volume (seconds to restore, if it works at all). D gets the same result
  by not stopping the decoy session in the first place.
- **Pre-started decoy greeter or session in a separate namespace** (the reverse
  of D: the hidden desktop on the host, the decoy in a box). That does not help:
  the hidden desktop would run on the decoy root and need today's heuristics,
  and a boxed decoy is a weaker decoy.
- **A dedicated second seat** (`loginctl attach`) needs a second GPU and second
  input devices. `attach` writes udev rules to `/etc/udev/rules.d`, which is a
  decoy write, unless the rules are placed in `/run/udev/rules.d` by hand. Not
  a laptop design.
- **DRM leases** give a client a connector, not a VT. They are meant for VR
  headsets and second displays, not for switching a whole screen between two
  sessions. Not useful here.

## Decision matrix

Scores: ++ strong, + good, 0 neutral, − weak, −− disqualifying. Inferred unless
noted.

| Criterion | A today | B soft-reboot | C soft-reboot + autologin | **D dual root** | D+ hardened | E nspawn | N nested |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Emergency keeps the logged-in decoy desktop (rule 3) | + (but it is the hidden desktop) | −− | −− (a fresh session) | ++ | ++ | ++ | ++ |
| Emergency speed (rule 1) | + | − 5–20 s | −− | ++ < 1 s | ++ | ++ | ++ < 0.1 s |
| First glance after emergency (rule 4) | − hidden windows remain | 0 greeter | − visible restart | ++ the decoy as left (maybe locked) | ++ | ++ | ++ |
| Display manager and X untouched (rule 2) | ++ | −− | −− | ++ | ++ | ++ | ++ |
| No decoy-disk write on emergency (rule 5) | + | − decoy boot writes | − | ++ | ++ | ++ | ++ |
| Backend closable on emergency | −− in a graphical session | ++ | ++ | ++ | ++ | ++ | ++ |
| Process heuristics needed | −− | ++ | ++ | ++ | ++ | ++ | ++ |
| Missed-writer leak class | −− | ++ | ++ | + (shared daemons, /proc as root) | ++ | ++ | 0 (decoy session sees input and pixels) |
| Shared system daemons write for the hidden user | − | ++ | ++ | − | + | ++ | − |
| Hidden GNOME/KDE | ++ | ++ | ++ | ++ | + (needs the bus filter right) | −− GNOME / 0 KDE X11 | + (nested) |
| NVIDIA risk | ++ | 0 | 0 | − VT handover | − | − | ++ |
| Debian/Ubuntu fit | − heuristics per distro | 0 systemd ≥ 254 | − per DM | + systemd ≥ 250 | + | + | ++ |
| NixOS hidden toplevel | ++ (exists) | + | + | 0 user env yes, system services translated | 0 | + container config | 0 like D |
| Complexity | exists | XL | XL | M | L | L | M |
| VM testability | ++ | + | − | + (spike) | + | + | + (nested Wayland in VM) |

## Recommendation (proposed)

1. **Make D the hidden-session architecture to pursue** ("dual root on one
   seat"), and keep its emergency as specified: `chvt` to the decoy VT, then
   `cgroup.kill` on the hidden slices, strict unmount, backend close. It is the
   only option that keeps whole-root isolation for every hidden process **and**
   meets all five rules. It also fixes two weaknesses of today's emergency: the
   hidden windows left on screen and the backend that cannot be closed.
2. **Plan D+ as the hardening track**, in this order: PID namespace, private
   `/run`, filtered system bus with hidden-root daemons, optional private
   network namespace. Until D+ step 3 lands, the shared system daemons are
   documented residual channels.
3. **Offer N as a fallback** for hardware where the VT handover fails, with its
   weaker isolation stated in the UX.
4. **Keep B (ADR 0008) as an opt-in maximum-isolation mode** whose emergency is
   power-off or greeter, labelled honestly (option G). Drop C.
5. **Keep A** until D reaches parity on NixOS (hidden system services) and
   Debian/Ubuntu.

## Go/no-go criteria (all must hold before implementation starts)

1. The spike passes: the decoy X server, display manager and logind session are
   the same objects before and after; the decoy session is active again on its
   VT; no hidden process remains; the overlay unmounts without a lazy detach; the
   LUKS volume closes; no hidden token is on the raw decoy disk; `active_ms`
   < 1000 in the VM.
2. Real hardware, 20 consecutive enter/emergency cycles each, on Intel or AMD
   and on NVIDIA proprietary (`nvidia-drm.modeset=1`), with decoys on GNOME
   Wayland, KDE Wayland and an X11 desktop, and hidden sessions on sway and
   GNOME. Each cycle must have no decoy compositor crash, no greeter, no logout,
   and the decoy usable in ≤ 1 s after the trigger. If NVIDIA fails, N must pass
   the same matrix on that hardware.
3. The decoy session does not suspend or log out while the hidden session runs
   (inhibitor tested), and the operator accepts the decoy lock-screen behaviour
   on return.
4. A shared-daemon audit: from the hidden session, add a Wi-Fi network, pair a
   Bluetooth device, print, mount a USB stick and change the power profile, then
   diff the decoy disk. Either D+ step 3 blocks every change, or the operator
   accepts the documented residuals for a first release.
5. NixOS: a hidden toplevel's user environment runs in the hidden root with a
   private `/run/current-system`, and there is a written plan (or a spike) for
   its system services.
6. A Debian trixie / Ubuntu noble variant of the spike passes on the nix-vm-test
   tier, including `libnss-systemd` resolution of the hidden user.

## Risk assessment

Checked on 2026-10-07, before any implementation. Each risk was researched in
upstream source at the versions that matter: systemd v259.3 (pinned nixpkgs),
v257 (Debian trixie, Ubuntu 25.10) and v255 (Ubuntu noble), Linux 6.18, polkit
124–127, NetworkManager 1.56.0, accountsservice 23.13.9, xdg-dbus-proxy 0.1.6,
kbd 2.9.0, the NVIDIA open kernel modules up to 615.71.09, gnome-settings-daemon
and gnome-shell `main`. Where a VM can show something, the second spike probes
it:

```
nix build .#legacyPackages.x86_64-linux.e2e.research-dual-root-risks -L
```

(`nix/e2e-tests/tests/research/dual-root-risks.nix`, tag `research`,
independent of the first spike). It logs `FINDING:` lines for measurements and
asserts only the mitigations this section claims work. Its first run (6adc66c,
KVM host, QEMU virtual display, decoy on VT 1, hidden X on VT 8) covered setup,
R5a and R1; it then stopped at the hidden `login -f` session (fixed since,
see the hidden-user mechanism). Results below marked [V-spike 6adc66c] come from
that log; [V-spike pending] probes have not run yet.

### Verdicts

| # | Risk | Verdict |
| --- | --- | --- |
| 1 | VT/DRM handover, hidden display server killed | Kernel side **solved** if the emergency path handles two races; the VM returns to the decoy in 0.1–0.4 s in all kill orders. Intel/AMD: **mitigable**, needs one hardware pass. NVIDIA: **needs real hardware**; known close-path deadlocks are a **blocker** on affected driver versions. nouveau: **needs real hardware** (no data) |
| 2 | Shared system daemons write for the hidden user | **Mitigable** with a runtime polkit rule, a D-Bus uid deny for non-polkit daemons, and blocking CUPS. Timing-only writes (NM timestamps, upower history) **cannot** be stopped per user. Hidden-root copies of daemons on the shared bus are **impossible** |
| 3 | Idle decoy over hours | **Mitigable**: an idle+sleep inhibitor held by a host unit. Lid close needs a `handle-lid-switch` lock. A lock screen on return is expected and is not a logout |
| 4 | Root in the hidden root reaches the decoy via `/proc/1/root` | **Mitigable**: `NoNewPrivileges=` everywhere plus a polkit deny; `PrivatePIDs=` for system-style hidden units (and the session leader, if probe R4b confirms logind accepts it). **Blocker** for `PrivatePIDs=` on `user@.service`; not available on systemd 255 |
| 5 | Mount-namespace copies of the hidden root | **Real leak** with the spike's private tmpfs (confirmed in the VM). **Solved** on systemd 259 with `systemd-run --root-directory=` from a pinned namespace; **mitigable** on 255/257 with an `nsenter` wrapper |
| 6 | Hidden NixOS system services | **Mitigable** for file/network services as runtime units with `RootDirectory=`, after rewriting `StateDirectory=` and friends. Services that own a bus name, logind, udev, journald: **blocker** on the host bus. nspawn for headless services: viable but splits the system bus |
| 7 | Other: audio, input, GPU, homed, AppArmor/snap, Secure Boot, seatd, DM user lists | Mostly **solved/mitigable**; **snaps on Ubuntu are a blocker** inside the hidden root (exclude them); NVIDIA D-state on kill **needs real hardware** |

### 1. VT/DRM handover

**Evidence.**

- `VT_ACTIVATE` is asynchronous. If the old VT is in `VT_PROCESS` mode, the
  kernel signals its owner and waits for `VT_RELDISP`, with **no timeout**. If
  the signal cannot be delivered (the owner was reaped), it resets the VT to
  `VT_AUTO` and completes the switch; the in-tree comment admits a switch can
  get "lost" if the owner dies after the signal [V-src: `vt_ioctl.c`
  `change_console`, `complete_change_console`, `vt_reldisp`]. `vt_reldisp`
  accepts `CAP_SYS_TTY_CONFIG`, so root can acknowledge a pending release on
  behalf of a dead X server.
- `cgroup.events populated 0` fires at task-dead time, after `exit_files`, so
  the hidden server's DRM fds (and DRM master) are gone, but the zombie can still
  receive the release signal until it is reaped [V-src: `kernel/exit.c`,
  `cgroup.c` `do_cgroup_task_dead`].
- DRM master drop does **no** modeset. If the dying client's framebuffer is
  being scanned out, its planes are disabled, so the screen goes black, not
  frozen on the hidden frame. fbdev restore runs only at last close, which never
  happens while the decoy holds the device [V-src: `drm_auth.c`,
  `drm_framebuffer.c`, `drm_file.c`]. `DRM_IOCTL_SET_MASTER` fails with
  `EBUSY` while any master exists, even for root.
- Only the decoy display server repaints on return: Xorg `EnterVT` does
  `SetMaster` (failure ignored) plus a full modeset; mutter and wlroots do a
  full re-modeset on logind `ResumeDevice` [V-src]. If the decoy's
  `SetMaster` fails because the hidden server still holds master, Xorg stays
  black until the next VT switch, and logind keeps a logind-managed device
  paused [V-src: `logind-session-device.c` "hope there is no-one else"].
- `chvt` (kbd ≥ 2.3; 2.9.0 pinned) retries `VT_ACTIVATE` every second with no
  deadline, which recovers a lost switch, but also blocks forever on a live, hung
  owner [V-src: `chvt.c`]. `loginctl activate` is a single `VT_ACTIVATE`
  without waiting or retry, and needs D-Bus at emergency time [V-src:
  `terminal-util.c chvt()`]. It is not faster.
- A logind-controlled hidden compositor is more robust than a rootful X: logind
  owns the VT (`VT_PROCESS` with its own signals), drops master and revokes
  input itself on leave, and restores the VT when the controller dies [V-src:
  `logind-session.c`]. A hung hidden compositor cannot block the switch.
- **NVIDIA.** Master drop and fd close run a modeset inside the close path in
  both `fbdev=1` and `fbdev=0` modes. Open reports: VT return freezes on 580.95.05
  (open-gpu-kernel-modules #957, 2025-11), KWin finds no usable output after VT
  leave/enter on 595.x (#1378, 2026-09), black screen with GLX-vblank X
  compositors since 545 (NVIDIA forum 328357), `fbdev=0` black VT on kernel ≥ 7.0
  until 610.57.04, and an `nvkms_close` deadlock on 580.126.09 where "SIGKILL is
  ineffective" and VT switching is blocked until reboot (forum 367587), plus a
  pm-lock/RM-lock deadlock on 615.71.09 with VRR/HDR (#1371) [V-web]. The
  deadlock class is the worst case: the hidden server cannot die, master is never
  freed, the decoy cannot take the screen.
- Intel/AMD: no systematic current breakage found; individual regressions exist
  (i915 freeze on VT return since 6.16, LKML 2026-02) [V-web].

**Mitigation (emergency path).**

1. `VT_ACTIVATE` to the decoy VT and poll `VT_GETSTATE` for at most 1–2 s
   (never an unbounded `chvt`).
2. `cgroup.kill` the hidden slices and wait (bounded) for `populated 0`.
3. If the decoy VT is not active yet: `VT_RELDISP 1` on the hidden `/dev/ttyN`,
   or re-issue `VT_ACTIVATE` every 50–100 ms; make sure the hidden X server's
   parent is in the killed tree, so the zombie is reaped.
4. Optionally confirm the decoy holds master (`/sys/kernel/debug/dri/*/clients`).
5. Prefer a logind-managed hidden display server (`Xorg vt$XDG_VTNR -keeptty`, or
   a Wayland compositor) over a rootful X server.
6. NVIDIA: `nvidia-drm.modeset=1 fbdev=1`, no VRR/HDR (or
   `nvidia_modeset.conceal_vrr_caps=1`), `NVreg_PreserveVideoMemoryAllocations=1`;
   pin driver versions that pass the matrix. Option N stays the fallback.

**VM probe.** R1a–R1d: hidden rootful X on VT 8 with a full-screen red window,
decoy with a full-screen blue window; screenshots are classified by colour
share and pixel variance. R1a kills the hidden X while its VT is active and then
switches; R1b switches then kills (the product order); R1c kills while the
switch is in flight; R1d times `loginctl activate` against `chvt` (five rounds
each) to "VT active" and "logind session active". Asserted: the decoy renders
after each.

Results [V-spike 6adc66c]:

| Step | Screen (share of decoy blue / hidden red / black) | Time to decoy on screen |
| --- | --- | --- |
| Reference, decoy only | 0.931 / 0 / 0.002, stddev 30.6 | — |
| R1a: hidden X killed on its own VT, before any switch | 0 / 0 / **1.0**, stddev 0 (VT 8 still active) | — |
| R1a: then `chvt` to the decoy | 0.931 / 0 / 0.002 | 0.13 s (0.26 s total) |
| R1b: `chvt`, then kill (product order) | 0.931 / 0 / 0.002 | 0.12 s |
| R1c: kill racing the switch | 0.931 / 0 / 0.002, VT 1 active | 0.20 s |

The black screen after the kill confirms the source reading: the dying client's
framebuffer is removed and nothing is left on screen, neither the hidden frame
nor a console. The decoy Xorg repainted with a full modeset on `EnterVT` in every
case. R1d over five rounds each (milliseconds from the command; first round
includes cold caches):

| Method | Command returned | Kernel VT active | logind session active | Decoy on screen (host polling) |
| --- | --- | --- | --- | --- |
| `chvt` | 74–117 | 97–274 | 130–381 | 0.07–0.25 s |
| `loginctl activate` | 33–145 | 97–332 | 127–415 | 0.07–0.17 s |

`loginctl activate` returns sooner (it does not wait for the switch) but the
switch itself takes the same time; neither is faster. The emergency path keeps
the bounded switch with its own polling. These are virtio-gpu numbers; real
modesets are slower.

**Real hardware.** Section "Hardware test matrix" below.

### 2. Shared system daemons

**Evidence** (polkit defaults are any/inactive/active from the upstream
`.policy` files):

| Daemon | Decoy-disk write for the hidden user | Gate | Names the user |
| --- | --- | --- | --- |
| NetworkManager | keyfile in `/etc/NetworkManager/system-connections` (`settings.modify.own`: auth_self_keep/yes/**yes**; `.system`: auth_admin_keep with the default build); `timestamps` on any activation; DHCP leases; `seen-bssids` | polkit, except timestamps | keyfile: `permissions=user:<name>`; gnome-shell sets it itself |
| AccountsService | `/var/lib/AccountsService/users/<name>` on any setter (`change-own-user-data` yes/yes/yes); FindUser* only in RAM | polkit | yes (file name) |
| logind | `/var/lib/systemd/linger/<name>` (`set-self-linger` yes/yes/yes); hibernation image (`hibernate` …/yes) | polkit | yes |
| bluetoothd | link keys and device cache in `/var/lib/bluetooth` | **D-Bus policy only, no polkit** | no |
| CUPS | spool files with `job-originating-user-name`; `subscriptions.conf` `Owner <name>` written as soon as GNOME's print-notifications plugin starts | IPP over `/run/cups/cups.sock` or :631, not D-Bus | yes |
| PackageKit | `transactions.db` with uid and cmdline; `proxy(uid, session)` | polkit (refresh, proxy: …/yes) | yes (uid) |
| colord | `storage.db` rows with uid | polkit (…/yes) | yes (uid) |
| udisks2 | Debian/Ubuntu only: `/media/<user>` and `/var/lib/udisks2/mounted-fs-persistent` | polkit (mount …/yes) | yes on Debian; NixOS uses `/run` |
| fwupd | metadata refresh without polkit | none | no |
| power-profiles-daemon, systemd-rfkill, upower history | state files | polkit / none | no (timing only) |
| timedated, localed, hostnamed, PID 1 unit files | `/etc` | auth_admin_keep (NixOS also patches the setters off) | no |
| systemd-coredump | `/var/lib/systemd/coredump/core.<comm>.<uid>…` and a journal record | the kernel pipes hidden crashes to the host helper | yes |

[V-src for all; full citations in the research notes summarised under Sources.]

**Mitigation options.**

- **polkit rule in `/run/polkit-1/rules.d`: works** for every polkit-gated write.
  polkit reads `/run/polkit-1/rules.d` since **126** (Debian trixie yes, Ubuntu
  noble's 124 no; NixOS has 127). Files sort by basename across directories, so
  `00-….rules` runs first; `systemctl reload polkit` (SIGHUP, `Type=notify-reload`)
  picks it up without a new mount namespace. `subject.user` falls back to the
  decimal uid if `getpwuid()` fails, so the rule matches both [V-src:
  `polkitbackendduktapeauthority.c`, `polkitbackendcommon.c`]. On polkit ≤ 125:
  bind-mount a tmpfs copy over `/etc/polkit-1/rules.d` plus SIGHUP. The rule
  should deny everything except the login1 actions a desktop needs, and also deny
  `set-self-linger`, `hibernate*` and `set-reboot-*`.
- **D-Bus `<policy user="<uid>">` deny: works**, and is the only option for
  bluez and fwupd. Both dbus-daemon and dbus-broker parse a numeric uid without
  NSS; user policies override `context="default"` allows. Neither reads policy
  from `/run`, so it needs a bind mount of a tmpfs copy over the bus config plus
  `ReloadConfig`, or a static uid-free `<includedir>/run/dbus-1/system.d</includedir>`
  on the decoy (an enabler, ADR 0005's objection) [V-src].
- **CUPS:** do not bind `/run/cups` into the hidden root and reject the hidden
  uid on port 631 (`nft … meta skuid <uid> tcp dport 631 reject`, runtime).
- **xdg-dbus-proxy as the hidden root's system bus: works with constraints.**
  Unix fds pass through. The bus sees the proxy's credentials, so the proxy must
  run as the hidden uid (EXTERNAL auth) and inside the hidden session's scope
  (logind resolves `session/auto` from the peer's cgroup; TakeControl checks
  only the euid) [V-src: `flatpak-proxy.c`, `logind-dbus.c`,
  `logind-session-dbus.c`]. PAM's `CreateSession` must run as root on the real
  bus, so the filter can only be applied **after** login: the spike bind-mounts
  the proxy socket over `/run/dbus/system_bus_socket` inside the hidden mount
  namespaces with `nsenter`. A product would do this from a privileged session
  helper between `pam_open_session()` and the privilege drop. Two caveats: an
  allowlisted `org.freedesktop.login1` still lets `set-self-linger` through, so
  the polkit rule is needed anyway; and the proxy is a host-rooted, dumpable
  process of the hidden uid, so `/proc/<proxy>/root` is a door to the decoy for
  the hidden uid (deliberate misuse only, outside the threat model).
- **Hidden-root copies of NetworkManager, AccountsService etc. on the host bus:
  impossible** (well-known names are unique per bus). With a second, hidden bus
  the compositor still needs `org.freedesktop.login1` on the same bus; no
  existing tool forwards one name between buses. Rejected.
- **Private network namespace:** partial. It stops hidden network use from
  touching the decoy NM's state only if the device is first unmanaged through a
  runtime drop-in in `/run/NetworkManager/conf.d` (otherwise its disappearance
  writes timestamps). Wi-Fi moves with `iw phy … set netns` and returns to the
  init namespace when the namespace dies [V-src: `net/wireless/core.c`]. It does
  not cut D-Bus or path sockets.
- **Cross-cutting:** `LimitCORE=1` on hidden units (the kernel skips the pipe
  helper at a limit of 1), `AllowHibernation=no` in `/run/systemd/sleep.conf.d`,
  `memory.swap.max=0` on the hidden slices, hidden user never in `wheel`.

**Residual.** NM `timestamps`/`seen-bssids` on activation, upower history and
rfkill state cannot be stopped per user. They do not name the user, but their
timing correlates with hidden sessions. Document them.

**VM probe.** R2-A/B/C: as the hidden user inside its active seat0 session,
`nmcli connection add` (system and `permissions=user:aux`), AccountsService
`SetLanguage`, `timedatectl set-timezone`, `loginctl enable-linger`; hashes of
`/etc/NetworkManager`, `/var/lib/NetworkManager`, `/var/lib/AccountsService`,
`/etc/localtime` and `/var/lib/systemd/linger` before and after. A: no
mitigation (finding). B: the `/run` polkit rule (asserted: no new keyfile, no
AccountsService change, no time-zone change, no linger file, login1 still
usable). C: the proxy (asserted: no keyfile, no AccountsService or time-zone
change, `session/auto` through the proxy is the hidden session). The linger
write through the proxy and the `/proc/<proxy>/root` door are logged. [V-spike
pending]

**Real hardware.** Bluetooth pairing and Wi-Fi need real radios: pair a device
and join a network from the hidden session with the D-Bus deny in place, then
diff `/var/lib/bluetooth` and `/var/lib/NetworkManager`.

### 3. Idle decoy over hours

**Evidence.**

- logind is idle only if no idle inhibitor exists **and** every user/greeter
  session reports idle; an inactive session counts as idle only if its own hint
  says so [V-src: `logind-core.c manager_get_idle_hint`]. Graphical sessions
  report what the desktop sends with `SetIdleHint` (GNOME does; KDE does not:
  KDE bug 448942, so a Plasma decoy never becomes logind-idle). TTY sessions use
  the tty atime.
- logind re-reads its configuration on SIGHUP, but arms the idle timer only at
  startup and only when `IdleAction` is not `ignore` [V-src: `logind.c`
  `manager_dispatch_idle_action`, called once from `manager_startup`]. So a
  `/run/systemd/logind.conf.d` drop-in cannot turn idle actions **on** at
  runtime, and NixOS never restarts logind ("restarting breaks X11").
- An idle block inhibitor makes the system non-idle; a sleep block refuses
  `Suspend` calls, and since v257 even root's and the caller's own [V-src:
  `logind-core.c`, `logind-dbus.c verify_shutdown_creds`, NEWS v257].
  `LidSwitchIgnoreInhibited=yes` is the default, so only a `handle-lid-switch`
  lock stops the lid; handle-* locks from processes in an inactive session are
  ignored, locks from a system unit count [V-src: `logind-action.c`,
  `logind-inhibit.c`].
- Traces: inhibitor state is in `/run/systemd/inhibit` (RAM); start/stop is
  logged at debug level only, but a **refused** action logs at error level
  "Refusing … inhibited by UID …/user, PID …/comm" [V-src: `logind-action.c`].
  On the required volatile journal that is RAM only; the `--who`/`--why` must be
  neutral because `systemd-inhibit --list` shows them live.
- GNOME: gsd-power ignores idle transitions and clears its suspend timers while
  the session is inactive, and forces "normal" when it becomes active again
  [V-src: `gsd-power-manager.c`]; in a VM it disables suspend-on-idle entirely,
  so a VM cannot show the real path. gnome-shell locks on logind `Lock`,
  `PrepareForSleep` and its own idle watch; whether that idle watch fires while
  inactive is unverified, so a lock screen on return is likely. KDE PowerDevil
  clears idle timeouts on inactive sessions (bug 369584, fixed 5.7).
- A lock is not a logout: `LockSession` only emits the session's `Lock` signal
  [V-src: `logind-session-dbus.c`].

**Mitigation.** A host system unit in the hidden slice holds
`systemd-inhibit --what=idle:sleep:handle-lid-switch --mode=block` with neutral
names, only while the hidden session runs (emergency kills it with the slice).
Alternative for sleep: `--mode=delay` and react to `PrepareForSleep` by running
emergency within `InhibitDelayMaxSec`, which logs no refusal. Accept the decoy
lock screen on return (go/no-go 3).

**VM probe.** R3: the decoy has `IdleAction=suspend`, `IdleActionSec=20s` and
a stubbed `systemd-suspend.service`; the decoy session's idle hint is set by
root, the hidden tty session is idle by atime. Control without an inhibitor
(finding), then 75 s with the inhibitor (asserted: no "System idle" from logind
and no stubbed suspend, provided the control fired), then a decoy-user `Suspend`
call against the sleep lock (finding). [V-spike pending]

**Real hardware.** GNOME and KDE decoys left inactive for 1 h and 8 h on a laptop
on battery and on AC, lid closed and open, with the inhibitor; record lock
screen, blank, suspend and the first frame on return.

### 4. `/proc/1/root`

**Evidence.**

- An unprivileged hidden uid cannot follow `/proc/<pid>/root` of another uid,
  and not even of its own uid when the target is not dumpable [V-src:
  `fs/proc/base.c proc_fd_access_allowed`, `kernel/ptrace.c`]. `(sd-pam)` of
  `user@.service` drops privileges without exec, so `commit_creds` sets it to
  `suid_dumpable` (2 on NixOS via `50-coredump.conf`), and it is safe. Any
  host-rooted process of the hidden uid that **did** exec (the filtering proxy,
  a host-side greeter) is dumpable and is a door.
- `ProtectProc=invisible` / `hidepid=2` do not affect root [V-src:
  systemd.exec(5)].
- `PrivatePIDs=` exists since v257 (trixie, Ubuntu 25.10, 26.04, our 259; not
  noble's 255), service units only, not `Type=forking`. `setup_pam()` runs
  before the PID namespace is created, so pam_systemd still registers from the
  host PID namespace [V-src: `exec-invoke.c`]. It cannot be used on
  `user@.service`: `systemd --user` refuses to run as PID 1 ("Can't run --user
  mode as PID 1", `main.c`).
- NixOS's `/run/wrappers` allows setuid, so a hidden root that binds the host
  `/run` gets `/run/wrappers/bin/sudo`; it reads the hidden root's
  `/etc/sudoers`. `NoNewPrivileges=yes` blocks setuid and file capabilities, but
  not root reached through IPC (polkit-mediated `systemd-run`, `pkexec`, udisks
  …) [V-src: systemd.exec(5)].

**Mitigation.** `NoNewPrivileges=yes`, an empty `CapabilityBoundingSet=`,
`RestrictSUIDSGID=yes` on every hidden unit and the user@ drop-in; the polkit
rule from risk 2; `PrivatePIDs=yes` on hidden system-style units and, if R4b
shows logind accepts it, on the session leader's unit; no host-rooted exec'd process running as the hidden uid.
On 255: an `unshare --pid --fork --mount-proc` wrapper.

**VM probe.** R4: `/proc/1/root/<decoy-only tmpfs>` read as the hidden user in
its session, via `(sd-pam)`, as a hidden sudoer (hidden-root sudoers only) with
and without `NoNewPrivileges=` (asserted blocked with it), as hidden root with
nothing, `ProtectProc=invisible`, and `PrivatePIDs=yes` (asserted blocked); and
a second `login -f` session whose unit has `PrivatePIDs=yes` (finding: does
logind accept it, what does a hidden sudoer see). [V-spike pending]

### 5. Mount-namespace copies

**Evidence.** `CLONE_NEWNS` copies **every** mount, private and unbindable
included (`copy_mnt_ns` passes `CL_COPY_UNBINDABLE`); only nsfs bind mounts of
mount namespaces are skipped [V-src: `fs/namespace.c`;
`sharedsubtree.rst` §g]. So the spike's "private tmpfs at `/run/aux`" does
**not** stop a decoy service started later (with `PrivateTmp=`,
`ProtectSystem=`, or any D-Bus-activated daemon with a sandbox, such as
accounts-daemon or timedated) from holding a frozen copy that pins the hidden
filesystem. The first spike's teardown already unmounts such copies with
`nsenter`; that works but is cleanup, not prevention, and the copies can see
the hidden root while they exist.

**Mitigation.**

- **systemd 259 (NixOS pin, Ubuntu 26.04):** build the overlay inside a mount
  namespace pinned on a file in `/run` (the pin is not copied into other
  namespaces), and start hidden units with
  `nsenter --mount=<pin> systemd-run --root-directory=<path> …`. systemd-run
  opens the tree with `open_tree(OPEN_TREE_CLONE)` in the caller's namespace and
  passes the fd as `RootDirectoryFileDescriptor=`; PID 1 moves it into the unit's
  own namespace [V-src: `run.c`, `namespace.c`]. The host tree never contains the
  overlay, and the units keep systemd's sandboxing. Limits: transient services
  only (not scopes, not `user@.service`; the user manager would need its own
  wrapper).
- **255/257:** the same pinned namespace with an `nsenter --mount=… --root=…`
  ExecStart wrapper, losing `RootDirectory=`/`BindPaths=` sandboxing.

**VM probe.** R5a (finding): a decoy service with `PrivateTmp=` started after
activation, with the hidden tree below a private, then an unbindable tmpfs. R5b
(asserted): an overlay that exists only in a pinned namespace is absent from the
host and from a decoy service started later; units entering it with `nsenter`
and with `systemd-run --root-directory=` are logged.

Results: R5a [V-spike 6adc66c] **confirms the leak**: a decoy service with
`PrivateTmp=` started after activation held a copy of the hidden root, both with
the hidden tree below a private tmpfs and with that tmpfs made unbindable. R5b
[V-spike pending].

### 6. Hidden NixOS system services

**Evidence.**

- With `RootDirectory=`, `StateDirectory=`, `CacheDirectory=` and
  `LogsDirectory=` are created on the **host** under `/var/lib`, `/var/cache`,
  `/var/log` and bind-mounted in [V-src: `exec-invoke.c` `setup_exec_directory`
  joins the host prefix]. That is a decoy-disk write with the service's name.
  `EnvironmentFile=` and the PAM stack are read on the host before the namespace
  exists.
- Portable services (`portablectl attach --runtime`, directory images) are the
  upstream form of "units from another root", but they keep state on the host by
  design and add `PORTABLE=` journal fields [V-src: `portable.c`].
- Bus-name owners (NetworkManager, accounts-daemon, …), logind, udev and
  journald cannot run a second time on the host bus (risk 2).
- logind in nspawn has no graphical seat (systemd #35114, #36673).

**Mitigation.** NAILS generates **runtime unit files** (not transient units) in
`/run/systemd/system` from the hidden toplevel's units, adds the hidden-root
properties (or the risk-5 fd mechanism), and rewrites `StateDirectory=` and
friends into directories that already exist in the hidden root. Units that own
a bus name or need a real init are dropped, or run in an nspawn container with
its own bus (headless only). A hybrid "nspawn for headless services plus the
dual-root desktop" is viable but gives the hidden session two system buses.

**VM probe.** R6: a hidden unit with `StateDirectory=`/`LogsDirectory=` (finding:
where the directories appear), and the rewritten variant (asserted: nothing on
the host, data in the upper). [V-spike pending]

### 7. Other risks

- **Audio: mitigable.** uaccess ACLs follow the active session; PipeWire 1.6.2
  watches `/dev/snd` with inotify and drops or re-adds cards as access changes
  [V-src: `alsa-udev.c`]. WirePlumber's device reservation is per user. After
  emergency the decoy's PipeWire re-adds the card once the hidden one's fds are
  closed. Breaks if either user is in the `audio` group (Debian installers used
  to add the first user); check it. Bluetooth audio needs real hardware.
- **Input: solved** for logind-managed displays (`EVIOCREVOKE` on leave); grabs die
  with the fd. New risk: Ctrl+Alt+F*n* from the decoy into an unlocked hidden
  desktop; lock the hidden session on deactivation or treat an unexpected
  deactivation as a trigger.
- **GPU held at SIGKILL: solved** normally (DRM scheduler discards queued jobs for
  a SIGKILLed task; master released at close). D-state on NVIDIA (pinned memory,
  nvkms deadlocks) **needs real hardware**; emergency must time out and report
  stuck tasks.
- **systemd-homed: solved** if the hidden record is a plain `/run/userdb` record
  (homed never writes it) and its uid avoids 60001–60513. A homed decoy with
  lock-on-suspend shows its lock screen after resume. The spike uses uid 60777
  (unused range 60706–61183, outside SDDM's default 1000–60000).
- **DM user lists: mitigable.** accounts-daemon lists only `/etc/passwd` users,
  but gnome-shell's user manager adds every user with a seat session (in memory)
  and GDM would show it; SDDM enumerates NSS, so userdb users within its uid
  range. Use a uid above 60000 in the unused range, a login shell missing from the
  host `/etc/shells` (accountsservice then treats the user as a system account),
  and a locked password.
- **AppArmor: same attachment** (paths are namespace-relative, the hidden root
  mirrors the host). **Snaps: blocker** inside the hidden root: snap-confine joins
  preserved namespaces under `/run/snapd/ns` built from the host root, and the
  overlay of `/` has no `/snap` loop mounts. Exclude snaps; use debs or user
  Flatpaks. SELinux: untested.
- **Secure Boot / lockdown: orthogonal** (no lockdown reason covers overlayfs,
  namespaces, `cgroup.kill` or VT ioctls; it blocks hibernation, which helps).
- **seatd vs logind: solved.** libseat's logind backend finds the session from
  `XDG_SESSION_ID`; sway/labwc work; GNOME and Plasma need the user@ drop-in
  because they start as user units.
- **Shared `/dev/shm`, SysV IPC, abstract sockets, `/run/utmp`:** RAM only, but
  visible to the decoy while the session runs and left behind after `cgroup.kill`
  (no DEAD_PROCESS utmp record). Teardown sweeps them; the hidden X server uses an
  explicit display number and `-nolisten local`. R7a probes `/dev/shm`, abstract
  sockets and the `/dev/dri` ACLs during and after the session.
- **Observer during the session** sees the extra session and processes; accepted,
  emergency removes them. **The panic trigger** must not depend on the hidden
  session being healthy (host-side evdev watcher without a grab) [I].

### Hardware test matrix (what the VM cannot answer)

1. GPUs: NVIDIA proprietary and open at 570, 580 (incl. 580.95.05, 580.126.09),
   595, ≥ 610.57.04 and 615 with `modeset`/`fbdev` 0/1; amdgpu (RDNA2/3), i915
   (Gen9/12), xe, nouveau. Kernels 6.12, 6.18 and 7.x.
2. Decoys: GNOME Wayland, Plasma 6 Wayland, sway, an X11 desktop with a GLX
   compositor and without one.
3. Hidden display: rootful Xorg vs logind-managed Xorg, mutter, KWin, sway.
4. Emergency variants: the bounded sequence above vs plain `chvt` vs
   `loginctl activate`; hidden server idle, under GPU load, mid-flip, and
   wedged.
5. Displays: eDP, HDMI, DP, MST dock, two monitors, VRR and HDR on/off, monitor
   in DPMS standby.
6. Duration: 1 min, 1 h, 8 h before emergency; record lock screen, blank and
   stale clock.
7. Measure time to a visible decoy, any visible hidden frame or console flash,
   the DRM master owner, and journal errors (`drmSetMaster failed`, flip
   timeouts, Xid, hung tasks). 50 cycles per cell.
8. Radios: Bluetooth pairing and Wi-Fi from the hidden session with the D-Bus
   deny and the polkit rule; diff the decoy state directories.

### What this changes in the design

- The emergency path is the bounded sequence in risk 1, not "chvt, then kill".
- D+ step 1 becomes `NoNewPrivileges=` plus `PrivatePIDs=` where systemd allows
  it; the user manager cannot have a PID namespace.
- D+ step 3 is replaced: no hidden copies of bus-name daemons; instead the
  polkit rule, a D-Bus uid deny and blocked CUPS, optionally the filtering proxy.
- The mount-namespace mitigation is the pinned namespace plus
  `systemd-run --root-directory=` (259), not the private tmpfs.
- Hidden NixOS services need unit rewriting (`StateDirectory=` etc.).
- The hidden user gets a uid in 60706–61183, a shell outside `/etc/shells`, a
  locked password, no `wheel`, `LimitCORE=1`, no swap, no hibernation.
- Ubuntu: no snaps inside the hidden root.

## What the spike does and does not show

It shows, in one graphical VM: a whole-root overlay on LUKS; a rootful X server
on VT 8 and a `login -f` logind session on tty9, both inside the hidden root; the
hidden user manager moved into the hidden root by a runtime drop-in; hidden
writes landing only in the upper; the decoy (lightdm autologin, icewm, xterm)
unchanged across the emergency; the emergency timings; strict unmount and close;
and a raw-disk grep. It also logs findings for the `/proc/1/root` probe (as root
and as the hidden user), hidden stdout in the host journal, utmp residue, where
lastlog2 went, the `(sd-pam)` helper's root, other mount namespaces holding a
copy of the hidden root, and the decoy's sector-write counters.

It does not show: real GPUs (QEMU's virtual display only), NVIDIA, Wayland
compositors under logind, GNOME/KDE, a private `/run`, or a hidden NixOS
toplevel. The shared-daemon audit, the PID namespace, the screen after a killed
hidden display server, idle inhibitors and the mount-namespace alternatives are
in the second spike (risk assessment). In the spike the logind session
(tty9) and the display (VT 8) are on different VTs, to keep the spike to a
rootful X server; a product would start a logind-managed compositor from the
session on the same VT.

## Sources

- systemd `exec_invoke()` (PAM before namespaces):
  https://github.com/systemd/systemd/blob/v259/src/core/exec-invoke.c
- systemd namespace setup, API VFS fallbacks overridden by explicit binds:
  https://github.com/systemd/systemd/blob/v259/src/core/namespace.c
- libuserdb drop-in fallback:
  https://github.com/systemd/systemd/blob/v259/src/shared/userdb.c ; user
  record format: https://systemd.io/USER_RECORD/ ; drop-in locations:
  https://www.freedesktop.org/software/systemd/man/latest/nss-systemd.html
- pam_systemd (session class handling, `systemd-user` special case):
  https://github.com/systemd/systemd/blob/v259/src/login/pam_systemd.c
- systemd.exec(5) (`RootDirectory=`, `BindPaths=`, `MountAPIVFS=`,
  `PrivatePIDs=` since v257):
  https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html ;
  v257 release notes: https://github.com/systemd/systemd/releases/tag/v257
- cgroup v2 `cgroup.kill`: https://docs.kernel.org/admin-guide/cgroup-v2.html
- Kernel VT switching and `reset_vc()`:
  https://github.com/torvalds/linux/blob/master/drivers/tty/vt/vt_ioctl.c
- logind in nspawn cannot open a seat (not supported):
  https://github.com/systemd/systemd/issues/35114 ; request for a graphical seat
  in nspawn: https://github.com/systemd/systemd/issues/36673
- Wireless interfaces in nspawn (v256+, moving the phy):
  https://blog.nspawn.org/posts/wireless-adapters-on-systemd-nspawn-containers/
- NVIDIA VT-switch / Wayland black-screen reports:
  https://github.com/NVIDIA/open-gpu-kernel-modules/issues/1378 ,
  https://forums.developer.nvidia.com/t/black-screen-when-switching-to-vt1-on-geforce-gt-650m/49805
- NixOS modules in the pinned nixpkgs: `programs/shadow.nix` (`login` with
  `updateWtmp`), `security/pam.nix` (pam_lastlog2),
  `services/x11/display-managers/lightdm.nix` (xserver wrapper),
  `system/boot/systemd.nix` (nss-systemd in `nsswitch.conf`)
- xdg-dbus-proxy (filtering D-Bus proxy): https://github.com/flatpak/xdg-dbus-proxy

Risk assessment (2026-10-07):

- Kernel VT switch and release handshake, lost switches:
  https://github.com/torvalds/linux/blob/v6.18/drivers/tty/vt/vt_ioctl.c ;
  DRM master release and framebuffer removal:
  https://github.com/torvalds/linux/blob/v6.18/drivers/gpu/drm/drm_auth.c ,
  https://github.com/torvalds/linux/blob/v6.18/drivers/gpu/drm/drm_framebuffer.c
- kbd `chvt` retries: https://github.com/legionus/kbd/blob/v2.9.0/src/chvt.c ;
  logind VT handling and paused devices:
  https://github.com/systemd/systemd/blob/v259/src/login/logind-session.c ,
  https://github.com/systemd/systemd/blob/v259/src/login/logind-session-device.c
- NVIDIA VT-return and close-path reports:
  https://github.com/NVIDIA/open-gpu-kernel-modules/issues/957 ,
  https://github.com/NVIDIA/open-gpu-kernel-modules/issues/1371 ,
  https://forums.developer.nvidia.com/t/vt-switch-results-in-black-screen-cursor-on-xorg-with-certain-compositors-545/328357 ,
  https://forums.developer.nvidia.com/t/nvkms-close-deadlock-on-semaphore-held-by-xorg-parked-in-nvkms-yield-580-126-09-rtx-3050-6-17-kernel/367587 ,
  https://forums.developer.nvidia.com/t/nvidia-drm-fbdev-0-with-kernel-7-x-causes-vt-black-screen/373248
- polkit rule directories (`/run/polkit-1/rules.d` since 126) and reload:
  https://github.com/polkit-org/polkit/blob/127/src/polkitbackend/polkitbackendduktapeauthority.c ,
  https://github.com/polkit-org/polkit/blob/125/src/polkitbackend/polkitbackendduktapeauthority.c ,
  https://github.com/polkit-org/polkit/blob/127/data/polkit.service.in
- Daemon policies and writes:
  https://gitlab.freedesktop.org/accountsservice/accountsservice/-/blob/23.13.9/data/org.freedesktop.accounts.policy.in ,
  https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/1.56.0/src/core/settings/nm-settings.c ,
  https://github.com/systemd/systemd/blob/v259/src/login/org.freedesktop.login1.policy ,
  https://github.com/bluez/bluez/blob/master/src/bluetooth.conf ,
  https://github.com/OpenPrinting/cups/blob/v2.4.16/scheduler/subscriptions.c
- xdg-dbus-proxy credential and fd forwarding:
  https://github.com/flatpak/xdg-dbus-proxy/blob/0.1.6/flatpak-proxy.c ;
  logind session lookup from the sender:
  https://github.com/systemd/systemd/blob/v259/src/login/logind-dbus.c
- logind idle computation and idle timer:
  https://github.com/systemd/systemd/blob/v259/src/login/logind-core.c ,
  https://github.com/systemd/systemd/blob/v259/src/login/logind.c ;
  KDE does not set the idle hint: https://bugs.kde.org/show_bug.cgi?id=448942
- `systemd --user` refuses PID 1:
  https://github.com/systemd/systemd/blob/v259/src/core/main.c ; `PrivatePIDs=`:
  https://github.com/systemd/systemd/blob/v259/src/core/exec-invoke.c
- Mount-namespace copies: https://github.com/torvalds/linux/blob/v6.18/fs/namespace.c
  (`copy_mnt_ns`), https://docs.kernel.org/filesystems/sharedsubtree.html ;
  `systemd-run --root-directory=`:
  https://github.com/systemd/systemd/blob/v259/src/run/run.c
- PipeWire device access: https://github.com/PipeWire/pipewire/blob/1.6.2/spa/plugins/alsa/alsa-udev.c ;
  snap-confine namespaces:
  https://github.com/canonical/snapd/blob/master/cmd/snap-confine/README.mount_namespace ;
  uid ranges: https://systemd.io/UIDS-GIDS/
