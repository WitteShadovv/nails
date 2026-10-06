# 9. Dual root on one seat: whole-root isolation with a non-disruptive emergency

- Status: proposed (research; a decision waits on the spike and the hardware matrix)
- Date: 2026-10-06
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
At the time of writing it has **not run yet**. It evaluates to a system closure
with a read-only store, but no Nix daemon or KVM was available.

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
| `/proc/<pid>/root` and `/proc/<pid>/cwd` of host processes | A **root** process in the hidden root can reach the decoy filesystem through `/proc/1/root` (same PID namespace). An unprivileged hidden user cannot (ptrace access check) [V-spike: both probes are logged] | A PID namespace for the hidden tree (`PrivatePIDs=`, systemd ≥ 257, or `unshare --pid`); keep hidden system services few |
| The host **journal** | stdout of hidden units, logind's "New session … of user aux", and the unit names reach the decoy's journald. On the required volatile journal that is RAM only [V-spike: the token stays off the raw disk] | Neutral unit names; `StandardOutput=null` or a hidden journald socket; scrub the volatile journal after teardown (emergency already does) |
| Shared `/run` | userdb records, drop-ins, `/run/user/<uid>`, utmp entries left after SIGKILL (no logout record) | Bind only the needed parts of `/run` (D+); remove what NAILS created at teardown; a private `/run/utmp` |
| Mount-namespace copies | A decoy service that creates its own mount namespace while the hidden root is mounted (an on-demand service with `PrivateTmp=` or `ProtectSystem=`) gets a private copy of the hidden mounts. It can see the hidden root, and its copy pins the hidden filesystem, so the backend cannot close [I; V-spike logs any such namespace] | Build the hidden root below a private tmpfs, so mounts made before a service starts are not propagated. At teardown, find namespaces whose `mountinfo` holds the hidden root and unmount the copy inside each with `nsenter -m` (structural, not heuristic). Longer term, mount the hidden root only inside a dedicated mount namespace |
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
2. A private `/run` in the hidden root with only the host system-bus socket, the
   logind state directories (`/run/systemd/{seats,sessions,users}`), `/run/udev`
   (read-only) and `/run/user/<uid>` bound in.
3. A filtered system bus for the hidden root (`xdg-dbus-proxy --filter
   --talk=org.freedesktop.login1 …` on a socket at the hidden root's
   `/run/dbus/system_bus_socket`), and hidden-root instances of the stateful
   daemons the hidden desktop needs. They are started by the host PID 1 as units
   with `RootDirectory=`, joined to the hidden namespaces with
   `JoinsNamespaceOf=`, and talk to a hidden dbus-daemon.
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

## Risks

- **VT/DRM handover on proprietary drivers** (NVIDIA): black screen after the
  switch back. That would be the worst possible emergency outcome. Mitigation:
  the hardware matrix, and N as the fallback.
- **The decoy desktop reacting to being inactive for hours**: screen lock (fine),
  idle suspend (not fine while the hidden session runs), or a desktop that
  treats a long-inactive session specially [I]. Mitigation: inhibitors, and
  measuring it.
- **Shared system daemons** writing decoy-disk state on the hidden user's behalf
  until D+ step 3 exists. This is the same *class* of leak as T-132, but limited
  to a short, enumerable list of D-Bus services instead of every process.
- **Root inside the hidden root** without a PID namespace can reach the decoy
  through `/proc/1/root`.
- **Observer during the session** sees an extra logind session and processes with
  `loginctl`/`ps`. That is accepted, because emergency removes them.
- **Display managers that react to a new seat0 session**: GDM's or SDDM's user
  switcher may list the hidden session while it exists [I]. Hidden sessions
  should use a class or type the greeter ignores, which needs checking per
  display manager.
- **Keyboard VT switching** (Ctrl+Alt+F*n*) lets anyone at the keyboard switch
  between the two desktops while the hidden one runs. That is also a feature: an
  instant, non-destructive "boss key". Hidden compositors can disable it if the
  operator prefers.
- **The panic trigger** must not depend on the hidden session being healthy. A
  host-side watcher that NAILS runs from the hidden volume, reading evdev without
  a grab, can fire emergency even if the hidden compositor hangs [I].

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
compositors under logind, GNOME/KDE, the shared-daemon audit, a private `/run`,
the PID namespace, or a hidden NixOS toplevel. In the spike the logind session
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
