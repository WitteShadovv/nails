# Research spike (ADR 0009): two roots, one seat. The decoy desktop keeps
# running on its own VT while a hidden display server and session run on
# another VT inside a whole-root overlay, and emergency is "kill the hidden
# cgroups, switch back to the decoy VT".
#
# This is NOT a regression test. It carries the `research` tag, which keeps it
# out of every default group (`ci`, `all`, the shards and `--affected`); build
# it explicitly:
#
#   nix build .#legacyPackages.x86_64-linux.e2e.research-dual-root-vt-emergency -L
#
# What it does:
#
#   1. Boots the graphical decoy from graphical-vm-config.nix (lightdm autologin
#      as testuser, icewm + xterm) and records its VT, X server PID, display
#      manager PID and logind session.
#   2. Builds a whole-root overlay at /run/aux/root: lower = a read-only bind of
#      the decoy root, upper/work on the LUKS volume (/mnt/data/root/...).
#   3. Makes a hidden user (uid 60123) resolvable on the host through a JSON
#      user record in /run/userdb (RAM; nss-systemd reads drop-ins in-process),
#      and gives user@60123.service a runtime drop-in in /run/systemd/system so
#      the hidden user manager also runs with the overlay as its root.
#   4. Starts a rootful X server on VT 8 as a transient unit in aux.slice with
#      RootDirectory=/run/aux/root. It takes the VT and DRM master; the decoy X
#      server keeps running on its own VT, still logged in, now inactive.
#   5. Runs `login -f aux` on tty9 inside the same root. login's PAM stack is
#      the overlay's /etc/pam.d/login, so pam_systemd registers a real logind
#      session on seat0 with the host logind, and every write PAM makes
#      (lastlog2, wtmp) lands in the upper. The session's ~/.bash_profile starts
#      icewm + xterm on the hidden display. If no session appears, a plain unit
#      starts the same clients so the core trick is still exercised (FINDING).
#   6. Emergency, timed from the host: `chvt <decoy VT>`, then cgroup.kill on
#      aux.slice and user-60123.slice, then wait until both are empty.
#   7. Asserts: the decoy X server, display manager and session are the same
#      objects as before and the session is active again on the decoy VT; no
#      hidden process is left; the overlay unmounts strictly (no lazy detach) and
#      the LUKS volume closes; no hidden token is anywhere on the raw decoy disk.
#
# The hidden programs (X, icewm, xterm, login) come from the decoy's own Nix
# store here, bound read-only into the hidden root. In NAILS they would come
# from the hidden store; that difference does not affect what is proven.
#
# How to read the log: lines starting with `FINDING:` are research output
# (timings, residue in RAM, leak probes), not assertions.
{ pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;

  # Neutral names only: everything below lives in RAM (/run, cgroups, the unit
  # table), but an observer at the keyboard can still list it while the hidden
  # session runs.
  hiddenUid = 60123;
  hiddenUser = "aux";
in
{
  name = "research-dual-root-vt-emergency";
  meta.tags = [ "research" ];
  # Estimate, not measured: one graphical boot, two X servers and one raw pass
  # over the 20 GiB decoy disk.
  globalTimeout = 1800;

  nodes.machine =
    {
      config,
      lib,
      pkgs,
      ...
    }:
    let
      dm = config.services.xserver.displayManager;
      # The environment lightdm's xserver wrapper exports (driver and XKB
      # paths). The hidden X server needs the same to find its modules.
      xEnv = lib.filterAttrs (_: v: v != null) config.systemd.services.display-manager.environment;
      exports = lib.concatStrings (
        lib.mapAttrsToList (n: v: "export ${n}=${lib.escapeShellArg (toString v)}\n") xEnv
      );
      # xserverArgs carries ":0" (the decoy display); the hidden server is :1.
      xArgs = lib.concatStringsSep " " (lib.filter (a: a != ":0") dm.xserverArgs);
    in
    {
      imports = [ ./../../lib/graphical-vm-config.nix ];

      environment.systemPackages = [
        pkgs.kbd # chvt
        pkgs.xprop
        pkgs.shadow # login -f

        # The hidden display server: rootful X on its own VT. `-nolisten local`
        # turns off the abstract socket, which lives in the shared network
        # namespace and would let decoy-side clients reach the hidden display.
        # The path socket in /tmp/.X11-unix is inside the overlay, so only
        # processes with the hidden root can connect. The log goes to /var/log
        # inside the overlay, i.e. to the upper.
        (pkgs.writeShellScriptBin "aux-display" ''
          ${exports}
          exec ${dm.xserverBin} ${xArgs} :1 vt"$1" -nolisten local -logfile /var/log/X.1.log
        '')

        # Emergency, as NAILS would run it from the host side. It prints
        # timings in milliseconds since the trigger.
        (pkgs.writeShellScriptBin "aux-emergency" ''
          set -u
          decoy_vt=$1
          shift
          now() { date +%s%N; }
          active() { cat /sys/class/tty/tty0/active; }
          t0=$(now)

          # 1. Bring the decoy VT to the front first. The hidden X server is
          #    asked to release the VT and drops DRM master; the decoy X server
          #    re-acquires both and repaints. Doing this before the kill means
          #    no frame of a dying hidden desktop and no text console shows.
          chvt "$decoy_vt" &
          chvt_pid=$!
          for _ in $(seq 1 50); do
            [ "$(active)" = "tty$decoy_vt" ] && break
            sleep 0.01
          done
          t_switch=$(now)

          # 2. Kill every hidden process at once. cgroup.kill is atomic per
          #    subtree (SIGKILL, no grace, no shutdown hooks). If the hidden X
          #    server had not acknowledged the VT release, its death lets the
          #    kernel complete the switch (the VT falls back to VT_AUTO).
          for cg in "$@"; do
            [ -e "$cg/cgroup.kill" ] && echo 1 > "$cg/cgroup.kill"
          done
          t_kill=$(now)

          for cg in "$@"; do
            while [ -e "$cg/cgroup.events" ] && grep -q '^populated 1' "$cg/cgroup.events"; do
              sleep 0.005
            done
          done
          t_dead=$(now)

          for _ in $(seq 1 500); do
            [ "$(active)" = "tty$decoy_vt" ] && break
            sleep 0.01
          done
          t_active=$(now)
          wait "$chvt_pid" 2>/dev/null || true

          ms() { echo $(( ($1 - t0) / 1000000 )); }
          echo "switch_ms=$(ms "$t_switch") kill_ms=$(ms "$t_kill") dead_ms=$(ms "$t_dead") active_ms=$(ms "$t_active") vt=$(active)"
        '')
      ];
    };

  testScript = ''
    import json
    import secrets
    import shlex
    import time

    HIDDEN = "/mnt/data"
    UPPER = HIDDEN + "/root/upper"
    WORK = HIDDEN + "/root/work"
    AUX = "/run/aux"
    ROOT = AUX + "/root"
    LOWER = AUX + "/lower"
    UID = ${toString hiddenUid}
    USER = "${hiddenUser}"
    # Discovered after boot (free_vts); the decoy VT varies.
    HIDDEN_VT = 0
    LOGIN_VT = 0
    LOGIN = "${pkgs.shadow}/bin/login"
    SLICE = "aux.slice"
    SLICE_CG = "/sys/fs/cgroup/aux.slice"
    USER_CG = f"/sys/fs/cgroup/user.slice/user-{UID}.slice"
    DROPIN_DIR = f"/run/systemd/system/user@{UID}.service.d"

    # The properties that put a unit's processes into the hidden root. A
    # recursive bind of the host /run carries the system bus, logind's state
    # files, /run/user/<uid> and /run/current-system; /dev comes from
    # MountAPIVFS (a bind of the host /dev, so DRM, input and the VTs are the
    # real devices). The Nix store is a separate mount in the test VM, so it is
    # bound read-only; on a real install it is part of the root overlay.
    HIDDEN_PROPS = [
        f"RootDirectory={ROOT}",
        "MountAPIVFS=yes",
        "BindPaths=/run",
        "BindReadOnlyPaths=${builtins.storeDir}",
    ]

    findings: list[str] = []
    tokens: dict[str, str] = {}


    def finding(message):
        findings.append(message)
        machine.log("FINDING: " + message)


    def token(kind):
        value = "aux-spike-" + kind + "-" + secrets.token_hex(12)
        tokens[value] = kind
        return value


    def hidden_run(unit, command, extra=(), wait=False, pipe=True):
        """Start `command` as a transient unit in the hidden root and aux.slice.

        With `wait`, block until it exits; with `pipe` as well, return its
        stdout instead of sending it to the journal.
        """
        props = " ".join(f"-p {shlex.quote(p)}" for p in HIDDEN_PROPS + list(extra))
        mode = "--collect"
        if wait:
            mode += " --wait --quiet" + (" --pipe" if pipe else "")
        return machine.execute(
            f"systemd-run {mode} --unit={unit} --slice={SLICE} {props} -- {command}",
            timeout=120,
        )


    def active_vt():
        return machine.succeed("cat /sys/class/tty/tty0/active").strip()


    def decoy_x_pids():
        # The decoy X server: an X binary in display-manager.service's cgroup.
        # The hidden X server matches the same pattern but lives in aux.slice.
        out = machine.succeed(
            "for p in $(pgrep -f '^[^ ]*/(X|Xorg|[.]Xorg-wrapped)( |$)'); do "
            "grep -q display-manager.service /proc/$p/cgroup 2>/dev/null && echo $p; done; true"
        )
        return sorted(out.split())


    def unit_prop(unit, prop):
        return machine.succeed(f"systemctl show {unit} -p {prop} --value").strip()


    def session_prop(sid, prop):
        return machine.succeed(f"loginctl show-session {sid} -p {prop} --value").strip()


    def sessions_of(uid):
        out = machine.succeed(
            "loginctl list-sessions --no-legend --json=short || echo '[]'"
        ).strip()
        return [s["session"] for s in json.loads(out or "[]") if int(s["uid"]) == uid]


    def root_of(pid):
        """How the host sees a process's root: readlink of /proc/<pid>/root
        plus whether it is the hidden root. readlink alone cannot tell: for a
        process whose root is the root mount of another mount namespace
        (RootDirectory= moves the overlay to "/" there), the kernel prints "/"
        to a reader in the host namespace. Comparing device and inode of the
        directory itself is exact."""
        link = machine.succeed(f"readlink /proc/{pid}/root").strip()
        return f"{link} (hidden root: {in_hidden_root(pid)})"


    def in_hidden_root(pid):
        rc, out = machine.execute(f"stat -L -c %d:%i /proc/{pid}/root/")
        want = machine.succeed(f"stat -L -c %d:%i {ROOT}/").strip()
        return rc == 0 and out.strip() == want


    def free_vts(decoy_vt, count):
        """VTs no logind session uses, from 8 up; the decoy's VT is discovered
        (lightdm may run it on VT 1 or VT 7)."""
        out = machine.succeed("loginctl list-sessions --no-legend --json=short || echo '[]'").strip()
        used = {decoy_vt}
        for s in json.loads(out or "[]"):
            vt = machine.succeed(f"loginctl show-session {s['session']} -p VTNr --value").strip()
            if vt.isdigit():
                used.add(int(vt))
        free = [n for n in range(8, 64) if n not in used]
        return free[:count]


    def sectors_written(dev):
        name = dev.removeprefix("/dev/")
        return int(machine.succeed(f"cat /sys/class/block/{name}/stat").split()[6])


    # ==================================================================
    # The decoy desktop.
    # ==================================================================
    machine.start()
    machine.wait_for_unit("display-manager.service")
    machine.wait_until_succeeds("systemctl is-active user@1000.service")
    machine.wait_until_succeeds("test -n \"$(loginctl list-sessions --no-legend | grep testuser)\"")
    machine.wait_until_succeeds(
        "for p in $(pgrep -f '^[^ ]*/(X|Xorg|[.]Xorg-wrapped)( |$)'); do "
        "grep -q display-manager.service /proc/$p/cgroup && exit 0; done; exit 1",
        timeout=120,
    )
    machine.wait_until_succeeds("pgrep -u testuser -x icewm", timeout=120)

    decoy_sid = [
        s for s in sessions_of(1000) if session_prop(s, "Type") == "x11"
    ][0]
    decoy_vt = int(session_prop(decoy_sid, "VTNr"))
    HIDDEN_VT, LOGIN_VT = free_vts(decoy_vt, 2)
    finding(f"hidden display on VT {HIDDEN_VT}, hidden login on tty{LOGIN_VT}")
    machine.wait_until_succeeds(f"test \"$(cat /sys/class/tty/tty0/active)\" = tty{decoy_vt}")
    decoy_dev = machine.succeed("findmnt -no SOURCE /").strip()
    finding(f"decoy session {decoy_sid} on VT {decoy_vt}, root device {decoy_dev}")
    machine.screenshot("decoy-before")

    with subtest("whole-root overlay on the hidden volume"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(
            # /run is a shared mount, so a mount made below it is copied into
            # the mount namespace of every service that is a slave of it
            # (logind, udevd, timesyncd ...). Once the overlay is private on
            # the host, its later unmount no longer reaches those copies, and
            # they would pin the hidden filesystem and block the LUKS close.
            # So first put a private tmpfs at /run/aux (only this empty tmpfs
            # is copied) and build everything below it.
            f"mkdir -p {AUX}",
            f"mount -t tmpfs -o mode=0700 tmpfs {AUX}",
            f"mount --make-private {AUX}",
            f"mkdir -p {UPPER} {WORK} {LOWER} {ROOT}",
            # Non-recursive and read-only: only the root filesystem, and no
            # atime updates on the decoy through the lower.
            f"mount --bind / {LOWER}",
            f"mount -o remount,bind,ro {LOWER}",
            f"mount -t overlay overlay -o lowerdir={LOWER},upperdir={UPPER},workdir={WORK} {ROOT}",
            # overlayfs holds private clones of its layers; the bind can go.
            f"umount {LOWER}",
        )
        # The hidden user's home exists only in the upper.
        machine.succeed(
            f"mkdir -p {ROOT}/home/{USER} && chown {UID}:{UID} {ROOT}/home/{USER} && chmod 700 {ROOT}/home/{USER}"
        )
        machine.fail(f"test -e /home/{USER}")

    with subtest("hidden user record and user-manager drop-in, RAM only"):
        record = {
            "userName": USER,
            "uid": UID,
            "gid": UID,
            "disposition": "regular",
            "homeDirectory": f"/home/{USER}",
            "shell": "/run/current-system/sw/bin/bash",
        }
        group = {"groupName": USER, "gid": UID, "disposition": "regular"}
        machine.succeed(
            "mkdir -p /run/userdb",
            f"echo {shlex.quote(json.dumps(record))} > /run/userdb/{USER}.user",
            f"ln -sf {USER}.user /run/userdb/{UID}.user",
            f"echo {shlex.quote(json.dumps(group))} > /run/userdb/{USER}.group",
            f"ln -sf {USER}.group /run/userdb/{UID}.group",
        )
        machine.succeed(f"getent passwd {USER} | grep -q ':{UID}:'")
        # NixOS glibc reaches NSS modules such as nss-systemd only through
        # nscd, and nscd has no shadow database. So getspnam() of a
        # /run/userdb-only user fails, and pam_unix's account check in
        # `login -f` returns PAM_AUTHINFO_UNAVAIL ("Authentication service
        # cannot retrieve authentication info"); the first runs on the KVM
        # host stopped there. The hidden root is the hidden system's own
        # /etc, so the user also gets ordinary passwd/group/shadow entries
        # there. They land in the upper only; the host keeps resolving the
        # user from /run/userdb (logind, PID 1, user@.service).
        _, shadow = machine.execute(f"getent shadow {USER} >/dev/null && echo found || echo missing")
        finding(f"host getent shadow for the /run/userdb-only user: {shadow.strip()}")
        machine.succeed(
            f"echo '{USER}:x:{UID}:{UID}::/home/{USER}:/run/current-system/sw/bin/bash' >> {ROOT}/etc/passwd",
            f"echo '{USER}:x:{UID}:' >> {ROOT}/etc/group",
            # Locked password, no aging fields (an empty last-change field
            # means "no aging", so pam_unix does not demand a new password).
            f"echo '{USER}:!*:::::::' >> {ROOT}/etc/shadow",
        )
        machine.fail(f"grep -q '^{USER}:' /etc/passwd /etc/group /etc/shadow")
        machine.fail(f"grep -q '^{USER}:' /etc/passwd")

        # user@60123.service is started by the host PID 1 when the hidden
        # session logs in. Without this drop-in the hidden user manager (and
        # everything it starts: the session bus, pipewire, portals) would run
        # on the decoy root.
        # user@.service runs PAM ("systemd-user") on the host, before its
        # namespace exists, so the host's pam_unix account check meets the
        # same missing shadow entry as login did, and the manager fails with
        # status 224/PAM (run fa0cc405). The decoy's PAM stack must not run
        # for the hidden user anyway (it is the decoy's, and it leaves a
        # host-rooted "(sd-pam)" helper of the hidden uid). An empty PAMName=
        # turns PAM off for the user manager; the runtime directory that
        # pam_systemd would announce is set directly.
        dropin = (
            "\n".join(["[Service]", "PAMName=", f"Environment=XDG_RUNTIME_DIR=/run/user/{UID}"] + HIDDEN_PROPS)
            + "\n"
        )
        machine.succeed(
            f"mkdir -p {DROPIN_DIR}",
            f"printf %s {shlex.quote(dropin)} > {DROPIN_DIR}/50-root.conf",
            "systemctl daemon-reload",
        )

    # Decoy baselines for the "untouched" assertions.
    x_before = decoy_x_pids()
    assert x_before, "the decoy X server must be running"
    dm_pid_before = unit_prop("display-manager.service", "MainPID")
    dm_enter_before = unit_prop("display-manager.service", "ActiveEnterTimestampMonotonic")
    decoy_leader_before = session_prop(decoy_sid, "Leader")
    lastlog_before = machine.execute("sha256sum /var/lib/lastlog/lastlog2.db 2>/dev/null")[1]
    wtmp_before = machine.execute("sha256sum /var/log/wtmp 2>/dev/null")[1]
    writes_session_start = sectors_written(decoy_dev)

    with subtest("hidden display server on its own VT, decoy stays logged in"):
        rc, out = hidden_run("aux-display", f"/run/current-system/sw/bin/aux-display {HIDDEN_VT}")
        assert rc == 0, out
        machine.wait_until_succeeds(f"test -S {ROOT}/tmp/.X11-unix/X1", timeout=60)
        machine.wait_until_succeeds(
            f"test \"$(cat /sys/class/tty/tty0/active)\" = tty{HIDDEN_VT}", timeout=30
        )
        # The display socket exists only in the upper, not on the decoy.
        machine.fail("test -e /tmp/.X11-unix/X1")
        x_hidden = unit_prop("aux-display.service", "MainPID")
        finding(f"hidden X server {x_hidden}: root {root_of(x_hidden)}")
        assert in_hidden_root(x_hidden), f"hidden X root: {root_of(x_hidden)}"
        # logind follows the VT: the decoy session is still there, inactive.
        assert session_prop(decoy_sid, "State") in ("online", "active"), session_prop(decoy_sid, "State")
        assert session_prop(decoy_sid, "Active") == "no"
        assert decoy_x_pids() == x_before

    with subtest("hidden logind session from inside the hidden root"):
        user_token = token("user-home")
        var_token = token("user-var")
        profile = (
            "export DISPLAY=:1\n"
            f"echo {user_token} > \"$HOME/canary\"\n"
            f"echo {var_token} > /var/tmp/aux-canary\n"
            "xterm > \"$HOME/xterm.log\" 2>&1 &\n"
            "exec icewm\n"
        )
        machine.succeed(
            f"printf %s {shlex.quote(profile)} > {ROOT}/home/{USER}/.bash_profile",
            f"chown {UID}:{UID} {ROOT}/home/{USER}/.bash_profile",
        )
        hidden_run(
            "aux-login",
            f"{LOGIN} -f {USER}",
            extra=[
                f"TTYPath=/dev/tty{LOGIN_VT}",
                "StandardInput=tty",
                "StandardOutput=tty",
                "TTYReset=yes",
            ],
        )
        logind_session = None
        for _ in range(60):
            found = sessions_of(UID)
            if found:
                logind_session = found[0]
                break
            time.sleep(1)
        if logind_session is None:
            _, status = machine.execute(
                "journalctl -b --no-pager | grep -e ' login\\[' -e ' aux-login' | tail -n 30"
            )
            finding(f"no logind session from `login -f` inside the hidden root:\n{status}")
            hidden_run(
                "aux-client",
                "/run/current-system/sw/bin/bash -l",
                extra=[f"User={UID}", f"Group={UID}", f"WorkingDirectory=/home/{USER}"],
            )
        else:
            props = {
                p: session_prop(logind_session, p)
                for p in ("Seat", "VTNr", "TTY", "Class", "Type", "Service", "Leader")
            }
            finding(f"hidden logind session {logind_session}: {props}")
            assert props["Seat"] == "seat0", props
            assert in_hidden_root(props["Leader"]), f"session leader root: {root_of(props['Leader'])}"

        machine.wait_until_succeeds(f"pgrep -u {UID} -x icewm", timeout=60)
        # xterm is decoration; the claims below need hidden processes, which
        # icewm already is. If it does not start, record why and go on.
        try:
            machine.wait_until_succeeds(f"pgrep -u {UID} -x xterm", timeout=30)
        except Exception:
            _, xlog = machine.execute(f"cat {ROOT}/home/{USER}/xterm.log 2>&1 | tail -n 20")
            finding(f"hidden xterm did not start; its output:\n{xlog.strip() or '(empty)'}")
        # Every process of the hidden uid runs in the hidden root, except the
        # "(sd-pam)" helper of user@<uid>.service: systemd forks it for PAM
        # before it sets up the unit's mount namespace, so it keeps the host
        # root. It only waits to call pam_close_session(), which cgroup.kill
        # never lets it reach.
        for pid in machine.succeed(f"pgrep -u {UID}").split():
            comm = machine.succeed(f"cat /proc/{pid}/comm").strip()
            if comm == "(sd-pam)":
                finding(f"hidden-uid helper {comm} (pid {pid}) has root {root_of(pid)}")
                continue
            assert in_hidden_root(pid), f"hidden process {pid} ({comm}) has root {root_of(pid)}"
        # The decoy side cannot reach the hidden display: no path socket in its
        # /tmp, and no abstract socket.
        machine.fail("DISPLAY=:1 xprop -root >/dev/null 2>&1")

        rc, um = machine.execute(f"systemctl show user@{UID}.service -p MainPID --value")
        um = um.strip()
        if rc == 0 and um not in ("", "0"):
            finding(f"user@{UID} root: {root_of(um)}")
            assert in_hidden_root(um), "the hidden user manager must run in the hidden root"
        else:
            finding(f"user@{UID} not running (no logind session or manager failed)")
        time.sleep(2)
        machine.screenshot("hidden-session")

    with subtest("hidden writes land only in the upper"):
        root_token = token("root-etc")
        rc, out = hidden_run(
            "aux-write",
            f"/bin/sh -c 'echo {root_token} > /etc/aux-canary && sync'",
            wait=True,
        )
        assert rc == 0, out
        machine.succeed(f"grep -q {root_token} {UPPER}/etc/aux-canary")
        machine.succeed(f"grep -q {user_token} {UPPER}/home/{USER}/canary")
        machine.succeed(f"grep -q {var_token} {UPPER}/var/tmp/aux-canary")
        machine.fail("test -e /etc/aux-canary")
        machine.fail("test -e /var/tmp/aux-canary")
        machine.succeed(f"test -e {UPPER}/var/log/X.1.log")

        # Leak probes (findings, not assertions).
        rc, out = hidden_run(
            "aux-probe-root",
            "/bin/sh -c 'test -e /proc/1/root/etc/os-release && echo reachable || echo blocked'",
            wait=True,
        )
        finding(f"root in the hidden root reaching the decoy via /proc/1/root: {out.strip()}")
        rc, out = hidden_run(
            "aux-probe-user",
            "/bin/sh -c 'ls /proc/1/root/ >/dev/null 2>&1 && echo reachable || echo blocked'",
            extra=[f"User={UID}", f"Group={UID}"],
            wait=True,
        )
        finding(f"hidden user reaching the decoy via /proc/1/root: {out.strip()}")
        # A hidden unit's stdout goes to the host journald unless the hidden
        # root has its own; on an amnesic decoy that is RAM only. The raw-disk
        # grep at the end covers this token too.
        journal_token = token("journal")
        hidden_run("aux-log", f"/bin/sh -c 'echo {journal_token}'", wait=True, pipe=False)
        machine.execute("journalctl --sync")
        rc, out = machine.execute(f"journalctl -b --no-pager | grep -c {journal_token} || true")
        finding(f"hidden stdout records in the decoy's (volatile) journal: {out.strip()}")
        rc, out = machine.execute(f"who 2>/dev/null | grep -c {USER} || true")
        finding(f"utmp entries for the hidden user visible to `who` on the host: {out.strip()}")
        rc, out = machine.execute(f"test -e {UPPER}/var/lib/lastlog/lastlog2.db && echo upper || echo none")
        finding(f"login's lastlog2 write went to: {out.strip()}")

    writes_before_emergency = sectors_written(decoy_dev)
    finding(
        f"decoy disk sectors written during the hidden session: {writes_before_emergency - writes_session_start}"
        " (the decoy itself keeps running; this is not attributed)"
    )

    with subtest("emergency: decoy VT to the front, hidden cgroups killed"):
        out = machine.succeed(f"aux-emergency {decoy_vt} {SLICE_CG} {USER_CG}").strip()
        finding(f"emergency timings: {out}")
        timings = dict(kv.split("=") for kv in out.split())
        writes_after_emergency = sectors_written(decoy_dev)
        finding(
            f"decoy disk sectors written during emergency: {writes_after_emergency - writes_before_emergency}"
        )
        machine.screenshot("decoy-after")

        assert timings["vt"] == f"tty{decoy_vt}", timings
        assert int(timings["active_ms"]) < 5000, timings
        assert int(timings["dead_ms"]) < 5000, timings

        # The decoy desktop is the very same session: same X server, same
        # display manager, same logind session and leader, active again.
        assert active_vt() == f"tty{decoy_vt}"
        assert decoy_x_pids() == x_before, f"decoy X changed: {x_before} -> {decoy_x_pids()}"
        assert unit_prop("display-manager.service", "MainPID") == dm_pid_before
        assert (
            unit_prop("display-manager.service", "ActiveEnterTimestampMonotonic") == dm_enter_before
        )
        assert session_prop(decoy_sid, "Leader") == decoy_leader_before
        machine.wait_until_succeeds(
            f"test \"$(loginctl show-session {decoy_sid} -p Active --value)\" = yes", timeout=10
        )
        machine.succeed("systemctl is-active user@1000.service")
        machine.succeed("pgrep -u testuser -x icewm")

        # Every hidden process is gone.
        machine.fail(f"pgrep -u {UID}")
        machine.succeed(f"! grep -q '^populated 1' {SLICE_CG}/cgroup.events")
        hidden_roots = machine.succeed(
            f"want=$(stat -L -c %d:%i {ROOT}/); for p in /proc/[0-9]*; do "
            "[ \"$(stat -L -c %d:%i $p/root/ 2>/dev/null)\" = \"$want\" ] && echo $p; done; true"
        ).split()
        assert not hidden_roots, f"processes still rooted in the hidden root: {hidden_roots}"
        machine.wait_until_succeeds(f"test -z \"$(loginctl list-sessions --no-legend | awk '$2 == {UID}')\"", timeout=30)

    with subtest("strict teardown and RAM residue"):
        # A service that created its own mount namespace while the overlay
        # existed (an on-demand decoy service with PrivateTmp= and the like)
        # holds a private copy of it, which pins the hidden filesystem. Find
        # such namespaces structurally, from mountinfo, report them, and
        # unmount the copy inside each one. This is the mitigation NAILS
        # would ship; the finding says whether it was needed here.
        host_ns = machine.succeed("readlink /proc/1/ns/mnt").strip()
        copies = machine.succeed(
            "for p in /proc/[0-9]*; do "
            f"grep -qs ' {ROOT} ' $p/mountinfo || continue; "
            "echo \"$(readlink $p/ns/mnt) $(basename $p) $(cat $p/comm)\"; done; true"
        ).splitlines()
        per_ns: dict[str, tuple[str, str]] = {}
        for line in copies:
            ns, pid, comm = line.split(" ", 2)
            if ns != host_ns:
                per_ns.setdefault(ns, (pid, comm))
        finding(f"other mount namespaces holding a copy of the hidden root: {sorted(per_ns.values()) or 'none'}")
        for pid, _comm in per_ns.values():
            machine.succeed(f"nsenter -t {pid} -m umount {ROOT}")

        # No lazy unmount: if anything still held the overlay this fails.
        machine.succeed(f"umount {ROOT}", f"umount {AUX}")
        machine.succeed(
            f"rm -rf {DROPIN_DIR} /run/userdb/{USER}.user /run/userdb/{UID}.user "
            f"/run/userdb/{USER}.group /run/userdb/{UID}.group",
            "systemctl daemon-reload",
            "systemctl reset-failed 'aux-*' || true",
        )
        machine.succeed("""${hiddenVolume.unmountHiddenVolumeStrict}""")
        machine.fail("test -e /dev/mapper/data")
        _, residue = machine.execute(
            f"ls -d /run/user/{UID} 2>/dev/null; systemctl list-units --all --plain --no-legend 'aux*' "
            f"'user@{UID}*' 'user-{UID}*' 2>/dev/null; grep -rl {USER} /run/systemd/sessions 2>/dev/null; true"
        )
        finding(f"hidden residue in /run and the unit table after teardown: {residue.strip() or 'none'}")
        rc, out = machine.execute(f"journalctl -b --no-pager | grep -c -e aux- -e 'user@{UID}' || true")
        finding(f"decoy journal records naming the hidden units/user (RAM, needs scrubbing): {out.strip()}")

    with subtest("nothing reached the decoy disk"):
        lastlog_after = machine.execute("sha256sum /var/lib/lastlog/lastlog2.db 2>/dev/null")[1]
        wtmp_after = machine.execute("sha256sum /var/log/wtmp 2>/dev/null")[1]
        assert lastlog_after == lastlog_before, "the decoy lastlog2 database changed"
        assert wtmp_after == wtmp_before, "the decoy wtmp changed"
        machine.fail(f"test -e /home/{USER}")
        machine.fail("test -e /etc/aux-canary")
        patterns = " ".join(f"-e {tok}" for tok in tokens)
        raw = machine.succeed(
            f"sync; echo 3 > /proc/sys/vm/drop_caches; "
            f"grep -a -o -F {patterns} {decoy_dev} | sort | uniq -c || true",
            timeout=1800,
        )
        hits = [line for line in raw.splitlines() if any(tok in line for tok in tokens)]
        assert not hits, "hidden tokens found on the raw decoy disk:\n" + "\n".join(hits)

    machine.log("FINDING: summary")
    for f in findings:
        machine.log("FINDING:   " + f.replace("\n", "\nFINDING:   "))
  '';
}
