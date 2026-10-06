# Research spike (ADR 0009, "Risk assessment"): probes for the risks of the
# dual-root design. It is independent of dual-root-vt-emergency.nix, so the two
# spikes fail separately; it repeats the small amount of setup it needs.
#
# This is NOT a regression test. It carries the `research` tag, which keeps it
# out of every default group; build it explicitly:
#
#   nix build .#legacyPackages.x86_64-linux.e2e.research-dual-root-risks -L
#
# What it probes, in this order (the numbers are the ADR's risk numbers):
#
#   setup  Graphical decoy (lightdm autologin, icewm) with a full-screen blue
#          marker window; whole-root overlay at /run/aux/root on the LUKS
#          volume; hidden user "aux" (uid 60123) as a /run/userdb record;
#          user@60123.service moved into the hidden root by a runtime drop-in.
#   R5a    A decoy service started while the hidden root is mounted: does its
#          new mount namespace hold a copy of the hidden root, even with the
#          hidden tree below a private (and then an unbindable) tmpfs?
#   R1     Hidden rootful X on VT 8 painting a full-screen red window. SIGKILL
#          it while its VT is active, switch back, and classify screenshots by
#          colour (blue = decoy, red = hidden, black) and pixel variance. Then
#          the emergency order (switch first, kill second) and a kill that
#          races the switch. Then `loginctl activate` against `chvt`, timed.
#   R7a    The hidden text session (login -f on tty9, active): uaccess ACLs on
#          /dev/dri, /dev/shm sharing, abstract sockets.
#   R2     As the hidden user inside its active seat0 session, create
#          NetworkManager connections, change an AccountsService property and
#          set the time zone through the system bus; hash the decoy state
#          directories before and after. Repeat with (B) a polkit rule in
#          /run/polkit-1/rules.d denying the hidden user, and (C) a filtering
#          xdg-dbus-proxy (run as the hidden uid inside the hidden session's
#          scope) bind-mounted over /run/dbus/system_bus_socket in the hidden
#          namespaces.
#   R4     /proc/1/root from the hidden root: as the hidden user, as a hidden
#          sudoer, as hidden root; with NoNewPrivileges=, PrivatePIDs= and
#          ProtectProc=invisible.
#   R3     logind IdleAction=suspend (configured at boot, see the node config;
#          systemd-suspend.service is stubbed so nothing really sleeps): does a
#          block inhibitor on idle:sleep held for the hidden session stop it?
#   R6     A hidden "system service" as a host unit with RootDirectory=: where
#          do StateDirectory= and LogsDirectory= end up?
#   R5b    The alternative to R5a: the hidden root mounted only inside a
#          dedicated mount namespace pinned on a file in /run.
#   end    Emergency (chvt + cgroup.kill), the ACLs and the decoy screen after
#          it, strict teardown.
#
# How to read the log: lines starting with `FINDING:` are research output.
# Assertions are used only for the mitigations ADR 0009 claims work, and for
# the decoy still rendering after the hidden display server was killed.
{ pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;

  hiddenUid = 60123;
  hiddenUser = "aux";
  hiddenVt = 8;
  loginVt = 9;
in
{
  name = "research-dual-root-risks";
  meta.tags = [ "research" ];
  # Estimate, not measured: one graphical boot, about ten X server starts, two
  # idle windows of up to two minutes each and several polkit/NM round trips.
  globalTimeout = 2400;

  # The screenshots are classified on the host side.
  extraPythonPackages = ps: [ ps.pillow ];

  nodes.machine =
    {
      config,
      lib,
      pkgs,
      ...
    }:
    let
      dm = config.services.xserver.displayManager;
      xEnv = lib.filterAttrs (_: v: v != null) config.systemd.services.display-manager.environment;
      exports = lib.concatStrings (
        lib.mapAttrsToList (n: v: "export ${n}=${lib.escapeShellArg (toString v)}\n") xEnv
      );
      xArgs = lib.concatStringsSep " " (lib.filter (a: a != ":0") dm.xserverArgs);
    in
    {
      imports = [ ./../../lib/graphical-vm-config.nix ];

      # R2: the shared system daemons under test.
      networking.networkmanager.enable = true;
      # vm-config.nix turns DHCP on; NetworkManager takes the interfaces over.
      networking.useDHCP = lib.mkForce false;
      services.accounts-daemon.enable = true;
      security.polkit.enable = true;

      # R3: a decoy that suspends when the whole system is idle. logind only
      # arms its idle timer at startup when IdleAction is not "ignore" (v259
      # logind.c: manager_dispatch_idle_action() returns before adding the
      # timer), so a /run drop-in plus SIGHUP cannot turn it on at runtime;
      # the decoy has to have it configured already, as here.
      services.logind.settings.Login = {
        IdleAction = "suspend";
        IdleActionSec = "20s";
      };
      # Never really suspend the VM: the stub records each suspend instead.
      systemd.services.systemd-suspend.serviceConfig.ExecStart = [
        ""
        "${pkgs.runtimeShell} -c 'date +%%s >> /run/suspend-probe'"
      ];

      environment.systemPackages = [
        pkgs.kbd # chvt
        pkgs.shadow # login -f
        pkgs.acl # getfacl
        pkgs.xdg-dbus-proxy
        pkgs.iproute2 # ss

        (pkgs.writeShellScriptBin "aux-display" ''
          ${exports}
          exec ${dm.xserverBin} ${xArgs} :1 vt${toString hiddenVt} -nolisten local -logfile /var/log/X.1.log
        '')

        # Times one VT switch done either with chvt or through logind.
        # ret_ms: the command returned; vt_ms: the kernel reports the target
        # VT active; active_ms: logind reports the target session active.
        (pkgs.writeShellScriptBin "aux-switch-timer" ''
          set -u
          method=$1 vt=$2 sid=$3
          now() { date +%s%N; }
          t0=$(now)
          if [ "$method" = chvt ]; then chvt "$vt"; else loginctl activate "$sid"; fi
          t_ret=$(now)
          i=0
          while [ "$(cat /sys/class/tty/tty0/active)" != "tty$vt" ] && [ $i -lt 5000 ]; do
            sleep 0.001
            i=$((i + 1))
          done
          t_vt=$(now)
          i=0
          while [ "$(loginctl show-session "$sid" -p Active --value)" != yes ] && [ $i -lt 2000 ]; do
            sleep 0.002
            i=$((i + 1))
          done
          t_act=$(now)
          ms() { echo $((($1 - t0) / 1000000)); }
          echo "ret_ms=$(ms "$t_ret") vt_ms=$(ms "$t_vt") active_ms=$(ms "$t_act") vt=$(cat /sys/class/tty/tty0/active)"
        '')
      ];
    };

  testScript = ''
    import importlib
    import json
    import os
    import shlex
    import time

    # Pillow, loaded dynamically so the driver's type check does not need
    # its stubs.
    Image = importlib.import_module("PIL.Image")
    ImageStat = importlib.import_module("PIL.ImageStat")

    HIDDEN = "/mnt/data"
    UPPER = HIDDEN + "/root/upper"
    WORK = HIDDEN + "/root/work"
    AUX = "/run/aux"
    ROOT = AUX + "/root"
    LOWER = AUX + "/lower"
    UID = ${toString hiddenUid}
    USER = "${hiddenUser}"
    HIDDEN_VT = ${toString hiddenVt}
    LOGIN_VT = ${toString loginVt}
    LOGIN = "${pkgs.shadow}/bin/login"
    SW = "/run/current-system/sw/bin"
    SLICE = "aux.slice"
    SLICE_CG = "/sys/fs/cgroup/aux.slice"
    USER_CG = f"/sys/fs/cgroup/user.slice/user-{UID}.slice"
    DROPIN_DIR = f"/run/systemd/system/user@{UID}.service.d"
    # Exists on the decoy only: a tmpfs mounted after the overlay, so it is
    # not part of the (non-recursive) lower.
    DECOY_ONLY = "/srv/decoy-only"
    DECOY_MARK = "decoy-only-marker"

    # Full-screen marker colours (X colour specs without '#', which the
    # shell would treat as a comment).
    BLUE = (0x20, 0x60, 0xC0)
    RED = (0xC0, 0x30, 0x20)
    BLUE_SPEC = "rgb:20/60/c0"
    RED_SPEC = "rgb:c0/30/20"

    HIDDEN_PROPS = [
        f"RootDirectory={ROOT}",
        "MountAPIVFS=yes",
        "BindPaths=/run",
        "BindReadOnlyPaths=${builtins.storeDir}",
    ]

    findings: list[str] = []


    def finding(message):
        findings.append(message)
        machine.log("FINDING: " + message)


    def hidden_run(unit, command, extra=(), wait=False, pipe=True, slice_=SLICE):
        props = " ".join(f"-p {shlex.quote(p)}" for p in HIDDEN_PROPS + list(extra))
        mode = "--collect"
        if wait:
            mode += " --wait --quiet" + (" --pipe" if pipe else "")
        return machine.execute(
            f"systemd-run {mode} --unit={unit} --slice={slice_} {props} -- {command}",
            timeout=120,
        )


    def active_vt():
        return machine.succeed("cat /sys/class/tty/tty0/active").strip()


    def decoy_x_pids():
        out = machine.succeed(
            "for p in $(pgrep -f '^[^ ]*/(X|Xorg|[.]Xorg-wrapped)( |$)'); do "
            "grep -q display-manager.service /proc/$p/cgroup 2>/dev/null && echo $p; done; true"
        )
        return sorted(out.split())


    def session_prop(sid, prop):
        return machine.succeed(f"loginctl show-session {sid} -p {prop} --value").strip()


    def sessions_of(uid):
        out = machine.succeed("loginctl list-sessions --no-legend --json=short || echo '[]'").strip()
        return [s["session"] for s in json.loads(out or "[]") if int(s["uid"]) == uid]


    def root_of(pid):
        return machine.succeed(f"readlink /proc/{pid}/root").strip()


    # ------------------------------------------------------------------
    # Screen classification.
    # ------------------------------------------------------------------
    def screen(name):
        """Screenshot `name` and return the share of decoy-blue, hidden-red
        and black pixels plus the mean channel standard deviation."""
        machine.screenshot(name)
        img = Image.open(os.path.join(str(machine.out_dir), name + ".png")).convert("RGB")
        total = img.size[0] * img.size[1]
        colors = img.getcolors(total) or []

        def share(ref, tol=40):
            hit = sum(
                n for n, c in colors if all(abs(c[i] - ref[i]) <= tol for i in range(3))
            )
            return round(hit / total, 3)

        stddev = ImageStat.Stat(img).stddev
        return {
            "decoy": share(BLUE),
            "hidden": share(RED),
            "black": share((0, 0, 0), 8),
            "stddev": round(sum(stddev) / len(stddev), 1),
        }


    def wait_for_screen(kind, prefix, timeout=10.0):
        """Poll screenshots until `kind` covers most of the screen. Returns
        (elapsed seconds on the host, last classification)."""
        t0 = time.monotonic()
        n = 0
        while True:
            c = screen(f"{prefix}-{n}")
            if c[kind] > 0.4 or time.monotonic() - t0 > timeout:
                return round(time.monotonic() - t0, 2), c
            n += 1


    # ------------------------------------------------------------------
    # The hidden session's command loop (R2, R4): the hidden user's login
    # shell runs whatever script the host drops into ~/q-<tty>, inside the
    # hidden logind session, and writes the output back. One directory per
    # tty, so a second session (R4b) has its own queue.
    # ------------------------------------------------------------------
    HOME_Q = f"{ROOT}/home/{USER}"
    Q = f"{HOME_Q}/q-tty{LOGIN_VT}"
    PROFILE = (
        "cd \"$HOME\"\n"
        "q=q-$(basename \"$(tty)\")\n"
        "mkdir -p $q\n"
        "while :; do\n"
        "  if [ -f $q/run.sh ]; then\n"
        "    mv $q/run.sh $q/cur.sh\n"
        "    sh $q/cur.sh > $q/out 2>&1\n"
        "    rm -f $q/cur.sh\n"
        "    touch $q/done\n"
        "  fi\n"
        "  sleep 0.2\n"
        "done\n"
    )


    def in_session(script, timeout=120, q=Q):
        machine.wait_until_succeeds(f"test -d {q}", timeout=60)
        machine.succeed(f"rm -f {q}/done {q}/out")
        machine.succeed(
            f"printf %s {shlex.quote(script)} > {q}/run.tmp",
            f"chown {UID}:{UID} {q}/run.tmp",
            f"mv {q}/run.tmp {q}/run.sh",
        )
        machine.wait_until_succeeds(f"test -e {q}/done", timeout=timeout)
        return machine.succeed(f"cat {q}/out")


    def results(out):
        """`RESULT <name> <rc>` lines from a probe script."""
        res = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[0] == "RESULT":
                res[parts[1]] = int(parts[2])
        return res


    DECOY_STATE = [
        "/etc/NetworkManager",
        "/var/lib/NetworkManager",
        "/var/lib/AccountsService",
        "/etc/localtime",
    ]


    def decoy_state():
        """path -> short hash of (link target, content) for every file in
        the decoy state directories R2 cares about."""
        dirs = " ".join(DECOY_STATE)
        out = machine.succeed(
            f"for d in {dirs}; do find $d -xdev \\( -type f -o -type l \\) 2>/dev/null; done | sort | "
            "while read -r f; do printf '%s %s\\n' \"$f\" "
            "\"$( (readlink \"$f\"; cat \"$f\") 2>/dev/null | sha256sum | cut -c1-16)\"; done"
        )
        return dict(line.rsplit(" ", 1) for line in out.splitlines() if " " in line)


    def state_diff(before, after):
        added = sorted(set(after) - set(before))
        removed = sorted(set(before) - set(after))
        changed = sorted(p for p in set(before) & set(after) if before[p] != after[p])
        return {"added": added, "removed": removed, "changed": changed}


    def r2_probe(phase, lang, tz):
        script = (
            "set +e\n"
            f"B={SW}\n"
            f"$B/nmcli connection add type dummy ifname auxs{phase} con-name probe-sys-{phase}; "
            "echo \"RESULT nm-system $?\"\n"
            f"$B/nmcli connection add type dummy ifname auxo{phase} con-name probe-own-{phase} "
            f"connection.permissions user:{USER}; echo \"RESULT nm-own $?\"\n"
            "$B/busctl call org.freedesktop.Accounts /org/freedesktop/Accounts "
            f"org.freedesktop.Accounts FindUserById x {UID}; echo \"RESULT accounts-find $?\"\n"
            f"$B/busctl call org.freedesktop.Accounts /org/freedesktop/Accounts/User{UID} "
            f"org.freedesktop.Accounts.User SetLanguage s {lang}; echo \"RESULT accounts-set $?\"\n"
            f"$B/timedatectl set-timezone {tz}; echo \"RESULT timedate $?\"\n"
            "$B/busctl get-property org.freedesktop.login1 /org/freedesktop/login1/session/auto "
            "org.freedesktop.login1.Session Id; echo \"RESULT login1-auto $?\"\n"
            "$B/busctl --system list --no-legend --acquired | awk '{print $1}' | tr '\\n' ' '; echo\n"
        )
        before = decoy_state()
        out = in_session(script)
        machine.succeed("sync")
        time.sleep(2)
        after = decoy_state()
        return results(out), out, state_diff(before, after), before, after


    # ==================================================================
    # Decoy desktop.
    # ==================================================================
    machine.start()
    machine.wait_for_unit("display-manager.service")
    machine.wait_until_succeeds("systemctl is-active user@1000.service")
    machine.wait_until_succeeds(
        "for p in $(pgrep -f '^[^ ]*/(X|Xorg|[.]Xorg-wrapped)( |$)'); do "
        "grep -q display-manager.service /proc/$p/cgroup && exit 0; done; exit 1",
        timeout=120,
    )
    machine.wait_until_succeeds("pgrep -u testuser -x icewm", timeout=120)
    decoy_sid = [s for s in sessions_of(1000) if session_prop(s, "Type") == "x11"][0]
    decoy_vt = int(session_prop(decoy_sid, "VTNr"))
    assert decoy_vt not in (HIDDEN_VT, LOGIN_VT), f"decoy runs on VT {decoy_vt}"
    machine.wait_until_succeeds(f"test \"$(cat /sys/class/tty/tty0/active)\" = tty{decoy_vt}")

    # A full-screen blue window on the decoy display makes "the decoy is on
    # screen" measurable. It is a decoy-side unit, not part of the hidden tree.
    xpid = decoy_x_pids()[0]
    xargs = machine.succeed(f"tr '\\0' '\\n' < /proc/{xpid}/cmdline").split("\n")
    xauth = xargs[xargs.index("-auth") + 1] if "-auth" in xargs else ""
    machine.succeed(
        f"systemd-run --unit=decoy-marker --setenv=DISPLAY=:0 --setenv=XAUTHORITY={xauth} "
        f"{SW}/xterm -bg {BLUE_SPEC} -fg {BLUE_SPEC} -geometry 400x120+0+0"
    )
    _, ref = wait_for_screen("decoy", "r1-decoy-ref", timeout=30)
    finding(f"decoy session {decoy_sid} on VT {decoy_vt}; reference screen {ref}")
    assert ref["decoy"] > 0.4, f"the blue decoy marker is not on screen: {ref}"
    finding("suspend support in the VM (/sys/power/state): " + machine.succeed("cat /sys/power/state").strip())

    # ==================================================================
    # Hidden root, hidden user, user-manager drop-in.
    # ==================================================================
    with subtest("setup: whole-root overlay, userdb record, user@ drop-in"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(
            f"mkdir -p {DECOY_ONLY}",
            f"mkdir -p {AUX}",
            f"mount -t tmpfs -o mode=0700 tmpfs {AUX}",
            f"mount --make-private {AUX}",
            f"mkdir -p {UPPER} {WORK} {LOWER} {ROOT}",
            f"mount --bind / {LOWER}",
            f"mount -o remount,bind,ro {LOWER}",
            f"mount -t overlay overlay -o lowerdir={LOWER},upperdir={UPPER},workdir={WORK} {ROOT}",
            f"umount {LOWER}",
            # Decoy-only content, invisible in the hidden root.
            f"mount -t tmpfs tmpfs {DECOY_ONLY}",
            f"echo {DECOY_MARK} > {DECOY_ONLY}/marker",
            f"chmod 0644 {DECOY_ONLY}/marker",
        )
        machine.fail(f"test -e {ROOT}{DECOY_ONLY}/marker")
        machine.succeed(
            f"mkdir -p {ROOT}/home/{USER}",
            f"chown -R {UID}:{UID} {ROOT}/home/{USER}",
            f"chmod 700 {ROOT}/home/{USER}",
        )
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
        dropin = "\n".join(["[Service]"] + HIDDEN_PROPS) + "\n"
        machine.succeed(
            f"mkdir -p {DROPIN_DIR}",
            f"printf %s {shlex.quote(dropin)} > {DROPIN_DIR}/50-root.conf",
            "systemctl daemon-reload",
        )

    # ==================================================================
    # R5a: mount-namespace copies of the hidden root.
    # ==================================================================
    with subtest("R5a: a decoy service started after activation"):
        machine.succeed(
            "systemd-run --unit=decoy-late -p PrivateTmp=yes -p ProtectSystem=strict "
            "/run/current-system/sw/bin/sleep infinity"
        )
        machine.wait_until_succeeds("systemctl is-active decoy-late.service")
        pid = machine.succeed("systemctl show decoy-late -p MainPID --value").strip()
        rc, _ = machine.execute(f"grep -q ' {ROOT} ' /proc/{pid}/mountinfo")
        finding(
            "R5a: decoy service with PrivateTmp= started after activation, hidden root below a "
            f"private tmpfs: copy of the hidden root in its namespace = {rc == 0}"
        )
        machine.succeed("systemctl stop decoy-late.service")
        machine.succeed(f"mount --make-unbindable {AUX}")
        machine.succeed(
            "systemd-run --unit=decoy-late2 -p PrivateTmp=yes /run/current-system/sw/bin/sleep infinity"
        )
        machine.wait_until_succeeds("systemctl is-active decoy-late2.service")
        pid = machine.succeed("systemctl show decoy-late2 -p MainPID --value").strip()
        rc, _ = machine.execute(f"grep -q ' {ROOT} ' /proc/{pid}/mountinfo")
        finding(f"R5a: same with the tmpfs MS_UNBINDABLE: copy present = {rc == 0}")
        machine.succeed("systemctl stop decoy-late2.service")
        machine.succeed(f"mount --make-private {AUX}")

    # ==================================================================
    # R1: VT/DRM handover when the hidden display server dies.
    # ==================================================================
    display_round = [0]


    def start_hidden_display():
        display_round[0] += 1
        n = display_round[0]
        machine.succeed(f"rm -f {ROOT}/tmp/.X11-unix/X1 {ROOT}/tmp/.X1-lock")
        rc, out = hidden_run(f"aux-display-{n}", f"{SW}/aux-display")
        assert rc == 0, out
        machine.wait_until_succeeds(f"test -S {ROOT}/tmp/.X11-unix/X1", timeout=60)
        machine.wait_until_succeeds(f"test \"$(cat /sys/class/tty/tty0/active)\" = tty{HIDDEN_VT}", timeout=30)
        hidden_run(
            f"aux-paint-{n}",
            f"{SW}/xterm -display :1 -bg {RED_SPEC} -fg {RED_SPEC} -geometry 400x120+0+0",
        )
        elapsed, c = wait_for_screen("hidden", f"r1-hidden-{n}", timeout=30)
        assert c["hidden"] > 0.4, f"the hidden red window never showed: {c}"
        return f"{SLICE_CG}/aux-display-{n}.service"


    with subtest("R1a: SIGKILL the hidden X while its VT is active, then switch"):
        cg = start_hidden_display()
        machine.succeed(f"echo 1 > {cg}/cgroup.kill")
        machine.wait_until_succeeds(f"! grep -q '^populated 1' {cg}/cgroup.events", timeout=10)
        time.sleep(1)
        c = screen("r1a-after-kill")
        finding(f"R1a: screen after the hidden X died on its own VT (still {active_vt()}): {c}")
        t0 = time.monotonic()
        machine.succeed(f"chvt {decoy_vt}")
        elapsed, c = wait_for_screen("decoy", "r1a-after-switch")
        finding(f"R1a: decoy visible {elapsed}s after chvt (host-side screenshot polling): {c}")
        assert c["decoy"] > 0.4, f"decoy not rendered after the hidden X was killed: {c}"
        assert xpid in decoy_x_pids(), "the decoy X server changed"
        finding(f"R1a: total {round(time.monotonic() - t0, 2)}s; Xorg log of the decoy after return:")
        _, log = machine.execute("tail -n 15 /var/log/X.0.log 2>/dev/null || true")
        finding(log.strip() or "(no /var/log/X.0.log)")

    with subtest("R1b: emergency order, switch first then kill"):
        cg = start_hidden_display()
        t0 = time.monotonic()
        machine.succeed(f"chvt {decoy_vt}; echo 1 > {cg}/cgroup.kill")
        elapsed, c = wait_for_screen("decoy", "r1b-after")
        finding(f"R1b: decoy visible {elapsed}s after chvt+kill: {c}")
        assert c["decoy"] > 0.4, f"decoy not rendered after switch+kill: {c}"

    with subtest("R1c: kill racing the VT switch"):
        cg = start_hidden_display()
        machine.succeed(f"(chvt {decoy_vt} &) ; echo 1 > {cg}/cgroup.kill")
        elapsed, c = wait_for_screen("decoy", "r1c-after")
        finding(f"R1c: decoy visible {elapsed}s after a kill that raced the switch: {c}; VT {active_vt()}")
        assert c["decoy"] > 0.4, f"decoy not rendered after a racing kill: {c}"
        machine.wait_until_succeeds(f"test \"$(cat /sys/class/tty/tty0/active)\" = tty{decoy_vt}", timeout=10)

    with subtest("R1d: loginctl activate against chvt"):
        cg = start_hidden_display()
        timings: dict[str, list[str]] = {"chvt": [], "loginctl": []}
        for _ in range(5):
            for method in ("loginctl", "chvt"):
                machine.succeed(f"chvt {HIDDEN_VT}")
                machine.wait_until_succeeds(f"test \"$(loginctl show-session {decoy_sid} -p Active --value)\" = no")
                out = machine.succeed(f"aux-switch-timer {method} {decoy_vt} {decoy_sid}").strip()
                elapsed, c = wait_for_screen("decoy", f"r1d-{method}-{len(timings[method])}")
                timings[method].append(f"{out} screen_s={elapsed} decoy={c['decoy']}")
                assert c["decoy"] > 0.4, f"decoy not rendered after {method}: {c}"
        for method, rows in timings.items():
            finding(f"R1d: {method}: " + " | ".join(rows))
        machine.succeed(f"echo 1 > {cg}/cgroup.kill")
        machine.wait_until_succeeds(f"! grep -q '^populated 1' {cg}/cgroup.events", timeout=10)

    # ==================================================================
    # The hidden text session (tty9), active on seat0.
    # ==================================================================
    with subtest("hidden logind session on tty9, active"):
        machine.succeed(
            f"printf %s {shlex.quote(PROFILE)} > {ROOT}/home/{USER}/.bash_profile",
            f"chown {UID}:{UID} {ROOT}/home/{USER}/.bash_profile",
        )
        hidden_run(
            "aux-login",
            f"{LOGIN} -f {USER}",
            extra=[f"TTYPath=/dev/tty{LOGIN_VT}", "StandardInput=tty", "StandardOutput=tty", "TTYReset=yes"],
        )
        machine.wait_until_succeeds(f"loginctl list-sessions --no-legend | awk '$2 == {UID}' | grep -q .", timeout=60)
        hidden_sid = sessions_of(UID)[0]
        machine.succeed(f"chvt {LOGIN_VT}")
        machine.wait_until_succeeds(f"test \"$(loginctl show-session {hidden_sid} -p Active --value)\" = yes", timeout=20)
        hidden_leader = session_prop(hidden_sid, "Leader")
        assert root_of(hidden_leader) == ROOT
        out = in_session("id; echo $XDG_RUNTIME_DIR; readlink /proc/self/root; cat /proc/self/cgroup\n")
        finding(f"hidden session {hidden_sid} (leader {hidden_leader}) active; probe loop says:\n{out.strip()}")
        um = machine.succeed(f"systemctl show user@{UID}.service -p MainPID --value").strip()
        finding(f"user@{UID} MainPID {um}, root {root_of(um) if um != '0' else '-'}")

    # ==================================================================
    # R7a: shared devices and RAM channels while the hidden session is active.
    # ==================================================================
    with subtest("R7a: uaccess ACLs, /dev/shm, abstract sockets"):
        _, acl = machine.execute("getfacl -p /dev/dri/card* 2>/dev/null | grep '^user:' || true")
        finding(f"R7a: uaccess ACLs on /dev/dri with the hidden session active: {acl.split() or 'none'}")
        hidden_run("aux-shm", "/bin/sh -c 'echo x > /dev/shm/aux-shm-probe'", wait=True)
        rc, _ = machine.execute("test -e /dev/shm/aux-shm-probe")
        finding(f"R7a: a hidden unit's /dev/shm is the host's /dev/shm: {rc == 0}")
        machine.execute("rm -f /dev/shm/aux-shm-probe")
        _, abstract = machine.execute("ss -xlpn 2>/dev/null | grep ' @' || true")
        finding(f"R7a: listening abstract unix sockets (shared network namespace):\n{abstract.strip() or 'none'}")
        _, ap = machine.execute(f"test -e /var/lib/AccountsService/users/{USER} && echo present || echo absent")
        finding(f"R2: decoy AccountsService file for the hidden user right after login: {ap.strip()}")

    # ==================================================================
    # R2: shared system daemons writing to the decoy disk.
    # ==================================================================
    with subtest("R2-A: no mitigation"):
        res, out, diff, _, _ = r2_probe("a", "de_DE.UTF-8", "Europe/Berlin")
        finding(f"R2-A results (0 = the daemon accepted the request): {res}")
        finding(f"R2-A decoy state diff: {diff}")
        finding("R2-A probe output:\n" + out.strip())

    with subtest("R2-B: polkit rule in /run denying the hidden user"):
        rule = (
            "polkit.addRule(function(action, subject) {\n"
            f"  if ((subject.user == \"{USER}\" || subject.user == \"{UID}\") &&\n"
            "      action.id.indexOf(\"org.freedesktop.login1.\") != 0) {\n"
            "    return polkit.Result.NO;\n"
            "  }\n"
            "});\n"
        )
        machine.succeed(
            "mkdir -p /run/polkit-1/rules.d",
            f"printf %s {shlex.quote(rule)} > /run/polkit-1/rules.d/00-aux.rules",
            # polkit.service is Type=notify-reload: reload = SIGHUP, no new
            # mount namespace (a restart would copy the hidden root, R5a).
            "systemctl reload polkit.service",
        )
        res, out, diff, before, after = r2_probe("b", "fr_FR.UTF-8", "Europe/Paris")
        finding(f"R2-B results: {res}")
        finding(f"R2-B decoy state diff: {diff}")
        finding("R2-B probe output:\n" + out.strip())
        conns = [p for p in diff["added"] if "system-connections" in p]
        assert not conns, f"NetworkManager wrote connections despite the polkit rule: {conns}"
        acct = f"/var/lib/AccountsService/users/{USER}"
        assert before.get(acct) == after.get(acct), "AccountsService changed the hidden user's file"
        assert before.get("/etc/localtime") == after.get("/etc/localtime"), "the time zone changed"
        assert res.get("login1-auto") == 0, "the polkit rule must leave login1 usable"

    with subtest("R2-C: filtering proxy over the system bus socket"):
        machine.succeed("rm -f /run/polkit-1/rules.d/00-aux.rules", "systemctl reload polkit.service")
        machine.succeed(f"mkdir -p /run/aux-bus && chown {UID}:{UID} /run/aux-bus && chmod 0700 /run/aux-bus")
        scope_cg = f"{USER_CG}/session-{hidden_sid}.scope"
        # The proxy runs on the host root (it must reach the real socket),
        # as the hidden uid and inside the hidden session's scope, so logind
        # still maps calls arriving through it to the hidden session.
        machine.succeed(
            "nohup sh -c "
            + shlex.quote(
                f"echo $$ > {scope_cg}/cgroup.procs; exec setpriv --reuid={UID} --regid={UID} --clear-groups "
                f"{SW}/xdg-dbus-proxy unix:path=/run/dbus/system_bus_socket /run/aux-bus/sock "
                "--filter --talk=org.freedesktop.login1"
            )
            + " >/dev/null 2>&1 &"
        )
        machine.wait_until_succeeds("test -S /run/aux-bus/sock", timeout=20)
        proxy_pid = machine.succeed("pgrep -f '^[^ ]*xdg-dbus-proxy unix:path=/run/dbus/system_bus_socket'").split()[0]
        # Overmount the canonical socket path in every hidden mount namespace
        # that exists now: the session's (login unit) and the user manager's.
        ns_pids = {hidden_leader}
        um = machine.succeed(f"systemctl show user@{UID}.service -p MainPID --value").strip()
        if um not in ("", "0"):
            ns_pids.add(um)
        for p in ns_pids:
            machine.succeed(f"nsenter -t {p} -m mount --bind /run/aux-bus/sock /run/dbus/system_bus_socket")
        res, out, diff, before, after = r2_probe("c", "es_ES.UTF-8", "Europe/Madrid")
        finding(f"R2-C results: {res}")
        finding(f"R2-C decoy state diff: {diff}")
        finding("R2-C probe output:\n" + out.strip())
        conns = [p for p in diff["added"] if "system-connections" in p]
        assert not conns, f"NetworkManager wrote connections through the filtered bus: {conns}"
        acct = f"/var/lib/AccountsService/users/{USER}"
        assert before.get(acct) == after.get(acct), "AccountsService changed the hidden user's file"
        assert before.get("/etc/localtime") == after.get("/etc/localtime"), "the time zone changed"
        assert res.get("login1-auto") == 0, "login1 must still resolve the caller's session through the proxy"
        assert f'"{hidden_sid}"' in out, "session/auto through the proxy must be the hidden session"
        # Deliberate bypasses, for the record (the threat model does not
        # cover malicious hidden code).
        out = in_session(
            f"ls -d /proc/{proxy_pid}/root/run/dbus/system_bus_socket && echo REACH-BUS || echo NO-BUS\n"
            f"cat /proc/{proxy_pid}/root{DECOY_ONLY}/marker 2>/dev/null || echo NO-DECOY\n"
        )
        finding(f"R2-C/R4: a hidden-uid process on the host root (the proxy) is a door for the hidden user:\n{out.strip()}")

    # ==================================================================
    # R4: /proc/1/root.
    # ==================================================================
    with subtest("R4: /proc/1/root from the hidden root"):
        probe = f"/bin/sh -c 'cat /proc/1/root{DECOY_ONLY}/marker 2>/dev/null || echo blocked'"
        out = in_session(f"cat /proc/1/root{DECOY_ONLY}/marker 2>/dev/null || echo blocked\n")
        finding(f"R4: hidden user in its session: {out.strip()}")
        sdpam = machine.succeed(f"pgrep -u {UID} -x '(sd-pam)' || true").split()
        if sdpam:
            out = in_session(f"cat /proc/{sdpam[0]}/root{DECOY_ONLY}/marker 2>/dev/null || echo blocked\n")
            finding(f"R4: hidden user via the (sd-pam) helper's /proc/<pid>/root (host-rooted, same uid): {out.strip()}")
        # A hidden sudoer: sudoers inside the hidden root only (upper).
        sudoers = machine.succeed(f"cat {ROOT}/etc/sudoers")
        machine.succeed(
            f"rm -f {ROOT}/etc/sudoers",
            f"printf %s {shlex.quote(sudoers + chr(10) + USER + ' ALL=(ALL) NOPASSWD: ALL' + chr(10))} > {ROOT}/etc/sudoers",
            f"chown root:root {ROOT}/etc/sudoers",
            f"chmod 0440 {ROOT}/etc/sudoers",
        )
        machine.fail(f"grep -q '^{USER} ' /etc/sudoers")
        sudo_probe = (
            f"/bin/sh -c '/run/wrappers/bin/sudo -n cat /proc/1/root{DECOY_ONLY}/marker 2>&1 || echo blocked'"
        )
        _, out = hidden_run("aux-r4-sudo", sudo_probe, extra=[f"User={UID}", f"Group={UID}"], wait=True)
        finding(f"R4: hidden sudoer without NoNewPrivileges: {out.strip()}")
        _, out = hidden_run(
            "aux-r4-sudo-nnp", sudo_probe, extra=[f"User={UID}", f"Group={UID}", "NoNewPrivileges=yes"], wait=True
        )
        finding(f"R4: hidden sudoer with NoNewPrivileges=yes: {out.strip()}")
        assert DECOY_MARK not in out, "NoNewPrivileges= must stop the hidden sudoer"
        _, out = hidden_run("aux-r4-root", probe, wait=True)
        finding(f"R4: hidden root, no mitigation: {out.strip()}")
        _, out = hidden_run("aux-r4-hidepid", probe, extra=["ProtectProc=invisible"], wait=True)
        finding(f"R4: hidden root with ProtectProc=invisible: {out.strip()}")
        _, out = hidden_run("aux-r4-pidns", probe, extra=["PrivatePIDs=yes"], wait=True)
        finding(f"R4: hidden root with PrivatePIDs=yes: {out.strip()}")
        assert DECOY_MARK not in out, "PrivatePIDs= must hide the decoy's PID 1"
        _, out = hidden_run(
            "aux-r4-pidns-ls", "/bin/sh -c 'ls /proc | grep -c \"^[0-9]\"; readlink /proc/1/exe'",
            extra=["PrivatePIDs=yes"], wait=True,
        )
        finding(f"R4: with PrivatePIDs=yes the hidden unit sees this many PIDs / PID 1 is: {out.split()}")
        # user@.service cannot take PrivatePIDs=: systemd refuses "--user mode
        # as PID 1" (v259 src/core/main.c). The session leader can: a second
        # hidden login session whose unit has its own PID namespace.
        hidden_run(
            "aux-login-pidns",
            f"{LOGIN} -f {USER}",
            extra=[
                f"TTYPath=/dev/tty{LOGIN_VT + 1}",
                "StandardInput=tty",
                "StandardOutput=tty",
                "TTYReset=yes",
                "PrivatePIDs=yes",
            ],
        )
        second = None
        for _ in range(30):
            others = [s for s in sessions_of(UID) if s != hidden_sid]
            if others:
                second = others[0]
                break
            time.sleep(1)
        if second is None:
            _, status = machine.execute("systemctl status --no-pager aux-login-pidns.service 2>&1 | tail -n 20")
            finding(f"R4b: no logind session from login -f under PrivatePIDs=yes:\n{status}")
        else:
            props = {p: session_prop(second, p) for p in ("Seat", "TTY", "Leader", "Scope")}
            out = in_session(
                f"echo pid1=$(cat /proc/1/comm); ls /proc | grep -c '^[0-9]'; "
                f"/run/wrappers/bin/sudo -n cat /proc/1/root{DECOY_ONLY}/marker 2>&1 || echo blocked\n",
                q=f"{HOME_Q}/q-tty{LOGIN_VT + 1}",
            )
            finding(f"R4b: hidden session under PrivatePIDs=yes: {second} {props}; inside: {out.split()}")

    # ==================================================================
    # R3: idle over time.
    # ==================================================================
    def idle_lines(cursor):
        _, out = machine.execute(
            f"journalctl -u systemd-logind --after-cursor={shlex.quote(cursor)} --no-pager -o cat | grep 'System idle' || true"
        )
        return [line for line in out.splitlines() if line.strip()]


    def cursor():
        return machine.succeed("journalctl -n 0 --show-cursor --no-pager | sed -n 's/^-- cursor: //p'").strip()


    with subtest("R3: IdleAction=suspend against an inhibitor"):
        finding("R3: logind settings: " + machine.succeed(
            "busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager IdleAction; "
            "busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager IdleActionUSec"
        ).replace("\n", " "))
        boot_suspends = machine.succeed("cat /run/suspend-probe 2>/dev/null | wc -l").strip()
        finding(f"R3: stubbed suspends before the test (the idle period during boot counts): {boot_suspends}")
        machine.succeed("rm -f /run/suspend-probe")
        # An idle decoy desktop: GNOME and KDE set the session idle hint when
        # the user is away. icewm does not, so set it as root.
        machine.succeed(
            f"busctl call org.freedesktop.login1 /org/freedesktop/login1/session/{decoy_sid} "
            "org.freedesktop.login1.Session SetIdleHint b true"
        )
        # Control: without an inhibitor the system must go idle (the hidden
        # tty session is idle by its tty atime).
        c0 = cursor()
        fired = False
        for _ in range(24):
            if idle_lines(c0):
                fired = True
                break
            time.sleep(5)
        finding(f"R3 control (no inhibitor): logind idle action fired = {fired}: {idle_lines(c0)[:2]}")
        machine.succeed(
            f"systemd-run --unit=aux-inhibit --slice={SLICE} --collect "
            f"{SW}/systemd-inhibit --what=idle:sleep:handle-lid-switch --mode=block "
            "--who=session --why=busy /run/current-system/sw/bin/sleep infinity"
        )
        machine.wait_until_succeeds("systemd-inhibit --list --no-legend | grep -q busy")
        machine.succeed("rm -f /run/suspend-probe")
        c1 = cursor()
        time.sleep(75)
        lines = idle_lines(c1)
        finding(f"R3 with the inhibitor: idle actions in 75 s: {lines}")
        finding("R3: inhibitor state: " + machine.succeed("ls /run/systemd/inhibit; systemd-inhibit --list --no-legend").strip())
        if fired:
            assert not lines, f"the idle inhibitor did not stop IdleAction: {lines}"
            machine.fail("test -s /run/suspend-probe")
        else:
            finding("R3: the control never went idle, so the inhibitor result above is not conclusive")
        rc, out = machine.execute(
            "su testuser -s /bin/sh -c 'busctl call org.freedesktop.login1 /org/freedesktop/login1 "
            "org.freedesktop.login1.Manager Suspend b false' 2>&1"
        )
        finding(f"R3: decoy user requests suspend while the sleep inhibitor is held: rc={rc} {out.strip()}")
        machine.succeed(
            f"busctl call org.freedesktop.login1 /org/freedesktop/login1/session/{decoy_sid} "
            "org.freedesktop.login1.Session SetIdleHint b false"
        )
        finding("R3: stubbed suspends during the inhibitor phase: "
                + machine.succeed("cat /run/suspend-probe 2>/dev/null | wc -l").strip())

    # ==================================================================
    # R6: a hidden system service as a host unit.
    # ==================================================================
    with subtest("R6: StateDirectory= and LogsDirectory= under RootDirectory="):
        cmd = "/bin/sh -c 'echo s > /var/lib/auxsvc/s; echo l > /var/log/auxsvc/l'"
        _, out = hidden_run("auxsvc", cmd, extra=["StateDirectory=auxsvc", "LogsDirectory=auxsvc"], wait=True)
        _, where = machine.execute(
            "for p in /var/lib/auxsvc /var/log/auxsvc /var/lib/private/auxsvc; do test -e $p && echo host:$p; done; "
            f"for p in {UPPER}/var/lib/auxsvc {UPPER}/var/log/auxsvc; do test -e $p && echo upper:$p; done; true"
        )
        finding(f"R6: StateDirectory=/LogsDirectory= with RootDirectory= created: {where.split() or 'nothing'} {out.strip()}")
        machine.execute("rm -rf /var/lib/auxsvc /var/log/auxsvc")
        # Mitigation: drop the directives and create the directories inside
        # the hidden root.
        machine.succeed(f"mkdir -p {ROOT}/var/lib/auxsvc2 {ROOT}/var/log/auxsvc2")
        rc, out = hidden_run(
            "auxsvc2", "/bin/sh -c 'echo s > /var/lib/auxsvc2/s; echo l > /var/log/auxsvc2/l'", wait=True
        )
        assert rc == 0, out
        machine.fail("test -e /var/lib/auxsvc2 || test -e /var/log/auxsvc2")
        machine.succeed(f"test -e {UPPER}/var/lib/auxsvc2/s")

    # ==================================================================
    # R5b: a dedicated mount namespace for the hidden root.
    # ==================================================================
    with subtest("R5b: hidden root only inside a pinned mount namespace"):
        machine.succeed(
            "mkdir -p /run/aux-ns",
            "mount -t tmpfs -o mode=0700 tmpfs /run/aux-ns",
            "mount --make-private /run/aux-ns",
            "mkdir -p /run/aux-ns/root",
            "touch /run/aux-ns/mnt",
            "unshare --mount=/run/aux-ns/mnt --propagation private sh -c '"
            "mkdir -p /run/aux-ns/l && mount -t tmpfs tmpfs /run/aux-ns/l && "
            "mkdir -p /run/aux-ns/l/lower /run/aux-ns/l/upper /run/aux-ns/l/work && "
            "mount --bind / /run/aux-ns/l/lower && mount -o remount,bind,ro /run/aux-ns/l/lower && "
            "mount -t overlay overlay -o lowerdir=/run/aux-ns/l/lower,upperdir=/run/aux-ns/l/upper,workdir=/run/aux-ns/l/work "
            "/run/aux-ns/root'",
        )
        machine.succeed("nsenter --mount=/run/aux-ns/mnt findmnt /run/aux-ns/root")
        machine.fail("findmnt /run/aux-ns/root")
        rc, out = machine.execute(
            "systemd-run --wait --pipe --quiet --collect --unit=aux-ns-run "
            "nsenter --mount=/run/aux-ns/mnt --root=/run/aux-ns/root /bin/sh -c 'readlink /proc/self/root; "
            "echo x > /etc/aux-ns-probe && echo wrote'"
        )
        finding(f"R5b: a unit entering the pinned namespace: rc={rc} {out.split()}")
        machine.fail("test -e /etc/aux-ns-probe")
        machine.succeed(
            "systemd-run --unit=decoy-late3 -p PrivateTmp=yes /run/current-system/sw/bin/sleep infinity"
        )
        machine.wait_until_succeeds("systemctl is-active decoy-late3.service")
        pid = machine.succeed("systemctl show decoy-late3 -p MainPID --value").strip()
        machine.fail(f"grep -q ' /run/aux-ns/root ' /proc/{pid}/mountinfo")
        machine.succeed("systemctl stop decoy-late3.service")
        # Unpinning the namespace (no process left in it) frees the overlay.
        machine.succeed("umount /run/aux-ns/mnt", "umount /run/aux-ns")

    # ==================================================================
    # Emergency and teardown.
    # ==================================================================
    with subtest("emergency: back to the decoy, hidden tree killed"):
        machine.succeed(f"chvt {decoy_vt}")
        for cg in (SLICE_CG, USER_CG):
            machine.succeed(f"test ! -e {cg}/cgroup.kill || echo 1 > {cg}/cgroup.kill")
        for cg in (SLICE_CG, USER_CG):
            machine.wait_until_succeeds(f"test ! -e {cg}/cgroup.events || ! grep -q '^populated 1' {cg}/cgroup.events", timeout=20)
        machine.fail(f"pgrep -u {UID}")
        elapsed, c = wait_for_screen("decoy", "end-decoy")
        assert c["decoy"] > 0.4, f"decoy not rendered after the final emergency: {c}"
        machine.wait_until_succeeds(f"test \"$(loginctl show-session {decoy_sid} -p Active --value)\" = yes", timeout=10)
        _, acl = machine.execute("getfacl -p /dev/dri/card* 2>/dev/null | grep '^user:' || true")
        finding(f"R7a: uaccess ACLs on /dev/dri after emergency: {acl.split() or 'none'}")

    with subtest("teardown"):
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
        finding(f"end: other mount namespaces holding a copy of the hidden root: {sorted(per_ns.values()) or 'none'}")
        for pid, _comm in per_ns.values():
            machine.succeed(f"nsenter -t {pid} -m umount -R {ROOT}")
        machine.succeed(f"umount {DECOY_ONLY}", f"umount {ROOT}", f"umount {AUX}")
        machine.succeed(
            f"rm -rf {DROPIN_DIR} /run/aux-bus /run/userdb/{USER}.user /run/userdb/{UID}.user "
            f"/run/userdb/{USER}.group /run/userdb/{UID}.group",
            "systemctl daemon-reload",
        )
        machine.succeed("""${hiddenVolume.unmountHiddenVolumeStrict}""")
        machine.fail("test -e /dev/mapper/data")

    machine.log("FINDING: summary")
    for f in findings:
        machine.log("FINDING:   " + f.replace("\n", "\nFINDING:   "))
  '';
}
