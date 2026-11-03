# Probe, not for merging: the window's emergency requests where they overlap
# a deactivation, or come in a session without a plan, and how long the
# window's stand-in lives after each. What each case ended in goes to
# probe-results.txt in the test's output.
#
# Each client speaks the window's half of the protocol to
# `nails helper --stdio`, as the window does, and stands in for the window:
# it marks each quarter of a second it lives on the serial console after its
# emergency request, and once it outlives the window's grace of 3 seconds it
# runs the window's own power-off, `systemctl poweroff --no-ask-password`.
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  packages = self.packages.x86_64-linux;
  windowEngine = packages.nails.overrideAttrs (old: {
    pname = "nails-window";
    cargoBuildFlags = old.cargoBuildFlags ++ [
      "--features"
      "gui"
    ];
  });
  # The helper as the window starts it, its requests through a fifo and its
  # frames into a file on the hidden volume, so that what it answers stays
  # readable after the client that stands in for the window is gone.
  helperStart = name: ''
    out=/mnt/data/probe-out-${name}.txt
    fifo=/mnt/data/probe-in-${name}
    rm -f "$out" "$fifo"
    mkfifo "$fifo"
    /mnt/data/nails --config /mnt/data/config/nails.toml helper --stdio <"$fifo" >"$out" 2>/dev/null &
    exec 8>"$fifo"
    wait_for() {
      local i
      for i in $(seq 1 600); do
        grep -q -- "$1" "$out" && return 0
        sleep 0.1
      done
      return 1
    }
    wait_for '"hello"' || { say "no hello"; exit 1; }
    hello=$(head -n 1 "$out")
    theirs=''${hello#'{"hello":'}
    theirs=''${theirs%'}'}
    printf '{"v":1,"id":1,"op":{"hello":%s}}\n' "$theirs" >&8
    wait_for '"id":1,' || { say "no answer to the hello"; exit 1; }
  '';
  # The window's stand-in after its request: the beats, then the window's
  # own power-off once it outlives the grace.
  standIn = ''
    for beat in 1 2 3 4 5 6 7 8 9 10 11 12; do
      sleep 0.25
      say "alive $((beat * 250)) ms after the request"
    done
    say "outlived the grace: the window's own power-off"
    /run/current-system/sw/bin/systemctl poweroff --no-ask-password </dev/null >/dev/null 2>&1
    say "the window's own power-off returned $?"
    sleep 600
  '';
  # The emergency `request` alone.
  alone =
    name: request:
    pkgs.writeShellScript "window-alone-${name}" ''
      set -u
      say() { echo "window-alone-${name}: $*" >/dev/ttyS0; }
      ${helperStart "alone-${name}"}
      printf '%s\n' '${request}' >&8
      say "request written"
      ${standIn}
    '';
  # The plan of a return to the decoy, its apply, and right behind the apply
  # the emergency `request`, as the window writes it while Ending the Hidden
  # Session shows.
  overlap =
    name: request:
    pkgs.writeShellScript "window-overlap-${name}" ''
      set -u
      say() { echo "window-overlap-${name}: $*" >/dev/ttyS0; }
      ${helperStart "overlap-${name}"}
      printf '%s\n' '{"v":1,"id":2,"op":{"deactivate_plan":{"poweroff":false}}}' >&8
      wait_for '"id":2,' || { say "no answer to the plan"; exit 1; }
      token=$(grep '"id":2,' "$out" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p' | head -n 1)
      [ -n "$token" ] || { say "no token: $(grep '"id":2,' "$out" | head -c 400)"; exit 1; }
      printf '{"v":1,"id":3,"op":{"deactivate_apply":{"token":"%s"}}}\n%s\n' "$token" '${request}' >&8
      say "request written"
      ${standIn}
    '';
  returnLine = ''{"v":1,"id":0,"op":{"emergency":{"poweroff":false,"reboot":false}}}'';
  powerOffLine = ''{"v":1,"id":0,"op":{"emergency":{"poweroff":true,"reboot":false}}}'';
  rebootLine = ''{"v":1,"id":0,"op":{"emergency":{"poweroff":false,"reboot":true}}}'';
  aloneReturn = alone "return" returnLine;
  aloneReboot = alone "reboot" rebootLine;
  aloneRebootNoPlan = alone "reboot-no-plan" rebootLine;
  overlapReturn = overlap "return" returnLine;
  overlapPowerOff = overlap "poweroff" powerOffLine;
  overlapPowerOffAgain = overlap "poweroff-again" powerOffLine;
in
{
  name = "session-window-emergency";
  meta.tags = [ "session" ];

  globalTimeout = 2400;

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      security.polkit.enable = true;
      system.extraDependencies = [
        windowEngine
        aloneReturn
        aloneReboot
        aloneRebootNoPlan
        overlapReturn
        overlapPowerOff
        overlapPowerOffAgain
      ];
    };

  testScript = _: ''
    import json

    from nails_e2e import session

    CONFIG = "/mnt/data/config/nails.toml"
    UPPER = "/mnt/data/root/upper"
    results: list[str] = []

    def write_results():
        (machine.out_dir / "probe-results.txt").write_text("\n".join(results) + "\n")

    def lines_of(since, name):
        return [line for line in machine.full_console_log[since:] if name in line]

    def ended(since):
        reader = getattr(machine, "serial_thread", None)
        if reader is not None:
            reader.join(timeout=30)
        console = "\n".join(machine.full_console_log[since:])
        if session.PANIC_MARKER in console:
            return "kernel panic"
        if session.RESTART_MARKER in console:
            return "full reboot"
        if session.POWER_DOWN_MARKER in console:
            return "power-off"
        return "QEMU exited without a marker"

    def note(label, since, name, outcome):
        seen = lines_of(since, name)
        results.append(f"== {label}: {outcome}")
        results.extend(seen[-40:])
        machine.log(f"PROBE {label}: {outcome}")

    def activate(label):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        session.follow_soft_reboot(
            machine,
            f"su testuser -c 'sudo /mnt/data/nails --config {CONFIG} activate -y --overlay-only' "
            f"> /mnt/data/activate-{label}.log 2>&1",
            f"activate for {label}",
        )
        session.assert_hidden_root(machine, UPPER)

    def frames(name):
        # What the helper answered, from its frames on the hidden volume.
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        text = machine.succeed(f"cat /mnt/data/probe-out-{name}.txt 2>/dev/null || true")
        machine.succeed("""${hiddenVolume.unmountHiddenVolumeStrict}""")
        results.append(f"-- helper frames of {name}:")
        for line in text.splitlines():
            try:
                frame = json.loads(line)
            except ValueError:
                results.append(f"   unreadable: {line[:300]}")
                continue
            result = frame.get("result")
            if result is None:
                results.append(f"   {line[:300]}")
                continue
            data = (result.get("envelope") or {}).get("data") or {}
            keep = {
                k: data.get(k)
                for k in (
                    "status",
                    "side",
                    "requested",
                    "dispatched",
                    "fallback",
                    "kernel_power_off",
                    "elapsed_ms",
                    "phases",
                    "backend_left_open",
                )
                if k in data
            }
            results.append(
                f"   result id={result.get('id')} exit={result.get('exit')} "
                f"ok={(result.get('envelope') or {}).get('ok')} {json.dumps(keep)[:900]}"
            )

    def soft_reboot_or_off(label, trigger, name):
        since = len(machine.full_console_log)
        try:
            session.follow_soft_reboot(machine, trigger, label)
        except AssertionError as error:
            if machine.process is not None and machine.process.poll() is None:
                note(label, since, name, f"no soft-reboot, the machine still runs: {str(error)[:300]}")
                write_results()
                raise
            outcome = ended(since)
            note(label, since, name, f"{outcome} ({str(error)[:200]})")
            machine.start()
            machine.wait_for_unit("multi-user.target")
            return
        root = machine.succeed("findmnt -no FSTYPE,SOURCE /").strip()
        note(label, since, name, f"soft-reboot, / is now {root}")
        session.assert_decoy_root(machine)
        machine.wait_until_succeeds("test ! -e /dev/mapper/data", timeout=60)

    def until_qemu_exits(label, client, name):
        since = len(machine.full_console_log)
        machine.execute(
            f"({client}) </dev/null >/dev/null 2>/dev/null &",
            check_return=False,
            check_output=False,
        )
        session.wait_for_power_off(machine, 300)
        note(label, since, name, ended(since))
        machine.start()
        machine.wait_for_unit("multi-user.target")

    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("set up and activate"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("install -m 0755 ${windowEngine}/bin/nails /mnt/data/nails")
        machine.succeed(
            "mkdir -p /mnt/data/config && "
            f"cat > {CONFIG} <<'EOF'\n"
            "hidden_volume_root = \"/mnt/data\"\n"
            "minimum_space_mb = 100\n"
            "EOF"
        )
        session.follow_soft_reboot(
            machine,
            f"su testuser -c 'sudo /mnt/data/nails --config {CONFIG} activate -y --overlay-only' "
            "> /mnt/data/activate.log 2>&1",
            "activate",
        )
        session.assert_hidden_root(machine, UPPER)

    with subtest("A: the emergency's return alone"):
        soft_reboot_or_off("A return alone", "${aloneReturn}", "window-alone-return")
        frames("alone-return")

    with subtest("B: the emergency's return right behind a deactivation's return"):
        activate("B")
        soft_reboot_or_off("B overlap return", "${overlapReturn}", "window-overlap-return")
        frames("overlap-return")

    with subtest("C: the emergency's power-off right behind a deactivation's return"):
        activate("C")
        soft_reboot_or_off("C overlap poweroff", "${overlapPowerOff}", "window-overlap-poweroff")
        frames("overlap-poweroff")

    with subtest("C again"):
        activate("C-again")
        soft_reboot_or_off(
            "C again overlap poweroff", "${overlapPowerOffAgain}", "window-overlap-poweroff-again"
        )
        frames("overlap-poweroff-again")

    with subtest("D: the emergency's restart alone"):
        activate("D")
        until_qemu_exits("D reboot alone", "${aloneReboot}", "window-alone-reboot")
        frames("alone-reboot")

    with subtest("E: the emergency's restart in a session without a plan"):
        activate("E")
        machine.succeed("rm -f /run/overlay-runtime/plan.json")
        until_qemu_exits("E reboot without a plan", "${aloneRebootNoPlan}", "window-alone-reboot-no-plan")
        frames("alone-reboot-no-plan")

    write_results()
    machine.log("PROBE RESULTS:\n" + "\n".join(results))
  '';
}
