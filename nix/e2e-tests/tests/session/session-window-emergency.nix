# Probe, not for merging: the window's emergency power-off right behind the
# apply of a deactivation's return to the decoy. "before" is the window as it
# was: the request alone, and its own power-off only once it outlives its
# grace of 3 seconds. "at-once" is the window now: the request, then its own
# power-off (`systemctl poweroff --no-ask-password`) right after it, with the
# press 0, 100 or 200 ms after the apply. What each case ended in goes to
# probe-results.txt in the test's output.
#
# Each client speaks the window's half of the protocol to
# `nails helper --stdio`, as the window does, and stands in for the window:
# it marks each quarter of a second it lives on the serial console after its
# emergency request. It runs as root, so its power-off skips the polkit check
# the window's goes through.
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
  helperStart = ''
    coproc HELPER { exec /mnt/data/nails --config /mnt/data/config/nails.toml helper --stdio 2>/dev/null; }
    IFS= read -r -t 60 hello <&"''${HELPER[0]}" || { say "no hello"; exit 1; }
    theirs=''${hello#'{"hello":'}
    theirs=''${theirs%'}'}
    printf '{"v":1,"id":1,"op":{"hello":%s}}\n' "$theirs" >&"''${HELPER[1]}"
    IFS= read -r -t 60 answer <&"''${HELPER[0]}"
    case "$answer" in
      *'"id":1'*'"ok":true'*) ;;
      *) say "the helper did not take the hello: $answer"; exit 1 ;;
    esac
  '';
  powerOffLine = ''{"v":1,"id":0,"op":{"emergency":{"poweroff":true,"reboot":false}}}'';
  ownPowerOff = ''
    /run/current-system/sw/bin/systemctl poweroff --no-ask-password </dev/null >/dev/null 2>&1
  '';
  # The plan of a return to the decoy and its apply; `delay` seconds after the
  # apply the emergency's power-off, as the window writes it while Ending the
  # Hidden Session shows; then, `atOnce`, the window's own power-off right
  # after it, else the beats and that power-off once the grace is out.
  overlap =
    name: delay: atOnce:
    pkgs.writeShellScript "window-overlap-${name}" ''
      set -u
      say() { echo "window-overlap-${name}: $(date +%s.%N) $*" >/dev/ttyS0; }
      ${helperStart}
      printf '%s\n' '{"v":1,"id":2,"op":{"deactivate_plan":{"poweroff":false}}}' >&"''${HELPER[1]}"
      token=
      while IFS= read -r -t 60 line <&"''${HELPER[0]}"; do
        case "$line" in
          *'"result"'*'"id":2'*)
            token=$(printf '%s' "$line" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
            break
            ;;
          *'"error"'*) say "plan refused: ''${line:0:400}"; exit 1 ;;
        esac
      done
      [ -n "$token" ] || { say "no token"; exit 1; }
      exec 7<&"''${HELPER[0]}"
      (
        while IFS= read -r -t 120 line <&7; do
          say "frame ''${line:0:700}"
        done
      ) &
      printf '{"v":1,"id":3,"op":{"deactivate_apply":{"token":"%s"}}}\n' "$token" >&"''${HELPER[1]}"
      say "apply written"
      sleep ${delay}
      printf '%s\n' '${powerOffLine}' >&"''${HELPER[1]}"
      say "request written"
      ${
        if atOnce then
          ''
            ${ownPowerOff}
            say "the window's own power-off at once returned $?"
          ''
        else
          ""
      }
      for beat in 1 2 3 4 5 6 7 8 9 10 11 12; do
        sleep 0.25
        say "alive $((beat * 250)) ms after the request"
      done
      ${
        if atOnce then
          ""
        else
          ''
            say "outlived the grace: the window's own power-off"
            ${ownPowerOff}
            say "the window's own power-off returned $?"
          ''
      }
      sleep 600
    '';
  before = overlap "before" "0" false;
  atOnce0 = overlap "at-once-0" "0" true;
  atOnce0b = overlap "at-once-0b" "0" true;
  atOnce100 = overlap "at-once-100" "0.1" true;
  atOnce200 = overlap "at-once-200" "0.2" true;
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
        before
        atOnce0
        atOnce0b
        atOnce100
        atOnce200
      ];
    };

  testScript = _: ''
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

    def logged(label):
        # What the engine logged on the hidden volume about it.
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        out = machine.succeed(
            "grep -rh -e 'emergency hot path finished' -e 'the way back is enqueued' "
            "-e 'soft-reboot was not started' /mnt/data/logs 2>/dev/null | tail -n 6 || true"
        )
        results.append(f"-- engine log after {label}:")
        results.extend(line[:900] for line in out.splitlines())
        machine.succeed("""${hiddenVolume.unmountHiddenVolumeStrict}""")

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

    with subtest("before: the request alone, 0 ms after the apply"):
        soft_reboot_or_off("before 0 ms", "${before}", "window-overlap-before")
        logged("before")

    for label, trigger, name in [
        ("at-once 0 ms", "${atOnce0}", "window-overlap-at-once-0:"),
        ("at-once 0 ms again", "${atOnce0b}", "window-overlap-at-once-0b"),
        ("at-once 100 ms", "${atOnce100}", "window-overlap-at-once-100"),
        ("at-once 200 ms", "${atOnce200}", "window-overlap-at-once-200"),
    ]:
        with subtest(label):
            activate(label.replace(" ", "-"))
            soft_reboot_or_off(label, trigger, name)
            logged(label)

    write_results()
    machine.log("PROBE RESULTS:\n" + "\n".join(results))
  '';
}
