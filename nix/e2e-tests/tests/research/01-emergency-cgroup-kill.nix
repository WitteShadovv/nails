# Research test for the emergency's cgroup kill. Tagged `research`, so it
# is in no default group (not `ci`, not `all`); run it by name:
#
#   nix build .#e2e.research-emergency-cgroup-kill --no-link -L
#
# The kernel side of `cgroup.kill` is proven without a VM by
# `the_kill_empties_every_cgroup_but_the_invocations` in
# nails-core/tests/whole_root_kernel.rs. This test answers what that cannot: how
# systemd reacts when emergency kills a *service* through its own cgroup, on a
# real systemd host with a live overlay mounted over its own lower directory
# (the NAILS live-overlay shape).
#
# Each variant runs a `Restart=always` unit whose working directory is inside the
# overlay and which writes a heartbeat there, then tears the overlay down a
# different way:
#
#   raw   - write cgroup.kill, wait for `populated 0`, unmount.
#   stop  - enqueue `systemctl stop --no-block`, then cgroup.kill, wait, unmount.
#   sdkill- `systemctl kill --signal=SIGKILL`, wait, unmount.
#
# For each it records: kill-to-empty and kill-to-unmount latency, whether the
# overlay came off with a *non-lazy* umount, whether the upper is released
# (index=on probe mount), whether systemd restarted the unit, whether the
# restarted unit wrote onto the decoy directory, and how many journal lines the
# teardown produced. A desktop stand-in unit in its own cgroup must survive every
# variant. Hard assertions cover only the properties the emergency design
# relies on; the rest is printed as findings.
_: {
  name = "research-emergency-cgroup-kill";
  meta.tags = [ "research" ];

  nodes.machine =
    { pkgs, ... }:
    let
      worker = tag: {
        description = "Research worker ${tag}";
        serviceConfig = {
          WorkingDirectory = "/srv/${tag}/decoy";
          ExecStart = "${pkgs.bash}/bin/bash -c 'sleep 600 & while :; do date >> heartbeat; sleep 0.2; done'";
          Restart = "always";
          RestartSec = "200ms";
        };
      };
    in
    {
      imports = [ ./../../lib/vm-config.nix ];
      systemd.services = {
        research-worker-raw = worker "raw";
        research-worker-stop = worker "stop";
        research-worker-sdkill = worker "sdkill";
        research-desktop = {
          description = "Research desktop stand-in";
          serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
        };
      };
    };

  testScript = _: ''
    import json

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("systemctl start research-desktop.service")
    desktop_pid = machine.succeed("systemctl show -p MainPID --value research-desktop").strip()

    def setup(tag):
        machine.succeed(
            f"mkdir -p /srv/{tag}/decoy /srv/hidden-{tag} /srv/probe-{tag} && "
            f"echo decoy > /srv/{tag}/decoy/decoy.txt && "
            f"mount -t tmpfs -o size=32m tmpfs /srv/hidden-{tag} && "
            f"mkdir /srv/hidden-{tag}/upper /srv/hidden-{tag}/work /srv/hidden-{tag}/probe-work && "
            f"mount -t overlay overlay -o lowerdir=/srv/{tag}/decoy,"
            f"upperdir=/srv/hidden-{tag}/upper,workdir=/srv/hidden-{tag}/work,index=on /srv/{tag}/decoy"
        )
        machine.succeed(f"systemctl start research-worker-{tag}.service")
        machine.wait_until_succeeds(f"test -s /srv/hidden-{tag}/upper/heartbeat")
        machine.fail(f"umount /srv/{tag}/decoy")  # pinned by the worker

    def teardown(tag, prekill, use_cgroup_kill):
        cg = f"/sys/fs/cgroup/system.slice/research-worker-{tag}.service"
        cursor = json.loads(machine.succeed("journalctl -n1 -o json"))["__CURSOR"]
        kill = f"{{ echo 1 > {cg}/cgroup.kill; }} 2>/dev/null || true;" if use_cgroup_kill else ""
        out = machine.succeed(
            "t0=$(date +%s%N); "
            f"{prekill} {kill} "
            f"while grep -qs 'populated 1' {cg}/cgroup.events; do :; done; "
            "t1=$(date +%s%N); "
            f"if umount /srv/{tag}/decoy; then lazy=0; else umount -l /srv/{tag}/decoy; lazy=1; fi; "
            "t2=$(date +%s%N); "
            'echo "$(( (t1-t0)/1000 )) $(( (t2-t0)/1000 )) $lazy"'
        ).split()
        empty_us, unmount_us, lazy = int(out[0]), int(out[1]), out[2] == "1"
        released = machine.execute(
            f"mount -t overlay overlay -o lowerdir=/srv/{tag}/decoy,"
            f"upperdir=/srv/hidden-{tag}/upper,workdir=/srv/hidden-{tag}/probe-work,index=on "
            f"/srv/probe-{tag} && umount /srv/probe-{tag}"
        )[0] == 0
        # sync-lint: allow sleep -- an observation window longer than RestartSec, not a wait for a signal
        machine.sleep(3)
        state = machine.succeed(f"systemctl is-active research-worker-{tag} || true").strip()
        restarts = machine.succeed(f"systemctl show -p NRestarts --value research-worker-{tag}").strip()
        decoy_written = machine.execute(f"test -e /srv/{tag}/decoy/heartbeat")[0] == 0
        journal = machine.succeed(
            f"journalctl --after-cursor='{cursor}' -o short-monotonic | grep -v 'kernel:' || true"
        )
        lines = [line for line in journal.splitlines() if line.strip()]
        machine.succeed(f"systemctl stop research-worker-{tag} || true")
        finding = {
            "variant": tag,
            "kill_to_empty_ms": empty_us / 1000,
            "kill_to_unmount_ms": unmount_us / 1000,
            "needed_lazy_detach": lazy,
            "upper_released": released,
            "state_after_3s": state,
            "n_restarts": restarts,
            "restarted_unit_wrote_to_decoy": decoy_written,
            "journal_lines": len(lines),
        }
        print("RESEARCH-FINDING " + json.dumps(finding))
        print("\n".join("  journal: " + line for line in lines))
        return finding

    results = []
    for tag, prekill, use_kill in [
        ("raw", "", True),
        ("stop", "systemctl stop --no-block research-worker-stop;", True),
        ("sdkill", "systemctl kill --signal=SIGKILL research-worker-sdkill;", False),
    ]:
        setup(tag)
        results.append(teardown(tag, prekill, use_kill))

    # What the emergency design relies on.
    for r in results:
        assert not r["needed_lazy_detach"], f"{r['variant']}: the kill must free the overlay for a non-lazy umount"
        assert r["upper_released"], f"{r['variant']}: the upper must be released after the kill"
    stop = next(r for r in results if r["variant"] == "stop")
    assert stop["state_after_3s"] != "active", "an enqueued stop job must suppress Restart="
    assert not stop["restarted_unit_wrote_to_decoy"], "stop + cgroup.kill must leave the decoy untouched"
    machine.succeed(f"kill -0 {desktop_pid}")  # the desktop stand-in survived every variant

    print("RESEARCH-SUMMARY " + json.dumps(results))
  '';
}
