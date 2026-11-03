# What a guest that stopped answering waits on (nails_e2e.stall). When a switch
# or a power-off never ends, the test driver presses the SysRq keys and then
# Alt+ArrowUp through QMP. PID 1 starts kbrequest.target on Alt+ArrowUp;
# systemd ships no such unit, and here it starts a report of PID 1's job queue
# on the serial console. Nothing of it loads before the key is pressed, so a
# passing run never sees it, and neither unit has default dependencies, so the
# report also runs while a startup or a shutdown waits.
{ pkgs, ... }:
let
  # The serial console the test driver reads.
  inherit
    (import (pkgs.path + "/nixos/lib/qemu-common.nix") {
      inherit (pkgs) lib stdenv;
    })
    qemuSerialDevice
    ;
in
{
  systemd = {
    targets.kbrequest = {
      description = "Keyboard Request";
      unitConfig.DefaultDependencies = false;
      wants = [ "jobs-report.service" ];
    };
    services.jobs-report = {
      description = "Report of the service manager's jobs";
      unitConfig.DefaultDependencies = false;
      serviceConfig.Type = "oneshot";
      # Each job with the jobs it waits for and holds up, the units of the
      # jobs that wait with no job to wait for, the mount units' order against
      # the local filesystems and the unmount, and the mount table with
      # libmount's utab.
      script = ''
        set +e
        exec >/dev/${qemuSerialDevice} 2>&1
        echo pid1-jobs-report-begin
        systemctl list-jobs --after --before --full --no-pager
        stuck=()
        unit=""
        flush() {
          if [ -n "$unit" ] && [ "$state" = waiting ] && [ "$waits" = 0 ]; then
            stuck+=("$unit")
          fi
        }
        while read -r first second third fourth _; do
          if [[ $first =~ ^[0-9]+$ ]]; then
            flush
            unit=$second state=$fourth waits=0
          elif [ "$second $third" = "waiting for" ]; then
            waits=1
          fi
        done < <(systemctl list-jobs --before --no-legend --full)
        flush
        [ ''${#stuck[@]} -gt 0 ] && systemd-analyze dump "''${stuck[@]}"
        echo "--- mount units"
        systemd-analyze dump '*.mount' | grep -E \
          ' Unit [^ ]+:$|^[[:space:]]+(Where|What|Extrinsic|Options):|(Before|After|Conflicts): (local-fs|local-fs-pre|umount)\.target'
        echo "--- utab"
        cat /run/mount/utab
        echo "--- mountinfo"
        cat /proc/self/mountinfo
        echo pid1-jobs-report-end
      '';
    };
  };

  # The SysRq dumps of blocked tasks and of every task: systemd's default
  # sysctl lets the keyboard only sync (kernel.sysrq = 16).
  boot.kernelParams = [ "sysrq_always_enabled" ];
}
