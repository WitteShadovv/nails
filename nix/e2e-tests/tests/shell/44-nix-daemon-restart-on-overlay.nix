# Test 44: Nix Daemon Restart on Overlay

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  shellHelpers = import ./../../lib/shell-helpers.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  nixStorePrefix = "/nix" + "/store/";
  relocatableNixHelper =
    pkgs:
    let
      nixClosure = pkgs.closureInfo { rootPaths = [ pkgs.nix ]; };
    in
    pkgs.runCommand "relocatable-nix-helper" { } ''
      mkdir -p "$out/bin" "$out/store"
      cp ${pkgs.nix}/bin/nix "$out/bin/nix"
      cp ${nixClosure}/store-paths "$out/store-paths"
      : > "$out/lib-dirs"
      while IFS= read -r store_path; do
        cp -a "$store_path" "$out/store/"
        store_basename=''${store_path##*/}
        if [ -d "$out/store/$store_basename/lib" ]; then
          printf '%s\n' "store/$store_basename/lib" >> "$out/lib-dirs"
        fi
      done < ${nixClosure}/store-paths

      while IFS= read -r candidate; do
        needed_file=$(mktemp)
        if ${pkgs.patchelf}/bin/patchelf --print-needed "$candidate" > "$needed_file" 2>/dev/null; then
          chmod u+w "$candidate"
          while IFS= read -r needed; do
            case "$needed" in
              ${nixStorePrefix}*)
                ${pkgs.patchelf}/bin/patchelf \
                  --replace-needed "$needed" "$(basename "$needed")" \
                  "$candidate"
                ;;
            esac
          done < "$needed_file"
        fi
        rm -f "$needed_file"
      done < <(${pkgs.findutils}/bin/find "$out" -type f)
    '';
  lifecycleScript =
    pkgs:
    pkgs.writeShellScriptBin "nails-nix-daemon-overlay-lifecycle-test" ''
      set -eu
      config_path=/tmp/nails-nix-overlay.toml
      tmp_nix_dir=/tmp/nix-helper
      nix_bin=$tmp_nix_dir/bin/nix
      nails_bin=/tmp/nails
      busybox_bin=/tmp/busybox
      nix_loader=
      nix_lib_path=

      install_post_overlay_helpers() {
        mkdir -p "$tmp_nix_dir"
        cp -a ${relocatableNixHelper pkgs}/. "$tmp_nix_dir"/
        interpreter_path="$(${pkgs.patchelf}/bin/patchelf --print-interpreter ${pkgs.nix}/bin/nix)"
        interpreter_name=$(basename "$interpreter_path")
        interpreter_store_dir=""
        nix_rpath=""
        while IFS= read -r lib_dir; do
          [ -n "$lib_dir" ] || continue
          if [ -n "$nix_rpath" ]; then
            nix_rpath="$nix_rpath:$tmp_nix_dir/$lib_dir"
          else
            nix_rpath="$tmp_nix_dir/$lib_dir"
          fi
        done < "$tmp_nix_dir/lib-dirs"
        while IFS= read -r store_path; do
          store_basename=''${store_path##*/}
          copied_store_path="$tmp_nix_dir/store/$store_basename"
          case "$interpreter_path" in
            "$store_path"/*)
              interpreter_store_dir="$copied_store_path"
              ;;
          esac
        done < "$tmp_nix_dir/store-paths"
        if [ -z "$interpreter_store_dir" ]; then
          echo unable-to-find-interpreter-store-dir >&2
          exit 1
        fi
        nix_loader="$interpreter_store_dir/lib/$interpreter_name"
        nix_lib_path="$nix_rpath"
        chmod +x "$nix_bin"
        cp ${pkgs.pkgsStatic.busybox}/bin/busybox "$busybox_bin"
        chmod +x "$busybox_bin"
        cp ${self.packages.x86_64-linux.nails}/bin/nails "$nails_bin"
        chmod +x "$nails_bin"
      }

      run_nix() {
        "$nix_loader" --library-path "$nix_lib_path" "$nix_bin" "$@"
      }

      wait_for_nix_daemon() {
        attempt=0
        while [ "$attempt" -lt 100 ]; do
          if run_nix --extra-experimental-features nix-command store ping --store daemon >/dev/null 2>&1; then
            return 0
          fi
          attempt=$((attempt + 1))
          "$busybox_bin" sleep 0.1
        done

        run_nix --extra-experimental-features nix-command store ping --store daemon >/dev/null
      }

      has_nix_overlay() {
        while IFS= read -r line; do
          case "$line" in
            *" / /nix "*" - overlay overlay "*) return 0 ;;
          esac
        done < /proc/self/mountinfo
        return 1
      }

      find_nix_daemon_pid() {
        newest_pid=
        newest_starttime=

        for comm_path in /proc/[0-9]*/comm; do
          [ -r "$comm_path" ] || continue
          IFS= read -r comm < "$comm_path" || continue
          [ "$comm" = "nix-daemon" ] || continue

          pid=''${comm_path#/proc/}
          pid=''${pid%/comm}
          starttime=$(read_proc_starttime "$pid") || continue

          if [ -z "$newest_starttime" ] || [ "$starttime" -gt "$newest_starttime" ]; then
            newest_pid=$pid
            newest_starttime=$starttime
          fi
        done

        [ -n "$newest_pid" ] || return 1
        printf '%s\n' "$newest_pid"
      }

      read_proc_starttime() {
        stat_line=$(<"/proc/$1/stat")
        stat_fields=''${stat_line#*) }
        set -- $stat_fields
        printf '%s\n' "$20"
      }

      assert_nix_usable() {
        wait_for_nix_daemon
        added_path=$(run_nix --extra-experimental-features nix-command store add /etc/hostname)
        case "$added_path" in
          ${nixStorePrefix}*) ;;
          *) echo "unexpected store path: $added_path" >&2; exit 1 ;;
        esac
      }

      if has_nix_overlay; then
        echo unexpected-overlay-before-activation >&2
        exit 1
      fi

      install_post_overlay_helpers

      nix_daemon_pid_before=$(find_nix_daemon_pid) || {
        echo unable-to-find-nix-daemon-before-activation >&2
        exit 1
      }
      nix_daemon_starttime_before=$(read_proc_starttime "$nix_daemon_pid_before")

      assert_nix_usable
      echo MARKER:baseline-ok
      while IFS= read -r line; do
        case "$line" in
          *" /nix "*|*" ${"/nix" + "/store "}"*)
            printf 'MOUNTINFO:%s\n' "$line"
            ;;
        esac
      done < /proc/self/mountinfo

      "$nails_bin" \
        --config "$config_path" \
        activate --overlay-only --session keep -y

      has_nix_overlay
      echo MARKER:overlay-present

      assert_nix_usable
      echo MARKER:nix-usable-after-activation
      echo MARKER:daemon-active-after-activation

      nix_daemon_pid_after=$(find_nix_daemon_pid) || {
        echo unable-to-find-nix-daemon-after-activation >&2
        exit 1
      }
      nix_daemon_starttime_after=$(read_proc_starttime "$nix_daemon_pid_after")
      if [ -z "$nix_daemon_pid_after" ] || [ "$nix_daemon_pid_after" = 0 ]; then
        echo "invalid nix-daemon pid after activation: $nix_daemon_pid_after" >&2
        exit 1
      fi
      if [ "$nix_daemon_pid_after" = "$nix_daemon_pid_before" ]; then
        echo "nix-daemon pid did not change: before=$nix_daemon_pid_before after=$nix_daemon_pid_after" >&2
        exit 1
      fi
      echo MARKER:daemon-restarted

      # Write-landing probe: add a store path with unique, unpredictable content
      # through the daemon while /nix is overlaid. With the store self-bound into
      # the overlay this must land in the hidden upper; a pre-fix build resolves
      # the daemon's writable remount to the decoy backing store instead.
      hidden_probe_id=$("$busybox_bin" cat /proc/sys/kernel/random/uuid | "$busybox_bin" tr -d '-')
      hidden_probe_name="nails-leak-probe-$hidden_probe_id"
      hidden_probe_file="/tmp/$hidden_probe_name"
      printf 'unique-hidden-session-content-%s\n' "$hidden_probe_id" > "$hidden_probe_file"
      hidden_store_path=$(run_nix --extra-experimental-features nix-command store add --store daemon "$hidden_probe_file")
      case "$hidden_store_path" in
        ${nixStorePrefix}*) ;;
        *) echo "unexpected hidden store path: $hidden_store_path" >&2; exit 1 ;;
      esac
      hidden_store_basename=''${hidden_store_path##*/}
      # The path lands in the /nix overlay's hidden upper when the store is part
      # of /nix, or in the nested overlay's hidden upper when the store is its
      # own (here: overlay) mount that NAILS nests under the hidden root. Either
      # way it is on the hidden volume; the decoy-store check after deactivation
      # proves it never reached the decoy.
      hidden_landed=no
      for candidate in "/mnt/data${nixStorePrefix}$hidden_store_basename" "/mnt/data/.nails-submounts/nix%2Fstore/upper/$hidden_store_basename"; do
        if [ -e "$candidate" ]; then hidden_landed=yes; fi
      done
      if [ "$hidden_landed" != yes ]; then
        echo "hidden-session store path did not land in a hidden upper: $hidden_store_path" >&2
        exit 1
      fi
      printf 'MARKER:hidden-store-path=%s\n' "$hidden_store_path"
      echo MARKER:hidden-upper-present

    '';
in
{
  name = "nix-daemon-restart-on-overlay";
  meta.tags = [ "shell" ];

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        (lifecycleScript pkgs)
      ];
    };

  testScript = _: ''
    ${shellHelpers.writeNixOverlayConfigFn}
    ${testHelpers.canonicalDeactivateFn}
    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-nix-overlay.toml"
    write_nix_overlay_config(config_path)

    def assert_nix_usable():
        machine.succeed("nix --extra-experimental-features nix-command store ping --store daemon")
        added_path = machine.succeed("nix --extra-experimental-features nix-command store add /etc/hostname").strip()
        assert added_path.startswith("${nixStorePrefix}"), added_path

    with subtest("prepare hidden volume"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("systemctl start nix-daemon.service")
        machine.wait_for_unit("nix-daemon.service")
        assert machine.succeed("systemctl is-active nix-daemon.service").strip() == "active"
        assert_nix_usable()

    with subtest("overlaying /nix restarts nix-daemon and deactivation removes overlay"):
        console_log = machine.succeed("nails-nix-daemon-overlay-lifecycle-test 2>&1")

        assert "MARKER:baseline-ok" in console_log, console_log
        assert "MARKER:overlay-present" in console_log, console_log
        assert "MARKER:daemon-active-after-activation" in console_log, console_log
        assert "MARKER:daemon-restarted" in console_log, console_log
        assert "MARKER:nix-usable-after-activation" in console_log, console_log
        assert "MARKER:hidden-upper-present" in console_log, console_log
        hidden_store_path = None
        for line in console_log.splitlines():
            prefix = "MARKER:hidden-store-path="
            if line.startswith(prefix):
                hidden_store_path = line[len(prefix):].strip()
        assert hidden_store_path and hidden_store_path.startswith(
            "${nixStorePrefix}"
        ), console_log

        canonical_deactivate(config_path, unit_name="nails-deactivate-nix-daemon-overlay")

        assert machine.succeed("systemctl is-active nix-daemon.socket").strip() == "active"
        assert_nix_usable()
        assert machine.execute("mountpoint -q /nix")[0] != 0

        # Disk-image leak check: the hidden-session store path must be absent from
        # the decoy /nix after deactivation (it lived only in the hidden upper).
        # Fails on pre-fix builds that leaked the write onto the decoy backing.
        assert (
            machine.execute("test -e %s" % hidden_store_path)[0] != 0
        ), "hidden-session store path leaked onto the decoy /nix: %s" % hidden_store_path
  '';
}
