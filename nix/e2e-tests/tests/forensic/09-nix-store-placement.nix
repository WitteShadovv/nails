# Test 09: Hidden-session Nix store writes land in the hidden upper, not the decoy
#
# The regression gate for the /nix store-bind fix. A plain "nix store add
# succeeds" check cannot see where the output landed, because the default E2E VM
# shares the host store over 9p through a tmpfs layer and the hidden volume is a
# second disk. This test runs on the forensic profile (an on-disk, imageable
# decoy Nix store) and asks the one question that matters: when a hidden session
# realises a store path while /nix is overlaid, does any trace of it survive on
# the *decoy* root disk once the overlays are gone?
#
# It realises two run-unique paths through the overlaid store -- one via
# `nix store add` of a nonce file through the daemon, one via an offline
# `builtins.toFile` derivation -- confirms both live only under the hidden /nix
# upper while active, then deactivates, powers the machine off and images the
# decoy root. The nonce token must appear in neither the fls listing (deleted
# entries included), the raw image bytes, nor the registered paths in the decoy
# store's `db.sqlite`. On current code the paths exist only under the hidden
# upper; a pre-fix build that resolved the daemon's writable remount onto the
# decoy backing store leaks the nonce onto the root image and fails here.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  shellHelpers = import ./../../lib/shell-helpers.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  diskForensics = import ./../../lib/disk-forensics.nix { inherit pkgs; };
  nixStorePrefix = "/nix" + "/store/";

  # Copy `nix` and its closure out of the store, patch the RPATHs and interpreter
  # references to the copies, so the binary keeps working after /nix is overlaid
  # or replaced. Same helper the nix-daemon overlay lifecycle test relies on.
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

  storePlacementProbe =
    pkgs:
    pkgs.writeShellScriptBin "nails-nix-store-placement-probe" ''
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

      assert_under_hidden_upper() {
        store_path=$1
        store_basename=''${store_path##*/}
        if [ ! -e "/mnt/data${nixStorePrefix}$store_basename" ]; then
          echo "store path did not land in the hidden upper: $store_path" >&2
          exit 1
        fi
      }

      if has_nix_overlay; then
        echo unexpected-overlay-before-activation >&2
        exit 1
      fi

      install_post_overlay_helpers
      wait_for_nix_daemon

      "$nails_bin" \
        --config "$config_path" \
        activate --overlay-only --session keep --accept-persistent-decoy -y

      has_nix_overlay
      echo MARKER:overlay-present
      wait_for_nix_daemon

      # Run-unique nonce woven into both the store-path name and the file content,
      # so it is observable in fls names, raw strings and the store DB alike.
      nonce_id=$("$busybox_bin" cat /proc/sys/kernel/random/uuid | "$busybox_bin" tr -d '-')
      nonce_token="NAILS_STORE_NONCE_$nonce_id"
      printf 'MARKER:nonce-id=%s\n' "$nonce_id"
      printf 'MARKER:nonce-token=%s\n' "$nonce_token"

      # (1) nix store add of a nonce file through the daemon. The source file
      # lives on the hidden volume, never the decoy root, so the only way the
      # nonce can reach the imaged decoy disk is a genuine store-write leak.
      probe_file="/mnt/data/nails-nonce-$nonce_id"
      printf '%s hidden-session store write\n' "$nonce_token" > "$probe_file"
      added_store_path=$(run_nix --extra-experimental-features nix-command \
        store add --store daemon "$probe_file")
      case "$added_store_path" in
        ${nixStorePrefix}*) ;;
        *) echo "unexpected added store path: $added_store_path" >&2; exit 1 ;;
      esac
      assert_under_hidden_upper "$added_store_path"
      printf 'MARKER:added-store-path=%s\n' "$added_store_path"

      # (2) Offline writeText-style derivation realised through the overlaid
      # store. It must go through the daemon: the read-only self-bind on the
      # overlaid store blocks a direct client write, and only the daemon's
      # writable remount resolves into the overlay upper. Single-quote
      # concatenation keeps the Nix string literals' double quotes intact while
      # interpolating the nonce.
      decl_expr='builtins.toFile "nails-nonce-'"$nonce_id"'-decl" "'"$nonce_token"' declarative body"'
      decl_store_path=$(run_nix --extra-experimental-features nix-command \
        eval --store daemon --raw --expr "$decl_expr")
      case "$decl_store_path" in
        ${nixStorePrefix}*) ;;
        *) echo "unexpected declarative store path: $decl_store_path" >&2; exit 1 ;;
      esac
      assert_under_hidden_upper "$decl_store_path"
      printf 'MARKER:decl-store-path=%s\n' "$decl_store_path"

      echo MARKER:hidden-upper-present
    '';
in
{
  name = "nix-store-placement";
  meta.tags = [ "forensic" ];

  # Overlay the store, realise paths through the daemon, then power-cycle and
  # image the decoy root; the forensic imaging dominates the runtime.
  globalTimeout = 1800;

  nodes = {
    machine =
      { pkgs, ... }:
      {
        imports = [ ./../../lib/forensic-vm-config.nix ];
        environment.systemPackages = [
          self.packages.x86_64-linux.nails
          (storePlacementProbe pkgs)
        ];
      };
  };

  testScript = _: ''
    ${shellHelpers.writeNixOverlayConfigFn}
    ${testHelpers.canonicalDeactivateFn}
    ${diskForensics.pythonSetup}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-nix-overlay.toml"
    write_nix_overlay_config(config_path)

    with subtest("prepare the hidden volume and a usable daemon store"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("systemctl start nix-daemon.service")
        machine.wait_for_unit("nix-daemon.service")

    with subtest("realise hidden-session store paths through the overlaid /nix"):
        probe_log = machine.succeed("nails-nix-store-placement-probe 2>&1")
        assert "MARKER:overlay-present" in probe_log, probe_log
        assert "MARKER:hidden-upper-present" in probe_log, probe_log

        markers = {}
        for line in probe_log.splitlines():
            if line.startswith("MARKER:") and "=" in line:
                key, _, value = line[len("MARKER:"):].partition("=")
                markers[key] = value.strip()

        nonce_id = markers.get("nonce-id")
        nonce_token = markers.get("nonce-token")
        added_store_path = markers.get("added-store-path")
        decl_store_path = markers.get("decl-store-path")
        assert nonce_id and nonce_token, probe_log
        assert added_store_path and added_store_path.startswith("${nixStorePrefix}"), probe_log
        assert decl_store_path and decl_store_path.startswith("${nixStorePrefix}"), probe_log

        # The run-unique tokens that must never reach the decoy root disk. Both
        # the raw hashes-and-name of each store path and the content nonce count.
        nonce_tokens = [
            nonce_id,
            nonce_token,
            added_store_path.rsplit("/", 1)[-1],
            decl_store_path.rsplit("/", 1)[-1],
        ]

    with subtest("deactivate and confirm the paths are absent from the decoy /nix"):
        canonical_deactivate(
            config_path, unit_name="nails-deactivate-nix-store-placement"
        )
        # The forensic profile always keeps its own store overlay nested under
        # /nix; the trailing space pins this to the nails overlay at exactly /nix.
        assert machine.execute("mount | grep -E 'overlay on /nix '")[0] != 0, (
            "the /nix overlay is still mounted after deactivation"
        )
        # With the overlay gone /nix is the decoy store again; the hidden-session
        # paths must not resolve there.
        for leaked in (added_store_path, decl_store_path):
            assert machine.execute("test -e %s" % leaked)[0] != 0, (
                "hidden-session store path leaked onto the decoy /nix: %s" % leaked
            )

    with subtest("the powered-off decoy image carries no trace of the nonce"):
        post = disk_forensics.snapshot(machine, "post-nix-store-placement", restart=False)
        offset = disk_forensics.partition_offset(post)

        post_fls = disk_forensics.fls_paths(disk_forensics.run_fls(post, offset))
        fls_hits = sorted(
            name for name in post_fls if any(tok in name for tok in nonce_tokens)
        )
        assert not fls_hits, f"fls found nonce-named entries on the decoy image: {fls_hits}"

        string_hits = disk_forensics.run_strings_scan(post, nonce_tokens)
        assert not string_hits, f"strings found nonce content on the decoy image: {sorted(string_hits)}"

        store_hits = disk_forensics.run_store_scan(post, nonce_tokens, offset=offset)
        assert not store_hits, (
            f"the decoy store DB registered a hidden-session path: {sorted(store_hits)}"
        )
        print("✓ decoy image clean of the hidden-session store paths")
  '';
}
