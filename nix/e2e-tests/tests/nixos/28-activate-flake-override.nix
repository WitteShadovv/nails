# Test 28: Activate Flake Override

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "activate-flake-override";
  meta.tags = [ "nixos" ];

  nodes.machine =
    { lib, pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.python3
      ];
      nix.settings.experimental-features = [
        "nix-command"
        "flakes"
      ];
      # The guest is offline. The hidden toplevel is a store directory the flake
      # produces with `builtins.path` (a plain source copy of a committed
      # directory — no nixpkgs, no build), so the explicit `nix build` only has to
      # realise an already-local path; configuring no substituters (mkForce over
      # any profile or qemu-vm default) stops nix from querying an unreachable
      # cache for it.
      nix.settings.substituters = lib.mkForce [ ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.canonicalDeactivateFn}

    import json
    import uuid

    def read_status_json_local(config_path):
        return json.loads(machine.succeed(f"nails --config {config_path} status --json"))["data"]

    def assert_status_state_local(expected, config_path):
        payload = read_status_json_local(config_path)
        actual = str(payload["state"]["kind"])
        assert actual.startswith(expected.lower()), f"Expected {expected!r}, got: {payload}"

    def assert_overlay_mounted_local(path):
        machine.succeed(f"mountpoint -q {path}")
        assert machine.succeed(f"findmnt -n -o FSTYPE {path}").strip() == "overlay"

    def assert_no_overlays_local(paths):
        for path in paths:
            machine.fail(f"/bin/sh -lc 'mountpoint -q {path} && [ \"$(findmnt -n -o FSTYPE {path})\" = overlay ]'")

    # Distinctive string embedded in the hidden flake source. `nix flake
    # metadata`/`getFlake` copies the flake directory into the Nix store as a
    # `-source` path and seeds root's fetcher cache; if that ran before `/nix`
    # and `/root` were overlaid, the canary would land on the decoy's persistent
    # store and cache and survive deactivation. T-067 defers that validation to
    # the overlaid phase, so the canary must never reach the lower layer.
    #
    # Generated per run so the literal never appears in this test script itself:
    # the guest Nix store includes the host store, which holds the driver's own
    # test-script, so a fixed literal would make the forensic grep match the test
    # instead of a real leak. A fresh value also cannot match a leftover from an
    # earlier run.
    HIDDEN_FLAKE_CANARY = "NAILS_HIDDEN_FLAKE_" + uuid.uuid4().hex

    # Marker to scope the store scan to paths created after it. Touched before the
    # hidden flake exists, so the huge, older host store (including this test
    # script) is never scanned: the grep is both correct and fast (a full
    # grep -r over the whole Nix store otherwise eats most of the test budget).
    STORE_SCAN_MARKER = "/tmp/nails-store-scan-marker"

    def find_canary_in_decoy(store_dir, canary):
        # Returns the matching locations on the lower (decoy) layer. Greps only the
        # store paths created since STORE_SCAN_MARKER (any leaked `-source` copy,
        # which also covers the DB-registered path content) plus root's fetcher
        # cache.
        hits = machine.succeed(
            "/bin/sh -lc '"
            f"find {store_dir} -maxdepth 1 -newer {STORE_SCAN_MARKER} -print0 2>/dev/null "
            f"| xargs -0 -r grep -rl {canary} 2>/dev/null; "
            f"grep -rl {canary} /root/.cache/nix 2>/dev/null; "
            "true'"
        ).strip()
        return [line for line in hits.splitlines() if line]

    def assert_hidden_flake_absent_from_decoy(store_dir, context):
        hits = find_canary_in_decoy(store_dir, HIDDEN_FLAKE_CANARY)
        assert not hits, (
            f"hidden flake leaked onto the decoy {context}: {hits!r}"
        )

    def install_toplevel_fixture(marker_path):
        # The flake's `system.build.toplevel` is this committed directory, copied
        # into the store verbatim by `builtins.path`. nails builds it (an offline
        # source realise, no nixpkgs) and runs its `bin/switch-to-configuration
        # test`, exactly as it would a real toplevel — so the stub script stands in
        # for a full generation's activation and records that it ran. The
        # executable bit is the only permission the Nix store preserves, so the
        # copied script stays runnable.
        machine.succeed(
            f"""mkdir -p /mnt/data/nixos/toplevel/bin
    cat > /mnt/data/nixos/toplevel/bin/switch-to-configuration <<'EOF'
    #!/bin/sh
    mkdir -p "$(dirname {marker_path})"
    printf '%s\\n' 'flake-override-active' > {marker_path}
    exit 0
    EOF
    chmod 755 /mnt/data/nixos/toplevel/bin/switch-to-configuration"""
        )

    machine.start()
    machine.wait_for_unit("multi-user.target")

    # Resolve the store directory at runtime so the test carries no hard-coded
    # store path; the forensic greps run against this.
    nix_store = machine.succeed("nix eval --raw --expr builtins.storeDir").strip()

    headless_config = "/tmp/nails-headless.toml"
    flake_ref = "/mnt/data/nixos#nails-e2e"
    write_headless_config(headless_config)

    # Scope the later store scans to paths created from here on, before the hidden
    # flake (carrying the canary) exists anywhere.
    machine.succeed(f"touch {STORE_SCAN_MARKER}")

    with subtest("prepare hidden flake override"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mkdir -p /mnt/data/nixos")
        # Write the per-run canary as the first comment line (Nix ignores it), then
        # the flake body, so the canary lives in the flake source without the fixed
        # literal ever appearing in this test script.
        machine.succeed(
            f"printf '# %s forensic canary; see test script.\\n' {HIDDEN_FLAKE_CANARY} "
            "> /mnt/data/nixos/flake.nix"
        )
        machine.succeed("""cat >> /mnt/data/nixos/flake.nix <<'EOF'
    {
      description = "NAILS flake override E2E";
      # No nixpkgs input: a `path:` nixpkgs input would copy the entire nixpkgs
      # tree into the decoy store during the deferred `nix flake metadata`/eval —
      # several minutes of I/O on the space-limited test disk — without exercising
      # anything this test asserts. The real build+switch of a nixpkgs-backed
      # toplevel lives in test 27 (activate-full-rebuild); this test covers the
      # flake *dispatch* and the canary-leak invariant, which a minimal, input-less
      # flake drives on its own.
      #
      # nails builds the hidden toplevel explicitly (`nix build
      # ...system.build.toplevel`) and then runs that toplevel's own
      # `bin/switch-to-configuration test`. So the toplevel must be a real store
      # *directory* with a runnable switch script, not a bare file. Produce it with
      # `builtins.path`, a plain source copy of the committed ./toplevel directory:
      # it realises offline with no build and no fetch, and the only bit the Nix
      # store keeps — the executable bit — is enough to make the script runnable.
      outputs = { self }: {
        nixosConfigurations.nails-e2e.config.system.build.toplevel =
          builtins.path {
            path = ./toplevel;
            name = "nixos-system-nails-e2e";
          };
      };
    }
    EOF""")
        # A trivial lock for the input-less flake, on the hidden volume (never the
        # decoy store). It lets nails' deferred, overlaid `nix flake metadata`
        # resolve with --no-update-lock-file; running `nix flake lock` on the decoy
        # here would itself copy the canary-bearing source into the decoy store.
        machine.succeed("""cat > /mnt/data/nixos/flake.lock <<'EOF'
    {"nodes":{"root":{}},"root":"root","version":7}
    EOF""")
        install_toplevel_fixture("/etc/nails-flake-marker")

    with subtest("null control: the hidden flake has not touched the decoy store yet"):
        # Nothing has been activated, so no nix invocation has copied the hidden
        # flake onto the decoy store or cache.
        assert_hidden_flake_absent_from_decoy(nix_store, "before any activation")

    with subtest("positive control: the leak detector fires on a planted copy"):
        # The decoy store is an overlay mount that refuses remount,rw, so it cannot
        # be written to directly. Plant the canary in root's Nix fetcher cache
        # instead — the other decoy location the detector scans (see
        # find_canary_in_decoy) and a real leak vector for a hidden flake's inputs.
        planted_dir = "/root/.cache/nix"
        planted = f"{planted_dir}/nails-leak-canary-test.txt"
        machine.succeed(f"mkdir -p {planted_dir}")
        machine.succeed(f"printf '%s\\n' {HIDDEN_FLAKE_CANARY} > {planted}")
        assert find_canary_in_decoy(nix_store, HIDDEN_FLAKE_CANARY), \
            "detector must catch a deliberate hidden-flake copy in the decoy fetcher cache"
        machine.succeed(f"rm -f {planted}")
        assert_hidden_flake_absent_from_decoy(nix_store, "after removing the planted copy")

    with subtest("explicit flake override builds the flake toplevel and switches to it"):
        # nails resolves the flake toplevel installable, builds it explicitly with
        # `nix build` and activates it with the toplevel's own
        # `switch-to-configuration test` — no nixos-rebuild and no legacy
        # `-I nixos-config` path. Capture and always print the output: the build and
        # switch run inside the activation, so this is the only view of them when an
        # assertion below fails.
        rc, out = machine.execute(
            "set +e; "
            f"nails --config {headless_config} activate --session keep -y "
            f"--nixos-flake {flake_ref} 2>&1"
        )
        print(f"nails activate --nixos-flake exited rc={rc}; output follows:")
        print(out)
        assert rc == 0, f"flake-override activation failed (rc={rc})"
        assert "nixosConfigurations.nails-e2e" in out, (
            f"activation must build the flake-selected toplevel installable: {out!r}"
        )
        assert "nixos-config=/etc/nixos/configuration.nix" not in out, (
            f"the legacy nixos-config path must not be used with --nixos-flake: {out!r}"
        )

    with subtest("flake-selected system becomes active"):
        assert_status_state_local("Active", headless_config)
        assert_overlay_mounted_local("/etc")
        machine.succeed("grep -Fx 'flake-override-active' /etc/nails-flake-marker")
        machine.succeed("test -L /etc/nixos/nails/configuration.nix")

    with subtest("deactivate removes flake-selected runtime state"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-flake-override")
        assert_status_state_local("Inactive", headless_config)
        assert_no_overlays_local(["/etc", "/home", "/root", "/srv", "/tmp"])
        machine.fail("test -e /etc/nails-flake-marker")
        machine.fail("test -e /etc/nixos/nails/configuration.nix")

    with subtest("activation left no hidden flake copy on the decoy store or cache"):
        # The deferred flake validation ran `nix flake metadata`/eval only after
        # `/nix` and `/root` were overlaid, so any `-source` copy and fetcher
        # cache landed in the overlay upper and vanished with it on deactivation.
        # The lower layer, now visible again, must not reference the canary.
        assert_hidden_flake_absent_from_decoy(nix_store, "after an activate/deactivate cycle")
  '';
}
