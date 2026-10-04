# Test 28: Activate Flake Override

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  nixpkgsPath = pkgs.path;
in
{
  name = "activate-flake-override";
  meta.tags = [ "nixos" ];

  nodes.machine =
    { pkgs, ... }:
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
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.canonicalDeactivateFn}

    import json

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
    HIDDEN_FLAKE_CANARY = "NAILS_HIDDEN_FLAKE_CANARY_f067"

    def find_canary_in_decoy(store_dir, canary):
        # Returns the matching locations on the lower (decoy) layer. Greps the
        # Nix store (which holds any leaked `-source` copy and thus covers the
        # DB-registered path content) and root's fetcher cache.
        hits = machine.succeed(
            "/bin/sh -lc '"
            f"grep -rl {canary} {store_dir} 2>/dev/null; "
            f"grep -rl {canary} /root/.cache/nix 2>/dev/null; "
            "true'"
        ).strip()
        return [line for line in hits.splitlines() if line]

    def assert_hidden_flake_absent_from_decoy(store_dir, context):
        hits = find_canary_in_decoy(store_dir, HIDDEN_FLAKE_CANARY)
        assert not hits, (
            f"hidden flake leaked onto the decoy {context}: {hits!r}"
        )

    def install_nixos_rebuild_wrapper(log_path, marker_path):
        machine.succeed(
            f"""mkdir -p /tmp/nails-wrapper/bin
    rm -f {log_path}
    cat > /tmp/nails-wrapper/bin/nixos-rebuild <<'EOF'
    #!/bin/sh
    printf '%s\\n' "$*" >> {log_path}
    if [ "$1" = test ]; then
      mkdir -p "$(dirname {marker_path})"
      printf '%s\\n' 'flake-override-active' > {marker_path}
    fi
    exit 0
    EOF
    chmod 755 /tmp/nails-wrapper/bin/nixos-rebuild"""
        )
        return "PATH=/tmp/nails-wrapper/bin:$PATH"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    # Resolve the store directory at runtime so the test carries no hard-coded
    # store path; the forensic greps run against this.
    nix_store = machine.succeed("nix eval --raw --expr builtins.storeDir").strip()

    headless_config = "/tmp/nails-headless.toml"
    flake_ref = "/mnt/data/nixos#nails-e2e"
    write_headless_config(headless_config)

    with subtest("prepare hidden flake override"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mkdir -p /mnt/data/nixos")
        machine.succeed("""cat > /mnt/data/nixos/flake.nix <<'EOF'
    {
      # NAILS_HIDDEN_FLAKE_CANARY_f067 — forensic canary; see test script.
      description = "NAILS flake override E2E";
      inputs.nixpkgs.url = "path:${nixpkgsPath}";
      outputs = { self, nixpkgs }: {
        nixosConfigurations.nails-e2e = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            /etc/nixos/configuration.nix
            ({ ... }: {
              documentation.nixos.enable = false;
              environment.etc."nails-flake-marker".text = "flake-override-active";
            })
          ];
        };
      };
    }
    EOF""")
        machine.succeed("nix flake lock --offline /mnt/data/nixos")
        wrapper_env = install_nixos_rebuild_wrapper(
            "/tmp/nixos-rebuild-flake.log",
            "/etc/nails-flake-marker",
        )

    with subtest("null control: the hidden flake has not touched the decoy store yet"):
        # Nothing has been activated, so no nix invocation has copied the hidden
        # flake onto the decoy store or cache.
        assert_hidden_flake_absent_from_decoy(nix_store, "before any activation")

    with subtest("positive control: the leak detector fires on a planted copy"):
        planted = f"{nix_store}/nails-leak-canary-test.txt"
        machine.succeed(f"printf '%s\\n' {HIDDEN_FLAKE_CANARY} > {planted}")
        assert find_canary_in_decoy(nix_store, HIDDEN_FLAKE_CANARY), \
            "detector must catch a deliberate hidden-flake copy on the decoy store"
        machine.succeed(f"rm -f {planted}")
        assert_hidden_flake_absent_from_decoy(nix_store, "after removing the planted copy")

    with subtest("explicit flake override dispatches to nixos-rebuild --flake"):
        machine.succeed(
            f"{wrapper_env} nails --config {headless_config} activate --session keep -y --nixos-flake {flake_ref}"
        )
        rebuild_log = machine.succeed("cat /tmp/nixos-rebuild-flake.log")
        assert f"--flake {flake_ref}" in rebuild_log, \
            f"Expected explicit flake ref in nixos-rebuild invocation, got: {rebuild_log!r}"
        assert "-I nixos-config=/etc/nixos/configuration.nix" not in rebuild_log, \
            f"Did not expect legacy nixos-config path when using --nixos-flake, got: {rebuild_log!r}"

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
