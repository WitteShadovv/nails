# Test 27: Activate — real hidden NixOS rebuild, then fast-path re-activation
#
# Exercises the real build + switch path with no `nixos-rebuild`/`nix` stub on
# PATH: `nails activate` builds the hidden system toplevel explicitly
# (`nix build …#…system.build.toplevel`), caches its `nixos-system-*` store path
# in the state file, and switches to it before the session restart. After a
# deactivate-with-reboot, a second activation with the unchanged config must reuse
# the cached toplevel on the fast path (no rebuild) and re-apply the hidden marker.
#
# NOTE (evaluate under nix): this test performs a genuine offline toplevel build
# inside the VM, so it depends on the hidden flake's closure being available in the
# guest store (it imports the decoy's own configuration, so its closure is already
# present, plus a trivial marker derivation). The deeper offline-substituter and
# fixture wiring is owned by T-091; this test must be run with
# `nix build .#checks.x86_64-linux.activate-full-rebuild` and may need T-091's
# fixture tuning to build fully offline on constrained runners.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  nixpkgsPath = pkgs.path;
in
{
  name = "activate-full-rebuild";
  # A real offline toplevel build plus two activations and two deactivate-reboots
  # needs more than the default budget.
  globalTimeout = 1800;
  meta.tags = [
    "nixos"
    "slow"
  ];

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
      # Seed nixpkgs into the guest store so the hidden toplevel builds offline.
      virtualisation.additionalPaths = [ pkgs.path ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalDeactivateFn}

    import json
    import re
    import shlex
    import uuid

    HIDDEN_MARKER = "/etc/nails-hidden-marker"
    ONESHOT_MARKER = "/run/nails-hidden-oneshot"

    def run_capture(label, command):
        stem = f"/tmp/{label}-{uuid.uuid4().hex}"
        machine.succeed(
            "bash -lc "
            + shlex.quote(
                "set +e; " + command + f" > {stem}.out 2>&1; printf '%s' \"$?\" > {stem}.rc"
            )
        )
        rc = int(machine.succeed(f"cat {stem}.rc"))
        out = machine.succeed(f"cat {stem}.out")
        return rc, out

    def read_status(config_path):
        return json.loads(machine.succeed(f"nails --config {config_path} status --json"))["data"]

    def assert_state(expected, config_path):
        payload = read_status(config_path)
        actual = str(payload["state"]["kind"])
        assert actual.startswith(expected.lower()), f"Expected {expected!r}, got: {payload}"
        return payload

    def assert_overlay_mounted(path):
        machine.succeed(f"mountpoint -q {path}")
        assert machine.succeed(f"findmnt -n -o FSTYPE {path}").strip() == "overlay"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    # Resolve the store directory at runtime so the test carries no hard-coded
    # store path.
    nix_store = machine.succeed("nix eval --raw --expr builtins.storeDir").strip()
    nixos_system_re = re.compile("^" + re.escape(nix_store) + r"/[a-z0-9]+-nixos-system-")

    headless_config = "/tmp/nails-headless.toml"
    flake_ref = "/mnt/data/nixos#nails-e2e"
    write_headless_config(headless_config)

    with subtest("prepare a real hidden flake with a marker and a oneshot service"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mkdir -p /mnt/data/nixos")
        machine.succeed("""cat > /mnt/data/nixos/flake.nix <<'EOF'
    {
      description = "NAILS real-rebuild E2E";
      inputs.nixpkgs.url = "path:${nixpkgsPath}";
      outputs = { self, nixpkgs }: {
        nixosConfigurations.nails-e2e = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            /etc/nixos/configuration.nix
            ({ ... }: {
              documentation.nixos.enable = false;
              environment.etc."nails-hidden-marker".text = "hidden-rebuild-active";
              systemd.services.nails-hidden-canary = {
                wantedBy = [ "multi-user.target" ];
                serviceConfig = {
                  Type = "oneshot";
                  RemainAfterExit = true;
                  ExecStart = "/bin/sh -c 'echo hidden-oneshot-ran > /run/nails-hidden-oneshot'";
                };
              };
            })
          ];
        };
      };
    }
    EOF""")
        machine.succeed("nix flake lock --offline /mnt/data/nixos")
        assert_state("Inactive", headless_config)

    first_toplevel = None
    with subtest("first activation builds the hidden toplevel and switches to it"):
        rc, out = run_capture(
            "activate1",
            f"nails --config {headless_config} activate --session keep -y --flake {flake_ref}",
        )
        assert rc == 0, f"first activation failed: {out}"

        payload = assert_state("Active", headless_config)
        assert_overlay_mounted("/etc")
        assert_overlay_mounted("/home")

        first_toplevel = payload.get("hidden_toplevel")
        assert first_toplevel and nixos_system_re.match(first_toplevel), (
            f"state must record a nixos-system store toplevel, got {first_toplevel!r}"
        )

        machine.succeed(f"grep -Fx 'hidden-rebuild-active' {HIDDEN_MARKER}")
        machine.succeed(f"test -e {ONESHOT_MARKER}")

    with subtest("deactivate-with-reboot removes the hidden runtime state"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-full-rebuild")
        # The hidden volume is closed by the reboot; status reads a missing state
        # file as Inactive.
        assert_state("Inactive", headless_config)
        machine.fail(f"test -e {HIDDEN_MARKER}")

    with subtest("re-activation reuses the cached toplevel on the fast path"):
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        rc, out = run_capture(
            "activate2",
            f"nails --config {headless_config} activate --session keep -y --flake {flake_ref}",
        )
        assert rc == 0, f"re-activation failed: {out}"

        payload = assert_state("Active", headless_config)
        second_toplevel = payload.get("hidden_toplevel")
        assert second_toplevel == first_toplevel, (
            f"fast path must reuse the cached toplevel {first_toplevel!r}, got {second_toplevel!r}"
        )
        # The hidden marker and oneshot are applied again by the cached toplevel.
        machine.succeed(f"grep -Fx 'hidden-rebuild-active' {HIDDEN_MARKER}")
        # The fast path switches without rebuilding: the nails log records it.
        log = machine.succeed(
            "bash -lc 'cat /mnt/data/logs/*.log 2>/dev/null || true'"
        ).lower()
        assert "fast path" in log or "fast path" in out.lower(), (
            "the second activation should take the fast path (no rebuild); "
            f"activate output: {out!r}"
        )

    with subtest("final deactivate leaves no hidden overlays"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-full-rebuild-2")
        assert_state("Inactive", headless_config)
        machine.fail(f"test -e {HIDDEN_MARKER}")
  '';
}
