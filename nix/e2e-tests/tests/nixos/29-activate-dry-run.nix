# Test 29: `activate --dry-run` and `check` are read-only
#
# With a hidden flake named but the hidden NixOS layout never staged, `nails
# check --nixos-flake` reports its sections (pre-flight checks, the decoy
# filesystems of the hidden root, the session, the NixOS profile) and refuses
# with exit 4. `activate --dry-run` with the same arguments is a thin alias:
# identical output and exit code. Neither builds anything (no `nix build` or
# `nix-build` runs), prepares a next root at /run/nextroot, writes a state
# file or the hidden layout, or leaves the plain decoy root.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  nixpkgsPath = pkgs.path;
in
{
  name = "activate-dry-run";
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
    ${testHelpers.readStatusJsonFn}

    from nails_e2e import run_command_capture, session

    BUILD_LOG = "/run/nails-build-calls.log"


    def install_build_shims():
        """Put logging `nix` and `nix-build` shims first on PATH. They record
        every call and then run the real tool, so a read-only `nix eval` still
        works while any build shows up in the log."""
        machine.succeed(f"rm -f {BUILD_LOG} && mkdir -p /run/nails-shims")
        for tool in ("nix", "nix-build"):
            real = machine.succeed(f"bash -lc 'command -v {tool}'").strip()
            machine.succeed(
                f"cat > /run/nails-shims/{tool} <<'EOF'\n"
                "#!/bin/sh\n"
                f"printf '{tool} %s\\n' \"$*\" >> {BUILD_LOG}\n"
                f"exec {real} \"$@\"\n"
                "EOF\n"
                f"chmod 755 /run/nails-shims/{tool}"
            )
        return "PATH=/run/nails-shims:$PATH"


    def assert_no_build():
        rc, calls = machine.execute(f"cat {BUILD_LOG} 2>/dev/null")
        calls = calls if rc == 0 else ""
        builds = [
            line
            for line in calls.splitlines()
            if line.startswith("nix-build") or " build " in f" {line} "
        ]
        assert not builds, f"a read-only command started a build: {builds}"


    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/run/nails-headless.toml"
    flake_ref = "/mnt/data/nixos#dry-run-e2e"
    write_headless_config(headless_config)

    with subtest("prepare hidden flake and build shims"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mkdir -p /mnt/data/nixos")
        machine.succeed("""cat > /mnt/data/nixos/flake.nix <<'EOF'
    {
      description = "NAILS dry-run flake E2E";
      inputs.nixpkgs.url = "path:${nixpkgsPath}";
      outputs = { self, nixpkgs }: {
        nixosConfigurations.dry-run-e2e = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [ /etc/nixos/configuration.nix ];
        };
      };
    }
    EOF""")
        shim_env = install_build_shims()
        machine.fail("test -e /mnt/data/state.json")

    with subtest("check reports readiness without mutating anything"):
        check = run_command_capture(
            machine,
            "nails-check",
            f"{shim_env} nails --config {headless_config} check --nixos-flake {flake_ref}",
        )
        out = check["stdout"]
        for section in (
            "NAILS Readiness Check",
            "Pre-flight checks:",
            "Decoy filesystems in the hidden root:",
            "Session:",
            "NixOS profile:",
        ):
            assert section in out, f"missing {section!r} in check output: {out!r}"
        assert f"NixOS flake: {flake_ref}" in out, out
        # The hidden layout was never staged, so the read-only check refuses
        # (exit 4) with the nixos-config check instead of creating it.
        assert check["rc"] == 4, (
            f"expected check to refuse (rc=4), got rc={check['rc']}, stderr={check['stderr']!r}"
        )
        assert "Not ready" in out, out
        nixos_rows = [line for line in out.splitlines() if "nixos-config:" in line]
        assert nixos_rows and "/mnt/data/root/upper/etc/nixos" in nixos_rows[0], (
            f"expected the nixos-config check to name the missing layout: {out!r}"
        )
        assert_no_build()

    with subtest("activate --dry-run is a thin alias for check"):
        dry = run_command_capture(
            machine,
            "activate-dry-run",
            f"{shim_env} nails --config {headless_config} activate --dry-run --nixos-flake {flake_ref}",
        )
        assert dry["rc"] == check["rc"], f"dry-run rc={dry['rc']} must match check rc={check['rc']}"
        assert dry["stdout"] == check["stdout"], "dry-run and check must produce identical output"
        assert_no_build()

    with subtest("state, hidden volume and root remain untouched"):
        status = read_status_json(config_path=headless_config)
        assert status["posture"] == "decoy", status
        session.assert_decoy_root(machine)
        machine.fail("test -e /run/nextroot/etc")
        machine.fail("test -e /mnt/data/state.json")
        machine.fail("test -e /mnt/data/root/upper")
        machine.fail("test -e /mnt/data/config/nixos/configuration.nix")
        machine.fail("test -e /etc/nixos/nails/configuration.nix")
        assert machine.succeed("systemctl show -p SoftRebootsCount --value").strip() == "0"
  '';
}
