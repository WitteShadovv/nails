# Test 32: Config Inject Hardware Imports

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "config-inject-hardware-imports";
  meta.tags = [ "nixos" ];

  nodes.machine =
    { pkgs, lib, ... }:
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
      # The decoy's hardware-configuration.nix has NO imports attribute, so the
      # test exercises wrapper injection over a bare file. NixOS rewrites this
      # 0644 file into /etc on every boot, and canonical_deactivate reboots, so it
      # must be the node config (not a one-shot runtime edit) or the reboot would
      # clobber what NAILS restored and the final restore check would see the base
      # fixture's "imports = [ ]" stub instead.
      environment.etc."nixos/hardware-configuration.nix".text = lib.mkForce ''
        { config, lib, pkgs, ... }:
        {
          boot.loader.grub.enable = false;
        }
      '';
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

    def install_nixos_rebuild_wrapper(log_path):
        machine.succeed(
            f"""mkdir -p /var/lib/nails-tests/nails-wrapper/bin
    rm -f {log_path}
    cat > /var/lib/nails-tests/nails-wrapper/bin/nixos-rebuild <<'EOF'
    #!/bin/sh
    printf '%s\\n' "$*" >> {log_path}
    exit 0
    EOF
    chmod 755 /var/lib/nails-tests/nails-wrapper/bin/nixos-rebuild"""
        )
        return "PATH=/var/lib/nails-tests/nails-wrapper/bin:$PATH"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/var/lib/nails-tests/nails-headless.toml"
    write_headless_config(headless_config)
    wrapper_env = install_nixos_rebuild_wrapper("/var/lib/nails-tests/nixos-rebuild-hardware-imports.log")

    # Sanity: the decoy (defined in the node config) really has no imports list.
    decoy = machine.succeed("cat /etc/nixos/hardware-configuration.nix")
    assert "imports" not in decoy, f"decoy fixture should have no imports attribute, got: {decoy!r}"

    with subtest("first activation generates a valid wrapper from a no-imports hardware file"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.fail("test -e /mnt/data/etc/nixos/hardware-configuration.nix")
        machine.succeed("""cat > /mnt/data/config/nixos/configuration.nix <<'EOF'
    { ... }: {
      documentation.nixos.enable = false;
    }
    EOF""")
        machine.succeed(f"{wrapper_env} nails --config {headless_config} activate --session keep -y")
        assert_status_state_local("Active", headless_config)
        assert_overlay_mounted_local("/etc")

        # The hidden hardware config is the fixed wrapper; the original is preserved
        # verbatim as the base file.
        hidden_wrapper = machine.succeed("cat /mnt/data/etc/nixos/hardware-configuration.nix")
        assert hidden_wrapper.count("./nails/configuration.nix") == 1, \
            f"wrapper should import the hidden module exactly once, got: {hidden_wrapper!r}"
        assert "./hardware-configuration.base.nix" in hidden_wrapper, \
            f"wrapper should import the preserved base, got: {hidden_wrapper!r}"
        hidden_base = machine.succeed("cat /mnt/data/etc/nixos/hardware-configuration.base.nix")
        assert "boot.loader.grub.enable = false;" in hidden_base, \
            f"base should preserve the original hardware config, got: {hidden_base!r}"
        assert "imports" not in hidden_base, \
            f"base should be the verbatim no-imports original, got: {hidden_base!r}"

        # The composed files are valid Nix (this is what the preflight parse gate
        # checks; `--parse` only lexes/parses, it does not evaluate or realise).
        machine.succeed("nix-instantiate --parse /mnt/data/etc/nixos/hardware-configuration.nix")
        machine.succeed("nix-instantiate --parse /mnt/data/etc/nixos/hardware-configuration.base.nix")

        # The overlayed /etc/nixos shows the same wrapper + base, and the staged
        # nails symlink resolves.
        live_wrapper = machine.succeed("cat /etc/nixos/hardware-configuration.nix")
        assert "./nails/configuration.nix" in live_wrapper, \
            f"overlayed hardware config should be the wrapper, got: {live_wrapper!r}"
        assert "./hardware-configuration.base.nix" in live_wrapper, \
            f"overlayed hardware config should import the base, got: {live_wrapper!r}"
        machine.succeed("test -e /etc/nixos/hardware-configuration.base.nix")
        machine.succeed("test -L /mnt/data/etc/nixos/nails/configuration.nix")
        machine.succeed("test -L /etc/nixos/nails/configuration.nix")

        # The hidden config is applied: the rebuild ran against it.
        rebuild_log = machine.succeed("cat /var/lib/nails-tests/nixos-rebuild-hardware-imports.log")
        assert "test" in rebuild_log, f"expected a nixos-rebuild invocation, got: {rebuild_log!r}"

    with subtest("second activation is idempotent for the wrapper and base"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-hardware-imports-phase-1")
        assert_status_state_local("Inactive", headless_config)
        assert_no_overlays_local(["/etc", "/home", "/root", "/srv", "/tmp"])
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        before = machine.succeed("cat /mnt/data/etc/nixos/hardware-configuration.nix")
        before_base = machine.succeed("cat /mnt/data/etc/nixos/hardware-configuration.base.nix")
        machine.succeed(f"{wrapper_env} nails --config {headless_config} activate --session keep -y")
        assert_status_state_local("Active", headless_config)
        after = machine.succeed("cat /mnt/data/etc/nixos/hardware-configuration.nix")
        after_base = machine.succeed("cat /mnt/data/etc/nixos/hardware-configuration.base.nix")
        assert after == before, "hidden wrapper changed on second activation (not idempotent)"
        assert after_base == before_base, "preserved base changed on second activation (not idempotent)"

    with subtest("final deactivate restores decoy state cleanly"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-hardware-imports-phase-2")
        assert_status_state_local("Inactive", headless_config)
        assert_no_overlays_local(["/etc", "/home", "/root", "/srv", "/tmp"])
        machine.fail("test -e /etc/nixos/nails/configuration.nix")
        # The wrapper and base lived only in the overlay upper, so the decoy
        # /etc/nixos reverts to the original no-imports file.
        machine.fail("test -e /etc/nixos/hardware-configuration.base.nix")
        restored = machine.succeed("cat /etc/nixos/hardware-configuration.nix")
        assert "boot.loader.grub.enable = false;" in restored, \
            f"decoy hardware config should be restored, got: {restored!r}"
        assert "./nails/configuration.nix" not in restored, \
            f"decoy hardware config must be clean after deactivate, got: {restored!r}"
  '';
}
