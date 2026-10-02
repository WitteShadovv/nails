# Test 46: Init Idempotency

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
in
{
  name = "init-idempotency";
  meta.tags = [
    "init"
    "smoke"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("prepare bare hidden volume"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("bash -lc 'shopt -s dotglob nullglob && rm -rf /mnt/data/*'")
        machine.succeed("mkdir -p /tmp/init-idempotency-etc-nixos")
        machine.succeed(
            """cat > /tmp/init-idempotency-etc-nixos/hardware-configuration.nix <<'EOF'
    { config, lib, pkgs, modulesPath, ... }:
    {
      imports = [ (modulesPath + \"/installer/scan/not-detected.nix\") ];
    }
    EOF"""
        )
        machine.succeed("mount --bind /tmp/init-idempotency-etc-nixos /etc/nixos")

    with subtest("first init establishes baseline"):
        machine.succeed("nails init /mnt/data")
        machine.succeed("printf '\n# SENTINEL_KEEP\n' >> /mnt/data/config/nails.toml")
        before_hash = machine.succeed("sha256sum /mnt/data/config/nails.toml | cut -d\" \" -f1").strip()

    with subtest("second init is safe and non-destructive"):
        machine.succeed("nails init /mnt/data")
        after_hash = machine.succeed("sha256sum /mnt/data/config/nails.toml | cut -d\" \" -f1").strip()
        assert after_hash == before_hash, f"Config hash changed across repeated init: {before_hash} -> {after_hash}"

    with subtest("existing generated artifacts remain valid and non-duplicated"):
        config_text = machine.succeed("cat /mnt/data/config/nails.toml")
        assert "# SENTINEL_KEEP" in config_text, config_text
        machine.succeed("nails config validate /mnt/data/config/nails.toml")

        hardware_text = machine.succeed("cat /mnt/data/etc/nixos/hardware-configuration.nix")
        import_count = hardware_text.count("./nails/configuration.nix")
        assert import_count == 1, f"Expected one hidden import, saw {import_count}: {hardware_text}"

        machine.succeed("test -L /mnt/data/etc/nixos/nails/configuration.nix")
        target = machine.succeed("readlink /mnt/data/etc/nixos/nails/configuration.nix").strip()
        assert target == "/mnt/data/config/nixos/configuration.nix", target

        for path in [
            "/mnt/data/config",
            "/mnt/data/config/nixos",
            "/mnt/data/etc/nixos",
            "/mnt/data/etc/nixos/nails",
            "/mnt/data/.work",
        ]:
            perms = machine.succeed(f"stat -c %a {path}").strip()
            assert perms == "700", f"Expected 0700 on {path}, got {perms}"
  '';
}
