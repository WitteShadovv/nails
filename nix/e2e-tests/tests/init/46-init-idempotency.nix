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
        machine.succeed("bash -lc 'shopt -s dotglob nullglob && rm -rf /mnt/hidden-volume/*'")
    with subtest("first init establishes baseline"):
        machine.succeed("nails init /mnt/hidden-volume")
        machine.succeed("printf '\n# SENTINEL_KEEP\n' >> /mnt/hidden-volume/config/nails.yaml")
        before_hash = machine.succeed("sha256sum /mnt/hidden-volume/config/nails.yaml | cut -d\" \" -f1").strip()

    with subtest("second init is safe and non-destructive"):
        machine.succeed("nails init /mnt/hidden-volume")
        after_hash = machine.succeed("sha256sum /mnt/hidden-volume/config/nails.yaml | cut -d\" \" -f1").strip()
        assert after_hash == before_hash, f"Config hash changed across repeated init: {before_hash} -> {after_hash}"

    with subtest("existing generated artifacts remain valid and non-duplicated"):
        config_text = machine.succeed("cat /mnt/hidden-volume/config/nails.yaml")
        assert "# SENTINEL_KEEP" in config_text, config_text

        hardware_text = machine.succeed("cat /mnt/hidden-volume/etc/nixos/hardware-configuration.nix")
        import_count = hardware_text.count("./nails/configuration.nix")
        assert import_count == 1, f"Expected one hidden import, saw {import_count}: {hardware_text}"

        machine.succeed("test -L /mnt/hidden-volume/etc/nixos/nails/configuration.nix")
        target = machine.succeed("readlink /mnt/hidden-volume/etc/nixos/nails/configuration.nix").strip()
        assert target == "/mnt/hidden-volume/config/nixos/configuration.nix", target

        for path in [
            "/mnt/hidden-volume/config",
            "/mnt/hidden-volume/config/nixos",
            "/mnt/hidden-volume/etc/nixos",
            "/mnt/hidden-volume/etc/nixos/nails",
            "/mnt/hidden-volume/.work",
        ]:
            perms = machine.succeed(f"stat -c %a {path}").strip()
            assert perms == "700", f"Expected 0700 on {path}, got {perms}"
  '';
}
