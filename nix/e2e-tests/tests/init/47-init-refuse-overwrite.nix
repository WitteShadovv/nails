# Test 47: Init Refuse Overwrite

{ self, ... }:
let hiddenVolume = import ./../../lib/hidden-volume.nix;
in {
  name = "init-refuse-overwrite";
  meta.tags = [ "init" "smoke" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("prepare bare hidden volume with obstructing file"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("bash -lc 'shopt -s dotglob nullglob && rm -rf /mnt/hidden-volume/*'")
        machine.succeed("mkdir -p /etc/nixos")
        machine.succeed(
            """cat > /etc/nixos/hardware-configuration.nix <<'EOF'
    { config, lib, pkgs, modulesPath, ... }:
    {
      imports = [ (modulesPath + \"/installer/scan/not-detected.nix\") ];
    }
    EOF"""
        )
        machine.succeed("printf 'do-not-overwrite\n' > /mnt/hidden-volume/config")
        machine.succeed("test -f /mnt/hidden-volume/config")

    with subtest("init fails rather than replacing conflicting content"):
        machine.succeed(
            "bash -lc 'set +e; nails init /mnt/hidden-volume > /tmp/init-overwrite.stdout 2>/tmp/init-overwrite.stderr; printf \"%s\" \"$?\" > /tmp/init-overwrite.rc'"
        )
        rc = int(machine.succeed("cat /tmp/init-overwrite.rc").strip())
        stdout = machine.succeed("cat /tmp/init-overwrite.stdout")
        stderr = machine.succeed("cat /tmp/init-overwrite.stderr")
        combined = stdout + stderr

        assert rc != 0, f"init unexpectedly succeeded: stdout={stdout!r} stderr={stderr!r}"
        assert combined.strip(), "init failed without any diagnostic output"

    with subtest("original conflicting file remains intact"):
        machine.succeed("test -f /mnt/hidden-volume/config")
        contents = machine.succeed("cat /mnt/hidden-volume/config")
        assert contents == "do-not-overwrite\n", contents
        machine.fail("test -e /mnt/hidden-volume/config/nails.yaml")
  '';
}
