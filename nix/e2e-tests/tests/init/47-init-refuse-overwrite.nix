# Test 47: Init Refuse Overwrite

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
in
{
  name = "init-refuse-overwrite";
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

    with subtest("prepare bare hidden volume with obstructing file"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("bash -lc 'shopt -s dotglob nullglob && rm -rf /mnt/data/*'")
        machine.succeed("mkdir -p /tmp/init-refuse-overwrite-etc-nixos")
        machine.succeed(
            """cat > /tmp/init-refuse-overwrite-etc-nixos/hardware-configuration.nix <<'EOF'
    { config, lib, pkgs, modulesPath, ... }:
    {
      imports = [ (modulesPath + \"/installer/scan/not-detected.nix\") ];
    }
    EOF"""
        )
        machine.succeed("mount --bind /tmp/init-refuse-overwrite-etc-nixos /etc/nixos")
        machine.succeed("printf 'do-not-overwrite\n' > /mnt/data/config")
        machine.succeed("test -f /mnt/data/config")

    with subtest("init fails rather than replacing conflicting content"):
        machine.succeed(
            "bash -lc 'set +e; nails init /mnt/data > /tmp/init-overwrite.stdout 2>/tmp/init-overwrite.stderr; printf \"%s\" \"$?\" > /tmp/init-overwrite.rc'"
        )
        rc = int(machine.succeed("cat /tmp/init-overwrite.rc").strip())
        stdout = machine.succeed("cat /tmp/init-overwrite.stdout")
        stderr = machine.succeed("cat /tmp/init-overwrite.stderr")
        combined = stdout + stderr

        assert rc != 0, f"init unexpectedly succeeded: stdout={stdout!r} stderr={stderr!r}"
        assert combined.strip(), "init failed without any diagnostic output"

    with subtest("original conflicting file remains intact"):
        machine.succeed("test -f /mnt/data/config")
        contents = machine.succeed("cat /mnt/data/config")
        assert contents == "do-not-overwrite\n", contents
        machine.fail("test -e /mnt/data/config/nails.toml")

    with subtest("init refuses an unmounted target and leaves it empty"):
        # A plain directory on the root filesystem shares /'s device, so nothing
        # is mounted there. init must refuse before writing anything.
        machine.succeed("rm -rf /root/nails-unmounted && mkdir -p /root/nails-unmounted")
        machine.succeed(
            "bash -lc 'set +e; nails init /root/nails-unmounted > /tmp/init-unmounted.stdout 2>/tmp/init-unmounted.stderr; printf \"%s\" \"$?\" > /tmp/init-unmounted.rc'"
        )
        rc = int(machine.succeed("cat /tmp/init-unmounted.rc").strip())
        combined = machine.succeed("cat /tmp/init-unmounted.stdout /tmp/init-unmounted.stderr")
        assert rc != 0, f"init unexpectedly accepted an unmounted directory: {combined!r}"
        assert "mount the hidden volume first" in combined, combined
        machine.succeed('test -z "$(ls -A /root/nails-unmounted)"')
  '';
}
