# Scenario `init-refuse-overwrite` of the `init-config` batch:
#   tests/init/45-init-config.nix
# Formerly the stand-alone test
#   tests/init/47-init-refuse-overwrite.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix);
#
# Test 47: Init Refuse Overwrite
# `nails init` refuses before its first write: a file where the layout needs
# the config directory stays untouched, and a plain directory on the decoy
# root (not a mounted volume) is refused and left empty.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
in
{
  name = "init-refuse-overwrite";
  tags = [
    "init"
    "smoke"
  ];

  helpers = [
  ];

  script = ''
    def scenario_init_refuse_overwrite() -> None:
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
                "bash -lc 'set +e; nails init /mnt/data > /run/init-overwrite.stdout 2>/run/init-overwrite.stderr; printf \"%s\" \"$?\" > /run/init-overwrite.rc'"
            )
            rc = int(machine.succeed("cat /run/init-overwrite.rc").strip())
            stdout = machine.succeed("cat /run/init-overwrite.stdout")
            stderr = machine.succeed("cat /run/init-overwrite.stderr")
            combined = stdout + stderr

            assert rc != 0, f"init unexpectedly succeeded: stdout={stdout!r} stderr={stderr!r}"
            assert combined.strip(), "init failed without any diagnostic output"

        with subtest("original conflicting file remains intact"):
            machine.succeed("test -f /mnt/data/config")
            contents = machine.succeed("cat /mnt/data/config")
            assert contents == "do-not-overwrite\n", contents
            machine.fail("test -e /mnt/data/config/nails.toml")

        with subtest("init refuses an unmounted target and leaves it untouched"):
            # A plain directory on the root filesystem: nothing is mounted there.
            # init must refuse before writing or probing anything, so even the
            # directory's mtime and ctime stay as they were.
            machine.succeed("rm -rf /root/nails-unmounted && mkdir -p /root/nails-unmounted")
            machine.succeed("touch -m -d '2001-02-03 04:05:06' /root/nails-unmounted")
            before = machine.succeed("stat -c '%Y %Z' /root/nails-unmounted").strip()
            machine.succeed(
                "bash -lc 'set +e; nails init /root/nails-unmounted > /run/init-unmounted.stdout 2>/run/init-unmounted.stderr; printf \"%s\" \"$?\" > /run/init-unmounted.rc'"
            )
            rc = int(machine.succeed("cat /run/init-unmounted.rc").strip())
            combined = machine.succeed("cat /run/init-unmounted.stdout /run/init-unmounted.stderr")
            assert rc == 4, f"init did not refuse the unmounted directory: {rc} {combined!r}"
            assert (
                "/root/nails-unmounted is not a volume of its own: it is a folder on the "
                "filesystem mounted at /. Nothing was written."
            ) in combined, combined
            machine.succeed('test -z "$(ls -A /root/nails-unmounted)"')
            after = machine.succeed("stat -c '%Y %Z' /root/nails-unmounted").strip()
            assert after == before, (before, after)
  '';
}
