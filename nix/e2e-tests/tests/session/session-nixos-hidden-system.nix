# Entering a hidden NixOS toplevel without touching the bootloader (ADR 0008,
# section 3, variant B), through `nails activate --nixos-flake`.
#
# Replaces the live-overlay full-rebuild, flake-override, rebuild-failure and
# /var/lib/nixos drift tests. The hidden system is the VM's own `nails-hidden`
# specialisation (the running system plus fixtures/hidden-config/module.nix),
# prebuilt on the host, so the guest's `nix build --store /run/nextroot` only
# realises an existing path offline; the specialisation also keeps the test
# instrumentation, so the driver's backdoor starts in the hidden root.
#
#   1. Activation builds the hidden toplevel into the next root's store, runs
#      its activation chrooted, and the transition repoints /run/current-system
#      late: PID 1 starts the hidden systemd against the hidden /etc. The
#      hidden marker, its oneshot service and its canary user exist; the
#      kernel modules still come from /run/booted-system.
#   2. Deactivation repoints /run/current-system back to the decoy toplevel and
#      the decoy comes back without the marker, the canary user or any change
#      to its /var/lib/nixos and /etc/passwd.
#   3. A second activation re-enters the same toplevel.
#   4. A flake that does not evaluate refuses the entry and leaves nothing.
#   5. No boot entry or ESP file changed at any point (the VM has no
#      bootloader; the system profile is untouched too).
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  fixtureDir = ./../../fixtures/hidden-config;
in
{
  name = "session-nixos-hidden-system";
  meta.tags = [
    "nixos"
    "session"
    "slow"
  ];
  globalTimeout = 1800;

  nodes.machine =
    { lib, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.nails ];
      # The hidden system's closure is copied onto the hidden volume (T-137).
      virtualisation.emptyDiskImages = lib.mkForce [
        {
          size = 8192;
          driveConfig.deviceExtraOpts.serial = "data";
        }
      ];
      nix.settings = {
        experimental-features = [
          "nix-command"
          "flakes"
        ];
        substituters = lib.mkForce [ ];
      };
      specialisation.nails-hidden.configuration = {
        imports = [ ./../../fixtures/hidden-config/module.nix ];
      };
    };

  testScript = _: ''
    import shlex

    from nails_e2e import session

    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    FLAKE = "/mnt/data/nixos#nails-e2e"
    MARKER = "/etc/nails-hidden-marker"


    def nixos_state():
        return machine.succeed(
            "cd /var/lib/nixos && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum; "
            "sha256sum /etc/passwd /etc/group"
        )


    machine.start()
    machine.wait_for_unit("multi-user.target")
    decoy_system = machine.succeed("readlink -f /run/current-system").strip()
    booted_system = machine.succeed("readlink -f /run/booted-system").strip()
    hidden_system = machine.succeed(
        "readlink -f /run/current-system/specialisation/nails-hidden"
    ).strip()
    profile_before = machine.succeed("readlink -f /nix/var/nix/profiles/system || true").strip()

    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "rebuild_space_mb = 64\n"
        "EOF"
    )
    machine.succeed("mkdir -p /mnt/data/nixos && cp -rT ${fixtureDir} /mnt/data/nixos")
    machine.succeed("chmod -R u+w /mnt/data/nixos")
    machine.succeed(
        "sed -i " + shlex.quote(f"s|@toplevel@|{hidden_system}|") + " /mnt/data/nixos/flake.nix"
    )
    state_before = nixos_state()

    with subtest("activation enters the hidden toplevel in one soft-reboot"):
        canonical_activate(CONFIG, f"--nixos-flake {FLAKE}", "activate-1")
        current = machine.succeed("readlink -f /run/current-system").strip()
        assert current == hidden_system, f"current-system is {current}, not {hidden_system}"
        booted = machine.succeed("readlink -f /run/booted-system").strip()
        assert booted == booted_system, "the booted system (kernel modules) must stay the decoy's"
        machine.succeed(f"grep -Fx hidden-rebuild-active {MARKER}")
        machine.wait_for_unit("nails-hidden-canary.service")
        machine.succeed("test -e /run/nails-hidden-oneshot")
        machine.succeed("getent passwd hiddencanary")
        machine.succeed("modprobe dummy && rmmod dummy")
        # The hidden /etc lives in the upper.
        machine.succeed("test -e /mnt/data/root/upper/etc/nails-hidden-marker")
        out = machine.succeed(f"nails --config {CONFIG} status")
        assert hidden_system in out, out

    with subtest("deactivation returns to the decoy toplevel with its state untouched"):
        canonical_deactivate(CONFIG, "deactivate-1")
        current = machine.succeed("readlink -f /run/current-system").strip()
        assert current == decoy_system, f"current-system is {current} after the way back"
        machine.fail(f"test -e {MARKER}")
        machine.fail("getent passwd hiddencanary")
        machine.fail("test -e /run/nails-hidden-oneshot")
        assert nixos_state() == state_before, "the decoy's /var/lib/nixos or passwd changed"

    with subtest("a second activation re-enters the same toplevel"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        canonical_activate(CONFIG, f"--nixos-flake {FLAKE}", "activate-2")
        current = machine.succeed("readlink -f /run/current-system").strip()
        assert current == hidden_system, current
        canonical_deactivate(CONFIG, "deactivate-2")

    with subtest("a configuration that does not evaluate refuses the entry and leaves nothing"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        machine.succeed("cp /mnt/data/nixos/flake.nix /mnt/data/nixos/flake.nix.good")
        machine.succeed("echo 'this is not nix' > /mnt/data/nixos/flake.nix")
        rc, out = machine.execute(
            f"nails --config {CONFIG} activate -y --no-preflight --nixos-flake {FLAKE} 2>&1"
        )
        machine.log(out)
        assert rc != 0, "a broken hidden configuration must refuse the entry"
        session.assert_decoy_root(machine)
        machine.fail("test -e /run/overlay-runtime")
        machine.fail("test -e /run/systemd/system/systemd-soft-reboot.service.d")
        machine.succeed("mv /mnt/data/nixos/flake.nix.good /mnt/data/nixos/flake.nix")

    with subtest("no bootloader state or system profile changed"):
        profile_after = machine.succeed("readlink -f /nix/var/nix/profiles/system || true").strip()
        assert profile_after == profile_before, f"system profile moved: {profile_after}"
  '';
}
