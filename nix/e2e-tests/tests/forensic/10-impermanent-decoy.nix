# Test 10 (forensic): the impermanent decoy profile holds its invariants and a
# hidden session leaves nothing on the persisted decoy state.
#
# This is the forensic consumer of lib/impermanent-decoy.nix. It proves two
# things the profile is meant to guarantee, so the heavier drift and canary work
# (T-092) can rely on them:
#
#   1. The decoy root is a volatile tmpfs and only /nix (the on-disk store image)
#      and /var/lib/nixos are persisted — everything else a hidden session touches
#      on the decoy root is gone on power-off.
#   2. An auto-mode hidden session writes to its overlay uppers on the hidden
#      volume, not to the persisted /persist trees, so a disk image of the decoy
#      shows no hidden residue there after an emergency teardown.
#
# NOTE (evaluate under nix): the tmpfs-root override, the /persist disk and its
# binds, and offline closure completeness can only be confirmed by
# `nix build .#checks.x86_64-linux.impermanent-decoy` on a Nix host.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "impermanent-decoy";
  meta.tags = [
    "forensic"
    "slow"
  ];

  # A store-image boot plus an activate/teardown cycle needs more than the
  # default budget.
  globalTimeout = 1800;

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/impermanent-decoy.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${testHelpers.writeAutoConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("the decoy root is a volatile tmpfs with the persisted trees bound"):
        assert machine.succeed("findmnt -n -o FSTYPE /").strip() == "tmpfs", (
            "the impermanent decoy root must be a tmpfs"
        )
        machine.succeed("mountpoint -q /persist")
        machine.succeed("mountpoint -q /var/lib/nixos")

    config_path = "/tmp/nails-impermanent.toml"
    write_auto_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("an auto-mode session overlays /var and /nix and writes to the hidden upper"):
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --session keep -y"
        )
        assert_status_state("active", config_path=config_path)
        for path in ["/etc", "/var", "/nix"]:
            assert_overlay_mounted(path)

        # A write to an overlaid decoy tree lands on the hidden volume's upper,
        # never on the persisted decoy state.
        machine.succeed("printf %s hidden > /etc/nails-session-marker")
        machine.succeed("test -f /mnt/data/etc/nails-session-marker")
        machine.fail("test -e /persist/nails-session-marker")

    with subtest("emergency teardown leaves no hidden residue on the persisted state"):
        machine.succeed(f"nails --config {config_path} emergency")
        assert_no_overlays(["/etc", "/var", "/nix"])
        machine.fail("test -e /etc/nails-session-marker")
        residue = machine.succeed(
            "find /persist -name 'nails-*' -printf '%p\\n' || true"
        ).strip()
        assert residue == "", f"hidden residue persisted on the decoy state: {residue!r}"
  '';
}
