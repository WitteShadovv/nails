# Fault test (c): the hidden upper fills up while the hidden session runs.
#
# Once the hidden filesystem that holds the root overlay's upper is full, every
# new write in the hidden root returns ENOSPC. Leaving must not depend on free
# space there: both a normal `nails deactivate` and the `emergency` panic button
# have to power the machine off for real while the upper has nothing left to
# allocate, and the next cold boot is the plain decoy with the hidden mapping
# closed.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  backendFault = import ./../../lib/backend-fault.nix;
in
{
  name = "faults-full-upper-teardown";
  meta.tags = [
    "faults"
    "security"
  ];
  # Two sessions (a soft-reboot in, a power-off and a cold boot out) at about
  # 30 s each, plus setup.
  globalTimeout = 1500;

  testScript = _: ''
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${backendFault.emergencyOutcomeFn}
    ${backendFault.assertFaultExitFn}

    CONFIG = "/mnt/data/config/nails.toml"


    def fill_upper():
        # The overlay writes its upper with the mounter's credentials (root),
        # and root may draw on ext4's reserved blocks, which `df` reports as
        # unavailable. Drop the reserve so "available" is what overlay writes
        # can reach, then leave only a sliver free.
        machine.succeed("tune2fs -m 0 /dev/mapper/data")
        avail = int(machine.succeed("df -B1 --output=avail /mnt/data | tail -1").strip())
        machine.succeed(f"fallocate -l {max(0, avail - 1048576)} /mnt/data/fill")
        # A fresh write in the hidden root now fails for lack of space.
        machine.fail("dd if=/dev/zero of=/root/overflow bs=1M count=4 conv=fsync")


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "EOF"
    )

    with subtest("deactivate completes on a full upper"):
        canonical_activate(CONFIG, "--overlay-only", "activate-1")
        fill_upper()
        # canonical_deactivate follows the power-off and asserts the cold
        # boot's plain decoy with the mapping closed.
        canonical_deactivate(CONFIG, "deactivate-full")

    with subtest("emergency completes on a full upper"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        # Free the space so the next activation passes its space check.
        machine.succeed("rm -f /mnt/data/fill")
        canonical_activate(CONFIG, "--overlay-only", "activate-2")
        fill_upper()
        outcome = emergency_outcome(f"nails --config {CONFIG} emergency", "emergency-full")
        assert_fault_exit(outcome)
  '';
}
