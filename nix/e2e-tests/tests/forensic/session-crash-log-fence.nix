# The write fence stops the kernel's crash log from reaching the firmware.
#
# pstore's EFI backend (`efi_pstore`, built into the NixOS kernel) writes the
# kernel log of every panic and oops into an EFI variable itself, past
# efivarfs, and the next boot finds it in /sys/fs/pstore, where
# systemd-pstore copies it onto the disk. A panic of the hidden session would
# hand the decoy's next boot the session's kernel log.
#
#   1. Control, on the plain decoy: a panic (`sysrq c`) leaves a crash record
#      that the next boot shows, so the firmware and the backend work here.
#      The record is removed again.
#   2. In the hidden session the backend is no longer registered and its
#      switch reads `Y`. The same panic leaves no record: after the next cold
#      boot no new EFI variable, nothing in /sys/fs/pstore and nothing
#      archived below /var/lib/systemd/pstore.
#
# The VM boots through OVMF with a persistent variable store, as
# `uefi-esp-nvram-invariant` does, and with `panic=1`: the kernel resets after
# a panic, and the driver's `-no-reboot` turns the reset into an exit.
{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "session-crash-log-fence";
  # Three cold boots through OVMF, one session.
  globalTimeout = 1500;
  meta.tags = [
    "forensic"
    "security"
  ];

  nodes.machine =
    { lib, pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      virtualisation = {
        useBootLoader = true;
        useEFIBoot = true;
        efi.keepVariables = true;
      };
      boot.loader = {
        systemd-boot.enable = true;
        efi.canTouchEfiVariables = true;
        timeout = lib.mkForce 1;
      };
      boot.kernelParams = [ "panic=1" ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.e2fsprogs
      ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalActivateFn}

    from nails_e2e import session

    CONFIG = "/tmp/nails-headless.toml"
    #: Where a crash record shows after a boot: the variables efi_pstore writes,
    #: the pstore filesystem and systemd-pstore's archive on the disk.
    RECORDS = (
        "{ ls -1 /sys/firmware/efi/efivars | grep -i '^dump-' || true; "
        "find /sys/fs/pstore /var/lib/systemd/pstore -type f 2>/dev/null || true; } "
        "| LC_ALL=C sort"
    )


    def boot():
        machine.start()
        machine.wait_for_unit("multi-user.target")


    def panic():
        machine.execute(
            "(sleep 1; echo c > /proc/sysrq-trigger) </dev/null >/dev/null 2>&1 &",
            check_return=False,
            check_output=False,
        )
        session.wait_for_power_off(machine, 300)


    def records():
        return [line for line in machine.succeed(RECORDS).splitlines() if line.strip()]


    def clear_records():
        machine.succeed(
            "for v in /sys/firmware/efi/efivars/dump-*; do "
            "  [ -e \"$v\" ] || continue; chattr -i \"$v\"; rm -f \"$v\"; done",
            "rm -f /sys/fs/pstore/* 2>/dev/null || true",
            "rm -rf /var/lib/systemd/pstore/* 2>/dev/null || true",
            "sync",
        )


    boot()
    machine.succeed("test -d /sys/firmware/efi/efivars")
    backend = machine.succeed("cat /sys/module/pstore/parameters/backend").strip()
    assert backend == "efi_pstore", f"the crash log goes to {backend}, not to EFI"
    clear_records()
    assert records() == [], records()

    with subtest("control: a panic on the decoy leaves a crash record"):
        panic()
        boot()
        left = records()
        machine.log(f"records after the decoy's panic: {left}")
        assert left, "the decoy's panic left no crash record: the control does not hold"
        clear_records()
        assert records() == [], records()

    with subtest("in the session the EFI backend is off"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        write_headless_config(CONFIG)
        canonical_activate(CONFIG, "--overlay-only", "activate")
        backend = machine.succeed("cat /sys/module/pstore/parameters/backend").strip()
        assert backend == "(null)", f"a crash log backend is registered: {backend}"
        switch = machine.succeed("cat /sys/module/efi_pstore/parameters/pstore_disable").strip()
        assert switch == "Y", switch

    with subtest("a panic in the session leaves no crash record"):
        panic()
        boot()
        session.assert_decoy_root(machine)
        assert records() == [], f"the session's panic left a crash record: {records()}"
  '';
}
