# The login- and boot-record regression scenarios, one per affected family.
#
# Kept apart from images.nix and the smoke suite: these run on nix-vm-test's
# `driver` target (host, with network) rather than `sandboxed`, because the
# Debian one installs wtmpdb in the guest. The flake exposes them as
# `legacyPackages.<system>.e2e-distro.<name>-records`; a run realises `<attr>`
# and executes its `bin/test-driver`, on a KVM host by hand or in the records
# suite of distro-e2e.yml, whose job builds the driver and runs it on a hosted
# KVM runner. NixOS is not here: its records already read as a power cycle, so
# there is nothing to neutralise.
{
  self,
  pkgs,
  nix-vm-test,
}:
let
  makeRecords = import ./tests/session-records.nix { inherit self pkgs nix-vm-test; };
  entry = distro: image: release: { inherit distro image release; };

  # Recent Debian installs wtmpdb at priority "standard"; the generic cloud
  # image omits it, so a standard install is reproduced by installing it; the
  # test then power-cycles before it measures. Its boot writer is what names a
  # boot row "soft-reboot".
  debianInstall = ''
    set -eu
    export DEBIAN_FRONTEND=noninteractive
    for attempt in 1 2 3; do
      if apt-get update; then break; fi
      sleep 5
    done
    apt-get install -y wtmpdb
    # The boot writer records the boot row on start and the shutdown time on
    # stop; enable it so the power cycle, the way back and the control
    # soft-reboot all exercise it.
    systemctl enable wtmpdb-update-boot.service
  '';

  # Distribution -> its records scenario.
  drivers = {
    # Debian 13: wtmpdb's SQLite boot writer, which names a soft-reboot boot row.
    "debian-13" = makeRecords {
      entry = entry "debian" "13" "13";
      install = debianInstall;
      assertKind = "wtmpdb";
    };

    # Ubuntu 24.04 LTS: classic wtmp on systemd 255, whose boot record carries
    # the decoy's first boot time across a soft-reboot. No install -- the cloud
    # image carries the classic files.
    "ubuntu-24.04" = makeRecords {
      entry = entry "ubuntu" "24_04" "24.04";
      install = "";
      assertKind = "classic-wtmp";
    };
  };
in
{
  inherit drivers;
  # Every scenario can run: nix-vm-test pins both images.
  runnable = builtins.attrNames drivers;
  # The seconds a run gets, from the boot to its last assertion: an install, a
  # power cycle, a session kept until the kernel has been up past wtmpdb's five
  # minutes, the way back and a control soft-reboot. A hosted run stops the
  # driver after them.
  timeout = 1800;
}
