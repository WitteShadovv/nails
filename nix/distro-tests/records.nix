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
  images = import ./images.nix { inherit pkgs; };
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

    # Fedora 44 and 45, booted with SELinux enforcing as the image table pins
    # them: classic wtmp on systemd 259 and newer, which resets the start time
    # across a soft-reboot, so a login and a failed login run in the session.
    # Fedora 44's pam_lastlog2 fails to load, as the admission gate's runs on
    # it show, so only Fedora 45 writes the login's lastlog2 row.
    "fedora-44" = makeRecords {
      entry = images."fedora-44";
      assertKind = "classic-wtmp-reset";
      login = true;
      lastlog2 = false;
    };
    "fedora-45" = makeRecords {
      entry = images."fedora-45";
      assertKind = "classic-wtmp-reset";
      login = true;
    };
  };
in
{
  inherit drivers;
  # Every scenario can run: nix-vm-test pins the Debian and Ubuntu images, and
  # the image table the Fedora ones.
  runnable = builtins.attrNames drivers;
  # The seconds a run gets, from the boot to its last assertion: an install, a
  # power cycle, a session kept until the kernel has been up past wtmpdb's five
  # minutes, the way back and a control soft-reboot. A hosted run stops the
  # driver after them.
  timeout = 1800;
}
