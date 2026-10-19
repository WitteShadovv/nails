# The login- and boot-record regression scenarios, one per affected family.
#
# Kept apart from images.nix and the smoke suite: these run on nix-vm-test's
# `driver` target (host, with network) rather than `sandboxed`, so they are not
# CI targets. The flake exposes them as
# `legacyPackages.<system>.e2e-distro.<name>-records`; a run realises `<attr>`
# and executes its `bin/test-driver` under the heavy-job lock. NixOS is not here:
# its records already read as a power cycle, so there is nothing to neutralise.
{
  self,
  pkgs,
  nix-vm-test,
}:
let
  makeRecords = import ./tests/session-records.nix { inherit self pkgs nix-vm-test; };
  entry = distro: image: release: { inherit distro image release; };

  # Recent Debian installs wtmpdb at priority "standard"; the generic cloud
  # image omits it, so a standard install is reproduced by installing it before
  # measuring. Its boot writer is what names a boot row "soft-reboot".
  debianInstall = ''
    set -eu
    export DEBIAN_FRONTEND=noninteractive
    for attempt in 1 2 3; do
      if apt-get update; then break; fi
      sleep 5
    done
    apt-get install -y wtmpdb
    # The boot writer records the boot row on start and the shutdown row on
    # stop; enable it so a soft-reboot (and the way back) exercises it.
    systemctl enable wtmpdb-update-boot.service
  '';
in
{
  # Debian 13: wtmpdb's SQLite boot writer, which names a soft-reboot boot row.
  "debian-13-records" = makeRecords {
    entry = entry "debian" "13" "13";
    install = debianInstall;
    assertKind = "wtmpdb";
  };

  # Ubuntu 24.04 LTS: classic wtmp on systemd 255, whose boot record carries the
  # decoy's first boot time across a soft-reboot. No install -- the cloud image
  # carries the classic files.
  "ubuntu-24.04-records" = makeRecords {
    entry = entry "ubuntu" "24_04" "24.04";
    install = "";
    assertKind = "classic-wtmp";
  };
}
