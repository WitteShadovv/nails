# Test 13: Forensic-oracle real-image slice -- retain before/control/after.raw
#
# This spec does not assert on the images itself; its job is to PRODUCE the
# three real decoy disk images the forensic oracle scans. It drives the
# canonical activate/populate/deactivate workflow on one decoy-root lineage
# (the same shape as forensic/06) and, at each of the three forensic stages,
# retains a sparse copy of the powered-off decoy root into the test's
# out_dir/forensics as before.raw / control.raw / after.raw (the mapping
# disk_forensics.oracle_image_name encodes: baseline->before, control->control,
# post->after). ci/oracle/run-scan.sh ORACLE_IMAGES_DIR mode then scans those
# raws and renders the nails-oracle verdict; this spec never runs the scan (it
# needs root + docker and is run in a coordinated job later).
#
# Coverage canary and baseline carriers (planted BEFORE the baseline snapshot,
# so they are present identically on before/control/after and the oracle's
# after - before - control set difference subtracts them away):
#
#   * a coverage canary at /var/lib/nails-oracle/canary carrying the reserved
#     address canary@oracle.example. bulk_extractor carves the address from the
#     raw image bytes, so the oracle emits it at (bulk_extractor, email,
#     canary@oracle.example) -- the key ci/oracle/controls-real.json pins.
#     Finding it in `after` proves the scan actually read the image.
#   * three address-FREE baseline carrier files (a wtmpdb login/boot carrier at
#     /var/log/wtmp.db, a lastlog2 carrier at /var/lib/lastlog/lastlog2.db and a
#     pacman history at /var/log/pacman.log), byte-for-byte the baselines that
#     ci/oracle/make-sample-images.sh plants on every synthetic image. They
#     carry NO @oracle.example sentinel address here, so the retained snapshots
#     stay a pure decoy baseline.
#
# The positive-control SENTINEL addresses are NOT planted here. run-scan.sh
# appends them, in place, to these carriers on a throwaway working copy of
# after.raw only -- before.raw, control.raw and the retained after.raw are
# never modified. The carriers must already exist on before/control (that is
# why they are planted here and not only on the working copy): the oracle's
# restore channel keys every recovered file by its path, so a carrier that
# existed only on the injected `after` would surface as unexplained restore-path
# residue. Planting the carriers on all three images means only the new @oracle
# address (and any genuine hidden-session leak) survives the set difference.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  diskForensics = import ./../../lib/disk-forensics.nix { inherit pkgs; };
in
{
  name = "oracle-images";
  meta.tags = [ "forensic" ];

  # Imaging the decoy root three times (baseline, control, post), one extra
  # reboot for the control run, the activate/deactivate soft-reboots and three
  # sparse retain copies; the same generous margin forensic/06 uses.
  globalTimeout = 2700;

  nodes = {
    machine =
      { lib, ... }:
      {
        imports = [ ./../../lib/forensic-vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];

        # Image the decoy configuration NAILS actually guarantees: a VOLATILE
        # decoy. NAILS refuses to activate on a persistent-journald decoy by
        # default (docs/decoy-requirements.md, --allow-persistent-decoy), because
        # what the decoy logs while it shuts down for the soft-reboot and starts
        # again -- the /mnt/data mount/unmount, the dm-crypt filesystem, the
        # soft-reboot markers -- would survive on its disk. The forensic profile
        # forces persistent journald to image log residue for OTHER tests; here
        # we override it back to the volatile default (journald writes to tmpfs,
        # wiped at power-off) so the imaged decoy disk reflects the supported,
        # guaranteed posture. The on-disk Nix store (useNixStoreImage) stays, so
        # store and file residue are still imaged and scanned adversarially.
        services.journald.settings.Journal.Storage = lib.mkForce "volatile";
      };
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${diskForensics.pythonSetup}

    from nails_e2e import session

    UPPER = "/mnt/data/root/upper"

    # The reserved coverage-canary address. Kept in step with the committed
    # default in ci/oracle/controls-real.json (and run-scan.sh's canary_default).
    CANARY = "canary@oracle.example"

    def plant_oracle_baseline():
        # Planted on the decoy root BEFORE the baseline snapshot, so present on
        # before/control/after. Mirrors ci/oracle/make-sample-images.sh's
        # populate_base so the real pipeline's restore/plaso behaviour matches the
        # proven synthetic path: the carrier contents are identical across the
        # three images (they subtract away), only the address run-scan.sh later
        # appends to `after` is new. No @oracle sentinel address is planted here.
        machine.succeed("mkdir -p /var/lib/nails-oracle /var/log /var/lib/lastlog")

        # Coverage canary (carries the reserved address; the only @oracle address
        # on the pure baseline, and present on every image, so it subtracts from
        # the residue yet is still detected in `after` by the canary check).
        machine.succeed(
            "printf '# NAILS forensic-oracle coverage canary (synthetic)\\n"
            "canary address: " + CANARY + "\\n' > /var/lib/nails-oracle/canary"
        )

        # wtmpdb login/boot carrier (address-free baseline).
        machine.succeed(
            "printf '# synthetic wtmpdb login/boot carrier\\n"
            "boot\\t~\\tlocalhost\\t2026-01-01T00:00:00+00:00\\n"
            "login\\troot\\tlocalhost\\t2026-01-01T00:01:00+00:00\\n"
            "login\\tuser\\tlocalhost\\t2026-01-01T00:02:00+00:00\\n' "
            "> /var/log/wtmp.db"
        )

        # lastlog2 last-login carrier (address-free baseline).
        machine.succeed(
            "printf '# synthetic lastlog2 last-login carrier\\n"
            "root\\tpts/0\\tlocalhost\\t2026-01-01T00:01:00+00:00\\n"
            "user\\ttty1\\tlocalhost\\t2026-01-01T00:02:00+00:00\\n' "
            "> /var/lib/lastlog/lastlog2.db"
        )

        # pacman history carrier (address-free baseline).
        machine.succeed(
            "printf '[2026-01-01T00:00:00+0000] [PACMAN] Running pacman -Syu\\n"
            "[2026-01-01T00:00:01+0000] [ALPM] installed base (3.0-1)\\n"
            "[2026-01-01T00:00:02+0000] [ALPM] installed coreutils (9.5-1)\\n' "
            "> /var/log/pacman.log"
        )
        machine.succeed("sync")

    machine.start()
    machine.wait_for_unit("multi-user.target")
    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)

    with subtest("plant the canary and baseline carriers, then image the decoy baseline"):
        # The hidden-volume mount point is a legitimate, permanent part of the
        # decoy; create it before the baseline so it is on every image, exactly
        # as forensic/06 does.
        machine.succeed("mkdir -p /mnt/data")
        plant_oracle_baseline()
        # dhcpcd.wait = "background" (vm-config.nix) lets multi-user.target come
        # up before dhcpcd has leased eth0, so /var/lib/dhcpcd/eth0.lease -- and
        # the 10.0.2.x lease addresses bulk_extractor carves from it -- would
        # land only on `after` (long enough for the background lease to finish)
        # and not on the briefer before/control, surfacing as false residue.
        # Hold for the lease so it is present identically on all three images and
        # subtracts away. The QEMU user-mode network hands out the same 10.0.2.15
        # every boot, so the carved addresses match across images too.
        machine.wait_until_succeeds("test -s /var/lib/dhcpcd/eth0.lease")
        before_raw = disk_forensics.snapshot(machine, "baseline", retain=True)
        print(f"retained before.raw from {before_raw}")

    with subtest("control run: a plain reboot with no hidden session"):
        # The workflow below spans the boot after the control snapshot and the
        # activate/deactivate soft-reboots, so the control is one plain reboot;
        # whatever it changes is boot noise the oracle subtracts.
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        # The control reboot re-leases eth0; hold for the lease to be rewritten
        # before imaging, the same background-lease wait as the baseline, so
        # control carries the same eth0.lease (and 10.0.2.x) as before/after.
        machine.wait_until_succeeds("test -s /var/lib/dhcpcd/eth0.lease")
        control_raw = disk_forensics.snapshot(machine, "control", retain=True)
        print(f"retained control.raw from {control_raw}")

    with subtest("run a full activate/populate/deactivate workflow"):
        # setupHiddenVolume is driven here, right before activate (not before the
        # baseline): the control reboot above closes the LUKS backend, so the
        # volume must be freshly set up immediately before the session, as in
        # forensic/06.
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        # No --allow-persistent-decoy: the decoy is volatile (journald override
        # above), so NAILS's persistent-decoy preflight passes and activation
        # runs the default, supported path.
        canonical_activate(headless_config, "--overlay-only", "activate")
        machine.succeed("su - testuser -c 'id -un | grep -qx testuser'")
        machine.succeed("su - testuser -c 'mkdir -p ~/work/project'")
        machine.succeed(
            "su - testuser -c 'for i in $(seq 1 50); do echo content > ~/work/project/file_$i.txt; done'"
        )
        machine.succeed("su - testuser -c 'cd ~/work/project && git init 2>/dev/null || true'")
        machine.succeed(
            "su - testuser -c 'printf \"#!/bin/bash\\necho test\\n\" > ~/work/script.sh && chmod +x ~/work/script.sh'"
        )
        machine.succeed("sync")
        # The work is in the hidden root's upper on the hidden volume.
        machine.succeed(f"test -f {UPPER}/home/testuser/work/project/file_50.txt")
        machine.succeed(f"test -x {UPPER}/home/testuser/work/script.sh")
        canonical_deactivate(headless_config, "deactivate")
        status = read_status_json(config_path=headless_config)
        assert status["place"] == "decoy", f"expected the plain decoy, got {status}"
        machine.fail("test -e /home/testuser/work")

    with subtest("no overlay, next root or hidden-volume mount remains"):
        session.assert_decoy_root(machine)
        machine.fail("grep -E ' /mnt/data|/dev/mapper/data' /proc/mounts")
        machine.fail("test -e /dev/mapper/data")

    with subtest("image the powered-off decoy as the oracle's after image"):
        after_raw = disk_forensics.snapshot(machine, "post", restart=False, retain=True)
        print(f"retained after.raw from {after_raw}")

    # The three raws are now under out_dir/forensics as before.raw / control.raw /
    # after.raw for ci/oracle/run-scan.sh ORACLE_IMAGES_DIR mode. This spec runs
    # no scan.
  '';
}
