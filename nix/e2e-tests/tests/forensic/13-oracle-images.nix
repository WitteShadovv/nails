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
# Coverage canary (planted BEFORE the baseline snapshot, so it is present
# identically on before/control/after and the oracle's after - before - control
# set difference subtracts it away): a file at /var/lib/nails-oracle/canary
# carrying the reserved address canary@oracle.example. bulk_extractor carves the
# address from the raw image bytes, so the oracle emits it at (bulk_extractor,
# email, canary@oracle.example) -- the key ci/oracle/controls-real.json pins.
# Finding it in `after` proves the scan actually read the image.
#
# The positive-control SENTINEL addresses are NOT planted here. run-scan.sh
# writes them into zero-filled free blocks of a throwaway working copy of
# after.raw only -- before.raw, control.raw and the retained after.raw are
# never modified.
#
# Session data a free-space carve recognises: inside the hidden session the
# workflow writes a reserved address and URL (session.oracle.example) into a
# file, syncs it to disk and deletes it, then checks the bytes are still on the
# hidden volume's block device, so the check is not vacuous: those bytes reach
# a disk and outlive the file. They must never reach the decoy disk. If a
# regression put the session's writes there, bulk_extractor would carve the
# address and URL from after.raw's free space, and the oracle would fail the
# run on them as unexplained residue.

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

    # Session data the oracle's bulk_extractor channel recognises (an e-mail
    # address, a domain and a URL), written in the hidden session only.
    SESSION_ADDRESS = "hidden-session@session.oracle.example"
    SESSION_URL = "https://session.oracle.example/hidden-session"

    def plant_oracle_canary():
        # Planted on the decoy root BEFORE the baseline snapshot, so present on
        # before/control/after: the only @oracle address on the pure baseline,
        # so it subtracts from the residue yet is still detected in `after` by
        # the canary check.
        machine.succeed("mkdir -p /var/lib/nails-oracle")
        machine.succeed(
            "printf '# NAILS forensic-oracle coverage canary (synthetic)\\n"
            "canary address: " + CANARY + "\\n' > /var/lib/nails-oracle/canary"
        )
        machine.succeed("sync")

    def write_and_delete_session_token():
        # Inside the hidden session: write the token to a file in the upper,
        # sync it to disk and delete the file. Its bytes stay in the hidden
        # volume's free space, where a carve of that disk finds them, which is
        # what makes their absence from after.raw mean something.
        note = "/home/testuser/work/note.txt"
        machine.succeed(
            "su - testuser -c 'printf \"%s\\n%s\\n\" "
            + SESSION_ADDRESS
            + " "
            + SESSION_URL
            + " > ~/work/note.txt' && sync"
        )
        machine.succeed(f"grep -qxF {SESSION_ADDRESS} {UPPER}{note}")
        machine.succeed("su - testuser -c 'rm ~/work/note.txt' && sync")
        machine.fail(f"test -e {UPPER}{note}")
        machine.succeed("echo 3 > /proc/sys/vm/drop_caches")
        machine.succeed(f"grep -qaF {SESSION_ADDRESS} /dev/mapper/data")

    machine.start()
    machine.wait_for_unit("multi-user.target")
    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)

    with subtest("plant the canary, then image the decoy baseline"):
        # The hidden-volume mount point is a legitimate, permanent part of the
        # decoy; create it before the baseline so it is on every image, exactly
        # as forensic/06 does.
        machine.succeed("mkdir -p /mnt/data")
        plant_oracle_canary()
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
        machine.succeed(
            "su - testuser -c 'printf \"#!/bin/bash\\necho test\\n\" > ~/work/script.sh && chmod +x ~/work/script.sh'"
        )
        machine.succeed("sync")
        # The work is in the hidden root's upper on the hidden volume.
        machine.succeed(f"test -f {UPPER}/home/testuser/work/project/file_50.txt")
        machine.succeed(f"test -x {UPPER}/home/testuser/work/script.sh")
        write_and_delete_session_token()
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
