# Test 12: `nails rehearse` end to end, with a positive control
#
# The operator-facing canary self-test, run the way the operator guide
# describes it: plant inside an active hidden session (entered by a
# soft-reboot into the whole-root overlay), deactivate (a soft-reboot back),
# reopen the hidden volume and scan. The decoy here keeps a persistent journal
# and an on-disk Nix store (forensic-vm-config), so the journal and process
# channels have somewhere durable to leak to.
#
# Plant writes its files through the root overlay: they land in the upper on
# the hidden volume. A scan in the hidden session itself is refused. The clean
# scan on the decoy must find nothing on the raw decoy devices. Then the test
# writes the token onto the decoy itself, once in ASCII and once in UTF-16LE,
# and the same scan must find both by offset: proof that the clean result came
# from a scan that can see the decoy, not from a scan that sees nothing. The
# token is read from the rehearsal state on the hidden volume; the command's own
# output must only ever carry its fingerprint.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "rehearse-canary";
  meta.tags = [ "forensic" ];

  # One session (two soft-reboots) and three raw scans of the 20 GB root disk
  # (mostly unallocated qcow2, so fast); generous margin.
  globalTimeout = 1800;

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/forensic-vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      };
  };

  testScript = _: ''
    import json
    import shlex

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    config = "/mnt/data/config/nails.toml"
    state_path = "/mnt/data/rehearse/state.json"
    UPPER = "/mnt/data/root/upper"

    def rehearse(args):
        # Capture under /run (tmpfs): nothing the test reads back may land on the
        # decoy disk the scan inspects.
        command = f"nails --config {shlex.quote(config)} --json rehearse {args}"
        machine.succeed(
            "bash -c "
            + shlex.quote(
                f"set +e; {command} > /run/rehearse.out 2>/run/rehearse.err;"
                " printf '%s' $? > /run/rehearse.rc"
            )
        )
        rc = int(machine.succeed("cat /run/rehearse.rc"))
        out = machine.succeed("cat /run/rehearse.out")
        err = machine.succeed("cat /run/rehearse.err")
        machine.succeed("rm -f /run/rehearse.out /run/rehearse.err /run/rehearse.rc")
        return rc, out, err

    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("plant the canary in an active hidden session"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        # The configuration lives on the hidden volume, off the scanned decoy.
        write_headless_config(config)
        canonical_activate(config, "--overlay-only --accept-persistent-decoy", "activate")
        rc, out, err = rehearse("plant --user testuser")
        assert rc == 0, (rc, out, err)
        token = json.loads(machine.succeed(f"cat {state_path}"))["token"]
        assert token not in out + err, "plant printed the token"
        data = json.loads(out)["data"]
        assert data["phase"] == "planted", data
        planted = {c["kind"] for c in data["channels"] if "skipped" not in c}
        for kind in ["overlay-file", "home-file", "recent-files", "system-log", "process-cmdline"]:
            assert kind in planted, (kind, data["channels"])
        # The canary is live in the session, and its files are in the root
        # overlay's upper on the hidden volume.
        machine.succeed(f"grep -q {token} /home/testuser/rehearse-{token}.txt")
        machine.succeed(f"grep -q {token} /home/testuser/.local/share/recently-used.xbel")
        machine.succeed(f"test -f {UPPER}/rehearse-{token}.txt")
        machine.succeed(f"test -f {UPPER}/home/testuser/rehearse-{token}.txt")
        machine.succeed(f"test -f {UPPER}/home/testuser/.local/share/recently-used.xbel")

    with subtest("a scan in the hidden session is refused"):
        rc, out, err = rehearse("scan")
        assert rc == 6, (rc, out, err)
        assert "same_boot" in out + err, (out, err)

    with subtest("deactivate and reopen the hidden volume"):
        canonical_deactivate(config, "deactivate")
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        machine.fail(f"test -e /rehearse-{token}.txt")
        machine.fail(f"test -e /home/testuser/rehearse-{token}.txt")

    def scan():
        rc, out, err = rehearse("scan")
        if rc == 6 and "same_boot" in out + err:
            # The soft-reboots kept the boot ID. A scan that still keys on the
            # boot ID alone refuses here although the session has ended; the
            # deactivation above is what makes the scan meaningful.
            machine.log("scan refused as the same boot after deactivation; rescanning with --allow-same-boot")
            rc, out, err = rehearse("scan --allow-same-boot")
        return rc, out, err

    with subtest("the raw decoy devices hold no trace of the canary"):
        rc, out, err = scan()
        assert token not in out + err, "scan printed the token"
        assert rc == 0, (rc, out, err)
        result = json.loads(out)["data"]["scan"]
        assert result["devices"], result
        for device in result["devices"]:
            assert "error" not in device, device
            assert device["hits"] == [], device
        assert any(d["bytes_scanned"] > 0 for d in result["devices"]), result
        assert any("SSD" in line for line in result["not_visible"]), result
        print(f"clean scan of {[d['device'] for d in result['devices']]}")

    with subtest("positive control: the token written to the decoy is found"):
        wide = "".join(f"\\x{ord(ch):02x}\\x00" for ch in token)
        machine.succeed(
            f"echo {token} > /root/control-ascii.txt",
            f"printf '{wide}' > /root/control-wide.bin",
            "sync",
        )
        rc, out, err = scan()
        assert rc == 11, (rc, out, err)
        result = json.loads(out)["data"]["scan"]
        hits = [hit for device in result["devices"] for hit in device["hits"]]
        encodings = {hit["encoding"] for hit in hits}
        assert {"ascii", "utf16-le"} <= encodings, hits
        machine.succeed("rm -f /root/control-ascii.txt /root/control-wide.bin", "sync")

    with subtest("reset removes the rehearsal from the hidden volume"):
        rc, out, err = rehearse("reset")
        assert rc == 0, (rc, out, err)
        machine.fail(f"test -e {state_path}")
        machine.fail(f"test -e {UPPER}/rehearse-{token}.txt")
        machine.fail(f"test -e {UPPER}/home/testuser/rehearse-{token}.txt")
  '';
}
