# Test 12: `nails rehearse` end to end, with a positive control
#
# T-141. The operator-facing canary self-test, run the way the operator guide
# describes it: plant inside an active hidden session, deactivate (which
# reboots), reopen the hidden volume and scan. The decoy here keeps a
# persistent journal and an on-disk Nix store (forensic-vm-config), so the
# journal and process channels have somewhere durable to leak to.
#
# The clean scan must find nothing on the raw decoy devices. Then the test
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

  # One activation cycle with a reboot and three raw scans of the 20 GB root
  # disk (mostly unallocated qcow2, so fast); generous margin.
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
    ${testHelpers.canonicalDeactivateFn}

    config = "/tmp/rehearse-headless.toml"
    state_path = "/mnt/data/rehearse/state.json"

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
        return rc, out, err

    machine.start()
    machine.wait_for_unit("multi-user.target")
    write_headless_config(config, overlay_var=True)

    with subtest("plant the canary in an active hidden session"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(
            f"nails --config {config} activate --overlay-only --session keep --accept-persistent-decoy -y"
        )
        rc, out, err = rehearse("plant --user testuser")
        assert rc == 0, (rc, out, err)
        token = json.loads(machine.succeed(f"cat {state_path}"))["token"]
        assert token not in out + err, "plant printed the token"
        data = json.loads(out)["data"]
        assert data["phase"] == "planted", data
        planted = {c["kind"] for c in data["channels"] if "skipped" not in c}
        for kind in ["overlay-file", "home-file", "recent-files", "system-log", "process-cmdline"]:
            assert kind in planted, (kind, data["channels"])
        overlay_targets = {
            c["location"].rsplit("/", 1)[0] or "/"
            for c in data["channels"]
            if c["kind"] == "overlay-file" and "skipped" not in c
        }
        for target in ["/etc", "/home", "/root", "/var", "/tmp"]:
            assert target in overlay_targets, (target, overlay_targets)
        # The canary is live in the session, in the overlay only.
        machine.succeed(f"grep -q {token} /home/testuser/rehearse-{token}.txt")
        machine.succeed(f"grep -q {token} /home/testuser/.local/share/recently-used.xbel")
        machine.succeed(f"test -f /mnt/data/etc/rehearse-{token}.txt")

    with subtest("a scan in the planting boot is refused"):
        rc, out, err = rehearse("scan")
        assert rc == 6, (rc, out, err)
        assert "same_boot" in out + err, (out, err)

    with subtest("deactivate, reboot and reopen the hidden volume"):
        canonical_deactivate(config, unit_name="nails-deactivate-rehearse")
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        machine.fail(f"test -e /etc/rehearse-{token}.txt")

    with subtest("the raw decoy devices hold no trace of the canary"):
        rc, out, err = rehearse("scan")
        assert token not in out + err, "scan printed the token"
        assert rc == 0, (rc, out, err)
        scan = json.loads(out)["data"]["scan"]
        assert scan["devices"], scan
        for device in scan["devices"]:
            assert "error" not in device, device
            assert device["hits"] == [], device
        assert any(d["bytes_scanned"] > 0 for d in scan["devices"]), scan
        assert any("SSD" in line for line in scan["not_visible"]), scan
        print(f"clean scan of {[d['device'] for d in scan['devices']]}")

    with subtest("positive control: the token written to the decoy is found"):
        wide = "".join(f"\\x{ord(ch):02x}\\x00" for ch in token)
        machine.succeed(
            f"echo {token} > /root/control-ascii.txt",
            f"printf '{wide}' > /root/control-wide.bin",
            "sync",
        )
        rc, out, err = rehearse("scan")
        assert rc == 11, (rc, out, err)
        scan = json.loads(out)["data"]["scan"]
        hits = [hit for device in scan["devices"] for hit in device["hits"]]
        encodings = {hit["encoding"] for hit in hits}
        assert {"ascii", "utf16-le"} <= encodings, hits
        machine.succeed("rm -f /root/control-ascii.txt /root/control-wide.bin", "sync")

    with subtest("reset removes the rehearsal from the hidden volume"):
        rc, out, err = rehearse("reset")
        assert rc == 0, (rc, out, err)
        machine.fail(f"test -e {state_path}")
        machine.fail(f"test -e /mnt/data/etc/rehearse-{token}.txt")
  '';
}
