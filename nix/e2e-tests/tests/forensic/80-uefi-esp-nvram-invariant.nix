# Test 80: UEFI ESP / EFI NVRAM invariant
#
# Enforces the bootloader/ESP/NVRAM invariant from docs/threat-model.md:
# activating and then deactivating the hidden environment must not change any
# boot entry, ESP file or EFI NVRAM variable beyond what a plain reboot already
# does. A boot entry, bootloader config file or NVRAM variable that enables the
# hidden mode is itself evidence, and none of it is captured by the overlay, so
# it cannot be rolled back by unmounting. Only a `switch-to-configuration switch`
# (or `boot`) would rewrite the ESP and EFI variables; activation and
# deactivation must stay on `test`.
#
# The test needs a real firmware surface, so it boots the VM through OVMF with a
# persistent EFI variable store and systemd-boot on a mounted ESP - unlike the
# rest of the suite, which direct-boots a kernel and has no ESP or efivarfs.
#
# A plain-reboot control runs first on the same machine. Several ESP files and
# EFI variables legitimately churn across any reboot (systemd-boot rewrites
# loader/random-seed, firmware bumps runtime variables, the boot-time activation
# may restat /var/lib/nixos). The control captures exactly that churn, and the
# NAILS activate/deactivate cycle is then required to change nothing a plain
# reboot would not - which is both robust to that churn and a true test that a
# hidden `switch` never ran.
{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "uefi-esp-nvram-invariant";
  # OVMF boot plus two full reboots (control and deactivation) and a LUKS setup
  # run well over a direct-boot test; this is a nightly-only forensic check.
  # Twice the estimated shard weight (300 s) until the nightly run refreshes it.
  globalTimeout = 1200;
  meta.tags = [ "forensic" ];

  nodes = {
    machine =
      { lib, pkgs, ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];

        # Boot through a real bootloader on a real ESP, with OVMF firmware and a
        # persistent EFI variable store, so the ESP and efivarfs exist and
        # survive the reboots this test performs.
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

        environment.systemPackages = [
          self.packages.x86_64-linux.nails
          pkgs.efibootmgr
          pkgs.dosfstools
        ];
      };
  };

  testScript = _: ''
    import json

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalDeactivateFn}

    def plain_reboot(unit_name="nails-plain-reboot-control"):
        # Mirror canonical_deactivate's robust shutdown wait, but trigger an
        # ordinary reboot (no NAILS involved) so we can measure the ESP/NVRAM
        # churn a plain reboot alone produces.
        import shlex
        import subprocess

        machine.succeed(
            "systemd-run --unit "
            + shlex.quote(unit_name)
            + " --no-block --service-type=exec /bin/sh -lc "
            + shlex.quote("systemctl reboot")
        )
        process = machine.process
        if process is not None:
            with machine.nested("waiting for the control plain reboot to power the VM off"):
                try:
                    process.wait(timeout=300)
                except subprocess.TimeoutExpired:
                    raise AssertionError("control plain reboot did not power off the VM within 300s")
        machine.wait_for_shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")

    def snapshot():
        # Capture the three firmware-visible surfaces a `switch`/`boot` would
        # write but a `test` activation never does.
        esp = machine.succeed(
            "find /boot -xdev -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum 2>/dev/null || true"
        )
        # Boot entries and order identify the bootloader install. BootCurrent is
        # volatile (which entry we booted) and is excluded by the hex-only match.
        nvram = machine.succeed(
            "efibootmgr -v 2>/dev/null | grep -E '^(Boot[0-9A-Fa-f]{4}|BootOrder:)' || true"
        )
        efivars = machine.succeed(
            "ls -1 /sys/firmware/efi/efivars 2>/dev/null | LC_ALL=C sort || true"
        )
        # Hash the content, not stat metadata: NixOS rewrites every one of these
        # files atomically on each boot, so the inode and mtime always change (and
        # the deactivation phase spans a reboot), which made an inode/mtime
        # comparison flag them on every run. A content hash ignores that churn
        # while still catching a hidden switch that actually rewrote a file (e.g.
        # added a user), which is the drift this invariant is about.
        vln = machine.succeed(
            "for f in declarative-users declarative-groups uid-map gid-map auto-subuid-map; do "
            "  p=/var/lib/nixos/$f; "
            "  if [ -e \"$p\" ]; then sha256sum \"$p\"; "
            "  else echo \"MISSING $p\"; fi; "
            "done"
        )
        return {"esp": esp, "nvram": nvram, "efivars": efivars, "vln": vln}

    def esp_map(block):
        result = {}
        for line in block.splitlines():
            line = line.strip()
            if not line:
                continue
            digest, _, path = line.partition("  ")
            # Compare by ESP-relative path so the listing is mount-point neutral.
            if path.startswith("/boot/"):
                path = path[len("/boot/"):]
            result[path] = digest
        return result

    def esp_changed(before, after):
        b, a = esp_map(before), esp_map(after)
        return {p for p in set(b) | set(a) if b.get(p) != a.get(p)}

    def line_set(block):
        return {line.strip() for line in block.splitlines() if line.strip()}

    def line_changed(before, after):
        return line_set(before) ^ line_set(after)

    def assert_within_control(label, nails_delta, control_delta):
        extra = nails_delta - control_delta
        if extra:
            print(f"FAIL: {label} changed beyond a plain reboot: {sorted(extra)}")
            print(f"  plain-reboot churn for {label}: {sorted(control_delta)}")
            assert False, (
                f"NAILS activate/deactivate changed {label} beyond a plain reboot: "
                f"{sorted(extra)}"
            )
        print(f"✓ {label}: NAILS introduced no change beyond the plain-reboot control")

    machine.start()
    machine.wait_for_unit("multi-user.target")

    print("\n" + "=" * 70)
    print("PHASE 0: CONFIRM A REAL UEFI BOOT SURFACE")
    print("=" * 70)

    # If the VM ever direct-boots (no OVMF), efivarfs and the ESP are absent and
    # the invariant becomes vacuous; fail loudly instead.
    machine.succeed("test -d /sys/firmware/efi/efivars")
    print("✓ Booted under UEFI firmware (efivarfs present)")

    baseline = snapshot()
    esp_files = esp_map(baseline["esp"])
    assert len(esp_files) >= 2, f"ESP snapshot unexpectedly small: {sorted(esp_files)}"
    assert any(p.lower().startswith("efi/") for p in esp_files), \
        f"ESP has no EFI/ payload: {sorted(esp_files)}"
    assert any(line.startswith("Boot") for line in line_set(baseline["nvram"])), \
        f"No EFI boot entries captured: {baseline['nvram']!r}"
    assert len(line_set(baseline["efivars"])) >= 1, "efivars listing is empty"
    assert "declarative-users" in baseline["vln"], \
        f"/var/lib/nixos snapshot missing expected files: {baseline['vln']!r}"
    print(f"✓ Snapshot is non-empty: {len(esp_files)} ESP files, "
          f"{len(line_set(baseline['nvram']))} NVRAM entries")

    print("\n" + "=" * 70)
    print("PHASE 1: PLAIN-REBOOT CONTROL")
    print("=" * 70)

    plain_reboot()
    after_control = snapshot()

    control_esp = esp_changed(baseline["esp"], after_control["esp"])
    control_nvram = line_changed(baseline["nvram"], after_control["nvram"])
    control_efivars = line_changed(baseline["efivars"], after_control["efivars"])
    control_vln = line_changed(baseline["vln"], after_control["vln"])
    print(f"✓ Plain-reboot churn captured: esp={sorted(control_esp)}, "
          f"nvram={sorted(control_nvram)}, efivars={len(control_efivars)} vars, "
          f"vln={sorted(control_vln)}")

    print("\n" + "=" * 70)
    print("PHASE 2: ACTIVATE AND DEACTIVATE")
    print("=" * 70)

    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)

    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    print("✓ Hidden volume created and mounted")

    # Snapshot immediately before activation; this is the pre-activation baseline
    # the deactivated state must match.
    pre_activation = snapshot()

    machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")
    machine.succeed("mount | grep 'overlay on /home'")
    print("✓ NAILS activated with overlays")

    canonical_deactivate(headless_config, unit_name="nails-deactivate-uefi-invariant")
    print("✓ Deactivated and rebooted to the decoy")

    status = json.loads(machine.succeed("nails status --json"))["data"]
    assert status["state"]["kind"] == "inactive", f"Expected inactive after reboot, got: {status}"
    print("✓ NAILS status reports Inactive")

    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
    print("✓ Hidden volume unmounted")

    post_deactivation = snapshot()

    print("\n" + "=" * 70)
    print("PHASE 3: FIRMWARE INVARIANT ASSERTIONS")
    print("=" * 70)

    nails_esp = esp_changed(pre_activation["esp"], post_deactivation["esp"])
    nails_nvram = line_changed(pre_activation["nvram"], post_deactivation["nvram"])
    nails_efivars = line_changed(pre_activation["efivars"], post_deactivation["efivars"])
    nails_vln = line_changed(pre_activation["vln"], post_deactivation["vln"])

    assert_within_control("ESP files", nails_esp, control_esp)
    assert_within_control("EFI boot entries", nails_nvram, control_nvram)
    assert_within_control("EFI variables", nails_efivars, control_efivars)
    assert_within_control("/var/lib/nixos", nails_vln, control_vln)

    print("\n" + "=" * 70)
    print("UEFI ESP/NVRAM INVARIANT HOLDS")
    print("=" * 70)
    print("""
    Verified that an activate/deactivate cycle changed:
      ✓ no ESP file beyond a plain reboot
      ✓ no EFI boot entry or boot order beyond a plain reboot
      ✓ no EFI variable beyond a plain reboot
      ✓ no /var/lib/nixos identity file beyond a plain reboot
    i.e. deactivation never ran switch-to-configuration switch/boot.
    """)
  '';
}
