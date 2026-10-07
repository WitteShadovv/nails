# Test 31: A base /etc/nixos that references the hidden module is refused
#
# The decoy's hardware-configuration.nix imports ./nails/configuration.nix, the
# trace a leaked hidden configuration would leave on the decoy. `nails check`
# reports the suspicious-nails-reference check as failing, and `nails activate`
# refuses (exit 4) before preparing anything: no next root at /run/nextroot, no
# soft-reboot, no runtime drop-in, no hidden module in /etc/nixos, and the machine
# stays on the plain decoy root.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "verify-base-config-clean";
  meta.tags = [ "nixos" ];

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.python3
      ];
      nix.settings.experimental-features = [
        "nix-command"
        "flakes"
      ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}

    from nails_e2e import run_command_capture, session

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/run/nails-headless.toml"
    write_headless_config(headless_config)

    with subtest("prepare hidden volume and dirty decoy nixos tree"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mkdir -p /run/dirty-etc-nixos")
        machine.succeed("cp -L /etc/nixos/configuration.nix /run/dirty-etc-nixos/configuration.nix")
        machine.succeed("""cat > /run/dirty-etc-nixos/hardware-configuration.nix <<'EOF'
    { ... }: {
      imports = [
        ./nails/configuration.nix
      ];
    }
    EOF""")
        machine.succeed("mount --bind /run/dirty-etc-nixos /etc/nixos")

    with subtest("check reports the dirty base config"):
        check = run_command_capture(
            machine, "check-dirty-base", f"nails --config {headless_config} check"
        )
        assert check["rc"] == 4, f"check must refuse (rc=4): {check}"
        rows = [
            line
            for line in check["stdout"].splitlines()
            if "suspicious-nails-reference:" in line
        ]
        assert rows and "suspicious hidden or nails references" in rows[0].lower(), (
            f"expected the base-config row to fail: {check['stdout']!r}"
        )

    with subtest("activation refuses before preparing the next root"):
        activate = run_command_capture(
            machine,
            "activate-dirty-base",
            f"nails --config {headless_config} activate -y --overlay-only",
        )
        assert activate["rc"] == 4, f"expected a pre-flight refusal (rc=4): {activate}"
        lowered = activate["combined"].lower()
        assert (
            "suspicious-nails-reference" in lowered
            or "suspicious hidden or nails references" in lowered
        ), f"expected the base-config diagnostic, got: {activate['combined']!r}"

    with subtest("refusal leaves the plain decoy untouched"):
        session.assert_decoy_root(machine)
        machine.fail("test -e /run/nextroot/etc")
        machine.fail("test -e /run/systemd/system/systemd-soft-reboot.service.d")
        assert machine.succeed("systemctl show -p SoftRebootsCount --value").strip() == "0"
        status = read_status_json(config_path=headless_config)
        assert status["posture"] == "decoy", status
        machine.succeed("umount /etc/nixos")
        machine.fail("test -e /etc/nixos/nails/configuration.nix")
  '';
}
