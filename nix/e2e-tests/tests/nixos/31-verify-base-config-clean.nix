# Test 31: A base /etc/nixos that references the hidden module is refused
#
# The decoy's hardware-configuration.nix imports ./nails/configuration.nix, the
# trace a leaked hidden configuration would leave on the decoy. `nails check`
# reports the suspicious-nails-reference check as failing and names the file,
# the line and the text, and `nails activate` refuses (exit 4) before preparing
# anything: no next root at /run/nextroot, no soft-reboot, no runtime drop-in,
# no hidden module in /etc/nixos, and the machine stays on the plain decoy root.

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

    import json

    from nails_e2e import run_command_capture, session

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/run/nails-headless.toml"
    write_headless_config(headless_config)
    dirty_file = "/etc/nixos/hardware-configuration.nix, line 3"


    def reference_row(label):
        """The suspicious-nails-reference row of `nails --json check`, with the
        exit code."""
        rc, out = machine.execute(
            f"nails --config {headless_config} --json check 2>/run/{label}.err"
        )
        rows = {row["name"]: row for row in json.loads(out)["data"]["checks"]}
        return rc, rows["suspicious-nails-reference"]


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

    with subtest("check names the file, line and text of the dirty base config"):
        check = run_command_capture(
            machine, "check-dirty-base", f"nails --config {headless_config} check"
        )
        assert check["rc"] == 4, f"check must refuse (rc=4): {check}"
        rows = [
            line
            for line in check["stdout"].splitlines()
            if "suspicious-nails-reference:" in line
        ]
        assert rows and dirty_file in rows[0], (
            f"expected the base-config row to name the file and line: {check['stdout']!r}"
        )
        rc, row = reference_row("check-dirty-json")
        assert rc == 4, f"check --json must refuse (rc=4): {rc}"
        assert row["status"] == "fail", row
        assert "'./nails/configuration.nix'" in row["message"], row
        assert row["remediation"].startswith("Remove it from that file"), row

    with subtest("activation refuses before preparing the next root"):
        activate = run_command_capture(
            machine,
            "activate-dirty-base",
            f"nails --config {headless_config} activate -y --overlay-only",
        )
        assert activate["rc"] == 4, f"expected a pre-flight refusal (rc=4): {activate}"
        assert (
            "suspicious-nails-reference" in activate["combined"]
            and dirty_file in activate["combined"]
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
