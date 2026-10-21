# Test 32: The hidden hardware configuration wraps a bare decoy file
#
# The decoy's hardware-configuration.nix has no `imports` attribute. `nails
# init` writes the hidden hardware configuration into the hidden root's upper
# (/mnt/data/root/upper/etc/nixos): the fixed wrapper importing the preserved
# base and ./nails/configuration.nix exactly once, the verbatim base, and the
# nails/configuration.nix symlink to the hidden module. All of it parses, and
# the nixos-config pre-flight check accepts it. In the hidden session (entered
# with --overlay-only, so no hidden system is built) /etc/nixos shows the
# wrapper, the base and the hidden module through the root overlay. After the
# way back the decoy /etc/nixos is the original no-imports file again, with no
# base file and no nails directory.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "config-inject-hardware-imports";
  meta.tags = [ "nixos" ];
  # Two soft-reboots at about 15 s each, plus setup.
  globalTimeout = 900;

  nodes.machine =
    { pkgs, lib, ... }:
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
      # The decoy's hardware-configuration.nix has NO imports attribute, so the
      # test exercises wrapper injection over a bare file.
      environment.etc."nixos/hardware-configuration.nix".text = lib.mkForce ''
        { config, lib, pkgs, ... }:
        {
          boot.loader.grub.enable = false;
        }
      '';
    };

  testScript = _: ''
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    from nails_e2e import run_command_capture

    CONFIG = "/mnt/data/config/nails.toml"
    HIDDEN_ETC_NIXOS = "/mnt/data/root/upper/etc/nixos"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    # Sanity: the decoy (defined in the node config) really has no imports list.
    decoy = machine.succeed("cat /etc/nixos/hardware-configuration.nix")
    assert "imports" not in decoy, f"decoy fixture should have no imports attribute, got: {decoy!r}"

    with subtest("init writes the wrapper and the verbatim base into the upper"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.fail(f"test -e {HIDDEN_ETC_NIXOS}/hardware-configuration.nix")
        machine.succeed("nails init /mnt/data")
        machine.succeed(
            f"cat > {CONFIG} <<'EOF'\n"
            "hidden_volume_root = \"/mnt/data\"\n"
            "minimum_space_mb = 100\n"
            "EOF"
        )

        wrapper = machine.succeed(f"cat {HIDDEN_ETC_NIXOS}/hardware-configuration.nix")
        assert wrapper.count("./nails/configuration.nix") == 1, (
            f"wrapper should import the hidden module exactly once, got: {wrapper!r}"
        )
        assert "./hardware-configuration.base.nix" in wrapper, (
            f"wrapper should import the preserved base, got: {wrapper!r}"
        )
        base = machine.succeed(f"cat {HIDDEN_ETC_NIXOS}/hardware-configuration.base.nix")
        assert "boot.loader.grub.enable = false;" in base, (
            f"base should preserve the original hardware config, got: {base!r}"
        )
        assert "imports" not in base, f"base should be the verbatim no-imports original, got: {base!r}"
        link = machine.succeed(f"readlink {HIDDEN_ETC_NIXOS}/nails/configuration.nix").strip()
        assert link == "/mnt/data/config/nixos/configuration.nix", link
        machine.succeed("test -s /mnt/data/config/nixos/configuration.nix")

        # The composed files are valid Nix (what the pre-flight parse gate
        # checks; `--parse` only parses, it does not evaluate or realise).
        machine.succeed(f"nix-instantiate --parse {HIDDEN_ETC_NIXOS}/hardware-configuration.nix")
        machine.succeed(f"nix-instantiate --parse {HIDDEN_ETC_NIXOS}/hardware-configuration.base.nix")

        # The decoy's own file is untouched.
        machine.fail("test -e /etc/nixos/hardware-configuration.base.nix")
        machine.fail("test -e /etc/nixos/nails")

    with subtest("the nixos-config pre-flight check accepts the staged layout"):
        check = run_command_capture(machine, "check-hardware-wrapper", f"nails --config {CONFIG} check")
        rows = [line for line in check["stdout"].splitlines() if "nixos-config:" in line]
        assert rows and "overlay structure is valid" in rows[0], (
            f"expected the nixos-config check to pass: {check['stdout']!r}"
        )

    with subtest("the hidden /etc/nixos is the wrapper over the base"):
        canonical_activate(CONFIG, "--overlay-only", "activate-hardware")
        status = read_status_json(config_path=CONFIG)
        assert status["place"] == "hidden", status
        live = machine.succeed("cat /etc/nixos/hardware-configuration.nix")
        assert live == wrapper, f"the hidden /etc/nixos should show the wrapper, got: {live!r}"
        live_base = machine.succeed("cat /etc/nixos/hardware-configuration.base.nix")
        assert live_base == base, live_base
        machine.succeed("test -s /etc/nixos/nails/configuration.nix")
        machine.succeed("nix-instantiate --parse /etc/nixos/hardware-configuration.nix")

    with subtest("the decoy /etc/nixos is the original file after the way back"):
        canonical_deactivate(CONFIG, "deactivate-hardware")
        machine.fail("test -e /etc/nixos/nails")
        machine.fail("test -e /etc/nixos/hardware-configuration.base.nix")
        restored = machine.succeed("cat /etc/nixos/hardware-configuration.nix")
        assert restored == decoy, f"decoy hardware config changed: {restored!r}"
  '';
}
