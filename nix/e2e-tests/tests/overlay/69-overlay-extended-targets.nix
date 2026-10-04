# Test 69: Overlay Extended Targets
# Historical name only: exercises explicit persistent overlays for additional
# targets, and requires those lower directories to exist before activation.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "overlay-extended-targets";
  meta.tags = [ "overlay" ];

  testScript = _: ''
    ${testHelpers.writeExtendedConfigFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${testHelpers.readStatusJsonFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mkdir -p /srv /opt /var/lib")

    config_path = "/tmp/nails-extended.toml"
    write_extended_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("mkdir -p /opt")
    machine.succeed(
        "mkdir -p /mnt/data/{root,tmp,srv,opt} /mnt/data/.work/{root,tmp,srv,opt}"
    )

    with subtest("phase 1: activate all extended targets"):
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --session keep -y"
        )
        for path in ["/var", "/tmp", "/srv", "/opt"]:
            assert_overlay_mounted(path)
        status = read_status_json(config_path=config_path)
        active_paths = {overlay["mount_point"] for overlay in status["overlays"]}
        assert {"/var", "/tmp", "/srv", "/opt"}.issubset(active_paths), status

    with subtest("phase 2: each extended target has an independent upperdir"):
        machine.succeed("printf %s var > /var/nails-var-marker")
        machine.succeed("printf %s tmp > /tmp/nails-tmp-marker")
        machine.succeed("printf %s srv > /srv/nails-srv-marker")
        machine.succeed("mkdir -p /opt/nails-test && printf %s opt > /opt/nails-test/marker")
        machine.succeed("test -f /mnt/data/var/nails-var-marker")
        machine.succeed("test -f /mnt/data/tmp/nails-tmp-marker")
        machine.succeed("test -f /mnt/data/srv/nails-srv-marker")
        machine.succeed("test -f /mnt/data/opt/nails-test/marker")

    with subtest("phase 3: emergency cleanup unmounts every extended target"):
        machine.succeed(f"nails --config {config_path} emergency")
        assert_no_overlays(["/var", "/tmp", "/srv", "/opt"])
        machine.fail("test -e /var/nails-var-marker")
        machine.fail("test -e /tmp/nails-tmp-marker")
        machine.fail("test -e /srv/nails-srv-marker")
        machine.fail("test -e /opt/nails-test/marker")
  '';
}
