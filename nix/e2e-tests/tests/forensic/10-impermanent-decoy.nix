# Test 10 (forensic): an impermanent decoy is refused and nothing is left behind
#
# The whole-root session leaves the decoy by mounting its root device again at
# /run/nextroot, which a volatile tmpfs root (lib/impermanent-decoy.nix: a tmpfs
# `/` over an on-disk Nix store, with only /var/lib/nixos persisted on
# /persist) does not have. So:
#
#   1. `nails check` fails its `decoy-root` check on this host (exit 4);
#   2. `nails activate` is refused by the same pre-flight (exit 4) before it
#      changes anything: no next root, no runtime directory, no overlay, no
#      soft-reboot, the decoy root is still the tmpfs, status still reports
#      the plain decoy, the hidden root's upper holds nothing, and the
#      persisted decoy state on /persist is byte-identical.
{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "impermanent-decoy";
  meta.tags = [
    "forensic"
    "slow"
  ];

  # A store-image boot needs more than the default budget.
  globalTimeout = 1800;

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/impermanent-decoy.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    import json

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}

    CONFIG = "/mnt/data/config/nails.toml"


    def persisted_state():
        return machine.succeed(
            "find /persist -xdev -printf '%p %y %m %s %T@\\n' | LC_ALL=C sort; "
            "find /persist -xdev -type f -exec sha256sum {} + | LC_ALL=C sort"
        )


    def nothing_left_behind():
        assert machine.succeed("findmnt -no FSTYPE /").strip() == "tmpfs"
        machine.fail("grep -q ' /run/nextroot' /proc/self/mountinfo")
        machine.fail("test -e /run/overlay-runtime")
        machine.fail("grep -q 'upperdir=/mnt/data' /proc/self/mountinfo")
        machine.fail("test -e /run/systemd/system/systemd-soft-reboot.service.d")
        count = machine.succeed("systemctl show -p SoftRebootsCount --value").strip()
        assert count == "0", f"SoftRebootsCount={count}"
        upper = machine.succeed(
            # No upper at all is the expected case: find fails then.
            "{ find /mnt/data/root/upper -mindepth 1 2>/dev/null || true; } | head -20"
        ).strip()
        assert upper == "", f"activation wrote into the hidden upper: {upper}"
        status = read_status_json(config_path=CONFIG)
        assert status["place"] == "decoy", status
        assert persisted_state() == persisted_before, (
            "the persisted decoy state changed"
        )


    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("the decoy root is a volatile tmpfs with the persisted trees bound"):
        assert machine.succeed("findmnt -n -o FSTYPE /").strip() == "tmpfs", (
            "the impermanent decoy root must be a tmpfs"
        )
        machine.succeed("mountpoint -q /persist")
        machine.succeed("mountpoint -q /var/lib/nixos")

    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    write_headless_config(CONFIG)
    persisted_before = persisted_state()

    with subtest("check fails the decoy-root check"):
        rc, out = machine.execute(
            f"nails --config {CONFIG} --json check --overlay-only 2>/dev/null"
        )
        assert rc == 4, f"check exited {rc}: {out}"
        checks = {row["name"]: row for row in json.loads(out)["data"]["checks"]}
        assert checks["decoy-root"]["status"] == "fail", checks.get("decoy-root")
        machine.log(f"decoy-root: {checks['decoy-root']['message']}")
        nothing_left_behind()

    with subtest("activate is refused by the same check and leaves nothing behind"):
        rc, out = machine.execute(
            f"nails --config {CONFIG} activate -y --overlay-only 2>&1"
        )
        machine.log(out)
        assert rc == 4, f"activate exited {rc} on an impermanent decoy: {out}"
        assert "decoy-root" in out or "decoy root" in out.lower(), out
        nothing_left_behind()
  '';
}
