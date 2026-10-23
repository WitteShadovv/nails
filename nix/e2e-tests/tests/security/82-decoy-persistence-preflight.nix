# Test 82: The decoy-persistence pre-flight refuses a persistent-log decoy
#
# A decoy that keeps a persistent journal, or runs rsyslog or auditd,
# records on its own disk what it logs while it shuts down for the soft-reboot
# into the hidden session and while it starts again on the way back, so
# activation must fail closed unless the operator explicitly accepts the risk.
# This node forces journald back to persistent storage (the standard decoy
# models an amnesic one) and runs rsyslogd (as syslog.service, the NixOS unit
# name) and auditd.
#
#   1. `nails check` and `nails activate` both refuse, naming each persistent
#      sink and the override; the refused activation leaves the plain decoy
#      root, no next root and no root upper on the hidden volume.
#   2. With --allow-persistent-decoy the activation soft-reboots into the
#      hidden root, and deactivation returns to the plain decoy.
{ self, pkgs, ... }:
let
  inherit (pkgs) lib;
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "decoy-persistence-preflight";
  meta.tags = [
    "security"
    "preflight"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      # vm-config models an amnesic decoy (volatile journald). Force a persistent
      # journal so the decoy-persistence check must fail closed.
      services.journald.settings.Journal.Storage = lib.mkForce "persistent";
      # Two more persistent log sinks the check must refuse.
      services.rsyslogd.enable = true;
      security.auditd.enable = true;
    };

  testScript = _: ''
    from nails_e2e import session

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    CONFIG = "/mnt/data/config/nails.toml"
    REFUSAL = [
        "persistent",
        "Storage=volatile",
        "syslog.service",
        "auditd",
        "--allow-persistent-decoy",
    ]

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    write_headless_config(CONFIG)

    # The decoy really presents persistent sinks, so a pass below is a genuine
    # override rather than an amnesic decoy slipping through.
    machine.succeed("grep -qi '^Storage=persistent' /etc/systemd/journald.conf")
    machine.wait_for_unit("syslog.service")
    machine.wait_for_unit("auditd.service")


    def assert_refused(label, command):
        result = run_command_capture(label, command)
        assert_command_failed(result)
        combined = {"out": result["stdout"] + result["stderr"]}
        assert_result_contains(combined, REFUSAL, stream="out")
        session.assert_decoy_root(machine)
        machine.succeed("test ! -e /mnt/data/root/upper")
        status = read_status_json(config_path=CONFIG)
        assert status["place"] == "decoy", status


    with subtest("check refuses the persistent-log decoy"):
        assert_refused(
            "preflight-decoy-persistence-check",
            f"nails --config {CONFIG} check --overlay-only",
        )

    with subtest("activate refuses it with remediation guidance and leaves nothing"):
        assert_refused(
            "preflight-decoy-persistence-activate",
            f"nails --config {CONFIG} activate -y --overlay-only",
        )

    with subtest("--allow-persistent-decoy overrides the refusal"):
        canonical_activate(
            CONFIG, "--overlay-only --allow-persistent-decoy", "activate-accepted"
        )
        status = read_status_json(config_path=CONFIG)
        assert status["place"] == "hidden", status
        canonical_deactivate(CONFIG, "deactivate-accepted")
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        status = read_status_json(config_path=CONFIG)
        assert status["place"] == "decoy", status
  '';
}
