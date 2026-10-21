# The README's terminal captures, taken on a decoy set up as the docs recommend.
#
# docs/assets/screenshots/ holds the output of `nails check`, `nails activate`
# and `nails status --json` from one run of this test (docs/assets/README.md
# says how to cut it from the log). The decoy is the standard test VM with what
# docs/decoy-requirements.md asks of a clean decoy: a closed lid locks the
# screen instead of suspending, systemd-coredump keeps no core on the disk, and
# the static binary sits on the hidden volume, off the decoy's PATH, and runs by
# its full path through sudo, as the README's quick start shows. On that decoy
# `check` and `activate` print no warning; a warning fails the test, so the
# captures cannot show one that only the test VM causes.
{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
in
{
  name = "session-readme-captures";
  meta.tags = [
    "session"
    "preflight"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];

      # docs/decoy-requirements.md, "Suspend and the lid switch".
      services.logind.settings.Login = {
        HandleLidSwitch = "lock";
        HandleLidSwitchExternalPower = "lock";
        HandleLidSwitchDocked = "ignore";
        IdleAction = "ignore";
      };

      # docs/decoy-requirements.md, NixOS: core dumps kept off the disk.
      systemd.coredump.settings.Coredump = {
        Storage = "none";
        ProcessSizeMax = 0;
      };
    };

  testScript = _: ''
    import json

    from nails_e2e import session

    NAILS = "/mnt/data/nails"
    # The CLI's warning mark: `[WARN]` when standard output is not a terminal,
    # as here, and the warning sign on one.
    WARNING_MARKS = ("[WARN]", "⚠")


    def operator(command):
        """`command` run as the README runs it: by testuser, through sudo."""
        return f"su - testuser -c 'sudo {NAILS} {command}'"


    def warnings_in(text):
        return [
            line for line in text.splitlines() if any(mark in line for mark in WARNING_MARKS)
        ]


    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("the binary on the hidden volume lays it out"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(
            f"install -m 0755 ${self.packages.x86_64-linux.nails}/bin/nails {NAILS}"
        )
        machine.succeed(operator("init /mnt/data"))

    # The test prints the output of each command whole for the captures:
    # `check` and the status JSON through the driver's log, the activation log
    # (standard output and standard error together) as it is.
    with subtest("check prints no warning"):
        rc, out = machine.execute(operator("check --overlay-only") + " 2>/run/check.stderr")
        machine.log(out)
        assert rc == 0, f"check refused the decoy (rc={rc})"
        stderr = machine.succeed("cat /run/check.stderr")
        found = warnings_in(out) + warnings_in(stderr)
        assert not found, f"check warned on a clean decoy: {found}"
        tally = out.strip().splitlines()[-1]
        assert "0 warnings, 0 failed" in tally, tally

    with subtest("activate prints no warning and enters the hidden session"):
        session.follow_soft_reboot(
            machine,
            operator("activate -y --overlay-only") + " > /mnt/data/activate.log 2>&1",
            "activate",
        )
        activation = machine.succeed("cat /mnt/data/activate.log")
        print(activation)
        session.assert_hidden_root(machine)
        found = warnings_in(activation)
        assert not found, f"activate warned on a clean decoy: {found}"

    with subtest("status --json reports the hidden session"):
        machine.succeed(operator("status --json") + " > /run/status.json")
        status = json.loads(machine.succeed("cat /run/status.json"))["data"]
        machine.log(json.dumps(status, indent=1))
        assert status["place"] == "hidden", status
        assert status["attention"] is None, status
  '';
}
