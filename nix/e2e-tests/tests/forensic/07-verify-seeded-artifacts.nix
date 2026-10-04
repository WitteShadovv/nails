# Test 07: verify flags every seeded artifact class and never false-positives
# on its own pipeline.
#
# A focused behaviour test for the verify rework: seed one instance of each
# single-path artifact class from the shared registry on the decoy, and confirm
# verify reports every one. Then confirm that running verify through a pipe
# (`nails verify | tee`) raises no *critical* process finding — the process check
# matches the binary by identity, not any command line that merely contains the
# word "nails". Finally, a clean host with the seeds removed verifies with exit 0.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "verify-seeded-artifacts";
  meta.tags = [
    "forensic"
    "contract"
  ];

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      };
  };

  testScript = _: ''
    import shlex

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runVerifyFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)
    # The hidden volume is mounted at /mnt/data so the hidden-root artifact
    # (state.json) resolves to a real path the scan can find.
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    def messages(payload):
        return [finding["message"] for finding in payload["findings"]]

    with subtest("seed one instance of each single-path artifact class"):
        # Runtime (Warn): the per-activation runtime directory.
        machine.succeed("mkdir -p /run/nails")
        # Runtime (Warn): the pivot staging base on the /run tmpfs.
        machine.succeed("mkdir -p /run/nails-pivot")
        # Decoy (Critical): the pivot staging base used by earlier builds, which
        # must never appear on the persistent decoy root.
        machine.succeed("mkdir -p /mnt/nails-pivot")
        # Decoy (Critical): the staged NixOS module link on the decoy.
        machine.succeed("mkdir -p /etc/nixos/nails")
        machine.succeed("touch /etc/nixos/nails/configuration.nix")
        # Hidden-root (Info): the activation state file on the hidden volume.
        machine.succeed("touch /mnt/data/state.json")

    with subtest("verify reports every seeded artifact class"):
        rc, payload = run_verify(
            "--deep", config_path=headless_config
        )
        found = messages(payload)
        for expected in [
            "/run/nails",
            "/run/nails-pivot",
            "/mnt/nails-pivot",
            "/etc/nixos/nails/configuration.nix",
            "/mnt/data/state.json",
        ]:
            assert any(expected in message for message in found), \
                f"verify missed seeded artifact {expected}: {payload}"
        # A decoy-scope critical artifact drives the critical exit code.
        assert rc == 11, f"expected critical exit 11, got {rc}: {payload}"
        assert payload["status"] == "critical", payload

    with subtest("piping verify through tee raises no critical process finding"):
        # The shell running `nails verify | tee` has "nails" on its command line,
        # but it is not the NAILS binary by identity, so it must not be critical.
        machine.succeed(
            "bash -lc "
            + shlex.quote(
                "nails --no-log-file --config "
                + headless_config
                + " verify | tee /tmp/verify-tee.out"
            )
        )
        rc, payload = run_verify(config_path=headless_config)
        critical_process = [
            finding
            for finding in payload["findings"]
            if finding["category"] == "process" and finding["severity"] == "critical"
        ]
        assert not critical_process, \
            f"verify pipeline produced a critical process finding: {critical_process}"

    with subtest("a clean host verifies with exit 0"):
        machine.succeed("rm -rf /run/nails /run/nails-pivot /mnt/nails-pivot /etc/nixos/nails")
        machine.succeed("rm -f /mnt/data/state.json")
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
        machine.succeed("rm -rf /mnt/data")
        rc, payload = run_verify(config_path=headless_config)
        assert rc == 0, f"expected clean verify exit 0, got {rc}: {payload}"
        assert payload["status"] == "secure", payload
        # The clean headline still discloses what it did not inspect.
        assert payload["areas_not_checked"], payload

    print("\n=== Seeded-artifact verify tests passed ===")
  '';
}
