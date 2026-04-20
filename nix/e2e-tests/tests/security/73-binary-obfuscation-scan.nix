# Test 73: Binary Obfuscation Scan
# Self-checks: with subtest; no time.sleep sync; hard assertions only; meta.tags set; shared helpers only; forensic invariants preserved.

{ self, pkgs, ... }:
let testBinary = "${self.packages.x86_64-linux.nails}/bin/nails";
in {
  name = "binary-obfuscation-scan";
  meta.tags = [ "security" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages =
      [ self.packages.x86_64-linux.nails pkgs.binutils ];
  };

  testScript = _: ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    binary = "${testBinary}"
    strings_output = machine.succeed(f"strings {binary}")
    lines = strings_output.splitlines()

    with subtest("security-critical paths and canaries are absent from plaintext strings"):
        forbidden_absent = [
            "nails.toml",
            "/var/log/nails",
            "/tmp/nails.log",
            "/var/log/nails.log",
            "/mnt/hidden-volume",
            ".nails/state.json",
            "NAILS_CANARY",
        ]

        leaks = {
            token: [line for line in lines if token in line]
            for token in forbidden_absent
        }
        leaks = {token: hits for token, hits in leaks.items() if hits}
        assert leaks == {}, f"Unexpected sensitive plaintext strings in binary: {leaks}"

    with subtest("public-facing tokens stay bounded to non-path contexts"):
        nails_log_hits = [line for line in lines if "nails.log" in line]
        hidden_volume_hits = [line for line in lines if "hidden-volume" in line]

        assert nails_log_hits, "Expected at least one public nails.log token for status/help output coverage"
        assert hidden_volume_hits, "Expected at least one public hidden-volume token for preflight/status output coverage"

        unexpected_nails_log_hits = [
            line for line in nails_log_hits
            if "/tmp/nails.log" in line or "/var/log/nails.log" in line or "/mnt/hidden-volume" in line
        ]
        unexpected_hidden_volume_hits = [
            line for line in hidden_volume_hits
            if "/mnt/hidden-volume" in line or "/tmp/test-hidden-volume" in line
        ]

        assert unexpected_nails_log_hits == [], \
            f"nails.log leaked in path-like context: {unexpected_nails_log_hits}"
        assert unexpected_hidden_volume_hits == [], \
            f"hidden-volume leaked in path-like context: {unexpected_hidden_volume_hits}"
  '';
}
