# Test 65: Help and Version Do Not Leak Paths
# Self-check: uses subtests, hard assertions, shared lib helpers, tags contract, no sleep.

{ self, pkgs, ... }:
let contractHelpers = import ./../../lib/contract-helpers.nix;
in {
  name = "help-version-no-leak";
  meta.tags = [ "contract" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages =
      [ self.packages.x86_64-linux.nails pkgs.python3 ];
  };

  testScript = _: ''
    ${contractHelpers.runCommandCaptureFn}
    ${contractHelpers.assertNoBlockedSubstringsFn}

    blocked_paths = [
        "/mnt/hidden-volume",
        "/mnt/hidden-volume/logs",
        "/mnt/hidden-volume/state.json",
        "/var/log/nails",
        "/etc/nixos/nails",
    ]

    def assert_help_or_version_is_clean(name, command, expected_fragment):
        result = run_command_capture(name, command)
        assert result["rc"] == 0, result
        assert expected_fragment in result["stdout"], result
        assert_no_blocked_substrings(result["combined"], blocked_paths, name)

    with subtest("boot test VM"):
        machine.start()
        machine.wait_for_unit("multi-user.target")

    with subtest("top-level help does not leak default paths"):
        assert_help_or_version_is_clean("help-main", "nails --help", "NixOS Anti-forensics Isolation & Layering System")

    with subtest("activate help does not leak default paths"):
        assert_help_or_version_is_clean("help-activate", "nails activate --help", "--no-color")

    with subtest("status help does not leak default paths"):
        assert_help_or_version_is_clean("help-status", "nails status --help", "--plain")

    with subtest("version output does not leak default paths"):
        version = run_command_capture("version-main", "nails --version")
        assert version["rc"] == 0, version
        assert version["stdout"].startswith("nails "), version
        assert_no_blocked_substrings(version["combined"], blocked_paths, "nails --version")
  '';
}
