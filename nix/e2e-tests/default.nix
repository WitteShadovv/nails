{ self, pkgs }:

let
  # Base VM test runner using NixOS VM testing
  runTest = testName: testScript:
    pkgs.testers.runNixOSTest {
      name = "e2e-${testName}";

      # VM configuration will be defined in individual tests
      nodes.machine = { ... }: {
        imports = [ ./lib/vm-config.nix ];

        # Inject NAILS binary into VM
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      };

      inherit testScript;
    };

  # Interactive test driver (for debugging)
  interactive-driver = pkgs.writeShellScriptBin "interactive-test" ''
    #!/usr/bin/env bash
    echo "Starting interactive NAILS E2E test VM..."
    echo "You will be dropped into a shell inside the VM"
    echo "Use 'exit' to quit"
    echo ""
    nix run .#checks.x86_64-linux.e2e-basic-workflow --interactive || true
  '';

in {
  # Individual test suites
  basic-workflow =
    runTest "basic-workflow" (builtins.readFile ./tests/01-basic-workflow.nix);
  emergency = runTest "emergency" (builtins.readFile ./tests/03-emergency.nix);
  forensic-clean =
    runTest "forensic-clean" (builtins.readFile ./tests/04-forensic-clean.nix);
  snapshot-diff =
    runTest "snapshot-diff" (builtins.readFile ./tests/06-snapshot-diff.nix);
  performance =
    runTest "performance" (builtins.readFile ./tests/07-performance.nix);

  # Run all tests
  all = pkgs.linkFarm "e2e-all" [
    {
      name = "basic-workflow";
      path = runTest "basic-workflow"
        (builtins.readFile ./tests/01-basic-workflow.nix);
    }
    {
      name = "emergency";
      path = runTest "emergency" (builtins.readFile ./tests/03-emergency.nix);
    }
    {
      name = "forensic-clean";
      path = runTest "forensic-clean"
        (builtins.readFile ./tests/04-forensic-clean.nix);
    }
    {
      name = "snapshot-diff";
      path = runTest "snapshot-diff"
        (builtins.readFile ./tests/06-snapshot-diff.nix);
    }
    {
      name = "performance";
      path =
        runTest "performance" (builtins.readFile ./tests/07-performance.nix);
    }
  ];

  # Interactive driver
  inherit interactive-driver;
}
