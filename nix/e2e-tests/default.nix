{ self, pkgs }:

let
  # Load individual test modules
  importTest = path: import path { inherit self pkgs; };

  # Individual test suites (each is a complete test module)
  tests = {
    basic-workflow =
      pkgs.testers.runNixOSTest (importTest ./tests/01-basic-workflow.nix);
    verify = pkgs.testers.runNixOSTest (importTest ./tests/02-verify.nix);
    emergency = pkgs.testers.runNixOSTest (importTest ./tests/03-emergency.nix);
    forensic-clean =
      pkgs.testers.runNixOSTest (importTest ./tests/04-forensic-clean.nix);
    snapshot-diff =
      pkgs.testers.runNixOSTest (importTest ./tests/06-snapshot-diff.nix);
    performance =
      pkgs.testers.runNixOSTest (importTest ./tests/07-performance.nix);
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

in tests // {
  ci = pkgs.linkFarm "e2e-ci" [
    {
      name = "basic-workflow";
      path = tests.basic-workflow;
    }
    {
      name = "verify";
      path = tests.verify;
    }
    {
      name = "emergency";
      path = tests.emergency;
    }
  ];

  # Run all tests
  all = pkgs.linkFarm "e2e-all" [
    {
      name = "basic-workflow";
      path = tests.basic-workflow;
    }
    {
      name = "verify";
      path = tests.verify;
    }
    {
      name = "emergency";
      path = tests.emergency;
    }
    {
      name = "forensic-clean";
      path = tests.forensic-clean;
    }
    {
      name = "snapshot-diff";
      path = tests.snapshot-diff;
    }
    {
      name = "performance";
      path = tests.performance;
    }
  ];

  # Interactive driver
  inherit interactive-driver;
}
