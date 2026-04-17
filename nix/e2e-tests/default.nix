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
    standard-deactivation-forensic = pkgs.testers.runNixOSTest
      (importTest ./tests/05-standard-deactivation-forensic.nix);
    snapshot-diff =
      pkgs.testers.runNixOSTest (importTest ./tests/06-snapshot-diff.nix);
    performance =
      pkgs.testers.runNixOSTest (importTest ./tests/07-performance.nix);
    config-handling =
      pkgs.testers.runNixOSTest (importTest ./tests/08-config-handling.nix);
    state-integrity =
      pkgs.testers.runNixOSTest (importTest ./tests/09-state-integrity.nix);
    permissions-security = pkgs.testers.runNixOSTest
      (importTest ./tests/10-permissions-security.nix);
    reactivation =
      pkgs.testers.runNixOSTest (importTest ./tests/11-reactivation.nix);
    status-verify =
      pkgs.testers.runNixOSTest (importTest ./tests/12-status-verify.nix);
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
    {
      name = "config-handling";
      path = tests.config-handling;
    }
    {
      name = "status-verify";
      path = tests.status-verify;
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
      name = "standard-deactivation-forensic";
      path = tests.standard-deactivation-forensic;
    }
    {
      name = "snapshot-diff";
      path = tests.snapshot-diff;
    }
    {
      name = "performance";
      path = tests.performance;
    }
    {
      name = "config-handling";
      path = tests.config-handling;
    }
    {
      name = "state-integrity";
      path = tests.state-integrity;
    }
    {
      name = "permissions-security";
      path = tests.permissions-security;
    }
    {
      name = "reactivation";
      path = tests.reactivation;
    }
    {
      name = "status-verify";
      path = tests.status-verify;
    }
  ];

  # Interactive driver
  inherit interactive-driver;
}
