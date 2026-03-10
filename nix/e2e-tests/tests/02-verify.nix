# Story 13.4b: Verify Command Contract Test
# Tests clean, dirty, active, and post-emergency verification states

{ self, ... }:
let hiddenVolume = import ./../lib/hidden-volume.nix;
in {
  name = "verify";

  nodes = {
    machine = { ... }: {
      imports = [ ./../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };
  };

  testScript = _: ''
        import json

        def run_verify(args=""):
            command = "nails verify --json"
            if args:
                command = f"{command} {args}"
            machine.succeed(
                f'''bash -lc 'set +e; output="$({command} 2>/tmp/verify.stderr)"; rc=$?; \
    printf "%s" "$output" > /tmp/verify.stdout; printf "%s" "$rc" > /tmp/verify.rc' '''
            )
            status = int(machine.succeed("cat /tmp/verify.rc"))
            output = machine.succeed("cat /tmp/verify.stdout")
            return status, json.loads(output)

        machine.start()
        machine.wait_for_unit("multi-user.target")

        print("\n=== Verifying clean decoy state ===")
        status, payload = run_verify()
        assert status == 0, f"Expected clean verify exit 0, got {status}"
        assert payload["status"] == "Secure", f"Expected Secure verify result, got: {payload}"
        print("✓ Clean decoy state verifies as Secure")

        print("\n=== Verifying artifact detection ===")
        machine.succeed("touch /tmp/nails.log")
        status, payload = run_verify()
        assert status == 1, f"Expected artifact verify exit 1, got {status}"
        assert payload["status"] == "Warning", f"Expected Warning verify result, got: {payload}"
        assert any("/tmp/nails.log" in finding["message"] for finding in payload["findings"]), \
            f"Expected /tmp/nails.log finding, got: {payload}"
        machine.succeed("rm -f /tmp/nails.log")
        print("✓ Verify reports decoy artifacts")

        print("\n=== Verifying active overlay detection ===")
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("sudo nails activate -y")

        status, payload = run_verify("--deep")
        assert status == 1, f"Expected active verify exit 1, got {status}"
        assert payload["status"] == "Critical", f"Expected Critical verify result, got: {payload}"
        assert any("Overlay mount found" in finding["message"] for finding in payload["findings"]), \
            f"Expected overlay finding, got: {payload}"
        print("✓ Verify reports active overlays as Critical")

        print("\n=== Verifying post-emergency cleanup ===")
        machine.succeed("sudo nails emergency")

        status, payload = run_verify("--deep")
        assert status == 0, f"Expected clean verify exit 0 after emergency, got {status}"
        assert payload["status"] == "Secure", f"Expected Secure after emergency, got: {payload}"
        print("✓ Verify returns to Secure after emergency cleanup")

        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
        print("\n=== Verify Command Tests Passed ===")
  '';
}
