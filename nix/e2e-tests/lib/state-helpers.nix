{
  captureCommandFns = ''
    def capture_command(label, command):
        import shlex

        prefix = "/tmp/" + label
        machine.succeed(
            "bash -lc "
            + shlex.quote(
                "set +e; "
                + command
                + f" > {prefix}.stdout 2> {prefix}.stderr; printf \"%s\" \"$?\" > {prefix}.rc"
            )
        )
        rc = int(machine.succeed(f"cat {shlex.quote(prefix + '.rc')}").strip())
        stdout = machine.succeed(f"cat {shlex.quote(prefix + '.stdout')}")
        stderr = machine.succeed(f"cat {shlex.quote(prefix + '.stderr')}")
        return rc, stdout, stderr

    def run_detached_captured_command(unit_name, label, command):
        prefix = "/tmp/" + label
        run_detached_command(
            unit_name,
            "set +e; "
            + command
            + f" > {prefix}.stdout 2> {prefix}.stderr; printf \"%s\" \"$?\" > {prefix}.rc",
        )

    def wait_for_captured_command(label, timeout=120):
        import shlex

        prefix = "/tmp/" + label
        machine.wait_until_succeeds(
            f"test -f {shlex.quote(prefix + '.rc')}",
            timeout=timeout,
        )
        rc = int(machine.succeed(f"cat {shlex.quote(prefix + '.rc')}").strip())
        stdout = machine.succeed(f"cat {shlex.quote(prefix + '.stdout')}")
        stderr = machine.succeed(f"cat {shlex.quote(prefix + '.stderr')}")
        return rc, stdout, stderr
  '';

  installSlowNixosRebuildGateFn = ''
    def install_slow_nixos_rebuild_gate(
        bin_dir="/tmp/nails-test-bin",
        gate_path="/tmp/nails-nixos-rebuild.gate",
        entered_path="/tmp/nails-nixos-rebuild-entered",
    ):
        import shlex

        real_nixos_rebuild = machine.succeed("command -v nixos-rebuild").strip()
        wrapper_path = bin_dir + "/nixos-rebuild"

        machine.succeed(f"mkdir -p {shlex.quote(bin_dir)}")
        machine.succeed(f"rm -f {shlex.quote(entered_path)}")
        machine.succeed(f"touch {shlex.quote(gate_path)}")
        machine.succeed(
            """cat > %s <<'EOF'
    #!/bin/sh
    set -eu
    : > %s
    while [ -e %s ]; do
      sleep 0.1
    done
    exec %s "$@"
    EOF
    chmod 0755 %s"""
            % (wrapper_path, entered_path, gate_path, real_nixos_rebuild, wrapper_path)
        )

        return bin_dir, gate_path, entered_path
  '';

  installActivationGateFn = ''
    def install_activation_gate(
        gate_path="/run/nails-tests/nails-activation.gate",
        entered_path="/run/nails-tests/nails-activation-entered",
    ):
        import shlex

        gate_dir = "/".join(gate_path.split("/")[:-1]) or "."
        machine.succeed(f"mkdir -p {shlex.quote(gate_dir)}")
        machine.succeed(f"rm -f {shlex.quote(entered_path)}")
        machine.succeed(f"touch {shlex.quote(gate_path)}")

        env_prefix = (
            "NAILS_TEST_ACTIVATING_GATE_PATH="
            + shlex.quote(gate_path)
            + " "
            + "NAILS_TEST_ACTIVATING_ENTERED_PATH="
            + shlex.quote(entered_path)
        )

        return env_prefix, gate_path, entered_path
  '';

  installDeactivationGateFn = ''
    def install_deactivation_gate(
        gate_path="/run/nails-tests/nails-deactivation.gate",
        entered_path="/run/nails-tests/nails-deactivation-entered",
    ):
        import shlex

        gate_dir = "/".join(gate_path.split("/")[:-1]) or "."
        machine.succeed(f"mkdir -p {shlex.quote(gate_dir)}")
        machine.succeed(f"rm -f {shlex.quote(entered_path)}")
        machine.succeed(f"touch {shlex.quote(gate_path)}")

        env_prefix = (
            "NAILS_TEST_DEACTIVATING_GATE_PATH="
            + shlex.quote(gate_path)
            + " "
            + "NAILS_TEST_DEACTIVATING_ENTERED_PATH="
            + shlex.quote(entered_path)
        )

        return env_prefix, gate_path, entered_path
  '';
}
