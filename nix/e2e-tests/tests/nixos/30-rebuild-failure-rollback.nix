# Test 30: A failed hidden switch is reported truthfully, and `nails reapply`
# applies the configuration once it is fixed.
#
# With `nixos_switch_required = false` a broken hidden configuration must not
# roll the overlays back: activation keeps the overlays and the session, exits
# with the dedicated success-with-warnings code (9), and reports
# `success_with_warnings` with a warnings array under `--json`. After the hidden
# configuration is fixed, `nails reapply` re-runs the build + switch in place
# (no reboot) and applies the hidden marker.
#
# Both configurations are flakes (nails builds `#…system.build.toplevel`
# explicitly). The broken one's toplevel throws on evaluation, so the explicit
# build fails and drives the success-with-warnings path. The fixed one points at
# the VM's own `nails-hidden` specialisation (the running system plus
# fixtures/hidden-config/module.nix), already in the guest store, through
# `builtins.storePath` — so the reapply build realises an already-present path
# offline, and switching to a specialisation of the running system leaves the test
# framework's instrumentation (backdoor, qemu-vm filesystems) in place instead of
# stopping the backdoor and unmounting the driver's store. `nixos_flake` is set in
# the config file (not just on the activate CLI) so reapply resolves the same
# flake.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "rebuild-failure-rollback";
  meta.tags = [ "nixos" ];

  nodes.machine =
    { lib, pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.python3
      ];
      nix.settings.experimental-features = [
        "nix-command"
        "flakes"
      ];
      # The VM is offline. The fixed hidden toplevel is the specialisation below,
      # already in the guest's (host-shared) store, so the explicit `nix build`
      # realises an already-present path. mkForce [] keeps the guest from querying
      # an unreachable substituter for it (no profile or qemu-vm default may
      # reintroduce one).
      nix.settings.substituters = lib.mkForce [ ];
      # The fixed hidden system: the running decoy plus the marker module.
      # Declaring it as a specialisation builds its toplevel on the host with the
      # VM and places it in the guest store, and keeps the VM's instrumentation in
      # the hidden config so switch-to-configuration never tears the driver down.
      specialisation.nails-hidden.configuration = {
        imports = [ ./../../fixtures/hidden-config/module.nix ];
      };
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}

    import json
    import shlex
    import uuid

    def run_command_capture(label, command):
        stem = f"/tmp/{label}-{uuid.uuid4().hex}"
        machine.succeed(
            "bash -lc "
            + shlex.quote(
                "set +e; "
                + command
                + f" > {stem}.stdout 2> {stem}.stderr; "
                + f"printf '%s' \"$?\" > {stem}.rc"
            )
        )
        return (
            int(machine.succeed(f"cat {stem}.rc")),
            machine.succeed(f"cat {stem}.stdout"),
            machine.succeed(f"cat {stem}.stderr"),
        )

    def last_json_line(text):
        lines = [line for line in text.splitlines() if line.strip()]
        assert lines, f"expected at least one output line, got: {text!r}"
        return json.loads(lines[-1])

    # A trivial lock for the input-less hidden flake, on the hidden volume. nails
    # never runs `nix flake update`, so a committed lock is required; this one keeps
    # the flake fully offline with no inputs to resolve.
    TRIVIAL_LOCK = '{"nodes":{"root":{}},"root":"root","version":7}'

    def write_broken_hidden_flake():
        # A syntactically valid flake whose toplevel throws on evaluation. The
        # `nixosConfigurations.nails-e2e` attribute exists (so the activation's
        # attribute preflight — a `hasAttr` check that never forces the toplevel —
        # passes and the switch is attempted), but the explicit `nix build` of
        # `…system.build.toplevel` forces the throw and fails, which is what drives
        # the success-with-warnings exit path.
        machine.succeed("""cat > /mnt/data/nixos/flake.nix <<'EOF'
    {
      outputs = { self }: {
        nixosConfigurations.nails-e2e.config.system.build.toplevel =
          builtins.throw "deliberately broken hidden configuration";
      };
    }
    EOF""")
        machine.succeed(
            "printf '%s' " + shlex.quote(TRIVIAL_LOCK) + " > /mnt/data/nixos/flake.lock"
        )

    def write_fixed_hidden_flake(spec_toplevel):
        # The fixed hidden toplevel is the VM's own `nails-hidden` specialisation,
        # already in the guest store. `builtins.storePath` references that exact
        # path, so the reapply build realises an already-present path offline (no
        # nixpkgs evaluation, no fetch). Switching to it applies the marker module.
        # Python injects the resolved store path, so a quoted heredoc is safe: the
        # shell performs no expansion on the already-complete Nix source.
        machine.succeed(
            "cat > /mnt/data/nixos/flake.nix <<'EOF'\n"
            "{\n"
            "  outputs = { self }: {\n"
            "    nixosConfigurations.nails-e2e.config.system.build.toplevel =\n"
            f"      builtins.storePath \"{spec_toplevel}\";\n"
            "  };\n"
            "}\n"
            "EOF"
        )

    machine.start()
    machine.wait_for_unit("multi-user.target")

    flake_ref = "/mnt/data/nixos#nails-e2e"
    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)
    # Point nails at the hidden flake through the config file, not only the activate
    # CLI, so `nails reapply` (a separate invocation) resolves the same flake.
    # Inserted after the top-level hidden_volume_root key so it is never folded into
    # the trailing [[overlays]] table, which `deny_unknown_fields` would reject.
    machine.succeed(
        "sed -i "
        + shlex.quote(
            "/^hidden_volume_root = /a nixos_flake = \"" + flake_ref + "\""
        )
        + " "
        + shlex.quote(headless_config)
    )
    machine.succeed(f"grep -qx 'nixos_flake = \"{flake_ref}\"' {shlex.quote(headless_config)}")
    # write_headless_config already sets `nixos_switch_required = false`, so a
    # failed switch keeps the overlays and session (the observable warning
    # outcome) instead of rolling back.
    machine.succeed(f"grep -qx 'nixos_switch_required = false' {shlex.quote(headless_config)}")

    with subtest("prepare a broken hidden flake"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mkdir -p /mnt/data/nixos")
        write_broken_hidden_flake()

    with subtest("a failed switch exits 9 and reports success_with_warnings"):
        rc, stdout, stderr = run_command_capture(
            "rebuild-failure",
            f"nails --config {headless_config} activate --session keep -y --json",
        )
        assert rc == 9, f"expected success-with-warnings exit code 9, got rc={rc} stderr={stderr!r}"
        result = last_json_line(stdout)
        assert result["status"] == "success_with_warnings", result
        assert result["ok"] is True, result
        warnings = result.get("warnings", [])
        assert warnings, f"expected a non-empty warnings array, got: {result}"
        assert any("not applied" in w for w in warnings), warnings

    with subtest("the failed switch leaves overlays mounted and state active"):
        payload = json.loads(
            machine.succeed(f"nails --config {headless_config} status --json")
        )["data"]
        assert str(payload["state"]["kind"]).startswith("active"), payload
        assert payload.get("hidden_config_warning"), \
            f"status must report the hidden configuration as not applied, got: {payload}"
        machine.succeed("mountpoint -q /etc")
        machine.succeed("mountpoint -q /home")

    with subtest("reapply applies the hidden marker once the config is fixed"):
        # Resolve the prebuilt specialisation toplevel and point the fixed flake at
        # it, so reapply realises an already-present store path offline.
        spec_toplevel = machine.succeed(
            "readlink -f /run/current-system/specialisation/nails-hidden"
        ).strip()
        write_fixed_hidden_flake(spec_toplevel)
        rc, stdout, stderr = run_command_capture(
            "reapply",
            f"nails --config {headless_config} reapply --json",
        )
        assert rc == 0, f"expected reapply to succeed, got rc={rc} stdout={stdout!r} stderr={stderr!r}"
        result = last_json_line(stdout)
        assert result["status"] == "success", result
        machine.succeed("test -e /etc/nails-hidden-marker")
        machine.succeed("grep -Fxq hidden-rebuild-active /etc/nails-hidden-marker")

    with subtest("status no longer reports the hidden configuration as unapplied"):
        payload = json.loads(
            machine.succeed(f"nails --config {headless_config} status --json")
        )["data"]
        assert not payload.get("hidden_config_warning"), \
            f"a clean reapply must clear the status warning, got: {payload}"
  '';
}
