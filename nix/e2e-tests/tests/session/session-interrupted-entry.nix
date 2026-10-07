# An activation interrupted after it built the next root, and the guards that
# keep the decoy safe from what it leaves behind.
#
# Replaces the live-overlay crash-mid-activation, signal-during-activation,
# emergency-from-activating, guard-rollback, kill-deactivating-recover and
# stale-active tests. The hidden "NixOS configuration" here is a flake whose
# toplevel is a build that sleeps, so the activation can be stopped at a known
# point: /run/nextroot is populated, the plan written but not armed, and the
# transition drop-in installed.
#
#   1. SIGKILL during the build. `status` reports the interrupted entry and
#      `check` refuses. A plain `systemctl reboot` becomes a soft-reboot
#      (systemd >= 255 does that for a populated /run/nextroot); the transition
#      step refuses the unarmed tree and detaches it, so the machine stays on
#      the plain decoy root.
#   2. SIGKILL again, then `nails recover` removes the next root, the plan and
#      the drop-in, and `check` passes its session-state check again.
#   3. Ctrl+C (SIGINT to the process group) during the build rolls the entry
#      back by itself.
#   4. `nails emergency` during the build detaches the next root and removes
#      the runtime files.
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
in
{
  name = "session-interrupted-entry";
  meta.tags = [
    "state"
    "faults"
    "session"
  ];
  globalTimeout = 1500;

  nodes.machine =
    { lib, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.nails ];
      nix.settings = {
        experimental-features = [
          "nix-command"
          "flakes"
        ];
        substituters = lib.mkForce [ ];
      };
      # The slow build's builder must be in the guest store and registered.
      system.extraDependencies = [ pkgs.bash ];
    };

  testScript = _: ''
    import shlex

    from nails_e2e import session

    CONFIG = "/mnt/data/config/nails.toml"
    BASH = "${pkgs.bash}"
    FLAKE = "/root/slow-hidden"


    def start_activation(label):
        """Start an activation that stops in its hidden build, as its own
        process group, and wait until the build runs."""
        machine.succeed(
            "setsid sh -c "
            + shlex.quote(
                f"nails --config {CONFIG} activate -y --no-preflight "
                f"--nixos-flake {FLAKE}#slow > /mnt/data/{label}.log 2>&1"
            )
            + " </dev/null >/dev/null 2>&1 &"
        )
        machine.wait_until_succeeds("pgrep -f 'sleep 6000'", timeout=180)
        machine.succeed("mountpoint -q /run/nextroot")
        machine.succeed("test -s /run/overlay-runtime/plan.json")
        machine.succeed(
            "test -s /run/systemd/system/systemd-soft-reboot.service.d/50-overlay-runtime.conf"
        )


    def kill_activation():
        machine.succeed("pkill -9 -x nails")
        machine.execute("pkill -9 -f 'sleep 6000'; pkill -9 -x nix")
        machine.wait_until_fails("pgrep -x nails", timeout=30)


    def leftovers():
        return {
            "nextroot": machine.execute("mountpoint -q /run/nextroot")[0] == 0,
            "plan": machine.execute("test -e /run/overlay-runtime")[0] == 0,
            "dropin": machine.execute(
                "test -e /run/systemd/system/systemd-soft-reboot.service.d"
            )[0]
            == 0,
        }


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "rebuild_space_mb = 64\n"
        "EOF"
    )
    machine.succeed(f"mkdir -p {FLAKE}")
    machine.succeed(
        f"cat > {FLAKE}/flake.nix <<'EOF'\n"
        "{\n"
        "  outputs = { self }: {\n"
        "    nixosConfigurations.slow.config.system.build.toplevel = derivation {\n"
        "      name = \"slow-hidden-system\";\n"
        "      system = \"x86_64-linux\";\n"
        f"      builder = builtins.storePath \"{BASH}\" + \"/bin/bash\";\n"
        "      args = [ \"-c\" \"sleep 6000\" ];\n"
        "    };\n"
        "  };\n"
        "}\n"
        "EOF"
    )

    with subtest("a killed activation leaves an interrupted entry that status reports"):
        start_activation("killed-1")
        kill_activation()
        assert leftovers() == {"nextroot": True, "plan": True, "dropin": True}, leftovers()
        rc, out = machine.execute(f"nails --config {CONFIG} status --json")
        machine.log(out)
        assert rc == 7, f"status exit {rc} for an interrupted entry"
        assert "nails recover" in out, out
        rc, out = machine.execute(f"nails --config {CONFIG} check --overlay-only")
        assert rc == 4, f"check must refuse an interrupted entry (rc={rc})"

    with subtest("a plain reboot never enters the leftover next root"):
        timings = session.follow_soft_reboot(machine, "systemctl reboot", "stray-reboot")
        machine.log(f"stray reboot timings: {timings}")
        session.assert_decoy_root(machine)
        assert leftovers() == {"nextroot": False, "plan": False, "dropin": False}, leftovers()

    with subtest("recover removes an interrupted entry"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        start_activation("killed-2")
        kill_activation()
        out = machine.succeed(f"nails --config {CONFIG} recover")
        assert "Removed" in out, out
        assert leftovers() == {"nextroot": False, "plan": False, "dropin": False}, leftovers()
        machine.succeed(f"nails --config {CONFIG} status")

    with subtest("Ctrl+C during the build rolls the entry back"):
        start_activation("interrupted")
        pgid = machine.succeed("ps -o pgid= -p $(pgrep -x nails)").strip()
        machine.succeed(f"kill -INT -- -{pgid}")
        machine.wait_until_fails("pgrep -x nails", timeout=60)
        machine.execute("pkill -9 -f 'sleep 6000'")
        assert leftovers() == {"nextroot": False, "plan": False, "dropin": False}, leftovers()

    with subtest("emergency during an entry detaches it"):
        start_activation("emergency-during")
        out = machine.succeed(f"nails --config {CONFIG} emergency")
        machine.log(out)
        assert "interrupted activation" in out, out
        machine.fail("mountpoint -q /run/nextroot")
        machine.fail("test -e /run/overlay-runtime")
        kill_activation()
        session.assert_decoy_root(machine)
  '';
}
