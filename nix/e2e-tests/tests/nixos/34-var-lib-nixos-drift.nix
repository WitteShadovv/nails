# Test 34: /var/lib/nixos drift — control run, both deactivation modes, canary user
#
# Root-causes the post-deactivation drift on the persisted decoy /var/lib/nixos
# (the declarative-users/declarative-groups and id-map rewrites) that earlier
# evaluation saw but never compared against a control. On the impermanent decoy
# profile — tmpfs root, on-disk store image, and only /persist/var/lib/nixos
# persisted — it:
#
#   1. CONTROL: snapshots /persist/var/lib/nixos by content hash, reboots the
#      decoy with no hidden session at all, and records the drift a plain boot
#      leaves. This is the boot-noise baseline (update-users-groups and the decoy
#      switch-to-configuration run on every boot regardless of NAILS).
#   2. STANDARD: re-baselines, activates the committed hidden configuration with a
#      real offline toplevel switch (the hidden config is overlaid onto /etc and
#      /var, so the hidden switch writes the user state into the overlay upper on
#      the hidden volume, not the decoy), then deactivates with reboot.
#   3. EMERGENCY: re-activates (reusing the cached toplevel) and tears down through
#      the emergency path, then reboots.
#
# After both deactivation modes it asserts the drift beyond the control set and a
# small switch-to-configuration allowlist is empty, and — the sharp check — that a
# declarative canary user that exists only in the hidden configuration
# (`hiddencanary`, uid/gid 64123) leaves no trace of its name or id on the decoy:
# not in /persist/var/lib/nixos, /etc/passwd, /etc/group, or the journal. The
# canary is proven present while the session is live, so its absence afterwards is
# containment, not a vacuous pass.
#
# The hidden system is this VM's own `nails-hidden` specialisation (the running
# decoy plus fixtures/hidden-config/module.nix), built on the host with the VM and
# already in the guest store; the committed hidden flake points at it through
# `builtins.storePath`, substituted at test time. The guest never evaluates
# nixpkgs — a genuine in-VM NixOS evaluation offline is not feasible without
# reproducing the test framework's own modules. Switching to a specialisation of
# the running system (not a bare one) keeps the driver backdoor and the qemu-vm
# filesystems in the hidden config, so switch-to-configuration never tears the
# driver down.
#
# NOTE (evaluate under nix): this performs a genuine offline toplevel switch inside
# an impermanent (tmpfs-root, on-disk store image) VM and exercises both
# deactivation modes. The tmpfs-root override, the specialisation toplevel, and the
# containment of the canary onto the overlay (rather than the persisted decoy) can
# only be confirmed with `nix build .#checks.x86_64-linux.var-lib-nixos-drift` on a
# Nix host. If the canary assertion reproduces there, the overlay is not covering
# the /var/lib/nixos bind submount; that must be converted to a tracked
# expected-fail with a linked TODO and a code fix (overlay handling for
# /var/lib/nixos; evaluate userborn/systemd-sysusers), not silenced.

{
  self,
  ...
}:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  emergency = import ./../../lib/emergency.nix;
  fixtureDir = ./../../fixtures/hidden-config;
  # The emergency runner bakes the config path into its unit; the test writes the
  # /var-overlaying config to this same path at runtime.
  varConfig = "/tmp/nails-var.toml";
in
{
  name = "var-lib-nixos-drift";
  # A control reboot, one real offline toplevel build, a cached re-activation and
  # two deactivations (one with reboot, one emergency) need a generous budget.
  globalTimeout = 2400;
  meta.tags = [
    "nixos"
    "slow"
  ];

  nodes.machine =
    { lib, ... }:
    {
      imports = [ ./../../lib/impermanent-decoy.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      # The emergency path drives a real tty1 shell.
      services.getty.autologinUser = "root";
      systemd.services.nails-emergency-test = emergency.makeEmergencyUnit self.packages.x86_64-linux.nails varConfig;
      nix.settings.experimental-features = [
        "nix-command"
        "flakes"
      ];
      # The hidden toplevel is already in the guest store (it is the `nails-hidden`
      # specialisation below, built with the VM), so the offline `nix build` only
      # realises an already-present path. mkForce [] keeps the guest from querying
      # an unreachable substituter — no profile or qemu-vm default may reintroduce
      # one.
      nix.settings.substituters = lib.mkForce [ ];
      # The hidden system: the running decoy plus the marker module. Declaring it as
      # a specialisation builds its toplevel on the host with the VM and places it
      # in the guest store, and keeps the VM's own instrumentation in the hidden
      # config so switch-to-configuration never tears the driver down.
      specialisation.nails-hidden.configuration = {
        imports = [ ./../../fixtures/hidden-config/module.nix ];
      };
    };

  testScript = _: ''
    ${emergency.prepareTty1ShellFn}
    ${emergency.waitForConsoleLogFn}
    ${emergency.rebootAfterEmergencyFn}
    ${emergency.runEmergencyCommandFn}
    ${testHelpers.canonicalDeactivateFn}

    import json
    import re
    import shlex
    import uuid

    HIDDEN_MARKER = "/etc/nails-hidden-marker"
    CANARY_NAME = "hiddencanary"
    CANARY_ID = "64123"
    PERSISTED_NIXOS = "/persist/var/lib/nixos"

    # Basenames /var/lib/nixos is known to churn on every boot and switch: the
    # declarative user/group state and the id maps. A hidden session may leave no
    # more than these on the persisted decoy state, and never the canary.
    NIXOS_STATE_DRIFT_ALLOWLIST = {
        "declarative-users",
        "declarative-groups",
        "uid-map",
        "gid-map",
        "auto-subuid-map",
    }

    def write_var_config(path):
        # The headless overlay set plus /var, so the hidden switch-to-configuration
        # writes user state (/etc/passwd and /var/lib/nixos) into the overlay upper
        # on the hidden volume rather than onto the persisted decoy.
        machine.succeed(
            "cat > " + shlex.quote(path) + " <<'EOF'\n"
            + 'hidden_volume_root = "/mnt/data"\n'
            + 'overlay_mode = "explicit"\n'
            + 'risky_services = "skip"\n'
            # The hidden data disk is only ~2 GB, below the 4 GB default
            # rebuild floor; the offline fixture build is tiny, so lower it.
            + 'rebuild_space_mb = 64\n'
            + "".join(
                f'\n[[overlays]]\nname = "{n}"\nlower = "/{n}"\n'
                f'upper = "/mnt/data/{n}"\nwork = "/mnt/data/.work/{n}"\ntarget = "/{n}"\n'
                for n in ("etc", "home", "root", "srv", "tmp", "usr", "bin", "lib64", "var")
            )
            + "EOF"
        )

    def run_capture(label, command):
        # /run, not /tmp: activation overlays /tmp, which would hide the
        # capture files from the post-activation reads. The bound turns a hung
        # step into a failure that still prints its output.
        stem = f"/run/{label}-{uuid.uuid4().hex}"
        machine.succeed(
            "bash -lc "
            + shlex.quote(
                "set +e; timeout 900 "
                + command
                + f" > {stem}.out 2>&1; printf '%s' \"$?\" > {stem}.rc"
            ),
            timeout=1000,
        )
        rc = int(machine.succeed(f"cat {stem}.rc"))
        out = machine.succeed(f"cat {stem}.out")
        return rc, out

    def assert_state(expected, config_path):
        payload = json.loads(
            machine.succeed(f"nails --config {config_path} status --json")
        )["data"]
        actual = str(payload["state"]["kind"])
        assert actual.startswith(expected.lower()), f"Expected {expected!r}, got: {payload}"
        return payload

    def assert_overlay_mounted(path):
        machine.succeed(f"mountpoint -q {path}")
        assert machine.succeed(f"findmnt -n -o FSTYPE {path}").strip() == "overlay"

    def snapshot_nixos_state():
        # Map each file under the persisted /var/lib/nixos to its content hash, so
        # the diff is by contents, not mtime.
        names = machine.succeed(
            f"find {PERSISTED_NIXOS} -type f -printf '%P\\n' 2>/dev/null | sort || true"
        ).split()
        state = {}
        for name in names:
            name = name.strip()
            if not name:
                continue
            digest = machine.succeed(
                "sha256sum " + shlex.quote(PERSISTED_NIXOS + "/" + name) + " | cut -d' ' -f1"
            ).strip()
            state[name] = digest
        return state

    def changed_files(before, after):
        changed = set()
        for name in set(before) | set(after):
            if before.get(name) != after.get(name):
                changed.add(name)
        return changed

    def unexpected_drift(before, after, tolerated):
        # A change is tolerated when its basename is known switch-to-configuration
        # churn or it was already seen in the control run.
        return sorted(
            name
            for name in changed_files(before, after)
            if name.split("/")[-1] not in NIXOS_STATE_DRIFT_ALLOWLIST
            and name not in tolerated
        )

    def assert_canary_absent_from_decoy(stage):
        # The canary must not survive on any persisted or regenerated decoy state.
        for token in (CANARY_NAME, CANARY_ID):
            rc, out = run_capture(
                f"canary-{stage}",
                f"grep -rIn {shlex.quote(token)} {PERSISTED_NIXOS} /etc/passwd /etc/group",
            )
            assert rc != 0, (
                f"[{stage}] canary token {token!r} leaked onto the decoy state:\n{out}"
            )
        # The decoy's own user database must not resolve the canary.
        machine.fail(f"getent passwd {CANARY_NAME}")
        machine.fail(f"getent group {CANARY_NAME}")
        machine.fail(f"getent passwd {CANARY_ID}")
        # The current (post-reboot, volatile) journal must not mention it either.
        rc, out = run_capture(
            f"canary-journal-{stage}",
            f"journalctl -b --no-pager | grep -F {shlex.quote(CANARY_NAME)}",
        )
        assert rc != 0, f"[{stage}] canary name found in the decoy journal:\n{out}"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    nix_store = machine.succeed("nix eval --raw --expr builtins.storeDir").strip()
    nixos_system_re = re.compile("^" + re.escape(nix_store) + r"/[a-z0-9]+-nixos-system-")

    flake_ref = "/mnt/data/nixos#nails-e2e"
    # The same path the emergency unit bakes in, written with a /var-overlaying
    # config so the hidden switch keeps its user state off the decoy.
    var_config = "${varConfig}"
    write_var_config(var_config)

    with subtest("point the committed hidden flake at the prebuilt specialisation toplevel"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mkdir -p /mnt/data/nixos")
        machine.succeed("cp -rT ${fixtureDir} /mnt/data/nixos")
        machine.succeed("chmod -R u+w /mnt/data/nixos")
        # The hidden toplevel is the VM's own `nails-hidden` specialisation, already
        # in the guest store. Resolve its store path and substitute it into the
        # flake so the guest's `nix build` realises that exact path offline instead
        # of evaluating nixpkgs.
        spec_toplevel = machine.succeed(
            "readlink -f /run/current-system/specialisation/nails-hidden"
        ).strip()
        assert nixos_system_re.match(spec_toplevel), (
            f"specialisation toplevel is not a nixos-system store path: {spec_toplevel!r}"
        )
        machine.succeed(
            "sed -i "
            + shlex.quote(f"s|@toplevel@|{spec_toplevel}|")
            + " /mnt/data/nixos/flake.nix"
        )
        assert_state("Inactive", var_config)

    with subtest("the hidden toplevel is already realised (nothing to build offline)"):
        # The flake's toplevel is a `builtins.storePath` of the prebuilt
        # specialisation, so a dry-run must schedule no build and no fetch. If it
        # does, the substitution or the specialisation closure is wrong, and a real
        # activation would stall offline with no substituters — long enough to blow
        # the global timeout, whose only symptom is an opaque driver "[Errno 9] Bad
        # file descriptor". Surface it here, fast.
        toplevel_attr = (
            "/mnt/data/nixos#nixosConfigurations.nails-e2e.config.system.build.toplevel"
        )
        rc, plan = machine.execute(
            "nix build --dry-run --offline --impure --no-link "
            + shlex.quote(toplevel_attr)
            + " 2>&1"
        )
        print(f"nix build --dry-run of the hidden toplevel exited rc={rc}; plan follows:")
        print(plan)
        assert rc == 0, f"evaluating the hidden toplevel failed offline:\n{plan}"
        assert "will be built" not in plan and "will be fetched" not in plan, (
            f"the hidden toplevel is not already realised offline:\n{plan}"
        )

    control_drift = set()
    with subtest("control: a plain reboot without NAILS establishes the boot-noise drift"):
        baseline = snapshot_nixos_state()
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        control_drift = changed_files(baseline, snapshot_nixos_state())
        # The canary never ran on the decoy, so a plain boot must not know it.
        assert_canary_absent_from_decoy("control")

    first_toplevel = None
    with subtest("standard: activate with a real offline build, canary lives only in the session"):
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        # The tmpfs root is wiped on every reboot, so re-write the config (and the
        # copy the emergency unit reads) after each boot.
        write_var_config(var_config)
        pre_activate = snapshot_nixos_state()
        rc, out = run_capture(
            "activate-standard",
            f"nails --config {var_config} activate --session keep -y --nixos-flake {flake_ref}",
        )
        assert rc == 0, f"standard activation failed: {out}"

        payload = assert_state("Active", var_config)
        assert_overlay_mounted("/etc")
        assert_overlay_mounted("/var")
        first_toplevel = payload.get("hidden_toplevel")
        assert first_toplevel and nixos_system_re.match(first_toplevel), (
            f"state must record a nixos-system toplevel, got {first_toplevel!r}"
        )
        machine.succeed(f"grep -Fx 'hidden-rebuild-active' {HIDDEN_MARKER}")
        # Sanity: the canary really exists while the hidden session is live, so
        # its later absence is containment and not a test that proves nothing.
        session_uid = machine.succeed(
            f"getent passwd {CANARY_NAME} | cut -d: -f3"
        ).strip()
        assert session_uid == CANARY_ID, (
            f"hidden canary not present in the live session: {session_uid!r}"
        )

    with subtest("standard deactivate leaves no canary and only known drift on the decoy"):
        canonical_deactivate(var_config, unit_name="nails-deactivate-drift-standard")
        write_var_config(var_config)
        assert_state("Inactive", var_config)
        machine.fail(f"test -e {HIDDEN_MARKER}")
        assert_canary_absent_from_decoy("standard")
        drift = unexpected_drift(pre_activate, snapshot_nixos_state(), control_drift)
        assert drift == [], (
            "standard deactivation left unexpected drift on the persisted decoy "
            f"/var/lib/nixos beyond the control run and allowlist: {drift}"
        )

    with subtest("emergency: re-activate (cached toplevel) then tear down through emergency"):
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        # Re-write the config the activation and the baked emergency unit both read.
        write_var_config(var_config)
        pre_activate = snapshot_nixos_state()
        rc, out = run_capture(
            "activate-emergency",
            f"nails --config {var_config} activate --session keep -y --nixos-flake {flake_ref}",
        )
        assert rc == 0, f"re-activation failed: {out}"
        payload = assert_state("Active", var_config)
        assert payload.get("hidden_toplevel") == first_toplevel, (
            "re-activation should reuse the cached toplevel"
        )
        machine.succeed(f"grep -Fx 'hidden-rebuild-active' {HIDDEN_MARKER}")
        session_uid = machine.succeed(
            f"getent passwd {CANARY_NAME} | cut -d: -f3"
        ).strip()
        assert session_uid == CANARY_ID, "hidden canary missing from the second session"

        # Emergency teardown, then reboot the decoy.
        run_emergency_command(reboot=True)
        write_var_config(var_config)
        assert_state("Inactive", var_config)
        machine.fail(f"test -e {HIDDEN_MARKER}")
        assert_canary_absent_from_decoy("emergency")
        drift = unexpected_drift(pre_activate, snapshot_nixos_state(), control_drift)
        assert drift == [], (
            "emergency deactivation left unexpected drift on the persisted decoy "
            f"/var/lib/nixos beyond the control run and allowlist: {drift}"
        )
  '';
}
