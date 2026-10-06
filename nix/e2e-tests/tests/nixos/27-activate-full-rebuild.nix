# Test 27: Activate — real, offline hidden NixOS switch, then fast-path re-activation
#
# Exercises the real build + switch path with no `nixos-rebuild`/`nix` stub on
# PATH: `nails activate` builds the hidden system toplevel explicitly
# (`nix build …#…system.build.toplevel`), caches its `nixos-system-*` store path
# in the state file, and switches to it before the session restart. After a
# deactivate-with-reboot, a second activation with the unchanged config must reuse
# the cached toplevel on the fast path — proven here by breaking the flake source
# so that any rebuild would fail, and asserting the re-activation still succeeds.
#
# The hidden system is this VM's own `nails-hidden` specialisation: the running
# decoy system plus fixtures/hidden-config/module.nix (an /etc marker, a oneshot
# service and a canary user). Its toplevel is built on the host with the VM, so it
# is already in the guest store; the committed hidden flake points at it through
# `builtins.storePath`, substituted at test time with the resolved specialisation
# path. A genuine in-VM NixOS evaluation offline is not feasible without
# reproducing the test framework's own modules, so the guest never evaluates
# nixpkgs — it realises an already-present store path, which is what keeps the
# `nix build` offline (no substituters configured) and fast.
#
# Switching to a specialisation of the running system (rather than a bare
# from-scratch system) is also what keeps the driver alive: the specialisation
# still declares the test framework's instrumentation (the backdoor service, the
# qemu-vm filesystems), so switch-to-configuration leaves them in place instead of
# stopping the backdoor and unmounting the driver's store image.
#
# The decoy runs the impermanent profile, so its only persisted non-store state is
# /var/lib/nixos, which is diffed against a pre-activation baseline after the final
# deactivate to bound the forensic drift.
#
# NOTE (evaluate under nix): the specialisation toplevel, the tmpfs-root override
# and the offline switch can only be confirmed with
# `nix build .#checks.x86_64-linux.activate-full-rebuild` on a Nix host.

{
  self,
  ...
}:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  fixtureDir = ./../../fixtures/hidden-config;
in
{
  name = "activate-full-rebuild";
  # A real offline toplevel build plus two activations and two deactivate-reboots
  # needs more than the default budget.
  globalTimeout = 1800;
  meta.tags = [
    "nixos"
    "slow"
  ];

  nodes.machine =
    { lib, ... }:
    {
      imports = [ ./../../lib/impermanent-decoy.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      nix.settings.experimental-features = [
        "nix-command"
        "flakes"
      ];
      # The hidden toplevel is already in the guest store (it is the `nails-hidden`
      # specialisation below, built with the VM), so the offline `nix build` only
      # realises an already-present path. mkForce [] keeps the guest from querying
      # an unreachable substituter for it — no profile or qemu-vm default may
      # reintroduce one.
      nix.settings.substituters = lib.mkForce [ ];
      # The hidden system: the running decoy plus the marker module. Declaring it
      # as a specialisation builds its toplevel on the host with the VM and places
      # it in the guest store, and keeps the VM's own instrumentation in the hidden
      # config so switch-to-configuration never tears the driver down.
      specialisation.nails-hidden.configuration = {
        imports = [ ./../../fixtures/hidden-config/module.nix ];
      };
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalDeactivateFn}

    import json
    import re
    import shlex
    import uuid

    HIDDEN_MARKER = "/etc/nails-hidden-marker"
    ONESHOT_MARKER = "/run/nails-hidden-oneshot"

    # Basenames /var/lib/nixos is known to churn when switch-to-configuration runs
    # against the (non-overlaid) decoy /var: the declarative user/group state and
    # the id maps. This drift is the subject of T-092; here it is the allowlist of
    # changes a hidden session may leave on the persisted decoy state.
    NIXOS_STATE_DRIFT_ALLOWLIST = {
        "declarative-users",
        "declarative-groups",
        "uid-map",
        "gid-map",
        "auto-subuid-map",
    }

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

    def read_status(config_path):
        return json.loads(machine.succeed(f"nails --config {config_path} status --json"))["data"]

    def assert_state(expected, config_path):
        payload = read_status(config_path)
        actual = str(payload["state"]["kind"])
        assert actual.startswith(expected.lower()), f"Expected {expected!r}, got: {payload}"
        return payload

    def assert_overlay_mounted(path):
        machine.succeed(f"mountpoint -q {path}")
        assert machine.succeed(f"findmnt -n -o FSTYPE {path}").strip() == "overlay"

    def snapshot_nixos_state():
        # Map each file under /var/lib/nixos to its content hash, so the diff is by
        # contents and not by mtime (what T-092 needs the baseline to be).
        names = machine.succeed(
            "find /var/lib/nixos -type f -printf '%P\\n' 2>/dev/null | sort || true"
        ).split()
        state = {}
        for name in names:
            name = name.strip()
            if not name:
                continue
            digest = machine.succeed(
                "sha256sum " + shlex.quote("/var/lib/nixos/" + name) + " | cut -d' ' -f1"
            ).strip()
            state[name] = digest
        return state

    def unexpected_nixos_drift(before, after):
        changed = set()
        for name in set(before) | set(after):
            if before.get(name) != after.get(name):
                changed.add(name)
        # A change is tolerated only when every path component's basename is in the
        # allowlist of known switch-to-configuration churn.
        return sorted(
            name
            for name in changed
            if name.split("/")[-1] not in NIXOS_STATE_DRIFT_ALLOWLIST
        )

    machine.start()
    machine.wait_for_unit("multi-user.target")

    # Resolve the store directory at runtime so the test carries no hard-coded
    # store path.
    nix_store = machine.succeed("nix eval --raw --expr builtins.storeDir").strip()
    nixos_system_re = re.compile("^" + re.escape(nix_store) + r"/[a-z0-9]+-nixos-system-")

    headless_config = "/tmp/nails-headless.toml"
    flake_ref = "/mnt/data/nixos#nails-e2e"
    toplevel_attr = "/mnt/data/nixos#nixosConfigurations.nails-e2e.config.system.build.toplevel"
    write_headless_config(headless_config)

    baseline_nixos_state = None
    with subtest("point the committed hidden flake at the prebuilt specialisation toplevel"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mkdir -p /mnt/data/nixos")
        # Copy the fixture (flake + trivial lock + module) off the read-only store.
        machine.succeed("cp -rT ${fixtureDir} /mnt/data/nixos")
        machine.succeed("chmod -R u+w /mnt/data/nixos")
        # The hidden toplevel is the VM's own `nails-hidden` specialisation,
        # already in the guest store. Resolve its store path and substitute it into
        # the flake so the guest's `nix build` realises that exact path offline
        # instead of evaluating nixpkgs.
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
        assert_state("Inactive", headless_config)
        baseline_nixos_state = snapshot_nixos_state()

    with subtest("the hidden toplevel is already realised (nothing to build offline)"):
        # The flake's toplevel is a `builtins.storePath` of the prebuilt
        # specialisation, so a dry-run must schedule no build and no fetch. If it
        # does, the substitution or the specialisation closure is wrong, and a real
        # activation would stall offline with no substituters — long enough to blow
        # the global timeout, whose only symptom is an opaque driver "[Errno 9] Bad
        # file descriptor". Surface it here, fast.
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

    first_toplevel = None
    with subtest("first activation builds the hidden toplevel offline and switches to it"):
        rc, out = run_capture(
            "activate1",
            f"nails --config {headless_config} activate --session keep -y --nixos-flake {flake_ref}",
        )
        assert rc == 0, f"first activation failed: {out}"

        payload = assert_state("Active", headless_config)
        assert_overlay_mounted("/etc")
        assert_overlay_mounted("/home")

        first_toplevel = payload.get("hidden_toplevel")
        assert first_toplevel and nixos_system_re.match(first_toplevel), (
            f"state must record a nixos-system store toplevel, got {first_toplevel!r}"
        )

        machine.succeed(f"grep -Fx 'hidden-rebuild-active' {HIDDEN_MARKER}")
        machine.succeed(f"test -e {ONESHOT_MARKER}")

    with subtest("deactivate-with-reboot removes the hidden runtime state"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-full-rebuild")
        # The hidden volume is closed by the reboot; status reads a missing state
        # file as Inactive.
        assert_state("Inactive", headless_config)
        machine.fail(f"test -e {HIDDEN_MARKER}")

    with subtest("re-activation takes the fast path even when the flake can no longer build"):
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        # Break the hidden flake source. The fingerprint covers the hidden
        # etc/nixos and config/nixos trees (absent here) plus the flake-ref string,
        # not this flake's source, so it is unchanged and the fast path still fires.
        machine.succeed(
            "echo 'this is not valid nix' > /mnt/data/nixos/flake.nix"
        )
        # Positive control: a rebuild of the broken flake genuinely fails, so a
        # successful re-activation can only be the no-rebuild fast path.
        machine.fail(f"nix build --offline --impure --no-link {shlex.quote(toplevel_attr)}")

        rc, out = run_capture(
            "activate2",
            f"nails --config {headless_config} activate --session keep -y --nixos-flake {flake_ref}",
        )
        assert rc == 0, f"fast-path re-activation failed: {out}"

        payload = assert_state("Active", headless_config)
        second_toplevel = payload.get("hidden_toplevel")
        assert second_toplevel == first_toplevel, (
            f"fast path must reuse the cached toplevel {first_toplevel!r}, got {second_toplevel!r}"
        )
        # The cached toplevel re-applies the hidden marker.
        machine.succeed(f"grep -Fx 'hidden-rebuild-active' {HIDDEN_MARKER}")

    with subtest("final deactivate leaves no hidden overlays and bounded nixos drift"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-full-rebuild-2")
        assert_state("Inactive", headless_config)
        machine.fail(f"test -e {HIDDEN_MARKER}")

        drift = unexpected_nixos_drift(baseline_nixos_state, snapshot_nixos_state())
        assert drift == [], (
            "the hidden session left unexpected drift on the persisted decoy "
            f"/var/lib/nixos (not in the known switch-to-configuration allowlist): {drift}"
        )
  '';
}
