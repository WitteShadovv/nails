# Test 27: Activate — real, offline hidden NixOS rebuild, then fast-path re-activation
#
# Exercises the real build + switch path with no `nixos-rebuild`/`nix` stub on
# PATH: `nails activate` builds the hidden system toplevel explicitly
# (`nix build …#…system.build.toplevel`), caches its `nixos-system-*` store path
# in the state file, and switches to it before the session restart. After a
# deactivate-with-reboot, a second activation with the unchanged config must reuse
# the cached toplevel on the fast path — proven here by breaking the flake source
# so that any rebuild would fail, and asserting the re-activation still succeeds.
#
# The hidden configuration is the committed fixtures/hidden-config fixture (a
# single /etc marker plus a oneshot service, importing the decoy's own
# configuration.nix so its closure is already present). The build runs fully
# offline: no substituters are configured and nixpkgs is seeded into the guest
# store, so nothing can be fetched. The decoy runs the impermanent profile, so its
# only persisted non-store state is /var/lib/nixos, which is diffed against a
# pre-activation baseline after the final deactivate to bound the forensic drift.
#
# NOTE (evaluate under nix): this performs a genuine offline toplevel build inside
# an impermanent (tmpfs-root, on-disk store image) VM. Closure completeness, the
# tmpfs-root override and the offline build can only be confirmed with
# `nix build .#checks.x86_64-linux.activate-full-rebuild` on a Nix host.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  fixtureDir = ./../../fixtures/hidden-config;
  nixpkgsPath = pkgs.path;
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
    { ... }:
    {
      imports = [ ./../../lib/impermanent-decoy.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      nix.settings.experimental-features = [
        "nix-command"
        "flakes"
      ];
      # Force the hidden build fully offline: nothing may be substituted, so the
      # toplevel must build from the seeded store alone.
      nix.settings.substituters = [ ];
      # Seed nixpkgs into the guest store so the hidden toplevel builds offline.
      # With the on-disk store image this lands in that image.
      virtualisation.additionalPaths = [ pkgs.path ];
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
        stem = f"/tmp/{label}-{uuid.uuid4().hex}"
        machine.succeed(
            "bash -lc "
            + shlex.quote(
                "set +e; " + command + f" > {stem}.out 2>&1; printf '%s' \"$?\" > {stem}.rc"
            )
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
    with subtest("prepare the committed hidden-config fixture as a real offline flake"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mkdir -p /mnt/data/nixos")
        # Copy the fixture off the read-only store and point it at the seeded
        # nixpkgs so it locks and builds offline.
        machine.succeed("cp -rT ${fixtureDir} /mnt/data/nixos")
        machine.succeed("chmod -R u+w /mnt/data/nixos")
        machine.succeed(
            "sed -i "
            + shlex.quote("s|@nixpkgs@|path:${nixpkgsPath}|")
            + " /mnt/data/nixos/flake.nix"
        )
        machine.succeed("nix flake lock --offline /mnt/data/nixos")
        assert_state("Inactive", headless_config)
        baseline_nixos_state = snapshot_nixos_state()

    first_toplevel = None
    with subtest("first activation builds the hidden toplevel offline and switches to it"):
        rc, out = run_capture(
            "activate1",
            f"nails --config {headless_config} activate --session keep -y --flake {flake_ref}",
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
            f"nails --config {headless_config} activate --session keep -y --flake {flake_ref}",
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
