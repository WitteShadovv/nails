# NAILS E2E Harness

## Layout

- `lib/`: shared Nix/Python helper snippets and VM profiles
- `fixtures/`: reusable config files and captured forensic tool output
- `tests/**`: auto-discovered NixOS tests

## Canonical skeleton

```nix
{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in {
  name = "example";
  meta.tags = [ "smoke" "security" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("phase 1"):
        ...
  '';
}
```

## Shared helpers

### `lib/test-helpers.nix`

- `writeHeadlessConfigFn` → `write_headless_config(path)` (writes a `nails.toml` with explicit overlays)
- `writeExtendedConfigFn` → `write_extended_config(path)`
- `runDetachedCommandFn` → `run_detached_command(unit_name, command)`
- `readStatusJsonFn` → `read_status_json(config_path=None)`
- `runVerifyFn` → `run_verify(args="", config_path=None)`
- `canonicalDeactivateFn` → `canonical_deactivate(config_path, unit_name="nails-deactivate", shutdown_timeout=300, diagnostics_timeout=90)`

### `lib/assertions.nix`

- `assert_status_state(expected, payload=None, config_path=None)`
- `assert_overlay_mounted(path)`
- `assert_no_overlays(paths)`
- `assert_hidden_volume_has(path)`
- `assert_verify_clean(config_path=None, deep=False)`

### `lib/emergency.nix`

- `prepare_tty1_shell()`
- `wait_for_console_log(regex, timeout, start_index=0)`
- `reboot_after_emergency()`
- `run_emergency_command()`
- `makeEmergencyUnit nailsPackage configPath`

### VM profiles

- `vm-config.nix`: base forensic-safe profile
- `graphical-vm-config.nix`: LightDM + autologin + shell/notification tooling
- `vfat-boot-vm-config.nix`: base profile plus VFAT `/boot`

## Tag taxonomy

Use only:

- `smoke`
- `config`
- `forensic`
- `lifecycle`
- `security`
- `performance`
- `preflight`
- `nixos`
- `session`
- `shell`
- `notification`
- `overlay`
- `state`
- `contract`

## Running tests

- One test directly: `nix build .#e2e.basic-workflow --no-link -L`
- One group directly: `nix build .#e2e.smoke --no-link -L`
- Runner, the `ci` group: `./scripts/run-e2e-tests.sh`
- Runner, one test or group: `./scripts/run-e2e-tests.sh basic-workflow`, `./scripts/run-e2e-tests.sh smoke`
- Runner, all tests: `./scripts/run-e2e-tests.sh all`
- Resolve only: `python3 -m ci.e2e resolve ci`, or `python3 -m ci.e2e resolve --affected origin/main`
- Interactive driver: `nix run .#e2e.basic-workflow.driverInteractive`, or `./scripts/run-e2e-tests.sh -i basic-workflow`

The tests, one link farm per group, and the metadata live under `legacyPackages.x86_64-linux` (`e2e.<name>` and `e2e-metadata`), not under `checks`, so `nix flake check` stays a fast lint gate. The short `.#e2e.<name>` form resolves on x86_64-linux hosts; elsewhere use `.#legacyPackages.x86_64-linux.e2e.<name>` with an x86_64-linux builder.

`scripts/run-e2e-tests.sh` wraps `python3 -m ci.e2e` (see `--help`). It expands groups such as `ci`, `all`, or tag names into leaf tests using the `e2e-metadata` output, removes duplicates in first-seen order, and builds every resolved test in one `nix build --keep-going`, so independent VMs run in parallel and one failure does not stop the rest. Without a target it runs the `ci` group; `NAILS_E2E_DEFAULT_TARGET` names a different default. `--exclude TARGET` leaves out the tests of a test or group.

- `--shard i/N` runs one of N weighted shards (see [Timeouts and shard weights](#timeouts-and-shard-weights)); `python3 -m ci.e2e plan` prints the split.
- `--retries 1` runs failed tests once more and reports a pass on that retry as FLAKY.
- `--execute` runs each test's driver directly instead of building the test, so a cached result does not count.
- `--durations-out FILE` writes one JSON line per test (`test`, `result`, `seconds`); `--log-dir DIR` keeps the log of every failed test.

Every VM gets 2 cores and 2 GB of memory, graphical nodes 4 GB (`lib/vm-config.nix`, `lib/graphical-vm-config.nix`). The size is fixed rather than derived from the host, so a test evaluates to the same derivation everywhere: the runner builds without `--impure`, the evaluation cache works, and a test that passed once can be fetched from a binary cache instead of being run again.

CI runs the suite through `.github/workflows/e2e.yml`, described in [docs/ci.md](../../docs/ci.md#e2eyml-behavior). The default runner target is the `ci` group (tier 3, the affected selection per pull request); the full suite runs nightly and on push to `main` (tier 4). See the [tier model](../../docs/ci.md#test-and-ci-tiers) for where each lane fits.

The interactive driver opens a Python prompt instead of running the test: `start_all()` boots the VMs, `test_script()` runs the whole test script and returns to the prompt, and `machine.shell_interact()` opens a shell in the guest. A `breakpoint()` in a `testScript` stops there when the script runs inside the interactive driver. `-i` takes exactly one leaf test; it refuses groups.

## Timeouts and shard weights

- Every test runs with a driver `globalTimeout` of 900 s (`defaultGlobalTimeout` in `default.nix`). A test that needs longer sets a top-level `globalTimeout` next to its `name`, with a comment giving its measured runtime (see `tests/performance/07-performance.nix`). `meta.timeout` is derived as `globalTimeout + 60` and must not be set by a test. The effective value of each test is published as `timeouts` in the E2E metadata.
- `canonical_deactivate` waits at most `shutdown_timeout` seconds (300 by default) for the VM to power off. On timeout it fails with the unit status, the unit and boot journals, pending systemd jobs and the process list, or with the serial console tail if the guest shell no longer answers.
- `shard-durations.json` holds one weight in seconds per leaf test, and every weight must satisfy `30 <= weight <= timeout / 2`. A weight at or above the test's timeout is a recorded hang: the planner refuses to use it. The remaining rules are enforced by `nix eval --json .#legacyPackages.x86_64-linux.e2e-metadata | python3 -m ci.e2e check --metadata -` and by the unit tests in `ci/tests/` (`python3 -m unittest discover -s ci/tests -t .`), which CI runs on every PR.
- Each E2E shard uploads its per-test durations as the `e2e-durations-shard-N` artifact and adds a drift report to its step summary: tests more than 25% off their weight after allowing for the runner's overall speed. The report never fails the job.

The nightly E2E run regenerates the weights from its own durations and uploads the result as the `shard-durations` artifact. To regenerate them by hand, download the `e2e-durations-*` artifacts of one or more runs (for example with `gh run download RUN_ID -p 'e2e-durations-*'`), then run:

```sh
python3 -m ci.e2e regen-weights e2e-durations-*/*.jsonl
```

`regen` takes the median of each test's passing runs of at least 30 s (a shorter pass was served from the Nix store without booting a VM), clamps it to half the test's timeout and reports every clamp, keeps the weights of tests without samples, and drops tests that no longer exist. Raise a test's `globalTimeout` instead of accepting a clamp.

## Forensic invariants

Do not violate:

- `swapDevices = lib.mkForce [ ]`
- static musl `self.packages.x86_64-linux.nails` in test VMs
- hidden root at `/mnt/data`
- hidden backing disk at `/dev/vdb`
- non-root `testuser`
- no softened assertions (see [Assertions must be able to fail](#assertions-must-be-able-to-fail))

## Assertions must be able to fail

A test earns its keep only when a regression turns it red, so an assertion that
cannot fail is worse than none: it hides the regression behind a green run. Two
checks guard against that, and both run inside `nix flake check` without
building a VM:

- `nix/e2e-tests/lint.nix` (the `e2e-soft-assertions` flake check) fails on the
  soft `print("Note: ...")` / `print(f"Note: ...")` branch, the idiom of
  reporting a problem and then letting the test pass. Replace each with a hard
  `assert ...` or `machine.fail(...)`.
- `default.nix` wraps every test's `testScript` so that a run which never boots
  a VM fails with `testScript never started a VM`. This catches a mis-indented
  Nix `''` block that folds the Python body into a helper string (so
  `machine.start()` never runs) and any test that asserts nothing against a
  booted guest.

A grep lint cannot judge the `|| echo 'CLEAN'` keyword filter, because a keyword
search still passes on drift that happens to carry no keyword. Prove cleanliness
with a full before/after diff of the file lists and checksums against an explicit
allowlist of volatile paths instead (see `tests/forensic/06-snapshot-diff.nix`).

## Adding a test

1. Place it under the correct `tests/<category>/` subfolder.
2. Preserve numeric filename form: `NN-name.nix`.
3. Set `name` (it must differ from every group and tag name) and `meta.tags`, and add an estimated weight to `shard-durations.json` (refresh it from the next full run).
4. Import shared helpers instead of duplicating Python.
5. Use `with subtest(...)` for each logical phase.
6. Assert against the booted guest with hard `assert ...` or `machine.fail(...)`; never a `print("Note: ...")` escape hatch (the `e2e-soft-assertions` lint rejects it).
7. Verify with a direct `nix build` target before sending for review.

## Adding a fixture

Add files under `fixtures/configs/` and reference them from tests via `${./../../fixtures/...}` (from nested tests) or copied paths inside the VM. The canonical `--json` schemas live at the repository root in `docs/schemas/`; contract tests reference them directly (`${./../../../../docs/schemas/...}`) so the published contract and the one the tests enforce cannot drift.

## Portable distribution tier (`nix/distro-tests/`)

The suite above runs on `pkgs.testers.runNixOSTest`, whose driver backdoor only
exists in NixOS guests, so it cannot catch a regression on another distribution.
The distribution tier under `nix/distro-tests/` boots real Debian and Ubuntu
cloud images on the same NixOS test driver through
[`numtide/nix-vm-test`](https://github.com/numtide/nix-vm-test), so the
overlay-only backend, platform detection, the read-only `/usr` guard and the
decoy-persistence preflight are exercised on a non-NixOS host. A container tier
cannot do this: a privileged container cannot host an overlay upper on an
overlay2 rootfs and cannot exercise journald or a reboot.

Layout:

- `images.nix`: the image table, `name -> { distro, release, format, image }`.
  Each image is a pinned fixed-output derivation (`pkgs.fetchurl`), so upstream
  pruning cannot change what the suite runs. **This is the one place to edit.**
- `lib/distro-vm.nix`: the single call into `nix-vm-test` (`buildVmTest`), so a
  change in its attribute layout is a one-line fix.
- `lib/hidden-root.nix`: the loop-backed ext4 (or LUKS, when `cryptsetup` ships)
  hidden root, mirroring `e2e-tests/lib/backends.nix`, and the volatile-journald
  switch the preflight needs.
- `tests/smoke.nix`: the smoke scenario, generated once per image-table entry.
- `default.nix`: maps the scenario over the table and exposes the metadata.

Each smoke scenario copies the static musl `nails` binary into the guest; asserts
platform detection selects the overlay-only Debian-family backend; runs the
decoy-persistence preflight (a stock persistent journal is refused, and passes
once journald is volatile); activates overlay-only over `/home`, `/etc`, `/srv`,
`/opt`, `/var`, `/tmp` and `/usr`, writing canaries; asserts a write under
`/usr`/`/usr/local` fails read-only (checked against a negative control that
leaves `/usr` writable); runs `status`, `verify`, `emergency` and
`deactivate` with a reboot; and runs the host-side decoy disk-image check
(`lib/disk_forensics.py`, shared with the NixOS suite) with null and positive
controls.

### Adding a distribution

Once a distribution's backend and detection have landed, add one entry to
`nix/distro-tests/images.nix`:

```nix
"fedora-41" = cloud {
  distro = "fedora";          # the nix-vm-test distribution attribute
  release = "41";
  url = "https://.../Fedora-Cloud-Base-...-x86_64.qcow2";
  sha256 = "sha256-...";      # see "Pinning images" below
};
```

The scenario, the flake's `e2e-distro` attribute and the CI matrix are all
derived by mapping over this table, so nothing else changes.

### Running and CI

The tier needs KVM, so it is a VM tier, not a container one. A hosted
`ubuntu-24.04` runner exposes `/dev/kvm`; a self-hosted KVM runner is selected by
passing its label list. The CI matrix is planned by
`python3 -m ci.e2e distro-plan` and kept at or below eight parallel jobs
(distributions times their shards). `.github/workflows/distro-e2e.yml` runs it on
a nightly schedule, when a pull request gets the `distro-e2e` label, and on
manual dispatch, with the runner as an input. The tier is informational and
gates no merge until promoted to a required check. The NixOS suite in `e2e.yml`
is unchanged and stays NixOS-only.

Build one scenario directly:

```sh
nix build -L .#legacyPackages.x86_64-linux.e2e-distro.debian-12-smoke
```

### Pinning images (deferred, needs network and Nix)

The `sha256` values in `images.nix` ship as `lib.fakeHash` placeholders: the
development sandbox has no network and no Nix daemon, so they cannot be computed
there, and `flake.lock` cannot pin the `nix-vm-test` input. Before the suite
builds, on a networked host with Nix:

1. `nix flake lock` to add and pin `nix-vm-test`.
2. For each image, `nix store prefetch-file --json <url>` and copy the printed
   `hash` into `images.nix` (the `buildVmTest` assertion fails loudly on a
   remaining placeholder).
3. Mirror the pinned image files into the project binary cache so a pruned
   upstream URL still resolves.
4. Confirm the `nix-vm-test` attribute spelling in `lib/distro-vm.nix` against
   the pinned revision, then
   `nix build .#legacyPackages.x86_64-linux.e2e-distro.debian-12-smoke` and the
   Ubuntu scenario on a KVM host.
