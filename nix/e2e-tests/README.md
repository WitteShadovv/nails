# NAILS E2E Harness

## Layout

- `lib/`: shared Nix/Python helper snippets and VM profiles
- `fixtures/`: reusable schemas and config files
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

CI runs the suite through `.github/workflows/e2e.yml`, described in [docs/ci.md](../../docs/ci.md#e2eyml-behavior).

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
- hidden root at `/mnt/hidden-volume`
- hidden backing disk at `/dev/vdb`
- non-root `testuser`
- no softened assertions

## Adding a test

1. Place it under the correct `tests/<category>/` subfolder.
2. Preserve numeric filename form: `NN-name.nix`.
3. Set `name` (it must differ from every group and tag name) and `meta.tags`, and add an estimated weight to `shard-durations.json` (refresh it from the next full run).
4. Import shared helpers instead of duplicating Python.
5. Use `with subtest(...)` for each logical phase.
6. Verify with a direct `nix build` target before sending for review.

## Adding a fixture

Add files under `fixtures/configs/` or `fixtures/schemas/` and reference them from tests via `${./../../fixtures/...}` (from nested tests) or copied paths inside the VM.
