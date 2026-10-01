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

- `writeHeadlessConfigFn` → `write_headless_config(path)`
- `writeExtendedConfigFn` → `write_extended_config(path)`
- `writeEphemeralConfigFn` → `write_ephemeral_config(path)`
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

- One test directly: `nix build .#checks.x86_64-linux.e2e-basic-workflow --no-link -L`
- Runner, one test: `./scripts/run-e2e-tests.sh basic-workflow`
- Runner, tag group: `./scripts/run-e2e-tests.sh smoke`
- Runner, CI subset: `NAILS_E2E_DEFAULT_TARGET=ci ./scripts/run-e2e-tests.sh`
- Runner, all tests: `./scripts/run-e2e-tests.sh all`
- Resolve only / dry-run: `./scripts/run-e2e-tests.sh --dry-run ci`
- Interactive: `nix run .#apps.x86_64-linux.e2e-test-interactive`
- Specific interactive test: `scripts/run-e2e-tests.sh --interactive basic-workflow`

The runner expands suites/groups such as `ci`, `all`, or tag names into concrete leaf tests using Nix metadata (`_testNames` and `_groups`) and then executes those leaf tests sequentially. Duplicate tests are removed in stable first-seen order, so mixed inputs such as `ci verify smoke` still run each resolved leaf test only once.

When `--shard-index/--shard-count` are used, `scripts/e2e_shard_weights.py plan` assigns the resolved tests to shards deterministically, balancing the checked-in weights in `nix/e2e-tests/shard-durations.json` (see [Timeouts and shard weights](#timeouts-and-shard-weights)). If that file is absent, tests are dealt round-robin. If the weights are unusable, the run stops instead of running an empty shard.

`--durations-out FILE` writes one JSON line per test (`test`, `result`, `seconds`) as soon as each test finishes, so the record survives a shard that is later killed.

VM CPU auto-sizing defaults to the full visible runner CPU budget (`NAILS_E2E_VM_CPU_TARGET_PERCENT=100`, `NAILS_E2E_VM_HOST_RESERVED_CORES=0`) unless the caller overrides those environment variables.

Default target selection is environment-aware:

- local shells default to `all`
- `CI` or `GITHUB_ACTIONS` defaults to `ci`
- `NAILS_E2E_DEFAULT_TARGET` overrides either default

CI intentionally uses the runner instead of building the aggregate `e2e-ci` link farm directly so the workflow exercises the same suite expansion logic, emits per-leaf progress, and serializes execution in a CI-safe way.

Inside a Python `testScript`, use `breakpoint()` for interactive debugging with `--interactive`.

## Timeouts and shard weights

- Every test runs with a driver `globalTimeout` of 900 s (`defaultGlobalTimeout` in `default.nix`). A test that needs longer sets a top-level `globalTimeout` next to its `name`, with a comment giving its measured runtime (see `tests/performance/07-performance.nix`). `meta.timeout` is derived as `globalTimeout + 60` and must not be set by a test. The effective value of each test is published as `timeouts` in the E2E metadata.
- `canonical_deactivate` waits at most `shutdown_timeout` seconds (300 by default) for the VM to power off. On timeout it fails with the unit status, the unit and boot journals, pending systemd jobs and the process list, or with the serial console tail if the guest shell no longer answers.
- `shard-durations.json` holds one weight in seconds per leaf test, and every weight must satisfy `30 <= weight <= timeout / 2`. A weight at or above the test's timeout is a recorded hang: the planner refuses to use it. The remaining rules are enforced by `python3 scripts/e2e_shard_weights.py check --weights nix/e2e-tests/shard-durations.json --metadata meta.json` and by the unit tests in `scripts/tests/` (`python3 -m unittest discover -s scripts/tests`), which CI runs on every PR.
- Each full E2E shard uploads its per-test durations as the `e2e-durations-shard-N` artifact and adds a drift report to its step summary: tests more than 25% off their weight after allowing for the runner's overall speed. The report never fails the job.

To regenerate the weights, download the `e2e-durations-shard-*` artifacts of one or more full runs (for example with `gh run download RUN_ID -p 'e2e-durations-shard-*'`), then run:

```sh
nix eval --json .#e2e-test-metadata.x86_64-linux > meta.json
python3 scripts/e2e_shard_weights.py regen \
  --weights nix/e2e-tests/shard-durations.json \
  --metadata meta.json e2e-durations-shard-*/shard-*.jsonl
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
3. Set `name` and `meta.tags`, and add an estimated weight to `shard-durations.json` (refresh it from the next full run).
4. Import shared helpers instead of duplicating Python.
5. Use `with subtest(...)` for each logical phase.
6. Verify with a direct `nix build` target before sending for review.

## Adding a fixture

Add files under `fixtures/configs/` or `fixtures/schemas/` and reference them from tests via `${./../../fixtures/...}` (from nested tests) or copied paths inside the VM.
