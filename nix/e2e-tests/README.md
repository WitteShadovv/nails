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
- `canonicalDeactivateFn` → `canonical_deactivate(config_path, unit_name="nails-deactivate")`

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

- One test: `nix build .#checks.x86_64-linux.e2e-basic-workflow --no-link -L`
- Tag group: `nix build .#checks.x86_64-linux.e2e-smoke --no-link -L`
- CI subset: `nix build .#checks.x86_64-linux.e2e-ci --no-link -L`
- All: `nix build .#checks.x86_64-linux.e2e-all --no-link -L`
- Interactive: `nix run .#apps.x86_64-linux.e2e-test-interactive`
- Specific interactive test: `scripts/run-e2e-tests.sh --interactive basic-workflow`

Inside a Python `testScript`, use `breakpoint()` for interactive debugging with `--interactive`.

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
3. Set `name` and `meta.tags`.
4. Import shared helpers instead of duplicating Python.
5. Use `with subtest(...)` for each logical phase.
6. Verify with a direct `nix build` target before sending for review.

## Adding a fixture

Add files under `fixtures/configs/` or `fixtures/schemas/` and reference them from tests via `${./../../fixtures/...}` (from nested tests) or copied paths inside the VM.
