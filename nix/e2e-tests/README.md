# NAILS E2E Harness

## Layout

- `lib/`: shared Nix/Python helper snippets and VM profiles
- `py/`: the `nails_e2e` package every driver imports (command capture, the
  scenario batch runner, the store image cache), with host-side unit tests
- `fixtures/`: reusable config files and captured forensic tool output
- `tests/**`: auto-discovered NixOS tests
- `scenarios/**`: bodies of former single-boot tests that now run as scenarios
  of one batched test (see [Batched scenarios](#batched-scenarios)); not
  discovered on their own

## Canonical skeleton

Most tests boot one machine that is nothing more than the standard decoy VM
plus the nails binary. Such a test declares no `nodes` at all: `default.nix`
injects the shared base node (`lib/base-node.nix`) as `machine`. A test that
needs `python3` in the guest sets a top-level `baseNode = { python3 = true; };`
instead of spelling out a full node. Only a test with bespoke hardware, a second
machine, extra packages or a non-default VM profile declares `nodes` itself.

```nix
_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in {
  name = "example";
  meta.tags = [ "smoke" "security" ];

  # No `nodes`: the shared base node (vm-config + nails) is injected as `machine`.
  # For a guest heredoc that needs Python, add instead:
  #   baseNode = { python3 = true; };

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

A test that imports `self` only for its node (the common case) takes no function
argument at all (`_:`); one that still needs `self` or `pkgs` in its `let` block
or `nodes` keeps `{ self, ... }:` or `{ self, pkgs, ... }:`.

## Shared helpers

### `lib/test-helpers.nix`

- `writeHeadlessConfigFn` → `write_headless_config(path)` (writes a `nails.toml` with explicit overlays)
- `writeExtendedConfigFn` → `write_extended_config(path)`
- `runDetachedCommandFn` → `run_detached_command(unit_name, command)`
- `readStatusJsonFn` → `read_status_json(config_path=None)` (requires exit 0) and `read_status_json_with_rc(config_path=None)` → `(rc, data)` for fail-closed postures (exit 6 unknown, 7 degraded/inconsistent)
- `runVerifyFn` → `run_verify(args="", config_path=None)`
- `canonicalDeactivateFn` → `canonical_deactivate(config_path, unit_name="nails-deactivate", shutdown_timeout=300, diagnostics_timeout=90)`

### `lib/base-os-overlays.nix`

The writable-trees pre-flight check refuses activation while a base-OS tree
(`/usr`, `/bin`, `/lib64` on the NixOS test VMs) is neither overlaid nor kept
read-only, so every hand-written explicit config must overlay them as well as
the subset the test is about.

- `toml` → the base-OS `[[overlays]]` stanzas for `/mnt/data`; interpolate it on
  its own line inside the config text
- `tomlFor root` → the same stanzas for another hidden root (also a Python
  f-string placeholder such as `"{hidden_root}"`)
- `targets` / `pythonTargets` → the base-OS targets, as a Nix list or a Python
  list literal for exact mount-set assertions

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
- `forensic-vm-config.nix` and `impermanent-decoy.nix`: an on-disk Nix store
  image (`useNixStoreImage`). The VM start script packs the whole closure into
  an erofs image on every start; `default.nix` gives every machine a copy of
  its start script that reuses the image of an earlier start of the same
  machine while it is unchanged (`py/nails_e2e/store_image.py`), so only the
  first start of a test pays for it. The driver log says `Reusing Nix store
  image.` on each later start.

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
- `research` (design-decision spikes under `tests/research/`: in no other group and not in `all`; see [Research spikes](#research-spikes-testsresearch))

## Running tests

- One test directly: `nix build .#e2e.basic-workflow --no-link -L`
- A former test that now runs as a scenario, by its old name: `nix build .#e2e.verify --no-link -L` builds its batch (`smoke-verify-config`); the runner and `python3 -m ci.e2e resolve` accept old names too, and `python3 -m ci.e2e list` shows each alias with its batch
- One group directly: `nix build .#e2e.smoke --no-link -L`
- Runner, the `ci` group: `./scripts/run-e2e-tests.sh`
- Runner, one test or group: `./scripts/run-e2e-tests.sh basic-workflow`, `./scripts/run-e2e-tests.sh smoke`
- Runner, all tests: `./scripts/run-e2e-tests.sh all`
- Resolve only: `python3 -m ci.e2e resolve ci`, or `python3 -m ci.e2e resolve --affected origin/main`
- Interactive driver: `nix run .#e2e.basic-workflow.driverInteractive`, or `./scripts/run-e2e-tests.sh -i basic-workflow`
- Local full or group run with bounded memory and parallel VMs: `just e2e-local [target] [jobs]` (see [docs/e2e-performance.md](../../docs/e2e-performance.md))
- Where a run's time went: `scripts/e2e-log-profile.py LOG...` (`nix build -L` logs or `nix log` output)

The tests, one link farm per group, and the metadata live under `legacyPackages.x86_64-linux` (`e2e.<name>` and `e2e-metadata`), not under `checks`, so `nix flake check` stays a fast lint gate. The short `.#e2e.<name>` form resolves on x86_64-linux hosts; elsewhere use `.#legacyPackages.x86_64-linux.e2e.<name>` with an x86_64-linux builder.

`scripts/run-e2e-tests.sh` wraps `python3 -m ci.e2e` (see `--help`). It expands groups such as `ci`, `all`, or tag names into leaf tests using the `e2e-metadata` output, removes duplicates in first-seen order, and builds every resolved test in one `nix build --keep-going`, so independent VMs run in parallel and one failure does not stop the rest. Without a target it runs the `ci` group; `NAILS_E2E_DEFAULT_TARGET` names a different default. `--exclude TARGET` leaves out the tests of a test or group.

- `--shard i/N` runs one of N weighted shards (see [Timeouts and shard weights](#timeouts-and-shard-weights)); `python3 -m ci.e2e plan` prints the split.
- `--retries 1` runs failed tests once more and reports a pass on that retry as FLAKY.
- `--execute` runs each test's driver directly instead of building the test, so a cached result does not count.
- `--jobs N` bounds the VM tests built at once (nix `--max-jobs`); `--jobs auto` sizes it from the host's RAM and cores (3 on a 15 GiB, 12-core host).
- `--eval-batch N` evaluates N tests per `nix eval` process before building them by derivation path, so evaluation memory stays bounded however many tests are selected. Without it every test is evaluated in its own process.
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

### Per-test fixed cost

Every test that boots pays a fixed cost before its first `with subtest(...)` can
run: building and starting its driver, the VM boot and
`wait_for_unit("multi-user.target")`. That cost sets the floor on the whole
suite, which is why single-boot tests with the same node run as scenarios of
one batched test (see [Batched scenarios](#batched-scenarios)) and why the
per-test node stays minimal.

On the local KVM workstation a boot to `multi-user.target` took a median of
21.8 s (p90 27.7 s) before dhcpcd stopped gating the boot, about 6 s less
after, and booting was 38% of all test-script time in a full run (190 boots
for 106 tests); see [docs/e2e-performance.md](../../docs/e2e-performance.md).

**GitHub-hosted runners: not measured yet.** No number is recorded here
because none has been measured, and the CI lanes cannot provide one as they
stand: `ci.e2e run` reads `nix build` output as `internal-json` and keeps the
driver log only of a failed test, so a green job log holds no driver lines. A
measurement needs one dispatched run that keeps the driver output, for
example a temporary job on `ubuntu-24.04` (after the usual checkout and Nix
setup steps of `e2e.yml`) that builds a handful of tests with one VM at a
time and uploads the log:

```yaml
      - run: |
          nix build --no-link -L --max-jobs 1 \
            .#legacyPackages.x86_64-linux.e2e.{preflight-checks,init-config,notify-dispatch,state-corruption,basic-workflow} \
            2>&1 | tee e2e-hosted.log
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
        with: { name: e2e-hosted-log, path: e2e-hosted.log }
```

Then, locally:

```sh
scripts/e2e-log-profile.py --json e2e-hosted.log > hosted.jsonl
python3 - <<'PY'
import json, statistics
rows = [json.loads(line) for line in open("hosted.jsonl")]
per_boot = [row["boot"] / row["boots"] for row in rows if row["boots"]]
print(f"{len(per_boot)} tests, median boot {statistics.median(per_boot):.1f} s")
PY
```

`boot` is the driver's own `(finished: waiting for unit multi-user.target, in
N seconds)` time, so it needs no wall-clock timestamps. The rest of the fixed
cost (evaluation, driver build, VM start) is the gap between a test's
`seconds` in the uploaded `e2e-durations-shard-*` artifact and its script
`total` in the profile. Record both medians here with the run's URL.

## Synchronisation rules

`ci/e2e_sync_lint.py` (run by CI's `lint-misc` job and `just e2e-sync-lint`)
enforces what the suite's past races taught:

- wait on the real completion signal (a result file under `/run`, the unit's
  state, a mountpoint, `nails status`), never a fixed sleep;
- never wait on a console regex: the emergency teardown restarts journald and
  can drop lines;
- capture command output under `/run`, never `/tmp` (activation overlays it and
  the forensic tests image the disk under it);
- every wait has a bounded timeout and a power-off wait goes through the QEMU
  process with a deadline (`canonical_deactivate`), not a bare
  `wait_for_shutdown()`.

A justified exception carries `sync-lint: allow <rule> -- <reason>` on the line
or the line above.

## Forensic invariants

Do not violate:

- `swapDevices = lib.mkForce [ ]`
- static musl `self.packages.x86_64-linux.nails` in test VMs
- hidden root at `/mnt/data`
- hidden backing disk at `/dev/vdb`
- non-root `testuser`
- no softened assertions (see [Assertions must be able to fail](#assertions-must-be-able-to-fail))

### The disk-image oracle

The forensic image tests read the powered-off decoy root from the host with
`lib/disk_forensics.py`. Names and tokens (`fls`, the byte scan, the journal
and store carves) miss a decoy file modified in place, so forensic/05, 06, 08
and the tcrypt backend test also diff MAC times and content hashes:
`image_state` takes a sleuthkit bodyfile (kept under `forensics/` in the test
output, ready for `mactime -b`) and a SHA-256 of every file, and
`assert_mac_unchanged` fails on any change to an existing inode that a
control run (the same number of plain reboots, no session) and the volatile
allowlist do not explain. atime drift is reported, not asserted.
forensic-clean (04) is the oracle's own null and positive control.

A Plaso (log2timeline) super-timeline lane was considered; Plaso is not
packaged in nixpkgs, so there is none. The bodyfiles feed `mactime` directly.

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

## Batched scenarios

A test that boots once and spends most of its time booting can run as a
scenario of a batched test instead, together with other tests that use an
identical node. Each batch lives in `tests/<group>/NN-<name>.nix` and is built
by `lib/batch.nix` (`mkBatch`); its scenarios live in
`scenarios/<group>/NN-<old-name>.nix`. The harness behind it is
`py/nails_e2e/batch.py`:

- the batch boots once and records what the fresh guest looks like;
- every scenario starts with a `<name>: starts from a clean guest` subtest
  that compares the guest with that baseline: no mount, device-mapper node,
  loop device or swap area that was not there at boot, no NAILS runtime entry
  (`/run/<16 hex digits>`, `/run/nails*`) or harness capture in `/run`, no
  NAILS state file, no new entry in `/tmp`, `/var/tmp`, `/mnt`, `/root` or
  `/home/testuser`, an unchanged `/etc/nixos`, a blank hidden-volume disk and
  no `nails` process or unit;
- between scenarios (`<name>: reset the guest`) the guest is brought back to
  that baseline. A scenario that left a NAILS session behind (an overlay, the
  runtime root, a live `nails` process) is reset by power-cycling the VM, so the
  harness never runs the teardown code under test; everything else is
  unmounted, closed, wiped and deleted in place. A guest that cannot be reset
  stops the batch and names the scenarios that did not run;
- a failing scenario is reported, the guest is reset and the batch goes on;
  the test fails at the end naming every failed scenario. The log has one
  `batch: <name> passed in N s` line per scenario, which
  `scripts/e2e-log-profile.py --json` reports under `scenarios`.

A scenario file evaluates to `{ name; tags; helpers; script; }`: `name` and
`tags` are the old test's, `helpers` the helper snippets its script used, and
`script` the old `testScript` as the body of
`def scenario_<name>() -> None:`, one level deeper, without `machine.start()`.
`mkBatch` deduplicates the helpers, asserts that the batch's tags cover every
scenario's tags (so no group loses a test) and lists the scenario names in
`replaces`, which keeps each old name an alias of the batch: `e2e.<old>`
builds the batch, the runner resolves it, and the `ci` group follows it.

Rules for adding a scenario to a batch:

1. Its node must be identical to the batch's. Compare the node derivations in
   one evaluation, for example
   `nix eval --json .#legacyPackages.x86_64-linux.e2e --apply 'e: map (t: e.${t}.config.nodes.machine.system.build.vm.drvPath) [ "<batch>" "<test>" ]'`.
   A test that adds packages, a profile or a second machine stays on its own.
2. Move the file with `git mv` to `scenarios/`, keep its subtests and
   assertions verbatim, and add it to the batch's `scenarios` list. Put a
   scenario that activates (and so may need a power cycle to reset) or that
   reboots last.
3. A helper that two scenarios need in different versions (several helper
   files define `run_command_capture`) must be renamed in one of them; the
   driver's type check rejects a second definition.
4. Move the old test's shard weight to the batch (`shard-durations.json`).

| Batch | Former tests (aliases) | Node |
| --- | --- | --- |
| `preflight-checks` | preflight-nixos-config, preflight-nixos-build-target, preflight-upper-fs-capability, preflight-state-check | base node |
| `preflight-vfat-targets` | preflight-overlay-compat, preflight-symlink-support | vm-config, nails, dosfstools |
| `preflight-hidden-root` | preflight-hidden-volume, preflight-mount-namespace | vm-config, nails, e2fsprogs |
| `init-config` | init-bootstrap, init-idempotency, init-refuse-overwrite, config-unknown-key | base node |
| `contract-json-schema` | verify-json-schema, contract-active-session | vm-config, nails, Python with jsonschema |
| `notify-dispatch` | notify-malformed-signal, notify-no-notify-send, notify-dispatch-signal-flow | base node |
| `smoke-verify-config` | verify, config-handling | base node |

Checks that need no VM move to the cargo tests instead of a batch:
`help-version-no-leak` is now four tests in `nails-cli/tests/cli_contract.rs`
(`root_help_lists_public_commands_and_no_internal_one`,
`version_prints_only_the_name_and_semver`,
`every_public_command_long_help_renders_examples`,
`hidden_commands_still_run_they_are_only_absent_from_help`), and the parsing
checks of config-unknown-key and config-handling run in
`nails-cli/tests/config_command.rs`.

## Adding a test

1. Place it under the correct `tests/<category>/` subfolder.
2. Preserve numeric filename form: `NN-name.nix`.
3. Set `name` (it must differ from every group and tag name) and `meta.tags`, and add an estimated weight to `shard-durations.json` (refresh it from the next full run).
4. Declare no `nodes` for the common single-machine case; the shared base node is injected. A short test on a node another batch already uses belongs in that batch as a scenario (see [Batched scenarios](#batched-scenarios)). Add `baseNode = { python3 = true; };` only for a guest that needs Python, and a full `nodes` block only for bespoke hardware, a second machine or a non-default profile.
5. Import shared helpers instead of duplicating Python.
6. Use `with subtest(...)` for each logical phase.
7. Assert against the booted guest with hard `assert ...` or `machine.fail(...)`; never a `print("Note: ...")` escape hatch (the `e2e-soft-assertions` lint rejects it).
8. Verify with a direct `nix build` target before sending for review.

## Research spikes (`tests/research/`)

A spike that answers a design question rather than guarding behaviour lives
under `tests/research/` and carries the `research` tag; `default.nix` asserts
that the two go together. A spike builds like any test
(`nix build .#legacyPackages.x86_64-linux.e2e.<name> -L`, or the whole
`e2e.research` link farm), but it is not a leaf test: it is in no tag group, not
in `ci` or `all`, not in the shards or `--affected`, not a runner target, and
needs no entry in `shard-durations.json`. Its log is the deliverable: lines
starting with `FINDING:` are research output, not assertions.

- `research-emergency-cgroup-kill`: shows that systemd restarts a killed
  `Restart=always` unit onto the decoy unless a stop job is enqueued first
  ([ADR 0007](../../docs/adr/0007-emergency-architecture.md)).
- `research-soft-reboot-whole-root`: enters a whole-root overlay with
  `systemctl soft-reboot` and returns, checking the vital paths and the decoy
  disk ([ADR 0008](../../docs/adr/0008-whole-root-soft-reboot.md)).
- `research-dual-root-vt-emergency`: runs a hidden display and session on their
  own VT inside a whole-root overlay while the decoy desktop keeps running, and
  makes emergency a cgroup kill plus a VT switch
  ([ADR 0009](../../docs/adr/0009-dual-root-emergency.md)).
- `research-dual-root-risks`: probes the dual-root design's risks (mount
  namespace copies, display and VT handling, shared-daemon writes)
  ([ADR 0009](../../docs/adr/0009-dual-root-emergency.md#risk-assessment)).

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

- `images.nix`: the distribution table, `name -> { distro, image, release }`.
  `distro` and `image` name a release in `nix-vm-test`, which pins every cloud
  image as a fixed-output derivation of a dated upstream build; the `flake.lock`
  pin of `nix-vm-test` therefore fixes exactly what the suite boots. **This is
  the one place to edit.**
- `lib/distro-vm.nix`: the single call into `nix-vm-test` (`buildVmTest`), so a
  change in its attribute layout is a one-line fix.
- `lib/hidden-root.nix`: the hidden root (ext4 on a loop device, or LUKS when
  `cryptsetup` ships) backed by an image file on a dedicated tmpfs, so it never
  touches the single decoy disk the forensic check images, with the layout of
  `e2e-tests/lib/backends.nix`; and the switch to a volatile journal (plus
  masking an active rsyslog) that the decoy-persistence preflight needs.
- `tests/smoke.nix`: the smoke scenario, generated once per image-table entry.
- `default.nix`: maps the scenario over the table and exposes the metadata.

Each smoke scenario shares the static musl `nails` binary into the guest over
9p (on `/run`, off the decoy disk); asserts platform detection selects the
overlay-only Debian-family backend; images the decoy as booted for a baseline;
runs the decoy-persistence preflight (a stock persistent journal is refused, and
passes once the decoy is amnesic); activates overlay-only over `/home`, `/etc`,
`/srv`, `/opt`, `/var` and `/tmp`, writing canaries, with `/usr` kept read-only
by the FHS guard rather than overlaid; asserts a write under `/usr`/`/usr/local`
fails read-only (checked against a negative control that leaves `/usr`
writable); runs `status`, `verify` (which must flag the active session),
`emergency` and `deactivate` with a reboot; and runs the host-side decoy
disk-image check (`lib/disk_forensics.py`, shared with the NixOS suite) with
null and positive controls.

`nix-vm-test` boots the image from the Nix store under QEMU `-snapshot`, so
guest writes vanish when QEMU exits and there is no root qcow2 for the forensic
helpers. The scenario therefore runs its lifecycle in one QEMU process started
with `allow_reboot=True` (the deactivation reboot keeps the disk) and, before
each image, mirrors the live disk into `<state_dir>/vm.qcow2` over QMP, where
`disk_forensics.snapshot` picks it up. The 9p share is mounted only once by
`nix-vm-test`, so the scenario remounts it after every boot.

### Adding a distribution

Once a distribution's backend and detection have landed, add one entry to
`nix/distro-tests/images.nix`:

```nix
"fedora-41" = entry "fedora" "41" "41";   # nix-vm-test set, its image key, release
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

### Moving to newer images

The images are those of the pinned `nix-vm-test` revision. To move forward,
update that input (`nix flake update nix-vm-test`), check that every
`distro`/`image` pair in `images.nix` still exists upstream (the `buildVmTest`
assertion names any that do not), and build the scenarios on a KVM host. An
attribute name containing a dot must be quoted on the command line, e.g.
`.#legacyPackages.x86_64-linux.e2e-distro."ubuntu-24.04-smoke"`.
