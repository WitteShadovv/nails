# NAILS E2E Harness

## Layout

- `lib/`: shared Nix/Python helper snippets and VM profiles
- `py/`: the `nails_e2e` package every driver imports (command capture, the
  scenario batch runner, the store image cache, and `session.py`, which follows
  a whole-root session across its soft-reboots), with host-side unit tests
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
in {
  name = "example";
  meta.tags = [ "smoke" "security" ];

  # No `nodes`: the shared base node (vm-config + nails) is injected as `machine`.
  # For a guest heredoc that needs Python, add instead:
  #   baseNode = { python3 = true; };

  testScript = _: ''
    from nails_e2e import session

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    write_headless_config("/mnt/data/config/nails.toml")

    with subtest("enter and leave the hidden session"):
        canonical_activate("/mnt/data/config/nails.toml", "--overlay-only")
        assert read_status_json("/mnt/data/config/nails.toml")["posture"] == "active"
        canonical_deactivate("/mnt/data/config/nails.toml")
        session.assert_decoy_root(machine)
  '';
}
```

A test that imports `self` only for its node (the common case) takes no function
argument at all (`_:`); one that still needs `self` or `pkgs` in its `let` block
or `nodes` keeps `{ self, ... }:` or `{ self, pkgs, ... }:`.

## Shared helpers

### `lib/test-helpers.nix`

- `writeHeadlessConfigFn` → `write_headless_config(path)` (a minimal `nails.toml`: `hidden_volume_root` and a lowered `rebuild_space_mb`)
- `runDetachedCommandFn` → `run_detached_command(unit_name, command)`
- `readStatusJsonFn` → `read_status_json(config_path=None)` (requires exit 0) and `read_status_json_with_rc(config_path=None)` → `(rc, data)` for fail-closed postures (exit 6 unknown, 7 degraded/inconsistent)
- `runVerifyFn` → `run_verify(args="", config_path=None)`
- `canonicalActivateFn` → `canonical_activate(config_path, extra_args="", label="activate")`: soft-reboots into the hidden root, follows the switch and asserts the hidden root; activate's output is in `/mnt/data/<label>.log`
- `canonicalDeactivateFn` → `canonical_deactivate(config_path, label="deactivate")`: soft-reboots back, asserts the plain decoy and waits for the hidden mapping to close

The soft-reboot helpers themselves (`follow_soft_reboot`, `assert_hidden_root`,
`assert_decoy_root`, `carried_run_residue`, `wait_for_power_off`, ...) live in
`py/nails_e2e/session.py`.

### `py/nails_e2e/session.py`

`nails activate`, `deactivate` and `emergency` end by enqueueing
`soft-reboot.target`: PID 1 stops every userspace process (the driver's backdoor
shell included), switches root and starts a fresh userspace, which starts the
backdoor again. `follow_soft_reboot(machine, trigger, label, deadline_s=600.0,
start=None)` runs `trigger` in the background and polls the driver's full
console log (not `wait_for_console_text`, which reads one queued line per
second while a soft-reboot prints hundreds). It fails at once if the new
userspace lands in emergency mode or PID 1 freezes, reconnects to the new
backdoor, and returns PID 1's own timings of the switch, logged as `TIMING:`
lines. A trigger's output is lost with the old userspace unless the trigger
redirects it to the hidden volume.

### `lib/backend-fault.nix`

- `emergencyOutcomeFn` → `emergency_outcome(trigger, label, deadline_s=600, console_index=None)`: follows a teardown with a failed backend to `"decoy"` or `"off"`
- `assertFaultExitFn` → `assert_fault_exit(outcome, run_before, wall)`

### VM profiles

- `vm-config.nix`: base forensic-safe profile. The pinned nixpkgs installs
  `soft-reboot.target` and `systemd-soft-reboot.service` itself, so the decoy and
  every hidden NixOS configuration can soft-reboot without the module that
  `nails check` prints for an older nixpkgs.
- `graphical-vm-config.nix`: LightDM + autologin + shell/notification tooling
- `notification-server.nix`: a user service of testuser that owns
  `org.freedesktop.Notifications` on testuser's session bus and records every
  call, with the uid and the program that made it, in testuser's runtime
  directory. NAILS shows its alerts as the operator, on the operator's bus;
  `py/nails_e2e/desktop.py` logs testuser in on the console (the owner of the
  active session on seat0, whom the session watcher alerts) and reads the
  records. No test stubs `notify-send`.
- `forensic-vm-config.nix` and `impermanent-decoy.nix`: an on-disk Nix store
  image (`useNixStoreImage`). The VM start script packs the whole closure into
  an erofs image on every start; `default.nix` gives every machine a copy of
  its start script that reuses the image of an earlier start of the same
  machine while it is unchanged (`py/nails_e2e/store_image.py`), so only the
  first start of a test pays for it. The driver log says `Reusing Nix store
  image.` on each later start.
- `blk-availability.nix`: the `blk-availability.service` that Debian's and
  Ubuntu's lvm2 package enables. Its stop, which every soft-reboot
  runs, unmounts the filesystems on device-mapper devices (`blkdeactivate
  -u`). A NixOS VM always carries its store mounts below the hidden volume, so
  the stop cannot unmount the volume itself there; a decoy filesystem on LVM
  shows the loss instead (`session-fstab-policy`). The distribution tier
  covers the volume itself.

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
- `session` (the whole-root session, `tests/session/`)
- `shell`
- `overlay`
- `faults`
- `state`
- `contract`
- `research` (design-decision spikes under `tests/research/`: in no other group and not in `all`; see [Research spikes](#research-spikes-testsresearch))

## Running tests

- One test directly: `nix build .#e2e.session-lifecycle --no-link -L`
- A former test that now runs as a scenario, by its old name: `nix build .#e2e.verify --no-link -L` builds its batch (`smoke-verify-config`); the runner and `python3 -m ci.e2e resolve` accept old names too, and `python3 -m ci.e2e list` shows each alias with its batch
- One group directly: `nix build .#e2e.smoke --no-link -L`
- Runner, the `ci` group: `./scripts/run-e2e-tests.sh`
- Runner, one test or group: `./scripts/run-e2e-tests.sh session-lifecycle`, `./scripts/run-e2e-tests.sh smoke`
- Runner, all tests: `./scripts/run-e2e-tests.sh all`
- Resolve only: `python3 -m ci.e2e resolve ci`, or `python3 -m ci.e2e resolve --affected origin/main`
- Interactive driver: `nix run .#e2e.session-lifecycle.driverInteractive`, or `./scripts/run-e2e-tests.sh -i session-lifecycle`
- Local full or group run with bounded memory and parallel VMs: `just e2e-local [target] [jobs]`
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
- `session.follow_soft_reboot` (and so `canonical_activate` and `canonical_deactivate`) waits at most `deadline_s` seconds (600 by default) for the new userspace's backdoor, and fails within seconds, printing the console's timeouts and failed dependencies, when the new userspace reaches emergency mode or PID 1 freezes. A soft-reboot takes about 10 to 15 s in the VM, so a test with several round trips sets its own `globalTimeout` (see `tests/session/session-lifecycle.nix`). `session.wait_for_power_off` bounds a power-off the same way.
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
after, and booting was 38% of all test-script time in a full run of the earlier
live-overlay suite (190 boots for 106 tests).

**GitHub-hosted runners: not measured yet.** No number is recorded here
because none has been measured, and the CI lanes cannot provide one as they
stand: `ci.e2e run` reads `nix build` output as `internal-json` and keeps the
driver log only of a failed test, so a green job log holds no driver lines. A
measurement needs one dispatched run that keeps the driver output, for
example a temporary job on `ubuntu-26.04` (after the usual checkout and Nix
setup steps of `e2e.yml`) that builds a handful of tests with one VM at a
time and uploads the log:

```yaml
      - run: |
          nix build --no-link -L --max-jobs 1 \
            .#legacyPackages.x86_64-linux.e2e.{preflight-checks,init-config,smoke-verify-config,state-corruption,session-lifecycle} \
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

- wait on the real completion signal (a result file, the unit's state, a
  mountpoint, `nails status`), never a fixed sleep;
- never wait on a console regex with `wait_for_console_text`: it reads one
  queued console line per second, and a soft-reboot prints hundreds. Follow a
  soft-reboot with `session.follow_soft_reboot`, which polls the full console
  log;
- capture command output under `/run`, never `/tmp` (`/tmp` is part of the root
  overlay in a session, and the forensic tests image the disk under it). The
  output of a command that triggers a soft-reboot goes to the hidden volume: the
  shell that ran it dies at the switch, and the way back scrubs what the hidden
  session added to `/run`;
- every wait has a bounded timeout and a power-off wait goes through the QEMU
  process with a deadline (`session.wait_for_power_off`), not a bare
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
  (`/run/overlay-runtime`, `/run/<16 hex digits>`, `/run/nails*`) or harness
  capture in `/run`, no
  NAILS state file, no new entry in `/tmp`, `/var/tmp`, `/mnt`, `/root` or
  `/home/testuser`, an unchanged `/etc/nixos`, a blank hidden-volume disk and
  no `nails` process or unit;
- between scenarios (`<name>: reset the guest`) the guest is brought back to
  that baseline. A scenario that left a NAILS session behind (an overlay, the
  runtime directory, a live `nails` process) is
  reset by power-cycling the VM, so the
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
| `preflight-vfat-targets` | preflight-symlink-support | vm-config, nails, dosfstools |
| `preflight-hidden-root` | preflight-hidden-volume, preflight-mount-namespace | vm-config, nails, e2fsprogs |
| `init-config` | init-bootstrap, init-idempotency, init-refuse-overwrite, config-unknown-key | base node |
| `contract-json-schema` | verify-json-schema, contract-active-session | vm-config, nails, Python with jsonschema |
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
  `Restart=always` unit onto the decoy unless a stop job is enqueued first; the
  emergency enqueues the soft-reboot before its `cgroup.kill` for this reason.
- `research-dual-root-vt-emergency`: runs a hidden display and session on their
  own VT inside a whole-root overlay while the decoy desktop keeps running, and
  makes emergency a cgroup kill plus a VT switch. This dual-root design was
  evaluated as a way to keep the decoy desktop through an emergency and was not
  adopted.
- `research-dual-root-risks`: probes the dual-root design's risks (mount
  namespace copies, display and VT handling, shared-daemon writes).
- `research-blockdev-fixtures`: builds an LVM-on-LUKS stack on a loop device
  and captures what sysfs says about it for the block-device walk's tests
  (`scripts/capture-kernel-fixtures.sh blockdev`); copy the contents of its
  `result/kernel-fixtures/` into `nails-base/tests/fixtures/kernel/vm/`.

The spike that proved the whole-root soft-reboot, formerly
`research-soft-reboot-whole-root`, is now the regular test
`soft-reboot-mechanics` in `tests/session/`: it enters a whole-root overlay with
`systemctl soft-reboot` and returns twice, checks the vital paths, the `/run`
scrub and the decoy journal, then power-cycles through the firmware and scans
the raw decoy disk.

## Session tests (`tests/session/`)

The `session` tag groups the tests of the whole-root session. Each follows real
soft-reboots with `py/nails_e2e/session.py`:

- `session-lifecycle`: `init` and `check`, activation into the hidden root, a
  hidden write that lands only in the upper, deactivation without hidden `/run`
  residue, the upper persisting into the next session, an emergency and its
  timed log, and `recover`/`emergency` on the plain decoy changing nothing;
- `session-emergency`: the activation command typed on a decoy tty never reaches
  its history, emergency from a hidden login shell, the decoy's avahi-daemon
  and a service with a PID file in `/run` starting again after the emergency
  killed their hidden copies, the boot-loader units masked in the hidden
  session only, `--poweroff`, and the next cold boot on the plain decoy with
  the backend closed;
- `session-interrupted-entry`: a killed activation that `status` reports as an
  interrupted entry, a plain reboot that never enters the leftover next root,
  `recover`, Ctrl+C during the build, and emergency during an entry;
- `session-dns-records`: a name server and a search domain that only the hidden
  session's NetworkManager uses stay off the decoy after the way back: out of
  the openresolv records in `/run`, out of the `/etc/resolv.conf` that the
  decoy's `resolvconf.service` writes at its start, and out of its journal;
- `session-fstab-policy`: the decision `check` reports for every decoy
  filesystem, the read-only ESP, a separate decoy filesystem overlaid with a
  hidden upper, masked swap, and no hidden write on any decoy disk afterwards;
  with Debian's `blk-availability.service` running, a decoy filesystem on LVM
  that the switch keeps mounted for the way back (the unit's stop is cleared
  for the session and back afterwards);
- `session-nixos-hidden-system`: a hidden NixOS toplevel entered in one
  soft-reboot, the way back to the decoy toplevel, re-entry, a configuration
  that does not evaluate refusing the entry, and no bootloader or system
  profile change;
- `session-nixos-store-gc`: the hidden NixOS closure copied onto the hidden
  volume at entry, a decoy rebuild and garbage collection between two hidden
  sessions that deletes the hidden toplevel from the decoy store, the second
  session still starting it, and the decoy store (database, writable store
  layer, profiles and roots) unchanged by each session;
- `session-alert-delivery`: the notification of `sudo nails rehearse plant` and
  the watcher's alert for a disk mounted read-write reaching a notification
  server on the operator's own session bus, from the operator's uid, once on a
  decoy with `notify-send` and once on one without it, where `busctl` carries
  them;
- `session-disk-mounts`: a second disk mounted read-write in the hidden session
  raising the watcher's alert, `deactivate` freeing it while busy, and with
  `[session_mounts] read_only` the disk read-only from the hidden boot on, a
  disk hot-plugged during the session made read-only by the udev rule alone,
  every write failing, and both disks writable again and unchanged after the
  way back;
- `session-sleep-guard`: each `sleep_policy.mode` against a virtual lid switch
  that logind watches like a laptop's: with `warn` a closed lid suspends the
  session, with `block` the guard holds sleep, idle and lid-switch inhibitors
  and a closed lid does not, and with `teardown` a closed lid powers the
  machine off before the suspend runs;
- `soft-reboot-mechanics`: the mechanism itself, described above.

## Adding a fixture

Add files under `fixtures/configs/` and reference them from tests via `${./../../fixtures/...}` (from nested tests) or copied paths inside the VM. The canonical `--json` schemas live at the repository root in `docs/schemas/`; contract tests reference them directly (`${./../../../../docs/schemas/...}`) so the published contract and the one the tests enforce cannot drift.

## Portable distribution tier (`nix/distro-tests/`)

The suite above runs on `pkgs.testers.runNixOSTest`, whose driver backdoor only
exists in NixOS guests, so it cannot catch a regression on another distribution.
The distribution tier under `nix/distro-tests/` boots real Debian 13 and Ubuntu
24.04 cloud images on the same NixOS test driver through
[`numtide/nix-vm-test`](https://github.com/numtide/nix-vm-test), so the
whole-root session, platform detection, the read-only ESP and the
decoy-persistence preflight are exercised on a non-NixOS host. Debian 12 is not
in the table: its systemd is too old for a soft-reboot. A container tier cannot
do this: a privileged container cannot host an overlay upper on an overlay2
rootfs and cannot exercise journald or a soft-reboot.

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
  `e2e-tests/lib/hidden-volume.nix`. The tmpfs is below `/run`, which a
  soft-reboot does not carry, so after the switch the file is reachable only
  through its loop device, which is attached without autoclear so that the
  hidden root can be opened again on the decoy after a session. It also
  switches to a volatile journal (plus masking an active rsyslog), which the
  decoy-persistence preflight needs.
- `tests/smoke.nix`: the smoke scenario, generated once per image-table entry.
- `default.nix`: maps the scenario over the table and exposes the metadata.

Each smoke scenario shares the static musl `nails` binary into the guest over
9p (on `/run`, off the decoy disk); asserts platform detection selects the
Debian-family backend; images the decoy as booted for a baseline; runs the
decoy-persistence preflight (a stock persistent journal is refused, and passes
once the decoy is amnesic); runs `blk-availability.service` as lvm2 ships it
(the image's own unit on Ubuntu, Debian's copy where only `dmsetup` is
installed) and asserts that it stays loaded and active in the hidden session;
runs a decoy service that keeps a PID file in `/run`; cancels an activation
with SIGINT while it runs its checks (exit 130, nothing left behind);
activates, soft-rebooting into the whole-root overlay and writing canaries,
including under `/usr`, that must land in the upper; asserts the ESP is
read-only in the hidden root and the boot-loader units masked there; runs
`emergency`, which soft-reboots back to the plain decoy, where the PID-file
service starts again; asserts the kernel log names no session drop-in and no
failed unmount of the hidden volume; runs a second session
that ends with `deactivate`, entered with `/boot` and the ESP unmounted where
`blk-availability.service` runs, so that nothing carried below the hidden
volume keeps the unit's stop from unmounting it; rehearses on that session
(`rehearse plant` in it, a refused scan there, and after the plain
`deactivate` a clean scan of the raw decoy devices in the same boot, which on
Ubuntu 24.04's systemd 255 only the session's entry time allows); and runs the
host-side decoy disk-image check (`lib/disk_forensics.py`, shared with the
NixOS suite) with null and positive controls.

`nix-vm-test` boots the image from the Nix store under QEMU `-snapshot`, so
guest writes vanish when QEMU exits and there is no root qcow2 for the forensic
helpers. The scenario therefore runs its lifecycle in one QEMU process (a
soft-reboot keeps the kernel and QEMU) and, before each image, mirrors the live
disk into `<state_dir>/vm.qcow2` over QMP, where `disk_forensics.snapshot` picks
it up. A soft-reboot carries `/run` but not the mounts below it, so the scenario
mounts the 9p share again after every switch.

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
`ubuntu-26.04` runner exposes `/dev/kvm`; a self-hosted KVM runner is selected by
passing its label list. The CI matrix is planned by
`python3 -m ci.e2e distro-plan` and kept at or below eight parallel jobs
(distributions times their shards). `.github/workflows/distro-e2e.yml` runs it on
a nightly schedule, when a pull request gets the `distro-e2e` label, and on
manual dispatch, with the runner as an input. The tier is informational and
gates no merge until promoted to a required check. The NixOS suite in `e2e.yml`
is unchanged and stays NixOS-only.

Build one scenario directly:

```sh
nix build -L .#legacyPackages.x86_64-linux.e2e-distro.debian-13-smoke
```

### Moving to newer images

The images are those of the pinned `nix-vm-test` revision. To move forward,
update that input (`nix flake update nix-vm-test`), check that every
`distro`/`image` pair in `images.nix` still exists upstream (the `buildVmTest`
assertion names any that do not), and build the scenarios on a KVM host. An
attribute name containing a dot must be quoted on the command line, e.g.
`.#legacyPackages.x86_64-linux.e2e-distro."ubuntu-24.04-smoke"`.
