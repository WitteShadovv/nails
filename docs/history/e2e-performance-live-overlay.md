# E2E suite performance and robustness

> [!NOTE]
> **Historical record.** These measurements were taken on the VM suite of the
> earlier live-overlay mode (removed by
> [ADR 0008](../adr/0008-whole-root-soft-reboot.md)). Many of the tests, batches
> and commands it names no longer exist, and its "this branch" refers to work
> that has since been merged. How to run and profile the current suite is in
> [nix/e2e-tests/README.md](../../nix/e2e-tests/README.md).

This page covers where the NixOS VM suite (`nix/e2e-tests`) spends its time,
what has already been changed to make it faster and less flaky, how to measure
the effect, and what larger changes are left. All numbers come from real logs
of full local runs on the KVM workstation (15 GiB RAM, 12 cores), unless a row
says "estimate".

## Summary

- **Last clean full run:** 106 tests with `--max-jobs 1`, one group after
  another, took 3 h 45 min of wall time (run `e14ab48`). 3.2 h of that was
  test-script time and about 45 min was evaluation, system builds and driver
  start-up. The 9-10 h runs before that were mostly hangs: about 30 tests ran
  into a one-hour (later 30 min) global timeout each. See
  [Robustness](#robustness).
- **Where script time goes:**

  | Category | Seconds | Share |
  | --- | ---: | ---: |
  | Host-side work in 12 forensic/persona/nixos tests ("unlogged") | 5,432 | 47% |
  | Booting (190 boots, 84 of them reboots) | 4,394 | 38% |
  | Other guest commands, mostly in-guest rebuilds | 1,301 | 11% |
  | nails commands | 249 | 2% |
  | Power-off waits | 235 | 2% |
  | Polling waits (`wait_until_*`) | 102 | 1% |
  | Fixed in-guest sleeps | 23 | 0.2% |

- **Changes on this branch:** the boot no longer waits about 6 s for a DHCP
  lease. Decoy-image token scans no longer read every byte of a sparse 20 GiB
  image (710 s down to 4 s per scan in a benchmark). A local runner evaluates
  in bounded batches and runs about three VMs at once without running out of
  memory. The rest are robustness fixes.
- **Expected result:** about 1 h of wall time for a full local run, against
  3 h 45 min. The estimates are under [Before and after](#before-and-after).
- **Biggest remaining lever:** booting fewer VMs, by merging tests, and moving
  the remaining forensic host work off the critical path. See
  [Roadmap](#roadmap).
- **Wave R (T-140):** 19 single-boot tests now run as scenarios of 7 batched
  tests, one boot each, and one more moved to the cargo tests; forensic VMs
  reuse their erofs store image across restarts. Expected: 13 fewer VM boots
  and about 17 fewer store-image packs per full run, roughly 15-30 min of
  serial time. Details, the mapping and the re-measure commands are under
  [Wave R: fewer boots, one store image](#wave-r-fewer-boots-one-store-image).

## Method

The driver prints no wall-clock timestamps, but every nested driver action ends
with `(finished: <action>, in N seconds)`. `scripts/e2e-log-profile.py` rebuilds
the nesting of those blocks per test from `nix build -L` logs, or from
`nix log` output. It then assigns each top-level action to one category.

| Category | What it counts |
| --- | --- |
| `boot` | A start or wait that contains "waiting for the VM to finish booting" |
| `poweroff` | Waiting for power-off, shutdown or crash |
| `poll` | `wait_until_*`, `wait_for_unit` once booted, file, port, X and window waits |
| `nails` | Guest commands that run the binary |
| `sleep` | In-guest `sleep N` |
| `guest` | Other guest commands |
| `forensic` | The timing lines `disk_forensics.py` now prints |
| `unlogged` | Whatever is left of the script time |

`unlogged` is host-side Python (disk imaging and scanning),
`machine.execute()` calls (the driver does not log them, and the rebuild
helpers use them) and `machine.start()` (the driver runs the start script
outside any log block). Boot sums can exceed a multi-machine test's total,
because its machines boot in parallel.

```sh
# Profile any set of logs; when a test appears in several logs, the last one wins.
scripts/e2e-log-profile.py --top 25 .worktrees/fullsuite-*/*.log
scripts/e2e-log-profile.py --json .worktrees/fullsuite-e14ab48/*.log > profile.jsonl
```

The measurements below combine the four latest full runs (`25acda8`,
`f37cf0c`, `e1d15be` and `e14ab48`), using each test's most recent passing log:
106 of 109 tests.

## Measurements

### Top 25 tests by script time

Times are in seconds. `boots` counts VM starts, so every boot after the first
is a reboot.

| test | total | boots | boot | poweroff | poll | nails | sleep | guest | unlogged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| tcrypt backend test (`backends/tcrypt-*.nix`) | 932 | 3 | 49 | 4 | 0 | 1 | 0 | 7 | 871 |
| post-emergency-image | 841 | 3 | 56 | 4 | 1 | 2 | 0 | 5 | 771 |
| forensic-clean | 734 | 3 | 56 | 4 | 0 | 0 | 0 | 0 | 673 |
| activate-flake-override | 564 | 2 | 44 | 3 | 0 | 0 | 0 | 510 | 6 |
| standard-deactivation-forensic | 520 | 3 | 50 | 3 | 0 | 1 | 0 | 5 | 461 |
| snapshot-diff | 481 | 3 | 51 | 5 | 0 | 2 | 0 | 5 | 418 |
| var-lib-nixos-drift | 479 | 4 | 86 | 7 | 1 | 14 | 0 | 9 | 362 |
| persona-fresh-home-no-sync | 456 | 4 | 72 | 8 | 2 | 1 | 0 | 15 | 358 |
| nix-store-placement | 450 | 2 | 36 | 5 | 0 | 0 | 0 | 11 | 398 |
| persona-sync-pullback | 389 | 4 | 70 | 9 | 5 | 2 | 0 | 12 | 291 |
| persona-stale-writer | 361 | 2 | 46 | 3 | 0 | 2 | 3 | 8 | 298 |
| activate-full-rebuild | 325 | 3 | 51 | 2 | 0 | 4 | 0 | 5 | 263 |
| state-integrity | 254 | 5 | 194 | 19 | 0 | 9 | 0 | 28 | 3 |
| impermanent-decoy | 193 | 1 | 20 | 0 | 0 | 6 | 0 | 7 | 159 |
| state-transitions-observability | 189 | 2 | 144 | 14 | 7 | 1 | 0 | 19 | 5 |
| overlay-opaque-whiteouts | 118 | 4 | 86 | 9 | 0 | 7 | 0 | 14 | 1 |
| state-guard-rollback | 110 | 2 | 64 | 0 | 24 | 2 | 0 | 19 | 2 |
| state-crash-mid-activation | 101 | 2 | 89 | 2 | 0 | 2 | 0 | 6 | 2 |
| performance-validation | 100 | 3 | 69 | 3 | 5 | 8 | 0 | 7 | 8 |
| config-explicit-overlays | 94 | 3 | 66 | 8 | 0 | 6 | 0 | 12 | 2 |
| overlay-reset-upper | 91 | 3 | 68 | 6 | 0 | 5 | 0 | 11 | 2 |
| session-detection | 91 | 4 | 67 | 7 | 1 | 4 | 0 | 11 | 1 |
| state-signal-during-activation | 88 | 1 | 34 | 0 | 11 | 7 | 0 | 27 | 8 |
| preflight-bypass | 84 | 2 | 62 | 7 | 0 | 3 | 0 | 11 | 1 |
| preflight-hidden-volume | 84 | 1 | 67 | 0 | 0 | 4 | 0 | 11 | 3 |
| **All 106 tests** | **11,467** | **190** | **4,394** | **235** | **102** | **249** | **23** | **1,301** | **5,432** |

The median test runs for 52 s. 49 tests boot once, 37 boot twice and 20 boot
three to five times.

### Boot

- **Boot to `multi-user.target`:** median 21.8 s and p90 27.7 s over 154 boots
  with the 9p host store, against 17.8 s and 19.6 s for the 17 boots of
  `useNixStoreImage` VMs. Their erofs image is packed before that window
  opens, inside `machine.start()` (see
  [Host-side forensic work](#host-side-forensic-work)), so the store image
  boots faster but its start does not.
- **Load sensitivity:** boots on a loaded host reached 54-88 s, with the kernel
  phase at 5-7 s instead of 1.5 s, in preflight-hidden-volume and
  state-transitions-observability. Parallel runs have to leave CPU headroom.
- **Boot breakdown:** the serial console of a typical boot (config-handling)
  reads 1.7 s kernel, 4.7 s initrd (already systemd stage 1) and 10.9 s
  userspace. The last **6 s** of userspace was dhcpcd waiting for a lease from
  QEMU's user-mode network: `networking.dhcpcd.wait = "any"` holds
  `multi-user.target` until it has one. RSA host-key generation for sshd ran in
  parallel (about 0.9 s of CPU).
- **Totals:** booting costs 23 s per boot on average, or 73 min per full run.
  The 84 reboots alone cost about 35 min, counting their power-off and boot.

### Host-side forensic work

- **Where it is:** 12 tests hold 5,323 s of the 5,432 unlogged seconds: the 8
  forensic and backend tests, the 3 persona disk-image tests and the two
  rebuild-heavy nixos tests, whose `execute()`-driven rebuilds are not logged.
- **`strings -a` on a sparse 20 GiB file with 300 MiB of data:** 710 s on the
  workstation under load. It reads every byte of the virtual disk.
  `qemu-img convert` leaves the unallocated clusters as holes, but strings does
  not skip them. The suite ran 16 such scans. The new native scan reads only
  the data extents and took 4.3 s on the same file with 23 tokens.
- **`qemu-img convert` and `fls -r -p`** on an empty 20 GiB ext4 image take
  0.1 s and 2.2 s, so they do not explain the remaining time.
- **The rest is `machine.start()`, confirmed:** for a `useNixStoreImage` VM the
  start script packs the whole closure into an erofs image on every start,
  outside any driver log block, and `machine.start()` blocks until QEMU runs.
  The timing line `snapshot()` prints settles it: in the last full run's
  standard-deactivation-forensic log, `disk_forensics: machine.start took
  79.29 seconds` sits between `Creating Nix store image...` and `Created Nix
  store image.`, and is 79 of the 91 s of the "capture the decoy baseline
  image" subtest; the guest then booted in 10 s. That log packs the image
  three times (the profiler's `store_image_builds`), once per start, so about
  240 s of the test went there under a three-VM load. The other starts are
  not timed (the first one, and the one inside `canonical_deactivate`), but
  they run the same script. The rest of the 400-460 s that earlier runs left
  unattributed was the `strings -a` scans, fixed by the native scan below.

### Group wall time against script time

| Group (run `e14ab48`) | Wall | Script | Overhead |
| --- | ---: | ---: | ---: |
| smoke | 1,305 s | 848 s | 457 s |
| forensic | 5,553 s | 5,030 s | 523 s |
| nixos | 1,709 s | 1,529 s | 180 s |
| session | 948 s | 773 s | 175 s |
| shell | 793 s | 572 s | 221 s |
| all 16 groups | 13,697 s | 11,005 s | 2,692 s (20%) |

The overhead is evaluation, building each test's system closure and driver,
and VM start-up. It is paid serially with `--max-jobs 1`.

### Evaluation memory

`nix build` of a group evaluates every test's NixOS system in one process, and
the evaluator frees nothing until it exits. A single NixOS evaluation takes
about 1.8-2 GB (NixOS/nix#5200), and nixpkgs#65690 measured about 24 GB for
100 container configurations. Building `all` in one process therefore exhausts
15 GB before a VM starts. Evaluation was the out-of-memory cause, not the VMs.

## Changes on this branch

Each change is a separate commit with its measured or estimated saving.

| Commit | Change | Saving |
| --- | --- | --- |
| `test(e2e): add a log profiler…` | `scripts/e2e-log-profile.py` with unit tests; the source of every number above | Measurement only |
| `test(e2e): stop dhcpcd and sshd from slowing every VM boot` | `dhcpcd.wait = "background"`; sshd off (`lib/vm-config.nix`) | About 6 s per boot, about 19 min per full run (estimate from the console timings) |
| `test(e2e): raise the 9p msize…` | `virtualisation.msize = 262144`, from the 16 KiB default | 1-3 s per boot plus store-heavy steps (estimate; QEMU and Debian report about 30% read throughput at 512 KiB) |
| `test(e2e): scan decoy images for tokens without reading their holes` | `run_strings_scan` reads only data extents; parity with `strings -a` checked by a randomised unit test; timing lines | Up to about 1 h per full run: 16 scans of up to about 290 s each on the host |
| `ci(e2e): evaluate in bounded batches and build VM tests by derivation` | `--eval-batch N`, building `<drv>^*`, `--jobs auto`, one-line-per-test summary with log paths | Makes three parallel VMs possible; the serial 3.2 h of script time becomes about 1.1-1.3 h |
| `build(just): add e2e-local…` | `just e2e-local [target] [jobs]` | Replaces the per-group `--max-jobs 1` loop |
| `test(e2e): give notify-session-push a shard weight` | Fixes the failing `ci.e2e check` / weights unit test | n/a |
| Robustness commits | See [Robustness](#robustness) | Removes hangs worth 5-30 min each |
| `test(e2e): time the VM restart inside forensic snapshots` | Attributes the remaining unlogged forensic time | Measurement only |

**VM sizing.** VM memory stays at 2 GiB (4 GiB for graphical nodes). QEMU
allocates guest RAM lazily, but the guest's page cache and its
tmpfs-backed writable store grow into the whole allocation during the
in-guest rebuild tests. Lowering it without a measurement would risk those
tests. Parallelism is sized in the runner instead: `--jobs auto` allows one VM
per 3.5 GiB above a 3 GiB reserve, and at most one per two host cores. That is
3 on the workstation, about 10.5 GiB worst case. To measure real guest use
before lowering `memorySize`, add
`machine.succeed("free -m; cat /sys/fs/cgroup/memory.peak || true")` at the end
of a rebuild test and a plain test.

**Not changed.**

- **Documentation off:** the in-guest rebuild tests build the hidden system
  from `/etc/nixos/configuration.nix`, so shrinking the decoy closure could
  make those builds need paths the guest store no longer has.
- **Reboots:** every reboot found comes from `nails deactivate` itself, which
  powers the machine off as product behaviour, or from a test of reboot or
  power-off. None could be dropped without a product mode; see
  [Roadmap](#roadmap).

## Running and measuring

```sh
# Bounded-parallel local run: eval 4 tests per process, about 3 VMs at once,
# failed logs and durations under ./e2e-logs, one summary line per test.
just e2e-local            # all tests
just e2e-local forensic   # one group
just e2e-local smoke 2    # force 2 VMs at once
# Equivalent:
./scripts/run-e2e-tests.sh run --jobs auto --eval-batch 4 --log-dir e2e-logs \
    --durations-out e2e-logs/durations.jsonl forensic
# The synchronisation lint (CI runs it in lint-misc):
just e2e-sync-lint
```

### Before and after

To separate the per-test savings from the parallelism, measure the same group
three ways and profile each:

```sh
before='git+file://<checkout>?ref=<branch>&rev=71f0b65ae822027afa3ef7f6347d2611a41a5358'
after='git+file://<checkout>?ref=<branch>'

# 1. Before, serial (as the full runs were made):
/usr/bin/time -v nix build --no-link -L --keep-going --max-jobs 1 \
    "$before#legacyPackages.x86_64-linux.e2e.forensic" > before-forensic.log 2>&1
# 2. After, serial: per-test savings only (dhcpcd, msize, the native scan):
/usr/bin/time -v nix build --no-link -L --keep-going --max-jobs 1 \
    "$after#legacyPackages.x86_64-linux.e2e.forensic" > after-serial-forensic.log 2>&1
# 3. After, with the runner (bounded evaluation, parallel VMs), from the
#    research-fastvm worktree:
/usr/bin/time -v just e2e-local forensic 2> after-parallel-forensic.txt

scripts/e2e-log-profile.py --top 15 before-forensic.log
scripts/e2e-log-profile.py --top 15 after-serial-forensic.log
```

The derivations differ between the revisions, so nothing is served from the
store. For a group without forensic tests, `smoke` (19 tests, 22 min serial)
shows the boot savings and the parallelism. `/usr/bin/time -v` reports the
peak memory of the nix process, which shows the evaluation bound.

**Estimates for a full run:**

| | Serial script time | Wall time |
| --- | ---: | ---: |
| Before (`e14ab48`, `--max-jobs 1`, per group) | 3.2 h | 3 h 45 min |
| After: dhcpcd (-19 min) and msize (about -5 min) | about 2.8 h | about 3 h 20 min |
| After: plus native scans (-40 to -60 min) | about 2.0-2.2 h | about 2.5 h serial |
| After: plus `just e2e-local` (3 VMs, batched evaluation) | same | **about 1 h** (long pole tcrypt about 8 min; eval about 10 min) |

## Wave R: fewer boots, one store image

Wave R (T-140, plus T-114's leftovers) changes nothing in the product. Each
item is its own commit on `chunk/r-vmspeed`.

### Batched single-boot tests

Tests with an identical node now run as scenarios of one test
(`lib/batch.nix`, `nix/e2e-tests/py/nails_e2e/batch.py`; how it works is in
[nix/e2e-tests/README.md](../../nix/e2e-tests/README.md#batched-scenarios)).
Every scenario starts with a check that the guest is as clean as it booted and
the guest is reset between scenarios, by a power cycle when a NAILS session was
left behind; the activating scenarios run last, so no batch needs one in a
passing run. The old names stay aliases of their batch.

Node identity was checked by evaluating the node's VM derivation of the batch
and of the tests it replaces in one evaluation: equal for every batch.
`preflight-mount-namespace` listed `util-linux` a second time (vm-config
installs it); its deduplicated package set equals `preflight-hidden-volume`'s.
Each scenario's statements were compared with the old test's as Python ASTs of
the rendered scripts: identical apart from the dropped `machine.start()`.

| Batch | Former tests | Their script time (s) | Of which first boots (s) |
| --- | --- | ---: | ---: |
| `preflight-checks` | preflight-nixos-config, -nixos-build-target, -upper-fs-capability, -state-check | 145 | 93 |
| `preflight-vfat-targets` | preflight-overlay-compat, -symlink-support | 43 | 35 |
| `preflight-hidden-root` | preflight-hidden-volume, -mount-namespace | 105 | 87 |
| `init-config` | init-bootstrap, -idempotency, -refuse-overwrite, config-unknown-key | 152 | 123 |
| `contract-json-schema` | verify-json-schema, contract-active-session | 52 | 41 |
| `notify-dispatch` | notify-malformed-signal, -no-notify-send, -dispatch-signal-flow | 114 | 89 |
| `smoke-verify-config` | verify, config-handling | 65 | 48 |
| **19 tests in 7 batches** | | **675** | **514** |

Times are from the four full runs profiled above (before the dhcpcd change).
`help-version-no-leak` (31 s, 29 s of it boot) moved to the cargo tests.

### Store image reuse

`default.nix` now gives every machine a copy of its start script in which the
erofs pack is skipped when an image from an earlier start of the same machine
is still there and unchanged (size and nanosecond mtime match a stamp written
after `mkfs.erofs` succeeded; anything else rebuilds as before). Machines
without a store image keep the stock script. The tests that power-cycle a
store-image VM restart it 17 times per full run: forensic-clean,
standard-deactivation-forensic, snapshot-diff, post-emergency-image and
the VeraCrypt backend test twice each, var-lib-nixos-drift three times,
activate-full-rebuild twice, nix-store-placement and decoy-journal-leak once.

### Expected savings

Estimates for a full local run; the merged tests are cheap, so most of the
merge's saving is serial time spread over the three parallel slots, while the
store image saving sits on the forensic tests, the long poles.

| Change | Serial | Wall at 3 VMs | Basis |
| --- | ---: | ---: | --- |
| 13 fewer boots (19 tests in 7 batches, 1 test moved to cargo) | 4-5 min | 1.5-2 min | 13 x 17-24 s per boot (median first boot 23.7 s, about 6 s less since the dhcpcd change), minus about 2 s per reset |
| 13 fewer test derivations | 2-5 min | about 1 min | 10-25 s each for evaluation, driver build (type check and lint) and VM start; the group overhead above is 25 s per test |
| Store image reuse | 11-23 min | 3-5 min | 17 restarts x 40-80 s (79 s measured once under a three-VM load) |
| **Total** | **about 17-33 min** | **about 6-8 min** | from the 75 min measured on `integrate` |

The per-group runs shrink more. Test derivations per group, before and after:
`all` 113 to 100, `preflight` 15 to 10, `smoke` 19 to 12, `contract` 6 to 4,
`notification` 5 to 3, `init` 4 to 2, `ci` 10 to 9; `config` stays at 3.

### Re-measuring

Measure at the commit before Wave R and at the branch head. The derivations
differ between the two revisions, so nothing is served from the store. On the
KVM workstation:

```sh
base=29c632d7533de4d29265dcf9deae2d09da8e63a4   # overhaul before Wave R
head=$(git rev-parse chunk/r-vmspeed)
git worktree add --detach .worktrees/measure-base "$base"
git worktree add --detach .worktrees/measure-head "$head"

# Run a selection on one side with one VM at a time (so script time and boots
# compare directly), then fetch every test's driver log with `nix log`: the
# runner keeps only the logs of failed tests. Evaluation stays bounded.
measure() {  # measure SIDE NAME TARGET...
  local side=$1 name=$2; shift 2
  ( cd ".worktrees/measure-$side" &&
    /usr/bin/time -v ./scripts/run-e2e-tests.sh run --jobs 1 --eval-batch 4 \
      --durations-out "../measure-$side-$name.jsonl" "$@" \
      2> "../measure-$side-$name.time"
    mkdir -p "../measure-$side-$name"
    for test in $(python3 -m ci.e2e resolve "$@"); do
      nix log ".#legacyPackages.x86_64-linux.e2e.$test" \
        > "../measure-$side-$name/$test.log" 2>&1
    done )
}

# 1. The merged groups (about 40 tests at the base, 30-40 min per side):
for side in base head; do
  measure "$side" merged preflight config contract init notification smoke
done
scripts/e2e-log-profile.py --top 40 .worktrees/measure-base-merged/*.log
scripts/e2e-log-profile.py --top 40 .worktrees/measure-head-merged/*.log

# 2. The store image, on two forensic tests (15-25 min per side):
for side in base head; do
  measure "$side" forensic standard-deactivation-forensic forensic-clean
  scripts/e2e-log-profile.py --json .worktrees/measure-$side-forensic/*.log |
    python3 -c 'import json,sys
for r in map(json.loads, sys.stdin):
    print(r["test"], r["total"], "packs", r["store_image_builds"], "reuses", r["store_image_reuses"])'
done
grep -h "machine.start took" .worktrees/measure-*-forensic/*.log

# 3. The full suite with the runner, as T-140's 75 min was measured:
( cd .worktrees/measure-head && /usr/bin/time -v just e2e-local all ) 2> e2e-wave-r.time
```

What to look for:

- in each batch's log, one `starting vm`, every `<name>: starts from a clean
  guest` subtest passing, one `batch: <name> passed in N s` line per scenario
  and no `power-cycled the VM` reset line;
- in each forensic log on the head side, `store image cache: machine:
  enabled`, one `Creating Nix store image...` and `Reusing Nix store image.`
  on every later start; `disk_forensics: machine.start took` should drop from
  tens of seconds to about a second;
- the sum of a batch's scenario times against the old tests' totals in the
  table above, and each batch's `seconds` in `e2e-logs/durations.jsonl`, which
  replace the estimated weights in `shard-durations.json` (`python3 -m ci.e2e
  regen-weights e2e-logs/durations.jsonl`).

## virtiofs and host memory

In October 2026 the flake's `nixpkgs` moved to `7fd4004d` (nixos-unstable of
2026-10-11), whose test VMs read the host store over virtiofs instead of 9p
(roadmap item 4). The start script runs one `virtiofsd` per shared directory
(the store, `xchg` and `shared`), and the guest RAM is a shared memfd
(`memory-backend-memfd,share=on`) that the daemons map to reach the guest's
buffers. `lib/vm-config.nix` lost its `msize` line, and `session-nixos-store-gc`
its 4 GiB guest, which only 9p needed.

`--jobs auto` budgets 3.5 GiB of host memory per test (`GIB_PER_TEST` in
`ci/e2e/run.py`), so the switch was checked against that budget. During a full
run of the 59 tests (56 min) with two tests at once (`--jobs 2`; up to three
VMs, since three of the tests start two VMs each), a sampler read `/proc` every
5 s for every QEMU process, its virtiofsd daemons and its test driver:

| At a test's peak | Largest | Typical |
| --- | ---: | ---: |
| Guest RAM the guest touched (QEMU's memfd, `RssShmem`) | 2.00 GiB, the whole guest | 0.5 GiB |
| QEMU's own memory (`RssAnon`) | 0.04 GiB | 0.04 GiB |
| The virtiofsd daemons (`RssAnon`) | 0.12 GiB | under 0.01 GiB |
| Test driver (`RssAnon`) | 0.06 GiB | 0.06 GiB |
| **The whole test** | **2.21 GiB** (`session-nixos-store-gc`) | **0.6 GiB** |

- A test costs the host at most its guest's RAM plus about 0.2 GiB. The
  daemons map the guest RAM but add almost nothing of their own; the most was
  `session-nixos-store-gc`, which copies and verifies a whole system closure
  through the store share.
- The memfd counts as `Shmem` in `/proc/meminfo`: `free` lists it under
  buff/cache, but `MemAvailable` does not count it as available.
- Four tests filled their 2 GiB guest (the two NixOS session tests,
  `examiner-audit` and `rehearse-canary`) and `soft-reboot-mechanics` came
  close with 1.93 GiB. The two graphical tests touched less than 1 GiB of
  their 4 GiB.
- Host-side work stayed small. For the second half of the run the sampler
  also summed each driver's whole process tree (22 tests, four of them
  forensic): the largest helper, `mkfs.erofs` packing a store image, held
  0.36 GiB, and no test held more than 0.42 GiB while its VM was not running.
- The running tests held at most 4.4 GiB together (`session-nixos-hidden-system`
  next to `session-nixos-store-gc`). `MemAvailable` never fell below 5.2 of
  15.4 GiB, with the desktop and other work running next to the suite.

So `GIB_PER_TEST` stays at 3.5 GiB: a test with a 2 GiB guest needs at most
2.2 GiB, which leaves room in the budget for a 4 GiB graphical guest that
fills its RAM, and a 15 GiB, 12-core host still runs three tests at once.

The run's one failure was the soft-reboot re-entry hang, not an effect of host
load: `performance-validation` entered the hidden session a second time in the
same VM (`perf-activate-1`), the new userspace's console went quiet after
`suid-sgid-wrappers.service`, and the driver gave up with
`no backdoor 600 s after the soft-reboot`. The test passed when run again.

## Robustness

A faster suite only helps if it does not flake, so the failure history in
`.worktrees/fullsuite-*` and `.worktrees/rerun-*` (18 runs, `25acda8` to
`e14ab48`) was classified. Only failures of a `vm-test-run-*` derivation itself
were counted, once per run. That gives 190 exit-1 failures and 63 exit-143
failures. Every exit 143 was the driver's global timeout firing. Most failures
at `25acda8`, `f37cf0c` and `d9640e3` were deterministic breakage while the
overhaul was in progress. What remains:

| Failure (runs) | Class | Fixed by |
| --- | --- | --- |
| About 25 emergency, faults and overlay tests hung to the global timeout (`25acda8`, `f37cf0c`, `d9640e3`). | Emergency killed the driver's control pipe (`Killed \| ( base64 -w 0; echo )`, then `Bad file descriptor`). | Product fixes `23a23911` … `9fa5b374` |
| var-lib-nixos-drift and activate-full-rebuild hung for 1,800 s. | Captures redirected into the overlaid `/tmp`. | `c1f25555`; the rest moved to `/run` on this branch |
| standard-deactivation-forensic: `introduced registry tokens onto the decoy image: ['nails.toml', 'state.json']`. | verify's capture on the decoy disk. | `d753f160` (run_verify under `/run`) |
| var-lib-nixos-drift: `Timed out after 30s waiting for console log regex: Emergency teardown complete`. | Console regex lost when journald restarted. | `31d67a9` (result file); emergency-backend-lock and performance-validation still had the pattern, fixed here |
| emergency, post-emergency-image: `emergency unit did not finish within 60s` with `inactive (dead)`. | The systemd reload wiped the unit's record. | `31d67a9` (ExecStopPost result under `/run`) |
| emergency-graphical: `pgrep -x Xorg failed`. | X snapshotted before the restarted X server was up. | `6440be9a` |
| notify-session-push: `mountpoint -q /home failed`. | Asserted before the detached activation committed. | `71f0b65a`; same ordering fixed in notify-autostart-lifecycle here |
| overlay-reverse-order-unmount: `got: []`. | Read the journal after emergency scrubbed it. | `dd6062a` |
| nix-store-placement: `UnicodeDecodeError` in `run_fls`, at one revision only. | Flaky: depended on bytes in the image. | `1007ea53` |
| performance-validation: 29.5 s over a 5 s budget. | Load-sensitive budget. | Product fixes `eb9c04f6` and `e1d15be`; still the most load-sensitive test |
| uefi-esp-nvram-invariant: `Buffer I/O error … lack of free disk space` (`e14ab48`). | Infrastructure: host disk full. | Keep about 30 GB free for parallel forensic runs (raw snapshots are sparse but written to the build directory). |

No test failed and then passed at the same revision, so the races above
showed up across revisions rather than as same-run flakes.

### Fixes on this branch

- **Captures under `/run`.** These helpers now capture to `/run`:
  `read_status_json`, both `run_command_capture` variants,
  `run_pty_command_capture`, the preflight capture, the `nails_e2e` package,
  the Syncthing REST payload and the hand-written captures in
  quickstart-zero-config and init-refuse-overwrite.
  - emergency-from-activating, state-concurrent-invocation and
    state-transitions-observability watched `/tmp/<label>.rc` for an early
    exit, but the helper writes `/run/<label>.rc`. That check could never fire,
    so an early exit cost 180 s and showed up as a generic timeout. It now
    fails at once.
- **Fail fast in `canonical_deactivate`.** It checks the deactivate unit from a
  daemon thread, so a dead shell cannot hang it. A unit that failed while the
  system is not stopping fails the test after a 30 s grace period, instead of
  after the 300 s power-off deadline.
- **A deadline on every power-off wait.** `canonical_deactivate_for_user`,
  `reboot_after_emergency` and shell-history-real-sudo used the driver's
  `wait_for_shutdown()`, which has no deadline. They now wait on the QEMU
  process with one and fail with the serial console tail.
- **No console-regex waits.** emergency-backend-lock waits on its unit's
  `/run` result file, which also requires a `success 0` exit.
  performance-validation reads the emergency's `duration_ms` from a file the
  unit writes directly (`StandardOutput=truncate:`), bypassing journald.
- **Detached activations.**
  - state-guard-rollback waited for `Inactive` in `state.json`, which the file
    can show before the worker has run, so its checks could pass without
    testing anything. It now waits for the worker unit to stop first.
  - notify-autostart-lifecycle asserts the `/home` overlay only after the
    commit.
- **The lint.** `ci/e2e_sync_lint.py` (CI `lint-misc`, `just e2e-sync-lint`)
  flags four patterns: fixed sleeps outside bounded polling loops,
  `wait_for_console_text` and `wait_for_console_log`, output redirected into
  `/tmp`, and `wait_for_shutdown()` without a bounded process wait.
  - Exceptions carry `sync-lint: allow <rule> -- <reason>`.
  - Four are allowed: three absence windows in the persona tests, where nothing
    happening is the assertion, and `canonical_deactivate`'s wait after QEMU
    has exited.

### Parallel safety and retries

- **Isolation.** Each test is its own sandboxed derivation, with its own build
  directory, network namespace and VDE switch. Driver-side temporary files use
  `tempfile.mkdtemp`, and no test forwards host ports or shares a host path,
  so concurrent tests cannot collide.
- **Execute mode.** `--execute` runs drivers one after another, each in its own
  scratch directory.
- **Failures and retries.** The runner keeps `--keep-going`, so one failure
  never stops the others. It adds no retry. The existing opt-in `--retries`
  reports any pass on a retry as FLAKY, and the nightly job does not hide it.
  A retry should be added only for a documented infrastructure cause.

### Remaining risks

- 52 waits rely on the driver's 900 s default timeout. Every test now has a
  900 s global timeout, so a hang is bounded, but a tighter timeout on the
  display-manager and `user@` waits would fail faster.
- performance-validation depends on host load by design. Run it alone, as the
  nightly job already does with `--execute`, rather than next to two other VMs.

## Options evaluated

| Option | Supported in pinned nixpkgs (26.05, `4bd9165a`)? | Assessment |
| --- | --- | --- |
| **VM memory/CPU sizing** | Yes | Keep 2 GiB and 2 cores. Size parallelism by host RAM (`--jobs auto`), not by shrinking guests. Free-page reporting needs `virtualisation.qemu.options` (`-device virtio-balloon-pci,free-page-reporting=on`). It returns freed guest pages but not page cache. |
| **Evaluation memory** | — | Done: evaluate in batches of N in short-lived processes, then build by `.drv`. `nix-eval-jobs` (≥ 2.35.3 caps `workers × max-memory-size` for the whole run) is the next step if batch evaluation becomes the long pole. Setting `node.pkgs` to share one pkgs instance across nodes cuts per-test evaluation cost (`nixos/lib/testing/nodes.nix`). |
| **9p msize** | Yes (`virtualisation.msize`, `qemu-vm.nix:414`) | Done (256 KiB). The virtio transport caps msize at `PAGE_SIZE*(VIRTQUEUE_NUM-3)`, about 500 KiB. |
| **virtiofs** | No: the flake's `nixpkgs` (`4bd9165a`, 26.05) has 9p only (`-virtfs`, no `virtiofs` anywhere in `qemu-vm.nix`) | nixpkgs PR #552774 (merged 2026-09-08) switched the test VMs to virtiofs, measuring 1.08-1.44x per test. The lock already holds a revision with it: `nix-vm-test`'s own `nixpkgs` input (`151fa4e8`, 2026-10-06), whose `qemu-vm.nix` sets `useVirtiofs = isLinux` with no opt-out, starts one `virtiofsd` per share, turns on `virtualisation.qemu.enableSharedMemory` by default and removes `virtualisation.msize` and `nixStore9pCache` (`mkRemovedOptionModule`, an evaluation error). So the switch is gated on bumping the flake's `nixpkgs` to that revision or later, in the same change that drops the `msize` line from `lib/vm-config.nix`; then re-check `--jobs auto` against the shared guest memory (PR #563324). The store image cache keeps working there: the start script still prints the same two markers. **Done (2026-10):** the flake's `nixpkgs` is `7fd4004d` (nixos-unstable of 2026-10-11); the memory check is under [virtiofs and host memory](#virtiofs-and-host-memory). |
| **`useNixStoreImage` (erofs)** | Yes (`qemu-vm.nix:825`) | Boots about 4 s faster than 9p here. It removes slow store metadata access: PR #181746 measured gitlab at 1,000 s on 9p against 249 s. The image is rebuilt by every start; within one test it is now reused (Wave R), but every test still packs it once, it needs `writableStore = true` for tests that add to the store, and in-guest rebuilds see only the closure. A prebuilt image as a derivation would be shared by every test with the same closure and by the binary cache, at the price of a store path of about the closure's size per distinct node. Switch one plain group and measure before switching all. |
| **`mountHostNixStore`** | Yes; it is the 9p default | Nothing to gain on its own. |
| **Lighter guest** | — | Done: dhcpcd background and no sshd. systemd initrd is already the default in 26.05. Documentation off is deferred (see above). X only runs on the graphical profile already. |
| **Avoiding reboots** | — | No safe case today: each reboot is `nails deactivate`'s own power-off or a reboot test. A soft-reboot (`systemctl soft-reboot`) mode for deactivation would cut about 25 s per reboot, if a whole-root mode makes that safe. |
| **Test merging** | — | 49 tests boot once and spend 1,208 of their 1,655 s booting. In the preflight, shell, security, overlay, session, notification, config, contract, init and smoke groups, boot plus power-off is 70-90% of the time. Done in Wave R for the tests with an identical node in the preflight, config, contract, init, notification and smoke groups (7 batches, `lib/batch.nix`). The overlay, faults, security and shell groups have more candidates on the shared base node. |
| **nspawn containers** | Yes (`containers` in `nixos/lib/testing/nodes.nix:185`, PR #478109). Needs `auto-allocate-uids` and `uid-range`. | About 25-30% faster than VMs in the PR's benchmark. The host kernel is shared: no kernel modules, no X11, no setuid binaries, no `reboot()`/`crash()`, `/proc` and `/sys` forwarded from the sandbox, and no loop devices, dm-crypt/LUKS or block devices. Overlayfs inside the unprivileged build sandbox is unverified. This only fits config/contract/CLI tests that need no hidden volume, and those are better served by tiering. |
| **QEMU savevm/loadvm** | No driver support; HMP/QMP is exposed | Blocked: QEMU's 9pfs adds a migration blocker once the share is mounted, and a 9p-store VM always mounts it. Possible only with a store-image VM and no 9p shares (xchg/shared are 9p too). High effort for a saving smaller than merging. |
| **Faster polling and fixed sleeps** | — | Polling costs 102 s and fixed sleeps 23 s of guest time. Driver polling is 1 s. Not worth more than the lint, which keeps new sleeps out. The 60 s of persona absence windows are assertions, not waits. |
| **Tiering to real-kernel tests** | — | The rootless user+mount namespace harness (`nails_core::test_support`, `docs/testing-strategy.md`) is on this branch. Done in Wave R: the help/version sweep and four config parsing checks moved to the cargo tests, since none of them needs a kernel feature, root or a boot. Next: the `nails init` scenarios (a tmpfs hidden root in the namespace, `/etc/nixos` bind-mounted), status/verify JSON for states that need no real activation. Whiteouts and opaque directories, LUKS, journald, reboot, session and activation tests stay in VMs. |

## Roadmap

Ranked by saving per unit of effort.

| # | Option | Saving (full run) | Effort | Risk |
| ---: | --- | --- | --- | --- |
| 1 | **Measure this branch** (commands above), then refresh `shard-durations.json` | Confirms about 1 h wall | 1 run | None |
| 2 | **Done in Wave R** for 19 tests (7 batches). **Merge independent single-boot tests**, starting with the preflight (13), config/contract/init (9), notification (5) and smoke (5) tests: one boot per group of scenarios, with a cleanup helper (deactivate if active, wipe `/mnt/data`, reset failed units) between them | 49 single-boot tests spend 1,208 s booting. Folding them into about 10 boots saves about 15 min serial, or 5 min wall at 3 jobs | Medium | Medium: a scenario's leftovers can mask or cause another's failure. Each merged scenario must start with an assertion that the previous one left no state, and must keep its own `subtest` |
| 3 | **Done in Wave R.** **Cache the erofs store image across starts of one forensic test**, or make the forensic VM boot from a prebuilt store disk (`useBootLoader`) | About 79 s per restart measured under load, 17 restarts per full run: 11-23 min serial | Low-medium | Low: the image contents do not change between starts |
| 4 | **Done (2026-10).** **nixpkgs bump to virtiofs** (PR #552774); `virtualisation.msize` dropped in the same change | 8-44% of guest IO time per test | Low (flake update) | Checked: a test needs at most its guest RAM plus about 0.2 GiB, so `--jobs auto` keeps 3.5 GiB per test ([virtiofs and host memory](#virtiofs-and-host-memory)) |
| 5 | **Started in Wave R** (help/version and config parsing). **Tier config/contract tests to real-kernel tests**; the `nails init` scenarios are next | About 5 min serial, plus faster CI feedback | Medium | Low if the VM test remains for one end-to-end path |
| 6 | **Soft-reboot or no-reboot deactivation mode** for tests that are not about the reboot (needs a product decision, and the whole-root mode) | About 25 s for each of 84 reboots, so up to 35 min serial | High | High: the power-off is the anti-forensic contract; a test-only mode must not weaken what the tests prove |
| 7 | **`useNixStoreImage` for the plain profile** | About 4 s per boot (190 boots, about 13 min) plus faster store scans | Low to try | Medium: in-guest rebuilds see only the closure; needs `writableStore = true`; image rebuilt per start |
| 8 | **nspawn containers** for tests without block devices | 25-30% per container test | High | High: no LUKS, loop or reboot, uncertain overlay behaviour in the build sandbox; tiering (5) covers the same tests better |
| 9 | **QEMU snapshots** | Setup time of the multi-phase tests | High | High: blocked by 9p migration blockers; needs store-image VMs without shares |

## Sources

- nixpkgs at the pinned revision: `nixos/modules/virtualisation/qemu-vm.nix`
  (`msize` :414, `useNixStoreImage` :825, `mountHostNixStore` :847,
  `nixStore9pCache` :856) and `nixos/lib/testing/nodes.nix` (nspawn
  `containers` :185; dhcpcd comment :93-96).
- 9p msize: <https://bugs-devel.debian.org/1033010>,
  <https://lists.gnu.org/archive/html/qemu-devel/2021-02/msg06951.html>, and
  the virtio cap in `net/9p/trans_virtio.c`. Cache modes:
  <https://docs.kernel.org/filesystems/9p.html>.
- virtiofs for test VMs: <https://github.com/NixOS/nixpkgs/pull/552774>; shared
  memory: <https://github.com/NixOS/nixpkgs/pull/563324>.
- erofs store image: <https://github.com/NixOS/nixpkgs/pull/181746>,
  <https://github.com/NixOS/nixpkgs/pull/241373>.
- nspawn test nodes: <https://github.com/NixOS/nixpkgs/pull/478109>.
- Evaluation memory: <https://github.com/NixOS/nix/issues/5200>,
  <https://github.com/NixOS/nixpkgs/issues/65690>, nix-eval-jobs
  <https://github.com/NixOS/nix-eval-jobs/releases/tag/v2.35.3>.
- 9p migration blocker: `hw/9pfs/9p.c` in QEMU (`v9fs_attach`).
- Free page reporting: <https://docs.kernel.org/mm/free_page_reporting.html>.
