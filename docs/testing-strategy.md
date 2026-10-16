# Testing strategy

This document says which test tier covers which kind of behaviour, and when a
mock is still the right tool. How to run each tier locally is in the
[development guide](development-guide.md#test-tiers); the CI jobs are in
[ci.md](ci.md).

The tiers grew out of bugs that passed every unit test and failed only in a VM,
found on the earlier live-overlay code; the next section names some of them.

## Why mocks are not enough

Filesystem access sits behind the `Filesystem` trait so orchestration can be
tested without root. Each test double encodes a belief about the kernel or a
tool, and nothing checks that belief unless a test also runs against the real
thing. Past examples: overlayfs reporting its own anonymous device rather than
the upper's, the kernel printing mount options octal-escaped, `redirect_dir=off`
meaning different things on different kernel builds, and a closed stderr
turning `eprintln!` into a panic.

Ordered by how much NAILS depends on the behaviour and how wrong a mock can be,
these need a real kernel or a booted system:

1. **Mount and overlay semantics.** Mount ids, the device an overlay reports,
   copy-up, whiteouts and opaque directories, busy unmounts, option escaping and
   what mountinfo prints.
2. **`/proc` inspection.** `stat` and `status` of real processes, cgroups, and
   mountinfo seen from another namespace.
3. **File metadata.** `st_dev` and `st_ino` through an overlay, atime under
   `O_NOATIME`, `trusted.*` against `user.*` xattrs.
4. **Process lifetimes.** Signals, cgroup kills, process groups, broken pipes.
5. **systemd.** The soft-reboot itself, unit ordering across it, output
   formats and timing. Only a booted system has these.

## The tiers

### (a) Real-kernel tests in an unprivileged user and mount namespace

`nails_base::test_support::Rerun` re-executes the calling test binary, filtered
to that one test. Before `exec`, while the child is still single-threaded, it
unshares `CLONE_NEWUSER | CLONE_NEWNS` and maps the caller to uid 0; the child
makes `/` recursively private and runs the body, and every mount dies with it,
even after a panic. `ScratchTmpfs` gives the body a tmpfs. On a host without user
namespaces the test prints why and passes vacuously; `NAILS_REQUIRE_USERNS=1`
turns that skip into a failure. A test that also needs something no CI runner
has (a delegated cgroup, a NixOS `/bin/sh`) ends with `skip_host` instead, which
stays a skip. Re-executing rather than forking avoids
inheriting a lock from another test thread, and works under libtest and nextest.

What runs in this tier:

| Tests | Covers |
| --- | --- |
| `nails-core/tests/whole_root_kernel.rs` | The session's own mechanics on real mounts: the root overlay and its upper, the read-only ESP, the fstab policy, the transition step against a live mount table, the way back, the cgroup kill, rollback of a failed entry, the chrooted NixOS activation and the kept store closure |
| `nails-cli/tests/early_dispatch.rs` | `emergency` detaching a leftover next root before it reads the configuration |
| `nails-cli/tests/maintenance_cli.rs` and the `kernel_tests` modules of `rehearse_cli.rs`, `cli_contract.rs`, `activate_gate.rs`, `nails-cli/src/cli/logging/tests.rs` and `nails-cli/src/cli/commands/init/tests.rs` | The real binary's write paths (state, lock, rehearsal state, log file, the init layout) on a tmpfs hidden root, through the real attach gate: the binary they spawn inherits the namespace, so no test hook stands in for a mounted volume. `activate_gate.rs` also mounts a second tmpfs over the root and checks that neither receives a file, and that `activate --json` writes only lines of its schema to stdout |
| `nails-core/tests/kernel_semantics.rs` | Mountinfo round trips of awkward layer paths; `copy_tree` leaving source atimes untouched on a `strictatime` filesystem; a root's `/etc/fstab` read without touching its atime on a `relatime` filesystem; the mount queries answering for the mount a lookup reaches (a stacked one, none under a covering mount) |
| `nails-core/tests/filesystem_contract.rs` | One file contract and one mount-query contract, run against `MockFilesystem` and `RealFilesystem` (tier d) |
| `nails-core/tests/privileged_mounts.rs` | Overlay behaviour through `nix::mount`; all but the whiteout test run rootless |
| `nails-cli/tests/broken_pipe.rs` | The stderr helpers surviving a reader that has gone |
| `kernel_tests` modules in the crates | Unit-level checks that need a real mount table or process |

The limits are the kernel's rules for unprivileged overlays: no redirects (hence
`redirect_dir=nofollow` everywhere), and no `trusted.*` xattrs, so directory
whiteouts and opaque directories need real root. That one test,
`privileged_mounts::whiteout_and_opaque_hide_lower_entries_without_deleting_them`,
stays `#[ignore]`d and runs in CI's `privileged-mounts` job.

### (b) Recorded real-world fixtures

`scripts/capture-kernel-fixtures.sh userns` captures, unprivileged, an overlay
scene, a hidden-root scene (a mapper-named tmpfs at a root with a space, an
overlay with its upper on it), a `setsid` child's `stat` and `status`, and
`/proc/swaps`. `... vm` captures the same from inside a live session. The files
live in `nails-base/tests/fixtures/kernel/` and `nails_base::kernel_fixtures`
reads them; the [fixture README](../nails-base/tests/fixtures/kernel/README.md)
says where each came from and which tests read it.

Fixtures catch format drift (escaping, extra columns, a missing field) at unit-test
speed. They do not catch semantics or timing, and they can go stale, so each set
records its kernel and systemd version.

### (c) NixOS and distribution VM tests

Whatever needs a booted system runs in the VM suites:
[nix/e2e-tests](../nix/e2e-tests/README.md) for NixOS and the distribution
tests in [nix/distro-tests](../nix/distro-tests/) for Debian and Ubuntu. They cover the soft-reboot in both directions,
emergency, recover, the forensic scans of the decoy disk after a session, and
the time budgets in `performance` (the `trigger_to_settled` time of activate and
deactivate and the `trigger_to_backdoor` time of emergency). A time budget turns
a slow regression into a failing test; budgets need generous headroom on shared
runners.

### (d) Contract tests: one body, mock and real

`nails-core/tests/filesystem_contract.rs` runs the same contract against both
`Filesystem` backends, the real one inside `Rerun::in_user_mount_ns`. Since the
whole-root session the trait no longer mounts, so the mount half is a
mount-query contract: the mock is seeded, the kernel mounts a tmpfs, and both
must answer the same. `nails-platform/src/platform/contract.rs` does the same
for the platform backends.

Doubles without a cheap real side (systemctl, journalctl) use tier (b) instead:
their scripted output is captured output, not invented output.

## Mock policy

A mock or fake is **allowed** for:

- orchestration branches, ordering and rollback, where the decision logic is the
  subject and the effect is covered elsewhere;
- **error injection** the kernel cannot produce on demand: fail operation N,
  `ENOSPC` mid-copy, a save that fails;
- effects that are destructive or host-global in a test process: a soft-reboot,
  a power-off, swapoff, killing processes outside a PID namespace;
- pure seams: environment, passwd, clock.

A mock is **not enough on its own** when:

1. **A parser reads kernel or tool output.** It needs at least one test fed with
   captured real output (tier b). Hand-written strings stay for edge cases.
2. **A `Filesystem` method's mock behaviour is relied on.** It belongs in the
   shared contract (tier d), or has a tier (a) counterpart.
3. **A `cfg(test)` hook bypasses host code.** A `should_skip_host_interaction()`
   early return, for example, needs a real-tier test of the code it skips.
   Splitting the host-touching function so it can be pointed at a test process
   or a scratch root usually makes that cheap.
4. **The code talks to systemd.** It needs a VM subtest (tier c), with a time
   budget when the cost matters.

And for every test: **assert the effect, not the call.** Check the state file,
the bytes in the upper, the mount table after the way back. A recorded operation
list is a supplement, never the only assertion.

The doubles in use, and what backs them: `MockFilesystem`
(`nails-base/src/filesystem/mock/`, backed by the contract), `FakePlatform`
(`nails-platform/src/platform/fake.rs`, backed by the platform contract),
`MockProcessRunner` (`nails-base/src/process/run/mock.rs`, backed by tests that
run a real `sh`) and `FakeJournalReader` (`nails-forensics/src/verify/journal.rs`,
not yet backed by a capture).

Reviewers apply this policy to new code. A pull request that adds a parser, a
`Filesystem` method or a test hook brings its real-tier test, or says which tier
owes one.

## What to run

- **Locally or in any sandbox:** `just kernel-tests` (fails rather than skips
  without user namespaces). Plain `just test` runs the same tests and skips them
  where user namespaces are missing.
- **CI:** the `rust` job clears `kernel.apparmor_restrict_unprivileged_userns`
  on the Ubuntu runner and sets `NAILS_REQUIRE_USERNS=1`; the `privileged-mounts`
  job runs the whiteout test as root.
- **VM:** the suites in `nix/e2e-tests`, as its README describes. When a captured
  format changes, refresh the fixture as the fixture README says.

## Fuzzing

The parsers that read what NAILS does not control are also fuzzed, with
[cargo-fuzz](https://rust-fuzz.github.io/book/) and libFuzzer, in the crate
`fuzz/`. It is a workspace of its own, so `just check`, cargo-deny and the
release build never see it. Each target in `fuzz/fuzz_targets/` drives product
code without touching the host (a filesystem is a `MockFilesystem`, a disk an
in-memory file) and checks more than that nothing panics or hangs:

| Target | Input | Checks |
| --- | --- | --- |
| `mountinfo` | a mount table and its overlay options | entries printed back as the kernel prints them parse the same; overlay layers survive NAILS's escaping and the kernel's; a lookup answers with a mount at the path asked for |
| `utab` | libmount's `utab` and two mount tables | each line reads as libmount 2.42 reads it; across a switch and on the way back only whole input lines survive, changed at most in their ID |
| `fstab_crypttab` | a decoy's fstab, crypttab and mount table | every swap and mount the session masks is masked under the unit name systemd generates; a crypttab device is the node systemd opens |
| `nixos_reference` | `configuration.nix` and udev's record of the hidden volume's partition | every reference lies in the file; ASCII case changes nothing; the scan reads forward only |
| `systemd_conf` | logind, journald, coredump and sleep configuration with drop-ins | the assignments are the ones the daemon applies, in order |
| `os_release` | `/etc/os-release` | written back with os-release(5) quoting, it reads the same |
| `disk_layout` | the start of a raw disk | partitions and free ranges lie on the disk, in order, apart |
| `raw_token_scan` | a canary token and a sparse disk image | the windowed scan finds what a scan of the whole image in one buffer finds |

What systemd and libmount do, where a target compares NAILS with them, is
modelled in `fuzz/src/`, each model written from the C function it follows.
Each target starts from its seed corpus in `fuzz/seeds/<target>/`, inputs
taken from the fixtures and tests, with a dictionary in `fuzz/dicts/`. The
proptests in `nails-core/src/fuzz/` (`just fuzz`) cover some of the same
parsers with generated inputs on every `cargo test`; the fuzz targets search
with coverage feedback, for much longer, in CI ([ci.md](ci.md#fuzzing)).

To run a target in the development shell, which provides cargo-fuzz:

```bash
just fuzz-run mountinfo        # for a minute
just fuzz-run utab 3600        # for an hour
```

The recipe builds the target as CI does (a release build with debug assertions,
overflow checks and the address sanitizer) with the pinned toolchain, starts
from the seeds and the dictionary, and keeps what it finds in
`fuzz/corpus/<target>/`. A crash stops it and leaves the input in
`fuzz/artifacts/<target>/`; replay it with
`RUSTC_BOOTSTRAP=1 cargo fuzz run --release --debug-assertions <target> <input>`.
For the exact build CI runs, use OSS-Fuzz's helper on a checkout named `nails`:
`python3 infra/helper.py build_image --external --no-pull <checkout>`, then
`build_fuzzers --external --sanitizer address <checkout>` and
`run_fuzzer --external <checkout> <target>`.

A crash is a bug in NAILS until shown otherwise: fix it with a regression unit
test next to the code, and add the input to the target's seeds, so every later
run starts from it. A target that checks something NAILS does not promise is
corrected instead.
