# Testing strategy: real kernels, recorded fixtures, honest mocks

This document records where the unit tests stop telling the truth, which test
tiers close the gap, and when a mock is still the right tool. The decision is
in [ADR 0006](adr/0006-real-kernel-test-tier.md). This document holds the
evidence, the plan and the migration list.

## The problem

[ADR 0002](adr/0002-trait-filesystem-testability.md) put every filesystem and
mount call behind the `Filesystem` trait so orchestration can be tested without
root. That worked: about 2,700 tests in `nails-core` and 460 in `nails-cli` run
in a normal `cargo test`. But each test double encodes a belief about the
kernel or a tool, and nothing checks that belief. The following bugs passed
every unit test and failed only in the NixOS VM suite:

| Bug | The belief that was wrong | Where the belief lived |
| --- | --- | --- |
| The journald re-home check compared `st_dev` | That overlayfs reports the upper layer's device for its files. It reports its own anonymous device, so the check had to compare mount ids. | Hand-made `JournalFdSite` values. The real inspection is skipped under `cfg(test)`. |
| `reapply` persisted nothing | That `save_cached_state` saves. With an empty cache it returned `Ok(())` and did nothing. | Tests that checked the operations were invoked, not the state file afterwards. |
| Emergency output panicked on a broken pipe after journald restarted | That stderr stays writable for a whole teardown. | A `FailingWriter`. The real stderr was never redirected. |
| `systemctl list-unit-files` added about 28 s per activation | That a systemctl call is cheap. | `record_service_action`, which only records a string. |
| Overlay-only activation disagreed with real mountinfo | That the planted mount table looks like the kernel's. | Hand-written mountinfo planted in `MockFilesystem`, and `reconcile_mounts_override`. |

Building the prototype for this document found three more such beliefs:

- **Overlay option decoding was wrong for awkward layer paths.** The parser test
  used `lowerdir=/a\,b`, the form NAILS *passes* to `mount(2)`. The kernel
  *prints* that option through `seq_show_option`, which octal-escapes the
  backslash and the comma, so the real line reads `/a\134\054b`.
  `parse_overlay_opts` split on `:` before it decoded the octal escapes, so a
  layer path containing `,`, `:` or `\` came back wrong. This would have fed
  `NailsMounts::discover` and the journald upper-dir match wrong paths. It is
  fixed now, and both real forms are pinned by tests (see
  `tests/fixtures/kernel/README.md`).
- **The same path reads back in two forms.** `mount(8)` uses `fsconfig(2)`, one
  option at a time, so the comma needs no backslash and prints as a bare
  `\054`. Only a capture shows this.
- **`redirect_dir=off` depends on the kernel build.** It means "follow" on a
  kernel built with `CONFIG_OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW` (the upstream
  default, and the case on NixOS) and "nofollow" otherwise. An unprivileged
  mount refuses the "follow" form. The overlays now pass
  `redirect_dir=nofollow`, which behaves the same on every kernel. NAILS never
  creates redirects, so following them never mattered for NAILS's own layers.
  This change needs one VM run to confirm (see [What to run](#what-to-run)).

## How much is mocked

`MockFilesystem` appears 1,735 times, in 143 source files and 4 integration
test files. The other doubles, and what they stand in for:

| Double | Stands in for | Real behaviour tested elsewhere? |
| --- | --- | --- |
| `MockFilesystem` (`filesystem/mock/`) | `Filesystem`: file operations, mounts, overlays, mountinfo, swap, statfs | File operations: yes, in `tests/filesystem_contract.rs`. Mounts: only the 7 `#[ignore]`d `privileged_mounts` tests, which need root. |
| `set_forced_journald_fd_check`, the `should_skip_host_interaction()` early returns (24 files) | `/proc/<pid>/fd`, `fdinfo`, `mountinfo`, and every host side effect | No, before this change. |
| `record_service_action` (`manager/helpers/service_controller.rs`) | every systemctl, journalctl and nix-daemon verb | No. |
| `MockSessionCommandExecutor` and its scripted and recording variants, (`process/session/`) | systemctl `is-active`, loginctl, kill | No. |
| `MockCommandExecutor` and `RecordingKillExecutor` (`process/restart/tests.rs`) | service restarts, signals | No. |
| `FakeJournalReader` (`verify/journal.rs`) | `journalctl --grep` | No. |
| `reconcile_mounts_override` (`manager/state_management.rs`) | the live mount table | No. |
| `MockProcessRunner` (`process/run/mock.rs`) | running a child process | Yes: `process/run/tests.rs` runs real `sh`. |
| `FsMountOps` over `MockFilesystem`, the in-memory table of `nails-teardown`'s `undo_tests.rs` | the teardown plan's mount operations | Yes: `manager::teardown_plan::kernel_tests` runs every kind of recorded step, the derived plan, `cgroup.kill` and the emergency hot path on real mounts in user, mount, cgroup and PID namespaces. |
| `FakePlatform`, `FakeConfigLayer` (`platform/`) | host backends, config layers | Yes: `platform/contract.rs` runs one contract against every backend. |
| `FakeEnv`, `FakePasswd`, `ScriptedNotifier`, `RuntimeEnv` | environment, passwd, notifications | These are pure-logic seams. |

Parsers of kernel or tool output, and what their tests use:

- **mountinfo** (`nails-teardown/src/mountinfo.rs`, re-exported by
  `filesystem/mountinfo.rs`): hand-written strings, a proptest over generated
  strings, and the real tables of the teardown plan's kernel tests.
- **fdinfo flags and `mnt_id`** (`process/detection`, `journald_fd.rs`):
  hand-written strings.
- **`systemctl list-units --plain`** (`parse_active_units`): hand-written
  strings. logind's session records (`nails-teardown/src/session.rs`): files
  written in a temporary directory.
- **`/proc/swaps`** (`classify_swap`): 21 hand-written cases.
- **`/proc/<pid>/stat`**: three copies of the same parser (`read_ppid` twice,
  `read_session_and_pgid`), none tested at the parser level.
- **`/proc/<pid>/status`** (`read_uid_from_status`): untested.

## What needs a real kernel

Ordered by how much the code depends on the behaviour and how wrong the mock
can be:

1. **Mount and overlay semantics.** Mount ids, the device an overlay reports,
   shadowing (an overlay on `/nix` hiding one on `/nix/store`), copy-up,
   busy-unmount and lazy detach, option escaping and what mountinfo prints.
2. **`/proc` inspection.** fd targets, the fdinfo `flags:` and `mnt_id:` lines,
   `stat` and `status` of real processes, and mountinfo seen from another
   process's namespace.
3. **File metadata.** `st_dev` and `st_ino` through an overlay, atime under
   `O_NOATIME` (which needs ownership or `CAP_FOWNER`), xattrs (`trusted.*`
   compared with `user.*`).
4. **Process lifetimes.** Signals, process groups and sessions, and broken
   pipes. Rust ignores `SIGPIPE`, so a closed reader gives `EPIPE`, and
   `println!` turns that into a panic.
5. **systemd and journald.** Output formats, restart timing, journald reopening
   its files, the cost of each call. Only a booted system has these.

## The tiers

### (a) Real-kernel tests in an unprivileged user + mount namespace

**This tier is built.** `nails_core::test_support::Rerun` re-executes the
calling test binary, filtered to that one test. Before `exec`, while the child
is still single-threaded, it unshares `CLONE_NEWUSER | CLONE_NEWNS` and maps
the caller to uid 0. The child then makes `/` recursively private and runs the
body. Every mount dies with the child, even after a panic. `ScratchTmpfs` gives
the body a tmpfs, optionally `strictatime`, and detaches it on drop so `TMPDIR`
stays empty. On a host without user namespaces the test prints why and passes
vacuously. With `NAILS_REQUIRE_USERNS=1` the skip becomes a failure instead.

Re-executing beats forking: a fork of the threaded test harness could inherit
a lock held by another test thread, and `unshare(CLONE_NEWUSER)` refuses a
multi-threaded caller anyway. The same code works under libtest and nextest.

What works where:

| Environment | User namespaces | tmpfs, bind, overlay in the namespace |
| --- | --- | --- |
| This sandbox (bubblewrap, Linux 7.2, no root) | yes, nested | yes |
| NixOS desktop | yes | yes |
| GitHub `ubuntu-24.04` | blocked by AppArmor (`kernel.apparmor_restrict_unprivileged_userns=1`): the namespace has no capabilities | yes after `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`. The `rust` job now does this. |
| Nix build sandbox | not used: the flake builds with `doCheck = false` | n/a |

The limits are the kernel's rules for unprivileged overlays. They cannot follow
redirects, hence `nofollow`. They cannot set `trusted.*` xattrs, so removing a
lower directory, which needs an opaque marker or a directory whiteout, fails
with `EIO` unless the mount uses `userxattr`. Production must not use
`userxattr`, so directory whiteouts and opaque directories stay in the root-only
tier. `O_NOATIME` works because the files belong to the mapped caller. Device
nodes cannot be created.

The tests, about 0.2 s together:

| Test | Would have caught |
| --- | --- |
| `journald_fd::kernel_tests::reopened_journal_fd_is_judged_by_mount_id_not_st_dev`: a base `/var` with a held fd, the production overlay mounted on `/var`, a reopened fd, then the real `/proc/<pid>/fd` + fdinfo + mountinfo inspection. It also asserts that the overlay `st_dev` differs from the upper file's. | the `st_dev` re-home bug |
| `kernel_semantics::live_overlay_mountinfo_round_trips_awkward_layer_paths` | the overlay option decoding bug (it found it) |
| `kernel_semantics::overlay_shadowed_by_a_parent_overlay_is_not_reported_mounted` | wrong `is_overlay_mounted` results for nested overlays, part of the overlay-only activation bug |
| `kernel_semantics::copy_tree_leaves_source_atimes_untouched_on_a_strictatime_fs`, with a control proving a plain read updates atime | a lost `O_NOATIME`, verified by mutation. The older unit test passes vacuously on a `noatime` host filesystem. |
| `nails-cli` `broken_pipe::stderr_helpers_survive_a_reader_that_has_gone`: a child whose stderr is a pipe with no reader, with a control asserting that `eprintln!` panics there | the emergency broken-pipe panic, verified by swapping the helper for `eprintln!` |

The root-only `privileged_mounts` suite passes rootless too, 6 of 7, under
`just privileged-rootless`. The exception is the whiteout test.

Cost and fit: about 300 lines of support code, no new dependencies, and
millisecond tests. CI already has a `rust` job, which now runs the tests with
coverage. Flakiness is low: the kernel either supports the operation or the
test skips. What remains is the usual fork/exec cost and the
`--exact` name matching, which `Rerun` asserts by checking that the child ran
exactly one test.

### (b) Recorded real-world fixtures

**This tier has started.** `scripts/capture-kernel-fixtures.sh userns` captures
a mountinfo and fdinfo scene unprivileged. The fixtures live in
`nails-core/tests/fixtures/kernel/userns/`, and the mountinfo and journald
classifier tests now read them. `... vm` captures, as root in a VM, the host's
and journald's mountinfo, journald's fds and fdinfo, `/proc/swaps`,
`stat`/`status`, and every systemctl and loginctl invocation the code makes.
The fixture README has the three-line VM test snippet.

Cost: one VM run per format change. CI fit: perfect, since fixtures are plain
unit-test inputs. Flakiness: none. What it catches: format drift such as the
escaping bug, `--plain` bullets, extra columns, and missing `mnt_id`. It does
not catch semantics (the `st_dev` bug needs the live inspection) or timing.
Captured data can go stale, so `kernel.txt` and `systemd-version.txt` record
the source.

### (c) A few fast "kernel-semantics" VM tests

These need systemd and journald: journald restarts and fd re-homing with the
real daemon, `systemctl` call cost, an emergency teardown whose stderr is the
journal stream, and overlay-only activation against the booted host's real
mountinfo. A single VM boot can host all four as subtests, about 2 to 3 minutes
on KVM. Assert the cost directly: wrap activation in a timer and fail when the
systemctl phase exceeds a budget. That turns the 28 s regression into a red
test instead of a slow one. CI fit: the existing `e2e.yml` and KVM runners.
Flakiness: moderate; timing budgets need headroom (for example 5x the
measured time).

### (d) Contract tests: one body, mock and real

`tests/filesystem_contract.rs` already does this for file operations. Its mount
section (lines 230 to 415: overlay validation, unmount idempotence, busy and
force, `is_mounted`, `is_overlay_mounted`) runs against the mock only. Tier (a)
removes the obstacle, so those cases can join the shared contract, with
`RealFilesystem` running inside `Rerun::in_user_mount_ns`. A mount-semantics
drift in the mock then fails the gate. Where both sides agree only by
convention (the mock's `unmount(force)` against the kernel's `EBUSY` and
`MNT_DETACH`), the contract forces a decision.

The other doubles have no cheap real side (systemctl, loginctl, journalctl).
For them, tier (b) fixtures serve as the contract: the scripted executor
returns captured output, not invented output.

### What each tier would have caught

| Bug | (a) userns | (b) fixtures | (c) VM | (d) contract |
| --- | --- | --- | --- | --- |
| journald `st_dev` | yes | partly: `mnt_id` yes, `st_dev` no | yes | no |
| `reapply` no-op | no | no | yes (it did) | no; a test that checks the state file afterwards does |
| broken pipe | yes | no | yes | no |
| list-unit-files 28 s | no | no | only with a time budget | no |
| overlay-only vs mountinfo | partly: shadowing, decoding | yes, with VM mountinfo | yes | yes, for `is_overlay_mounted` |
| overlay option decoding (new) | yes (found it) | yes | only for odd paths | yes |

The `reapply` bug is not a kernel problem. It is a policy problem: the tests
checked which operations ran, not what was persisted.

## Mock policy

A mock or fake is **allowed** for:

- orchestration branches, ordering and rollback, where the decision logic is
  the subject and the effect is covered elsewhere;
- **error injection** that the kernel cannot produce on demand: fail operation
  N, `ENOSPC` mid-copy, a save that fails;
- effects that are destructive or host-global in a test process: reboot,
  swapoff, `nixos-rebuild switch`, restarting host services, killing
  processes outside a PID namespace;
- pure seams: environment, passwd, clock, notification transport.

A mock is **not enough on its own** when:

1. **A parser reads kernel or tool output.** It needs at least one test fed with
   captured real output (tier b). Hand-written strings stay for edge cases.
2. **A `Filesystem` method's mock behaviour is relied on.** It belongs in the
   shared contract (tier d), or has a tier (a) or privileged counterpart.
3. **A `cfg(test)` hook bypasses host code.** Anything like
   `set_forced_journald_fd_check`, a `should_skip_host_interaction()` early
   return or `reconcile_mounts_override` needs a real-tier test of the code it
   skips. Splitting the host-touching function so it can be pointed at a test
   process, as `inspect_journal_fds_of(pid, ..)` is, usually makes that cheap.
4. **The code talks to systemd or journald.** It needs a tier (c) subtest, with a
   time budget when the cost matters.

And for every test: **assert the effect, not the call.** Check the state file
after `reapply`, the bytes in the upper layer, the mount table after teardown.
A recorded operation list is a supplement, never the only assertion.

Reviewers apply this policy to new code. A PR that adds a parser, a `Filesystem`
method or a test hook brings its real-tier test, or states which tier owes one.

## Migration list

**Done in this change:**

- `nails-core/src/test_support.rs`: `Rerun` and `ScratchTmpfs`.
- `journald_fd.rs`: `inspect_journal_fds_of` split out, with the live test and a
  fixture test in `journald_fd_kernel_tests.rs`.
- `nails-core/tests/kernel_semantics.rs`: mountinfo round trip, shadowed
  overlay, strictatime `copy_tree`.
- `nails-cli/tests/broken_pipe.rs`.
- `filesystem/mountinfo.rs`: decoding fixed, with kernel-form and fixture tests.
- The overlay options use `redirect_dir=nofollow` (in `mount_ops.rs` and the
  `upper_fs_probe.rs` trial mount).
- `just kernel-tests` and `just privileged-rootless`. The `rust` CI job clears
  the AppArmor sysctl and requires the namespace tests to run.

**Next, in this order:**

1. **Mount contract.** Move the mock-only mount section of
   `nails-core/tests/filesystem_contract.rs` into the shared contract and run it
   against `RealFilesystem` in `Rerun::in_user_mount_ns`. Fix whatever the mock
   gets wrong.
2. **The rootless `privileged_mounts`.** Run its 6 rootless tests through
   `Rerun` inside `just test`. Leave only
   `whiteout_and_opaque_hide_lower_entries_without_deleting_them` in the
   `sudo unshare` job.
3. **Capture the VM fixtures** (fixture README). Then feed them to:
   - `manager/helpers/service_controller.rs` (`parse_active_units`);
   - `manager/deactivation/session_guard.rs` (`parse_session_ids`,
     `parse_properties`);
   - `preflight/checks/swap.rs` (`classify_swap`);
   - `nixos/config/verify.rs` (its mountinfo reading);
   - `preflight/checks/backend_detect` (the planted mountinfo there);
   - `verify/tests.rs` and `nixos/config/tests.rs`, which plant hand-written
     `/proc/self/mountinfo` in `MockFilesystem`.
4. **`reconcile_mounts_override`** (`manager/state_management.rs`). Add a tier (a)
   test that reconciles state against a real mount table holding a live
   overlay, a missing one and a shadowed one.
5. **`/proc/<pid>/stat` and `status`.** Merge the three `stat` parsers
   (`process/detection/mod.rs`, `filesystem/real/system_ops.rs`,
   `manager/deactivation/process_teardown.rs`) into one. Test it against a real
   child whose `comm` contains `) (` and that runs in its own session and
   process group (`setsid`). Test `read_uid_from_status`
   (`process/session/management/mod.rs`) the same way. No namespace is needed.
6. **Signals and process trees.** For `process/restart` (`RecordingKillExecutor`)
   and the teardown kill path, add tier (a) tests in a PID namespace
   (`CLONE_NEWPID` alongside the user namespace). Real children are signalled
   there, so no host process can be hit. Assert who survives.
7. **The tier (c) VM test** "kernel-semantics": journald re-home with the real
   daemon, a systemctl cost budget, emergency stderr across a journald restart,
   and overlay-only activation on real mountinfo, all as subtests of one boot.
8. **Effect assertions.** Audit `manager/tests/activation/*` and
   `manager/tests/rollback.rs` for tests whose only assertion is the recorded
   `MockOp` list or `drain_recorded_service_actions()`. Add a state-file or
   mount-table assertion. The `reapply` test
   (`manager/tests/activation/nixos_switch.rs`) is the model.

**Keep as they are** (pure logic or error injection):

- `MockFilesystem` in the orchestration suites: `manager/tests/*`,
  `deactivation/tests/*`, `cleanup/*`, `state/*`, `preflight/*`. Rules 1 to 3
  apply to what those tests rely on.
- `FakePlatform` and `FakeConfigLayer` (`platform/fake.rs`,
  `platform/fake_layer.rs`), which are backed by `platform/contract.rs`.
- `MockProcessRunner`, which is backed by real-process tests.
- The `nixos::CommandExecutor` mocks (`nixos/tests.rs`,
  `activation/nixos_build.rs`, `activation/nixos_switch.rs`). Feed
  `classify_nixos_failure_category` captured `nixos-rebuild` errors when the VM
  fixtures are taken.
- `FakeEnv`, `FakePasswd`, `ScriptedNotifier`, `RuntimeEnv`, the save-fail
  injection in `state/file.rs`, and the rollback event recorder.

## What to run

- **Locally or in any sandbox:** `just kernel-tests` (fails rather than skips)
  and `just privileged-rootless`. Plain `just test` also runs the tier (a)
  tests.
- **CI:** the `rust` job now clears
  `kernel.apparmor_restrict_unprivileged_userns` and sets
  `NAILS_REQUIRE_USERNS=1`. The first run on GitHub confirms the sysctl is
  enough there. If it is not, remove the variable to fall back to skipping, and
  say so in the PR.
- **VM:** one full e2e run for the `redirect_dir=nofollow` change, with
  particular attention to the overlay, lifecycle and forensic groups. Separately,
  the fixture capture in `nails-core/tests/fixtures/kernel/README.md`.
