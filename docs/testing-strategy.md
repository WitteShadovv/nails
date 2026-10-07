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

This survey, like the tier (a) list below, was taken on the live-overlay code
base; the whole-root session removed much of what it names (see
[After the whole-root session](#after-the-whole-root-session)).

`MockFilesystem` appears 1,706 times in 157 files (1,755 before the T-139
migration). The other doubles, and what they stand in for:

| Double | Stands in for | Real behaviour tested elsewhere? |
| --- | --- | --- |
| `MockFilesystem` (`filesystem/mock/`) | `Filesystem`: file operations, mounts, overlays, mountinfo, swap, statfs | Yes: `tests/filesystem_contract.rs` runs one file contract and one mount contract against the mock and against `RealFilesystem`, the mount half as root of a user and mount namespace. `privileged_mounts` runs rootless too, except its whiteout test. |
| `set_forced_journald_fd_check`, the `should_skip_host_interaction()` early returns (24 files) | `/proc/<pid>/fd`, `fdinfo`, `mountinfo`, and every host side effect | No, before this change. |
| `record_service_action` (`manager/helpers/service_controller.rs`) | every systemctl, journalctl and nix-daemon verb | Partly: `parse_active_units` reads captured `systemctl list-units` output (VM capture), decoy-journal-leak requires the real journald re-home verdict, and performance-validation holds every systemctl call of an activation to a time budget. |
| `MockSessionCommandExecutor` and its scripted and recording variants, (`process/session/`) | systemctl `is-active`, loginctl, kill | Signals: yes, `process::session::management::kernel_tests` kills real processes in a PID namespace. systemctl and loginctl: VM session tests only. |
| `MockCommandExecutor` and `RecordingKillExecutor` (`process/restart/tests.rs`) | service restarts, signals | Signals: yes, `process::restart::kernel_tests` (PID namespace). Restarts: VM only. |
| `FakeJournalReader` (`verify/journal.rs`) | `journalctl --grep` | No. |
| `reconcile_mounts_override` (`manager/state_management.rs`) | the live mount table | Yes: `manager::state_management::kernel_tests` reconciles against a real table with a live, a missing and a shadowed overlay. |
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
  strings, plus the VM capture once it is taken. logind's session records
  (`nails-teardown/src/session.rs`): files written in a temporary directory,
  plus the graphical VM capture once it is taken.
- **`/proc/swaps`** (`classify_swap`): 21 hand-written cases and a captured
  table (userns now, VM once taken).
- **`/proc/<pid>/stat`**: one parser, `nails_teardown::proc::stat`, which every
  caller uses; tested on a live `setsid` child whose comm holds `) (`, on the
  same scene captured, and on journald's captured stat.
- **`/proc/<pid>/status`** (`proc::uid`, `parse_status_uid`): the same three
  ways.
- **mountinfo read by hand**: `verify`'s overlay and backing-source scans now
  use the shared parser (this found a bug, see below); `nixos/config/verify.rs`
  keeps its own reader, fed the captured hidden-root scene.

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

Added by T-139, as they stand after the whole-root session:

| Test | Covers |
| --- | --- |
| `filesystem_contract::real_filesystem_satisfies_mount_query_contract_in_a_user_namespace` | the mount queries the mock also answers: mount point, filesystem type, read-only flag and source, on a writable and a read-only tmpfs |
| `privileged_mounts` (6 tests) | the former root-only suite, now rootless in `just test`; it mounts straight through `nix::mount`, as the `Filesystem` trait no longer mounts |

The rest of the T-139 kernel tests (`reconcile_state`, the restart and session
kills, the snapshot pivot, the temp-file cleaner, the journald fd check) went
with the code they tested. The session's own mechanics run in
`tests/whole_root_kernel.rs`: the root overlay, the binds, the read-only ESP,
the transition step against a live mount table and the kill in a delegated
cgroup.

Only the whiteout and opaque-directory test of `privileged_mounts` still needs
real root.

Cost and fit: about 300 lines of support code, no new dependencies, and
millisecond tests. CI already has a `rust` job, which now runs the tests with
coverage. Flakiness is low: the kernel either supports the operation or the
test skips. What remains is the usual fork/exec cost and the
`--exact` name matching, which `Rerun` asserts by checking that the child ran
exactly one test.

### (b) Recorded real-world fixtures

**This tier is built.**
`scripts/capture-kernel-fixtures.sh userns` captures, unprivileged, an overlay
scene, a hidden-root scene (a mapper-named tmpfs at a root with a
space, an overlay with its upper on it, a shadowed overlay pair), a `setsid`
child's `stat` and `status`, and `/proc/swaps`. The fixtures live in
`nails-core/tests/fixtures/kernel/userns/` and `nails_core::kernel_fixtures`
reads them. `... vm` captures, as root in the hidden root of a live session,
the session's mountinfo, `/proc/swaps`, journald's `stat`, `status` and
`cgroup`, and the systemd version in the two invocations the session probe
uses. decoy-journal-leak runs it on every VM run; the files committed in `vm/`
come from the run at `27090f96`, before the whole-root session, and the
fixture README lists which of them the session's tests read.

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
mountinfo. Under T-139 they were covered by existing VM tests rather than a
new boot (the whole-root session retired the first two, see
[After the whole-root session](#after-the-whole-root-session)):

- journald re-home: decoy-journal-leak requires the activation's own log to
  carry the positive verdict of the fd check (an indeterminate one is only a
  warning), and the VM capture of journald's fds feeds the classifier;
- systemctl cost: performance-validation times every systemctl call of one
  activation through a wrapper bind-mounted over the binary, and
  fails on one call over 3 s or more than 4 s in all (times the TCG factor).
  It times the default activation: an overlay-only run without `/var` makes
  no systemctl call;
- emergency stderr: every emergency test runs nails from a unit whose stdout
  and stderr are the journal stream the teardown restarts, and requires exit 0;
- overlay-only activation: performance-validation, decoy-journal-leak and the
  overlay group activate with `--overlay-only` on the booted host. Assert the cost directly: wrap activation in a timer and fail when the
systemctl phase exceeds a budget. That turns the 28 s regression into a red
test instead of a slow one. CI fit: the existing `e2e.yml` and KVM runners.
Flakiness: moderate; timing budgets need headroom (for example 5x the
measured time).

### (d) Contract tests: one body, mock and real

**Done.** `tests/filesystem_contract.rs` runs a file contract and a mount
contract against both backends; `RealFilesystem` runs the mount half inside
`Rerun::in_user_mount_ns`. Since the whole-root session the trait no longer
mounts, so the mount half is a mount-query contract: the mock is seeded and the
kernel mounts a tmpfs, and both must answer the same. Its first run, on the
live-overlay trait, found three drifts, fixed in the mock:
`get_filesystem_type` reported nothing for an overlay or tmpfs; an overlay
mounted although its upper or work directory did not exist; and `unmount`
passed any tmpfs or bind through the ownership gate, which the kernel side
refuses outside the runtime root. Two known drifts stayed outside the
contract: the mock refused a second `mount_tmpfs` on one target where the
kernel stacks it, and the mock's `find_files_with_pattern` returns seeded
directories where the real walk returns only files (which mattered to the
temp-file cleaner; see the T-139 status in TODO.md). The session removed
`mount_tmpfs` and the cleaner.

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
- `just kernel-tests` (and a `just privileged-rootless` that T-139 later
  folded into it). The `rust` CI job clears the AppArmor sysctl and requires
  the namespace tests to run.

**Moved out of the VM tier (Wave R, T-140):** checks that need no kernel
feature, root or boot now run as cargo tests, and the VM keeps one end-to-end
path where a booted system matters.

- `help-version-no-leak` became four tests in `nails-cli/tests/cli_contract.rs`
  (the internal commands never appear in public help or version output, every
  public command renders EXAMPLES, the version line names nothing but the
  semver); the VM test is gone.
- The nested-key dry run and `config validate` of `config-unknown-key`, and the
  invalid-type check of `config-handling`, run in
  `nails-cli/tests/config_command.rs` against the same fixture files. The VM
  scenarios keep activation refused with nothing mounted, emergency on a broken
  config and the status and permission checks on a real hidden volume.
- Next candidates: the three `nails init` scenarios, in tier (a) with a
  `ScratchTmpfs` hidden root and `/etc/nixos` bind-mounted in the namespace.

**Done in T-139** (the eight steps, in order):

1. [x] **Mount contract.** The mock-only mount section of
   `filesystem_contract.rs` is gone; one mount contract runs against the mock
   and against `RealFilesystem` in `Rerun::in_user_mount_ns`. It found three
   mock drifts (see tier (d)).
2. [x] **The rootless `privileged_mounts`.** Its 6 rootless tests run through
   `Rerun` in `just test` and `just kernel-tests`;
   `whiteout_and_opaque_hide_lower_entries_without_deleting_them` alone stays
   `#[ignore]`d for the `sudo unshare` job. `just privileged-rootless` is gone.
3. [x] **Captured fixtures.** The userns capture feeds `nixos/config` (its own
   mountinfo reader), the `verify` overlay line and scans, `backend_detect`,
   `classify_swap` and the stat/status parser. The VM capture runs in
   decoy-journal-leak and emergency-graphical; `parse_active_units`, the
   journald re-home classifier, `classify_swap`, the stat parser and the
   teardown's logind spare set read it once it is committed. Feeding the
   hidden-root scene to `verify` found a bug: two scans matched raw mountinfo
   fields against the hidden root, so a root with a space or backslash hid
   every leftover overlay and made the volume's own mapper look foreign. Fixed.
   (`parse_session_ids`/`parse_properties` no longer exist: the teardown reads
   logind's session records, which the graphical capture now includes.)
4. [x] **`reconcile_mounts_override`.**
   `manager::state_management::kernel_tests` reconciles against a real table
   with a live, a missing and a shadowed overlay. The override stays for the
   orchestration tests.
5. [x] **`/proc/<pid>/stat` and `status`.** One parser,
   `nails_teardown::proc::stat` (now with the scheduler state), replaces the
   copies in `process/detection`, `filesystem/real/system_ops`,
   `deactivation/process_teardown`, `shell_cleanup` and
   `ProcessHandle::is_alive`; both `read_uid_from_status` copies use
   `proc::uid`. Tested on a live `setsid` child with comm `x) (y z`.
6. [x] **Signals and process trees.** `terminate` (TERM, then KILL for a
   process that ignores TERM), the session teardown's user-process kill and
   the interactive-shell kill run on real children as PID 1 of a PID
   namespace, asserting who survives. The `cgroup.kill` hot path already ran
   there (`manager::teardown_plan::kernel_tests`).
7. [x] **The tier (c) checks**, merged into existing VM tests (see tier (c)):
   the journald re-home verdict in decoy-journal-leak, the systemctl budget in
   performance-validation; emergency stderr and overlay-only activation were
   already covered.
8. [x] **Effect assertions.** No test asserts only on the `MockOp` list or
   `drain_recorded_service_actions()` any more (6 did). The history-edit and
   snapshot-pivot tests moved to real files and a real mount table; the
   emergency-order, journald re-home and read-only preflight tests gained
   state-file, mount-table or "nothing written" assertions. Tests that check
   only the calls made to `FakeConfigLayer` or a scripted session executor
   remain where the decision is the subject (allowed above).

Where a real file tree was practical, the mock also gave way: the history and
temp-file cleaner tests run on temporary homes and a private `/tmp`, and
configuration-only tests use `RealFilesystem` as the untouched backend.

### After the whole-root session

The whole-root soft-reboot session ([ADR 0008](adr/0008-whole-root-soft-reboot.md))
removed the live-overlay machinery, and with it most of what T-139 tested.
What stayed and what went:

- **Kept:** the file contract; the mount-query half of the mount contract
  (tier (d)); the rootless `privileged_mounts`, now on `nix::mount`; the one
  `/proc/<pid>/stat` and `status` parser in `nails_teardown::proc`, which
  `filesystem/real/system_ops` reads its parent pids through; `verify`'s
  mountinfo scans through the shared parser, with the captured hidden-root
  scene (the leftover-overlay scan returned in the session-leftovers check);
  the `nixos/config`, `backend_detect`, `classify_swap` and stat/status
  fixture tests.
- **New consumers of the captures:** the cgroup-to-unit mapping in
  `nails_teardown::cgroup` (journald's captured cgroup, and the
  `DelegateSubgroup=` case that T-139 fixed in the process detection's
  `system_unit_from_cgroup_line`), `session::systemd::parse_version` and the
  `session::probe` hidden-overlay-root test.
- **Gone with their code:** `reconcile_state` and its kernel test, the
  restart and session kills, the snapshot pivot, the temp-file and history
  cleaners, the journald fd check with its fixtures, `parse_active_units`,
  the logind spare set and the graphical capture, the journald re-home
  verdict in decoy-journal-leak and the systemctl budget in
  performance-validation (the calls it timed were the unit snapshots and
  restarts around a live switch; the activation's own systemctl calls now
  fall inside the `trigger_to_settled` budget of the soft-reboot).

**Next:**

- Feed `classify_nixos_failure_category` captured `nixos-rebuild` errors.
- The `nails init` scenarios in tier (a), as planned under T-140.
- Commit the first VM capture taken in a whole-root session (the fixture
  README says which files it adds).

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

- **Locally or in any sandbox:** `just kernel-tests` (fails rather than skips;
  it includes the mount-query contract, `privileged_mounts` and
  `whole_root_kernel`). Plain
  `just test` runs the same tests and skips them without user namespaces.
- **CI:** the `rust` job clears `kernel.apparmor_restrict_unprivileged_userns`
  and sets `NAILS_REQUIRE_USERNS=1`; the `privileged-mounts` job runs only the
  whiteout test as root.
- **VM:** the full suite. decoy-journal-leak also writes a fresh capture from
  inside the hidden root; copy it as the fixture README says when a format
  changes.
