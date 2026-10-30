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
| `nails-core/tests/whole_root_kernel.rs` | The session's own mechanics on real mounts: the root overlay and its upper, the SELinux labels copied from the decoy's directories onto an upper and along the way to the operator's home, never onto or through a link (on a host without SELinux), the read-only ESP, the fstab policy, the transition step against a live mount table, the way back, the cgroup kill, rollback of a failed entry, the chrooted NixOS activation and the kept store closure |
| `nails-core/tests/boot_records_kernel.rs` | The way back's login- and boot-record pieces: `/run` left executable for them and made `noexec` again by the reconcile step, the decoy's wtmp and the wtmpdb writer's unit read without touching their access times on a `strictatime` filesystem, and the wtmpdb writer started in a time namespace whose boot clock starts at the switch, kept from the system bus |
| The `kernel_tests` modules of `nails-cli/tests/config_write.rs`, `nails-core/src/app/config_edit_tests.rs` and `nails-base/src/filesystem/pinned_dir_tests.rs` | The settings writer on a tmpfs hidden volume, through the real attach gate: `config set` and `config unset` from the binary bound into the volume as `<volume>/nails`, the template's comments kept, an invalid value, a link at the file and a `--config` file off the volume refused with the file elsewhere left as it was, and eight processes at once each landing their change; a volume with no NAILS layout refused; a tmpfs or a file bound inside the volume refused as another filesystem on the way |
| `nails-cli/tests/early_dispatch.rs` | `emergency` detaching a leftover next root before it reads the configuration |
| `nails-cli/tests/maintenance_cli.rs` and the `kernel_tests` modules of `rehearse_cli.rs`, `cli_contract.rs`, `activate_gate.rs`, `helper_stdio.rs`, `nails-cli/src/cli/helper/switch_tests.rs` and `maintain_tests.rs` (the window's helper, when the `gui` feature is on), `nails-cli/src/cli/logging/tests.rs` and `nails-cli/src/cli/commands/init/tests.rs` | The real binary's write paths (state, lock, rehearsal state, log file, the init layout) on a tmpfs hidden root, through the real attach gate: the binary they spawn inherits the namespace, so no test hook stands in for a mounted volume. `activate_gate.rs` also mounts a second tmpfs over the root and checks that neither receives a file, and that `activate --json` writes exactly one envelope of its schema to stdout. The helper's tests run a discard, an activation, init, a rehearsal plant and a configuration change through it and compare each answer with the CLI's envelope and exit code for the same command, and check that a window closing its pipe before the point of no return cancels the activation and that a configuration change writes only with its token and while the file is still what its plan read |
| `nails-core/tests/kernel_semantics.rs` | Mountinfo round trips of awkward layer paths; `copy_tree` leaving source atimes untouched on a `strictatime` filesystem; a root's `/etc/fstab` read without touching its atime on a `relatime` filesystem; the mount queries answering for the mount a lookup reaches (a stacked one, none under a covering mount) |
| `nails-core/tests/network_way_back_kernel.rs` | The way back's network restore in a throwaway network namespace: the real `ip` deleting the session's links (one made again under the name of a decoy link included) and its policy-routing rules, setting a decoy device's address back on a link that is up and on one that is down, the settings below `/proc/sys/net` written back to what entry found in that namespace, not to the kernel's defaults (the namespace starts with the host's IPv4 settings, so forwarding is on where the host forwards, and the decoy's own `arp_ignore` and `src_valid_mark` are not the defaults), and the real `nft` deleting the session's firewall tables while the decoy's keeps its handle. A host without the `dummy` link type, `ip`, `nft` or nf_tables skips the test that needs it, and `NAILS_REQUIRE_USERNS=1` fails it |
| `nails-core/tests/filesystem_contract.rs` | One file contract and one mount-query contract, run against `MockFilesystem` and `RealFilesystem` (tier d) |
| `nails-core/tests/privileged_mounts.rs` | Overlay behaviour through `nix::mount`, the `kernel-modules` check against what the kernel leaves in an upper, and the whole upper-filesystem probe as `check` runs it; all but the whiteout test, the kernel-modules test and the probe test run rootless |
| `nails-cli/tests/broken_pipe.rs` | The stderr helpers surviving a reader that has gone |
| `kernel_tests` modules in the crates | Unit-level checks that need a real mount table or process |

The limits are the kernel's rules for unprivileged overlays: no redirects (hence
`redirect_dir=nofollow` everywhere), and no `trusted.*` xattrs, so directory
whiteouts and opaque directories need real root: the test of both, and the
test of the `kernel-modules` check, which reads the opaque directories the
kernel makes in an upper. So does the upper-filesystem probe as a whole, whose
first step sets a `trusted.*` xattr. Those three tests,
`privileged_mounts::whiteout_and_opaque_hide_lower_entries_without_deleting_them`,
`privileged_mounts::the_kernel_modules_check_reads_the_kernels_own_whiteouts_and_opaque_directories`
and `privileged_mounts::the_upper_fs_probe_as_root_passes_and_leaves_nothing`,
stay `#[ignore]`d and run in CI's `privileged-mounts` job. The probe's steps
after the xattr run rootless in the `kernel_tests` module of
`nails-core/src/preflight/checks/upper_fs_probe/tests.rs`: its trial overlay
works while the namespace's mount table neither lists it nor signals a change,
and nothing holds its upper once its descriptor is closed, or once a process
that holds it is killed with `SIGKILL`.

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
runners. On Fedora and Arch, which NAILS does not admit yet, a refusal scenario
run by hand checks that NAILS refuses them, that a refused `activate` changes
nothing on the hidden root, and that nothing on the decoy's disk filesystems or
in its journal names the refused run.

The dummy links of `network_way_back_kernel.rs` take a new MAC address while
they are up, so the way back's retry for a driver that refuses one (it takes
the device down for the change and brings it up again) is tested in a VM, by
`session-mac-restore`: on QEMU's emulated NE2000 card, whose driver refuses a
live change as many USB Ethernet adapters and Wi-Fi cards do, the card has its
permanent address back, and is up, after `deactivate` and after a plain
`emergency`.

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
not yet backed by a capture). A test that writes a program for itself or the
code under test to run (a stub `ip`, `systemctl` or `dmsetup`, a fake init)
writes it with `write_executable` from `nails_base::test_support`
(`crate::test_support` inside `nails-teardown`), and a test that copies one,
such as the built binary, copies it with `copy_executable` from the same module.
Both write the file from a child process: a write descriptor held by the test
process would pass to whatever another test thread forks until that process
calls `exec`, and running the file in that window fails with `ETXTBSY`.

Reviewers apply this policy to new code. A pull request that adds a parser, a
`Filesystem` method or a test hook brings its real-tier test, or says which tier
owes one.

## What to run

- **Locally or in any sandbox:** `just kernel-tests` (fails rather than skips
  without user namespaces, and without `ip`, `nft` with nf_tables or the `dummy`
  link type for the network way-back tests; `ip` and `nft` count only in the
  system locations, as the [development guide](development-guide.md#test-tiers)
  says). Plain `just test` runs the same tests and skips them where these are
  missing.
- **CI:** the `rust` job installs `nftables`, loads the `dummy` and `nf_tables`
  modules, clears `kernel.apparmor_restrict_unprivileged_userns` on the Ubuntu
  runner and sets `NAILS_REQUIRE_USERNS=1`; the `privileged-mounts` job runs the
  whiteout test, the kernel-modules test and the upper-filesystem probe test as
  root.
- **VM:** the suites in `nix/e2e-tests`, as its README describes. When a captured
  format changes, refresh the fixture as the fixture README says.

## Fuzzing

The parsers that read what NAILS does not control are also fuzzed, with
[cargo-fuzz](https://rust-fuzz.github.io/book/) and libFuzzer, in the crate
`fuzz/`. It is a workspace of its own, so `just check` checks only its
formatting, and clippy, cargo-deny and the release build never see it; like the
workspace, it denies unsafe code. Its `fuzz/Cargo.lock` takes the versions of
the crates it shares with NAILS from `Cargo.lock`: `just fuzz-lock` rewrites it
from there, and CI fails on one that no longer matches the manifests, as after a
version bump. Each target in `fuzz/fuzz_targets/` drives product code without
touching the host (a filesystem is a `MockFilesystem`, a disk an in-memory file)
and checks more than that nothing panics or hangs:

| Target | Input | Checks |
| --- | --- | --- |
| `mountinfo` | a mount table and its overlay options | entries printed back as the kernel prints them parse the same; overlay layers survive NAILS's escaping and the kernel's; a lookup answers with a mount at the path asked for |
| `utab` | libmount's `utab` and two mount tables | each line reads as libmount 2.42 reads it; across a switch and on the way back only whole input lines survive, changed at most in their ID |
| `fstab_crypttab` | a decoy's fstab, crypttab and mount table | every swap and mount the session masks is masked under the unit name systemd generates; a crypttab device is the node systemd opens |
| `nixos_reference` | `configuration.nix` and udev's record of the hidden volume's partition | every reference lies in the file; ASCII case changes nothing; the scan reads forward only |
| `systemd_conf` | logind, journald, coredump and sleep configuration with drop-ins | the assignments are the ones the daemon applies, in order |
| `autologin` | GDM's, SDDM's, Plasma Login Manager's and LightDM's configuration with drop-ins | the accounts listed are the ones each display manager may log in, read with its parser in each order its locale may sort the drop-ins in |
| `os_release` | `/etc/os-release` | written back with os-release(5) quoting, it reads the same |
| `config_edit` | an operator's `nails.toml`, then the edits `config set` and `config unset` make of it, one a line | an edit of a file that parses writes TOML that parses; each key set holds the value asked for and each key unset is gone, while every other key, known or not, holds what it held; every comment stays; when no value changes the file comes back byte for byte; the same edits a second time change nothing |
| `cryptsetup_version` | a decoy's dpkg `status` file, whose lines are also pacman entries and a store path's name | a version read comes from what names cryptsetup and reads back the same; another package's stanza or entry changes nothing |
| `nix_db` | the dump `run-scan.sh` writes of a decoy's Nix store database for the forensic oracle, one JSON row a line, then after a NUL the rows a session adds | the oracle reads exactly the lines a model of the row reads, one finding each, and reads each row the same under other ids, times and pages; two rows give one finding exactly when the model holds them the same; the verdict fails on exactly the added rows `before` holds none like, as added, and as removed when the session takes them away |
| `kernel_config_gzip` | the kernel's own config, `/proc/config.gz`, as a gzip stream, which is also the text of a stream the target writes | a member before the stream adds its text and changes nothing else, so no back-reference leaves its member; a stream that decodes stays within the limit and is refused one byte below it, cut short by a byte or followed by one, and decodes the same when its text is written again in stored blocks; the input written in fixed-Huffman and stored blocks, in two members, decodes back to it |
| `disk_layout` | the start of a raw disk | partitions and free ranges lie on the disk, in order, apart; what a rehearsal scan reads at the start of each region (its signature, a compressing filesystem's magic, an f2fs's compression feature, the size a superblock records) is read without an error |
| `raw_token_scan` | a canary token and a sparse disk image | the windowed scan finds what a scan of the whole image in one buffer finds |
| `helper_request` | a request line a window writes to the engine's root helper, for any of its operations, up to past its length limit | a line past the length limit is refused as too long and one holding a newline is refused; an accepted request follows the protocol's version, has arguments of the shape the protocol states, checked by the target on its own (absolute paths, a well-formed token, no two options the CLI refuses together, a configuration change of 1 to 32 keys of a setting's shape, each named once, with bounded values free of control characters), and written back reads as the same request, or is refused as too long where the written form, which names every field, no longer fits |

What systemd, libmount, GLib, GDM, LightDM, SDDM and KConfig do, where a
target compares NAILS with them, is modelled in `fuzz/src/`, each model
written from the C or C++ function it follows.
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
`fuzz/corpus/<target>/`. A crash, or an input that runs longer than 25 seconds
(a hang, here and in CI), stops it and leaves the input in
`fuzz/artifacts/<target>/`; replay it with
`RUSTC_BOOTSTRAP=1 cargo fuzz run --release --debug-assertions <target> <input>`.
For the exact build CI runs, use OSS-Fuzz's helper on a checkout named `nails`:
`python3 infra/helper.py build_image --external --no-pull <checkout>`, then
`build_fuzzers --external --sanitizer address <checkout>` and
`run_fuzzer --external <checkout> <target>`. `.dockerignore` sends Docker only
the files the build reads, so a development checkout with its `target/`
directories works as well as a fresh clone.

A crash is a bug in NAILS until shown otherwise: fix it with a regression unit
test next to the code, and add the input to the target's seeds, so every later
run starts from it. A target that checks something NAILS does not promise is
corrected instead.

**A new parser of bytes NAILS does not control is not admitted without a fuzz
target and a seed corpus.** Coverage-guided fuzzing has already caught real
parser bugs on hostile input, the kind that table tests with hand-written
strings miss, so this is a rule, not a preference: a change that adds code
reading bytes from the host or the decoy — a login record, a package database,
a unit drop-in, a label xattr — adds, in the same change, a target that drives
that parser and a seed corpus taken from its fixtures. `just new-fuzz-target
<name>` scaffolds the stub, an empty starter seed and the `[[bin]]` entry;
implement the stub, replace the starter seed with real inputs and run
`just fuzz-lock`. `scripts/check-fuzz-targets.sh`, which the pre-commit hook,
`just check` and CI's `lint` job run, enforces the mechanical half — every
target is wired into `fuzz/Cargo.toml`, is no longer the scaffold's stub (its
TODO markers, or a body that only discards the input), and has a seed corpus in
`fuzz/seeds/<target>/` with at least one input that is not empty, and no seed
corpus is orphaned — and the review keeps the other half, that a new parser has
a target at all and that the target checks it.
