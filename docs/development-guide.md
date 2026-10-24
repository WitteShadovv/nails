# Development guide

This guide covers the local workflows that are not obvious from `cargo` alone.
The development shell (`nix develop`) provides the pinned toolchain and every
tool the checks below need. For the per-tier test commands, runtimes and
prerequisites, see the [Testing section of CONTRIBUTING.md](../CONTRIBUTING.md#testing);
for the CI layout, [docs/ci.md](ci.md).

## Crates

The library is split into crates along the session's boundaries (see the
[architecture overview](architecture.md#crates)), from the bottom up:
`nails-teardown`, `nails-base`, `nails-platform`, `nails-session`,
`nails-forensics` and `nails-core`, with `nails-cli` on top. A crate depends
only on crates below it; `nails-core/tests/crate_graph.rs` fails on a new edge,
`nails-forensics/tests/boundary.rs` keeps verification read-only, and
`nails-teardown/tests/boundary.rs` keeps the emergency hot path's dependencies
to a reviewed list. Code
outside the library crates uses the `nails_core::` paths: `nails-core`
re-exports every module of the crates below.

When you add a crate:

- list it in the workspace `members`, in `crate_graph.rs` and in the crate list
  and graph of [docs/architecture.md](architecture.md#crates);
- give it `[lints] workspace = true`, the `#![cfg_attr(test, allow(unsafe_code))]`
  line and `nails_base::unit_test_mode!();` in its `lib.rs`, `test-hooks` and
  `test-support` features that forward to the crates below, and a self
  dev-dependency that turns both on, as the other library crates do;
- name its directory `nails-<name>/`: the `rust` filter in `ci/changes.py`,
  the orphan module check and the file size check cover every such directory;
- add its directory wherever the crate directories are listed: `sourceFiles` in
  `flake.nix`, the `nails-source` check in `nix/checks.nix` and the `relevant`
  filter in `.github/workflows/e2e.yml`. A `ci/tests` case fails when a member
  of the workspace is missing from either path filter.

`unit_test_mode!` keeps a crate's unit tests off the host: the base crate's
switches (the host-interaction skip, the state attach gate, immediate alerts)
ask `runtime_safety::in_unit_tests()`, which the macro sets before `main` in
that crate's unit-test binary. Integration tests and the `nails` binary built
for them are not marked: they skip host interaction only when the
`NAILS_TEST_RUNTIME` variable is set in the environment the binary starts with
(read once into `RuntimeEnv::test_hooks`, see below).

## Test tiers

Most of the suite is unprivileged and runs with a plain `cargo test
--workspace`: it drives the mount and overlay logic through `MockFilesystem` and
temporary directories, so it needs neither root nor an overlayfs-capable kernel.

A second tier exercises the real mount path — a live overlayfs with bind and
tmpfs submounts, a lazy unmount of a busy overlay and reverse-order teardown,
and `RealFilesystem`'s mount queries against the kernel's own table — without
root: each test re-runs itself as root of an unprivileged user + mount
namespace (`nails_core::test_support::Rerun`). The mount-query contract
(`nails-core/tests/filesystem_contract.rs`), `privileged_mounts.rs`,
`kernel_semantics.rs` and the `kernel_tests` modules run this way in the normal
`cargo test`; `just kernel-tests` runs only them and fails, instead of
skipping, on a host without user namespaces (see
[testing-strategy.md](testing-strategy.md)). The `init` command's
`kernel_tests` also need a host that runs systemd as PID 1 and is not
image-based, since the platform gate they pass reads both from the host; on
any other host they skip with a message, under `just kernel-tests` too.

One test needs real root: the whiteout and opaque-directory test in
`privileged_mounts.rs` needs `trusted.*` xattrs, which a user namespace cannot
set. It is `#[ignore]`d and CI runs it in the dedicated `privileged-mounts` job
of `ci.yml` on every PR, which `gate` aggregates.

The whole-root session's mechanics have a rootless real-kernel tier of their
own, `nails-core/tests/whole_root_kernel.rs`. Each test re-runs itself in a
private user and mount namespace and builds a decoy root with its own ESP, a
hidden volume and a `/run` with a next root on scratch tmpfs, then drives the
production mount primitives, the transition step and the cgroup kill against
them. It runs in the normal `cargo test` and skips, with a message, where user
namespaces or a delegated cgroup are not available. Only the soft-reboot itself
and the device mount of the way back need a VM; those are the session tests
under `nix/e2e-tests/tests/session/`.

## Tests and the process environment

All tests in a test binary share one process environment and run on parallel
threads, so no test reads its inputs from, or writes them to, that environment.
Product code does not read the environment either: `nails-cli` `main` reads it
once into a `nails_core::RuntimeEnv` (`RuntimeEnv::from_process_env`), passes
that snapshot to every handler, and installs it for the few leaf helpers below
every handler (the process runner, the runtime-safety switch), which read it
through `nails_core::runtime_env::current()`. A test builds the snapshot it
needs and injects it:

```rust
let env = RuntimeEnv::empty()
    .with_sudo_user("alice")
    .with_sudo_uid("1000");
let user = TargetUser::resolve_with(&env)?;

// Managers carry their own snapshot.
let manager = NailsManager::new(fs, config, state_path)
    .with_runtime_env(env.clone());
```

The test-only knobs (`NAILS_TEST_RUNTIME` and `NAILS_TEST_ENFORCE_ROOT`) live
in `RuntimeEnv::test_hooks`, compiled only with the `test-hooks` feature. A
test that exercises a leaf helper scopes a snapshot to its own thread with
`nails_core::runtime_env::ScopedRuntimeEnv`. A subprocess test sets the
child's variables on the `Command` and the child reads them once with
`RuntimeEnv::from_process_env` and installs them, exactly as `main` does. Never
call `std::env::set_var` or `remove_var`, and never change the working directory
in a test; the relative-flake tests, for example, spell their refs relative to
the shared working directory.

A shuffled run catches a test that depends on another test's leftovers. The
shuffle flag is unstable in libtest, so it needs `RUSTC_BOOTSTRAP` on the pinned
stable toolchain; the seed it prints reproduces a failing order with
`--shuffle-seed`:

```sh
RUSTC_BOOTSTRAP=1 cargo test --workspace -- -Z unstable-options --shuffle
```

## Running the root-only mount test

The whiteout test mounts and unmounts real filesystems with `trusted.*` xattrs,
so it needs `CAP_SYS_ADMIN` in the initial user namespace. It is run inside a
private mount namespace, which keeps every mount invisible to
the host and discards all of them when the process exits — a failing test cannot
leave a mount behind on your machine.

Build the test binary unprivileged, then run it elevated. On the ubuntu-26.04
runners the AppArmor policy blocks unprivileged user namespaces, so the run step
is the only part that needs `sudo`:

```sh
# 1. Build the test binary without running it, and capture its path.
bin=$(cargo test -p nails-core --test privileged_mounts --no-run \
  --message-format=json \
  | python3 -c '
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue
    target = msg.get("target") or {}
    if (
        msg.get("reason") == "compiler-artifact"
        and target.get("name") == "privileged_mounts"
        and msg.get("executable")
    ):
        print(msg["executable"])
')

# 2. Run the ignored test in a fresh private mount namespace.
sudo unshare --mount --propagation private "$bin" --ignored --test-threads=1
```

`--ignored` selects exactly the root-only test; the other tests of the binary
run rootless in the normal test run.

This is the same command the CI `privileged-mounts` job runs; it is part of the
required `gate` check, so the test must pass before a PR can merge.
