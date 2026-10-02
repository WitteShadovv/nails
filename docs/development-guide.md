# Development Guide

**Project:** NAILS (NixOS Anti-forensics Isolation & Layering System)

This guide covers the local workflows that are not obvious from `cargo` alone.
The development shell (`nix develop`) provides the pinned toolchain and every
tool the checks below need. For the per-tier test commands, runtimes and
prerequisites, see the [Testing section of CONTRIBUTING.md](../CONTRIBUTING.md#testing);
for the CI layout, [docs/ci.md](ci.md).

## Test tiers

Most of the suite is unprivileged and runs with a plain `cargo test
--workspace`: it drives the mount and overlay logic through `MockFilesystem` and
temporary directories, so it needs neither root nor an overlayfs-capable kernel.

A second, privileged tier exercises the real mount path — `RealFilesystem`
against a live overlayfs, with bind and tmpfs submounts, force-unmount, and
reverse-order teardown. Those tests live in
`nails-core/tests/privileged_mounts.rs`, are every one `#[ignore]`d, and are
skipped by the normal run. CI runs them in the dedicated `privileged-mounts`
job of `ci.yml` on every PR, which `gate` aggregates.

## Tests that touch the process environment

All tests in a test binary share one process environment and run on parallel
threads. `#[serial]` does not protect it, because it orders a test only against
other `#[serial]` tests. A test that reads or writes an environment variable, or
spawns a child that inherits one, holds an `EnvGuard`
(`nails_core::test_support::EnvGuard`, behind the `test-support` feature):

```rust
let mut env = EnvGuard::lock();
env.set("SUDO_USER", "alice").remove("NAILS_TARGET_USER");
// ... exercise the code under test ...
// dropping `env` restores both variables and releases the lock
```

The guard takes the single environment lock of the test binary, tolerates a
lock poisoned by a failed test, and is re-entrant on its thread. A test that only
reads the environment takes `let _env = EnvGuard::lock();`. Never call
`std::env::set_var` or `remove_var` directly, and never "clean up" with
`remove_var`: it deletes a value that existed before the test. Prefer passing a
value in over mutating the environment at all; for example, the NixOS builder
tests give `RealCommandExecutor::with_search_path` a stub directory instead of
changing `PATH`.

A shuffled run catches a test that depends on another test's leftovers. The
shuffle flag is unstable in libtest, so it needs `RUSTC_BOOTSTRAP` on the pinned
stable toolchain; the seed it prints reproduces a failing order with
`--shuffle-seed`:

```sh
RUSTC_BOOTSTRAP=1 cargo test --workspace -- -Z unstable-options --shuffle
```

## Running the privileged mount tests

The tests mount and unmount real filesystems, so they need `CAP_SYS_ADMIN`. They
are run inside a private mount namespace, which keeps every mount invisible to
the host and discards all of them when the process exits — a failing test cannot
leave a mount behind on your machine.

Build the test binary unprivileged, then run it elevated. On ubuntu-24.04 the
AppArmor policy blocks unprivileged user namespaces, so the run step is the only
part that needs `sudo`:

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

# 2. Run the ignored tests in a fresh private mount namespace, serially.
sudo unshare --mount --propagation private "$bin" --ignored --test-threads=1
```

`--ignored` selects exactly the privileged tests, and `--test-threads=1` keeps
them serial so each one owns its mount namespace state without racing another.

This is the same command the CI `privileged-mounts` job runs; it is part of the
required `gate` check, so these tests must pass before a PR can merge.
