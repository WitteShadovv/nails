# Development Guide

**Project:** NAILS (NixOS Anti-forensics Isolation & Layering System)

This guide covers the local workflows that are not obvious from `cargo` alone.
The development shell (`nix develop`) provides the pinned toolchain and every
tool the checks below need.

## Test tiers

Most of the suite is unprivileged and runs with a plain `cargo test
--workspace`: it drives the mount and overlay logic through `MockFilesystem` and
temporary directories, so it needs neither root nor an overlayfs-capable kernel.

A second, privileged tier exercises the real mount path — `RealFilesystem`
against a live overlayfs, with bind and tmpfs submounts, force-unmount, and
reverse-order teardown. Those tests live in
`nails-core/tests/privileged_mounts.rs`, are every one `#[ignore]`d, and are
skipped by the normal run. CI runs them in a dedicated `Privileged Mount Tests`
job on every PR.

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

This is the same command the CI `Privileged Mount Tests` job runs; the job is
required, so these tests must pass before a PR can merge.
