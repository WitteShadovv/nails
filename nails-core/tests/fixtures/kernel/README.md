# Captured kernel and systemd output

Real output from the kernel and from systemd's tools. The parser tests read
these files instead of hand-written strings, which can encode a format the
kernel never prints. The overlay option escaping is an example: a hand-written
`lowerdir=/a\,b` was accepted by the old parser, but the kernel actually prints
`/a\134\054b`.

`scripts/capture-kernel-fixtures.sh` produces every file here. Review the diff
before you commit a recapture.

## `userns/`: captured unprivileged, anywhere

`scripts/capture-kernel-fixtures.sh userns nails-core/tests/fixtures/kernel/userns`

The script builds one scene inside `unshare -Urm`: a tmpfs base `/var` and an
overlay mounted on top of it, using the production options and awkward layer
names (`lower, with:colon`, `upper\dir`, `work dir`). It records the scene's
mountinfo lines, with the random scratch path rewritten to `/fixture`.
`kernel.txt` names the kernel the capture ran on.

The capture uses `mount(8)`, which passes each option through `fsconfig(2)`.
The kernel therefore prints the comma in the lower layer's name as a bare
`\054`. NAILS mounts with `mount(2)` and one data string, so the same path reads
back as `\134\054`; that form is pinned in
`parse_overlay_opts_decodes_the_doubly_escaped_kernel_form`.

It then builds a second scene, `mountinfo-hidden-root.txt`: a tmpfs whose
source is `/dev/mapper/vault`, mounted at a directory named `hidden root` under
`/fixture/mnt` (the kernel prints the space as `\040`), a `/fixture/home` overlay whose upper and work
directories live on it, and a `/fixture/nix/store` overlay shadowed by a later
`/fixture/nix` overlay. It records the stat and status of a child in its own
session and process group whose comm is `x) (y z`, and `/proc/swaps`, which is
not namespaced: each file name is rewritten to `/fixture/swapN` and re-padded
the way the kernel pads it.

| File | Used by |
| --- | --- |
| `mountinfo-overlay-scene.txt` | the `nails-teardown` mountinfo parser tests |
| `mountinfo-hidden-root.txt` | `nixos::config` backing-device tests, the `verify` leftover-overlay and hidden-mapper tests, the `backend_detect` escaped-root test |
| `proc-stat-setsid-odd-comm.txt`, `proc-status-setsid-odd-comm.txt` | the `/proc/<pid>/stat` and `status` parser tests in `nails-teardown/src/proc.rs` |
| `proc-swaps.txt` | `preflight::checks::swap` fixture tests |

## `vm/`: captured as root inside a NixOS test VM

`security/83-decoy-journal-leak.nix` (`just e2e decoy-journal-leak`) runs
`capture-kernel-fixtures.sh vm` in the hidden root of a live session, right
after activation, and writes `kernel-fixtures/` to its output directory. Copy
the contents of `result/kernel-fixtures/` to `vm/`. The capture holds:

- the session's mountinfo (`/` is the hidden overlay) and `/proc/swaps`;
- journald's `stat`, `status` and `cgroup`;
- the systemd version in the two invocations `session::systemd` reads it
  through: the first line of `systemctl --version` and `systemctl show -p
  Version --value`.

The committed files come from the full VM run at `27090f96`, which ran before
the whole-root session (systemd and kernel in `systemd-version.txt` and
`kernel.txt`); the files that run recorded and no test of the session reads
any more are removed. `mountinfo-host.txt` and `systemd-show-version.txt` come
with the first capture in a whole-root session. Re-copy the capture when a VM
run changes a format; a test that finds its file missing prints so and
returns (`nails_core::kernel_fixtures::vm`).

| File | Used by |
| --- | --- |
| `mountinfo-host.txt` | the `session::probe` hidden-overlay-root test |
| `proc-swaps.txt` | `classify_swap` fixture test |
| `proc-stat-journald.txt`, `proc-status-journald.txt` | the `/proc/<pid>/stat` and `status` parser tests in `nails-teardown/src/proc.rs` |
| `proc-cgroup-journald.txt` | the `nails-teardown` cgroup-to-unit test |
| `systemd-version.txt`, `systemd-show-version.txt` | the `session::systemd` version parser test |

Review a capture before committing it: the VM is synthetic, but check it anyway
for anything that should not be published.
