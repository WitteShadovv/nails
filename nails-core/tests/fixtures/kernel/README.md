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

The script builds one scene inside `unshare -Urm`:

- a tmpfs base `/var`, with an `O_APPEND` fd held on a journal file;
- an overlay mounted on top, using the production options and awkward layer
  names (`lower, with:colon`, `upper\dir`, `work dir`);
- an append fd and a read-only fd reopened through the overlay.

It records the scene's mountinfo lines and the three fds' fdinfo. The random
scratch path is rewritten to `/fixture`. All the files come from the same scene,
so the `mnt_id` values in the fdinfo files match the mount ids in the mountinfo.
`kernel.txt` names the kernel the capture ran on.

The capture uses `mount(8)`, which passes each option through `fsconfig(2)`.
The kernel therefore prints the comma in the lower layer's name as a bare
`\054`. NAILS mounts with `mount(2)` and one data string, so the same path reads
back as `\134\054`; that form is pinned in
`parse_overlay_opts_decodes_the_doubly_escaped_kernel_form`.

It then builds a second scene, `mountinfo-hidden-root.txt`: a tmpfs whose
source is `/dev/mapper/vault`, mounted at `/fixture/mnt/hidden root` (the kernel
prints the space as `\040`), a `/fixture/home` overlay whose upper and work
directories live on it, and a `/fixture/nix/store` overlay shadowed by a later
`/fixture/nix` overlay. It records the stat and status of a child in its own
session and process group whose comm is `x) (y z`, and `/proc/swaps`, which is
not namespaced: each file name is rewritten to `/fixture/swapN` and re-padded
the way the kernel pads it.

| File | Used by |
| --- | --- |
| `mountinfo-overlay-scene.txt` | `filesystem::mountinfo` tests and the journald fd classifier test |
| `fdinfo-append-base.txt` | journald fd classifier test (the stale fd still on the base `/var`) |
| `fdinfo-append-overlay.txt` | journald fd classifier test (the fd re-homed onto the overlay) |
| `fdinfo-readonly-overlay.txt` | journald fd classifier test (a read-only fd, which is never a leak) |
| `mountinfo-hidden-root.txt` | `nixos::config` backing-device tests, `verify` overlay-line tests, the `backend_detect` escaped-root test |
| `proc-swaps.txt` | `preflight::checks::swap` fixture tests |

## `vm/` and `vm-graphical/`: captured as root inside NixOS test VMs

Two VM tests run `capture-kernel-fixtures.sh vm` and keep the result in their
output directory:

- `security/83-decoy-journal-leak.nix` (`just e2e decoy-journal-leak`), right
  after activation with `/var` overlaid and a persistent journal, writes
  `kernel-fixtures/`. Copy `result/kernel-fixtures/` to `vm/`.
- `security/80-emergency-graphical.nix` (`just e2e emergency-graphical`), with
  the lightdm autologin session up after activation, writes
  `kernel-fixtures-graphical/`. Copy `result/kernel-fixtures-graphical/` to
  `vm-graphical/`.

Each capture holds:

- the host's and journald's mountinfo, journald's journal fds with their
  fdinfo, and journald's `stat`, `status` and `cgroup`;
- `/proc/swaps`;
- `systemctl list-units` (`--all` and `--state=active`), `systemctl is-active`
  and `systemctl show -p MainPID --value systemd-journald.service`, each in
  exactly the invocation the code uses;
- `loginctl show-seat seat0 -p ActiveSession --value`, the active session's
  `User`, the cgroup of its leader, and logind's session records from
  `/run/systemd/sessions`.

Until a capture is committed, the tests that read it print that it is missing
and return (`nails_core::kernel_fixtures::vm`):

| File | Used by |
| --- | --- |
| `vm/systemctl-list-units-*.txt` | `parse_active_units` fixture tests (`service_controller`) |
| `vm/proc-swaps.txt` | `classify_swap` fixture test |
| `vm/systemctl-show-journald-mainpid.txt`, `vm/proc-stat-journald.txt`, `vm/mountinfo-journald.txt`, `vm/journald-fds.txt`, `vm/fdinfo-journald-*.txt` | the journald re-home fixture test (`journald_fd` kernel tests) |
| `vm-graphical/logind-sessions/`, `vm-graphical/proc-cgroup-*.txt` | `nails-teardown` session spare-set test |

Review a capture before committing it: the VM is synthetic, but check it anyway
for anything that should not be published.
