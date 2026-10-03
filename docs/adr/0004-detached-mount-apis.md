# 4. Path containment with openat2, and how we mount

- Status: accepted
- Date: 2026-10-02

## Context

NAILS builds overlays, binds and scaffolding on a host it does not fully trust.
Two long-standing patterns in that machinery predate the kernel features that
now replace them:

- Paths under the hidden volume were built with `Path::join` and opened with
  `std::fs`, so nothing stopped a symlink or a `..` planted *inside* the hidden
  volume from redirecting a create, open or remove onto the decoy root. A single
  planted link under an overlay upper could leak hidden-session writes back to
  the decoy filesystem — the exact failure NAILS exists to prevent.
- Overlays are mounted with `mount(2)` option strings, pivot targets need a
  staging mount that is visible while setup runs, and the read-only
  `/nix/store` self-bind is re-created in PID 1's mount namespace by `fork()` +
  `unshare(CLONE_FS)` + `setns()` running raw, async-signal-safe syscalls in the
  child.

The kernel offers `openat2` (5.6) for contained path resolution and the
detached-mount family — `fsopen`/`fsconfig`/`fsmount`/`move_mount` and
`open_tree(OPEN_TREE_CLONE)` (5.2) — for building and relocating mounts without a
visible staging point. This record captures which of these we adopt now and
which we defer, and why.

## Decision

### Path containment: adopt `openat2`, fail closed

`filesystem::safe_path::SafeRoot` holds an `O_PATH` directory fd for the hidden
root and resolves every relative path with
`openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`. The
root fd is the anchor, so a rename of the root after opening cannot redirect
later operations; `RESOLVE_BENEATH` refuses anything that would leave it;
`RESOLVE_NO_SYMLINKS` refuses to traverse any symlink, including the final
component; `RESOLVE_NO_MAGICLINKS` (implied, kept explicit) refuses `/proc`
magic links. Creation, atomic write (temp + `O_EXCL` + `renameat`), read, remove
and existence checks all go through it.

On a kernel without `openat2` the syscall returns `ENOSYS`. The helper **fails
closed**: it returns an error and never falls back to `std::fs`, because a
fallback would silently reinstate the symlink-following it exists to remove.
NAILS already requires a modern kernel for overlayfs and mount namespaces, so
refusing to run on a kernel too old for `openat2` costs nothing real.

Hidden-root directory creation now routes through a new
`Filesystem::create_hidden_dir_all(root, relative)`: the real filesystem
resolves it through `SafeRoot`, while the in-memory test double keeps the plain
join. The overlay upper/work setup in `create_overlay_config` is the first call
site moved over.

### Overlay mounts: keep `mount(2)` for now, defer `fsmount`

`fsopen("overlay")` + `fsconfig_set_string(...)` + `fsmount` + `move_mount`
straight onto the target would, where the kernel permits it, remove the pivot
staging mount and its bind entirely (the detached mount is attached atomically,
so it is never visible at an intermediate path). We keep `mount(2)` with option
strings as the mounting path in this change and do **not** switch the default,
for two reasons:

- The syscall sequence cannot be exercised here. This sandbox has no
  `CAP_SYS_ADMIN`, the Nix build/VM tier is unavailable, and overlay `fsconfig`
  semantics (repeated `lowerdir` keys, the `index`/`metacopy`/`redirect_dir`
  toggles) differ enough from the option string that landing it unverified would
  risk breaking activation on real hosts with no way to catch it. Behaviour
  changes need tests; this one can only be tested on a privileged host.
- Until the pivot staging work (T-069) finishes moving scaffolding into a
  per-activation tmpfs under `/run`, any staging mount still belongs there, not
  on the decoy root — a concern orthogonal to the mount syscall used.

The `move_mount`-based elimination of the staging mount, and the assertion that
`/proc/self/mountinfo` shows no staging mount during activation, are therefore
left to the privileged integration tier (T-008) and the VM E2E suite. This ADR
is the record that done-when requires "or the ADR explains why that is not
possible": it is not possible to validate in this environment.

### `/nix/store` self-bind: keep `fork`/`setns`

`open_tree(OPEN_TREE_CLONE)` + `move_mount` is the modern way to clone a mount
and reattach it, and could in principle replace the fork/`setns` helper that
re-creates the read-only `/nix/store` self-bind in PID 1's mount namespace. We
**keep** the fork/`setns` helper:

- The requirement is specifically to make the bind exist *in the init mount
  namespace* when the manager runs in a different one, so that a later
  `nix-daemon` `makeStoreWritable` remount resolves into the overlay upper rather
  than the decoy backing store. Entering another namespace to establish a mount
  there is what `setns` is for; `open_tree`/`move_mount` relocate a mount within
  the caller's namespace and do not by themselves place one into a foreign
  namespace without an equivalent `setns`, so they would not remove the
  namespace entry — only change the mount primitive.
- The helper is already async-signal-safe (raw syscalls only in the child, then
  `_exit`), re-checks namespace identity before acting, and is covered by the
  differing/identical-namespace unit tests. Replacing it blind, with no
  privileged tier to prove the read-only self-bind-into-overlay semantics still
  hold, trades a tested path for an unverifiable one.

This is the record that done-when requires: `restore.rs` keeps `fork`/`setns`,
justified here, and the primitive is revisited in the bind-teardown rework
(T-082) on a host where it can be proven.

### Rejected: cgroup freeze/thaw and `systemd-mount`

Neither is used to quiesce writers or to mount:

- cgroup-v2 freeze/thaw leaves frozen processes holding fds and cwd on lower
  dentries; after thaw they write straight to the decoy, so it gives no
  containment while adding a conspicuous artifact.
- `systemd-mount` creates transient units that log to the journal *before*
  `/var` is overlaid, leaving evidence on the decoy.

`rg 'cgroup.freeze|systemd-mount' nails-core` returns nothing and must stay that
way.

## Consequences

- A symlink or `..` planted under the hidden root can no longer redirect a
  NAILS-initiated create/open/remove outside it; the kernel refuses it at
  resolution time, and the helper fails closed on kernels without `openat2`.
- "No hidden-root path is opened outside the helper" is enforced by review with
  `rg`, not by clippy `disallowed-methods`: that lint is global and cannot tell a
  hidden-root `std::fs` open from a legitimate decoy-root one, so enabling it
  would fire on hundreds of valid call sites. The hidden-root *write* sites now
  route through `SafeRoot`: overlay upper/work creation
  (`Filesystem::create_hidden_dir_all`), the state-file write
  (`state/file.rs::save_internal`, resolved relative to the hidden root) and the
  notification directory and signal files (`notification/mod.rs`, via
  `SafeRoot::create_dir_all`/`create_new` with `fchmod`/`fchown` on the returned
  descriptors). `SafeRoot` gained `create_new` (exclusive create returning the
  handle) and `open_dir` (a directory fd for `fchmod`/`fchown`) for these. The
  remaining call sites to route as they are next touched are the opaque-xattr
  handling (`overlay/opaque.rs`, deferred to T-040: it is name-scoped to the one
  managed `/etc/nixos` upper and already uses `l*xattr`, which does not follow the
  final-component symlink) and the pivot/snapshot scaffolding under T-069. The
  notification *read* path (`read_pending`/`clear_*`) runs as the unprivileged
  operator over files they already own and creates nothing, so it stays on
  `std::fs` until `SafeRoot` grows a contained directory listing. The grep gate
  for the old leak-prone patterns rides with the T-074 artifact registry.
- The modern mount syscalls (`fsmount`/`move_mount`, `open_tree`) are recorded as
  the intended direction but remain unproven here. They must be validated on a
  privileged host / VM before any switch away from `mount(2)` and fork/`setns`.
