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

| File | Used by |
| --- | --- |
| `mountinfo-overlay-scene.txt` | `filesystem::mountinfo` tests and the journald fd classifier test |
| `fdinfo-append-base.txt` | journald fd classifier test (the stale fd still on the base `/var`) |
| `fdinfo-append-overlay.txt` | journald fd classifier test (the fd re-homed onto the overlay) |
| `fdinfo-readonly-overlay.txt` | journald fd classifier test (a read-only fd, which is never a leak) |

## `vm/`: captured as root inside a NixOS test VM

Not committed yet. The VM capture records the following:

- the host's and journald's real mountinfo while a session overlays `/var`;
- journald's journal fds, with their fdinfo;
- `/proc/<pid>/stat` and `/proc/<pid>/status`, and `/proc/swaps`;
- the `systemctl list-units`, `is-active` and `show` output, and the
  `loginctl list-sessions` and `show-session` output, each in exactly the
  invocation the code uses.

To produce it, add these lines to
`nix/e2e-tests/tests/security/83-decoy-journal-leak.nix` right after the
`nails ... activate` call and the `logger` line. That test keeps a persistent
journal and overlays `/var`.

```python
        machine.copy_from_host("${../../../../scripts/capture-kernel-fixtures.sh}", "/tmp/capture.sh")
        machine.succeed("bash /tmp/capture.sh vm /tmp/kernel-fixtures")
        machine.copy_from_vm("/tmp/kernel-fixtures", "kernel-fixtures")
```

Then run `just e2e decoy-journal-leak` and copy
`result/kernel-fixtures/kernel-fixtures/` (the test's output directory) to
`nails-core/tests/fixtures/kernel/vm/`. Drop the lines again afterwards. The
capture is a one-off; it is not part of the suite.
