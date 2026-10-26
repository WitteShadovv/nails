# Distribution probe fixtures

A probe boots one distribution's stock cloud image **without NAILS** and records
the host facts the cross-distribution work needs but cannot assert by reading
code, so that each becomes committed test data instead of a guess. The facts
are the ones the platform notes leave unverified for the families that are not
admitted yet (Fedora and Arch): the SELinux domain a backdoor-style service
lands in, the labels and policy loads around a soft-reboot, the kernel and its
module trees, the systemd version, the image's own mount layout and where each
mount, swap and automount unit comes from, the host tools actually present, the
state of the services the decoy-posture checks judge, the vendor journald
configuration and the journal storage that results, the units that fail on
their own, the `updatedb` prune paths, any AVC denials, whether a 9p share
works while SELinux is enforcing, the `os-release` values a derivative carries,
and what one plain soft-reboot changes.

These facts need a booted VM, which needs KVM, so they are recorded on a
KVM-capable host or a hosted runner (the build server has none): one JSON file
per probe, with `"recorded": false` until the probe has run on it.

## Files

One file per probe, named after the probe: the `../images.json` key of its
image, with `-enforcing` added for a Fedora image booted with SELinux enforcing.

- `fedora-44.json` -- the pinned Fedora 44 cloud image, booted with SELinux
  permissive as `../images.json` pins it (recorded)
- `fedora-44-enforcing.json` -- the same image booted with SELinux enforcing
  (recorded)
- `fedora-45.json`, `fedora-45-enforcing.json` -- Fedora 45 once its image is
  pinned
- `arch-boxes.json` -- the pinned Arch `arch-boxes` image (recorded)
- `arch-install.json` -- the `archinstall`-built Arch image, once hosted

Debian and Ubuntu need no probe: they are admitted and covered by the smoke
suite directly.

## Fact schema

Each file is an object:

- `image` -- the `../images.json` key of the image the probe booted.
- `osId` -- the decoy's `/etc/os-release` ID.
- `enforcing` -- `true` for the probe that left SELinux enforcing, `false`
  otherwise.
- `imageFile` -- the name of the pinned image file the facts come from, so that
  a repin shows which fixtures are older than the pin; `null` in a placeholder.
- `recorded` -- whether a probe run filled `facts`: `true` when they hold a
  kernel release in `kernelRelease` and a `softRebootsCount` of `1`, which
  every run on a booted image reads, and `false` for a placeholder or a run
  whose queries failed. A consumer must skip or xfail a fact file whose
  `recorded` is `false`.
- `facts` -- the recorded facts, in this order. A fact whose query has not run
  is `null`, or empty for a list or map. The SELinux facts are `null` on an
  image without SELinux.
  - `selinuxMode` -- what `getenforce` answers, in lower case (`enforcing`,
    `permissive` or `disabled`).
  - `selinuxBackdoorDomain` -- the SELinux domain a backdoor-style unit runs in
    on the stock image (the type of the backdoor shell's own context; a
    permissive boot labels processes as an enforcing one does, so it records
    the domain too).
  - `selinuxLabels` -- the labels of `/`, `/run` and `/run/systemd` at the end
    of the plain boot (`ls -Zd`): `{ "<path>": "<label>" }`.
  - `selinuxPolicyLoads` -- the SELinux policy lines of the kernel log at the
    end of the plain boot (`dmesg`), such as PID 1's "Successfully loaded
    SELinux policy" (list), without the timestamp and the time the load took.
  - `kernelRelease` -- the running kernel (`uname -r`).
  - `moduleDirs` -- the module trees in `/usr/lib/modules` (sorted list).
  - `systemdVersion` -- the first line `systemctl --version` prints, such as
    `systemd 259 (259.5-1.fc44)`; `null` when it printed no version.
  - `mounts` -- the image's own mount layout (`findmnt --real`), sorted by
    target: a list of `{ "target": ..., "fstype": ..., "options": ... }`.
  - `fstab` -- the entries of `/etc/fstab` in file order: a list of
    `{ "source", "target", "fstype", "options", "dump", "pass" }`, with
    fstab(5)'s default for a missing options, dump or pass field; `null` when
    the image has no `/etc/fstab`.
  - `swaps` -- the active swap areas (`swapon --show`): a list of
    `{ "name", "type", "size", "priority" }`, the size in bytes.
  - `mountUnits` -- every mount, swap and automount unit systemd knows, in
    `systemctl list-units --all` order: a list of
    `{ "unit", "load", "active", "sub", "fragmentPath", "sourcePath" }`.
    `fragmentPath` is the file the unit was loaded from (one below
    `/run/systemd/generator` was generated) and `sourcePath` the file it was
    generated from (`/etc/fstab` for an fstab entry); each is `null` where
    systemd names none.
  - `generatorUnits` -- what `/run/systemd/generator` and
    `/run/systemd/generator.late` hold: `{ "<directory>": [ ... ] }`, each list
    sorted, `null` for a directory that does not exist.
  - `tools` -- the programs the NAILS sources name, mapped to their absolute
    path on the image (`{ "<tool>": "<path>" }`); an absent tool is omitted.
  - `services` -- `auditd`, `tuned`, `firewalld` and `abrtd`, each
    `{ "enabled": ..., "active": ... }` as `systemctl is-enabled` and
    `systemctl is-active` answer; `not-found` is a unit the image does not
    have, also where an older systemctl fails on its unit file instead of
    naming it, and any other answer, such as an error, is kept as printed.
  - `auditdRefuseManualStop` -- whether the auditd unit refuses a manual stop
    (`systemctl show -p RefuseManualStop`), which a `systemctl stop` or
    `systemctl mask --now` of it meets; `null` when the unit is not loaded.
  - `packages` -- on Fedora, `audit`, `tuned`, `firewalld` and `abrt` mapped to
    the installed name-version-release (`rpm -q`), or `null` where rpm answers
    that it is not installed; a package rpm gives neither answer for holds what
    the query printed, such as an error. `null` on the other families.
  - `journaldVendorConfig` -- the `Storage=` the stock journald runs with and
    what it follows from, resolved in the order NAILS resolves it
    (`nails-core/src/preflight/checks/journald_storage.rs`):
    `{ "storage": ..., "sources": [ ... ], "credential": ..., "vendorHint": ... }`.
    `sources` lists the files that assign `Storage=` a value journald takes,
    under `[Journal]`, in the order journald reads them
    (`systemd-analyze cat-config`); the last value assigned is `storage`.
    When no file assigns one, `storage` is, from systemd 256 on, the
    `journal.storage` credential journald received, if its whole content is
    such a value (`credential` holds the content as read, `null` when journald
    received none or an empty one), and otherwise the built-in default of
    `systemdVersion`: `auto` before 259; from 259 `vendorHint`, or
    `persistent` without one. `vendorHint` is the `Storage=` that
    `/usr/lib/systemd/journald.conf` documents in a commented-out line under
    `[Journal]`, `null` without one; a commented-out line in any other file,
    `/etc/systemd/journald.conf` included, counts for nothing. `storage` is
    `null` when no file sets it and `systemdVersion` is `null`.
  - `failedBootUnits` -- the units that show as failed on a plain boot of the
    stock image (list of unit names).
  - `maskedUnits` -- every masked unit (list of unit names). The test harness
    masks some (the serial getty and SSH units, and on Arch a few more), so
    neither failed-unit list can show a failure of one of those.
  - `updatedbPrunePaths` -- the `PRUNEPATHS` the image's `updatedb` ships (list).
  - `avcs` -- the AVC and USER_AVC denials of the plain boot, from the kernel
    log and the audit log (`ausearch`), each denial once, as the record from
    `avc:  denied` on (list). A permissive boot logs each denial instead of
    enforcing it, so it can log denials an enforcing boot never reaches, and
    the reverse.
  - `ninePUnderEnforcing` -- whether the harness's 9p share mounted and a file
    reads through it while SELinux is enforcing (`true`/`false`); `null` unless
    the probe ran enforcing.
  - `derivativeOsRelease` -- for a derivative, the `ID`, `ID_LIKE` and
    `VARIANT_ID` its `os-release` carries (`{ ... }`); empty for the family's
    own image.
  - `softRebootsCount` -- PID 1's `SoftRebootsCount` after the one plain
    `systemctl soft-reboot` the probe ends with: `1` when the image
    soft-rebooted once without a new boot.
  - `failedUnitsAfterSoftReboot` -- the units that show as failed after that
    soft-reboot, with no NAILS involved (list of unit names); every way back is
    a soft-reboot, so these are the units the way back would have to mask.
  - `avcsAfterSoftReboot` -- the denials logged after those of the plain boot
    were read: what the soft-reboot and the userspace after it were denied.
    While auditd is down, from its stop on the way down to its start after the
    soft-reboot, the kernel log is the only record of a denial, and the units
    stopping fill that log's rate limit, so the probe lifts the limit before
    it soft-reboots.
  - `selinuxLabelsAfterSoftReboot` -- `selinuxLabels`, read after the
    soft-reboot.
  - `selinuxPolicyLoadsAfterSoftReboot` -- the policy lines the kernel log
    gained after those of the plain boot were read: the load of the PID 1 that
    started after the soft-reboot.

The `/nix/.ro-store` 9p share and the `backdoor.service` and
`mount-store.service` units belong to the test harness, not to the image, so
`mounts` and `mountUnits` leave out everything below `/nix`; the domain the
backdoor unit runs in is exactly what `selinuxBackdoorDomain` records.

## Regenerating

The queries and the reading of their output into the record are in
`../py/probe_facts.py`, unit-tested by the `distro-checks` flake check;
`../probe.nix` builds one host driver per probe (`<probe>-probe`, the same
`nix-vm-test` seam the smoke suite uses), which runs the queries, soft-reboots
the image and runs the rest. The driver prints one `=== <label> ===` block per
query and writes `<probe>.json`, the record, and `<probe>.raw.json`, every
query's output by label, into the directory `NAILS_PROBE_OUT` names, or the
one it runs in. A fixture is that record as written: copy `<probe>.json` over
the file here rather than editing it, once its `recorded` is `true`. The
`distro-checks` flake check fails a fixture that leaves the schema, is not
named after its probe, is not written the way the probe writes it, or whose
`recorded` does not follow from its facts.

On a KVM-capable host, build the driver and run it. The driver keeps the VM
state and its sockets in `XDG_RUNTIME_DIR`, falling back to `TMPDIR`; point
both at a short directory on disk, since a Unix socket path holds at most 107
bytes and the state is several GB. Write the JSON outside this folder, so that
the raw output stays out of it, and copy the record in:

```bash
nix build .#e2e-distro.fedora-44-probe -o fedora-44-probe
mkdir -p /var/tmp/p/out
TMPDIR=/var/tmp/p XDG_RUNTIME_DIR=/var/tmp/p NAILS_PROBE_OUT=/var/tmp/p/out \
  ./fedora-44-probe/bin/test-driver
cp /var/tmp/p/out/fedora-44.json nix/distro-tests/probe/
```

A Fedora image also has the enforcing variant, `<image>-enforcing-probe`, which
boots the same image with SELinux enforcing.

Without a KVM host, dispatch `.github/workflows/distro-e2e.yml` with the probe
suite: each named probe then runs on a hosted runner, and its job uploads the
`probe-<probe>` artifact with `<probe>.json`, `<probe>.raw.json` and the
driver's log (see [docs/ci.md](../../../docs/ci.md)). An empty `distros` runs
every probe whose image is pinned.

```bash
gh workflow run distro-e2e.yml --ref <branch> -f suite=probe \
  -f distros='fedora-44 fedora-44-enforcing arch-boxes'
```
