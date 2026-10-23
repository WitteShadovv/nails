# Distribution probe fixtures

A probe boots one distribution's stock cloud image **without NAILS** and records
the handful of host facts the cross-distribution work needs but cannot yet
assert, so that each becomes committed test data instead of a guess. The facts
are the ones the platform notes leave unverified for the families that are not
admitted yet (Fedora and Arch): the SELinux domain a backdoor-style service
lands in, the image's own mount layout, the host tools actually present, the
vendor journald configuration, the boot-loader units that fail on their own, the
`updatedb` prune paths, any AVC denials, whether a 9p share works while SELinux
is enforcing, and the `os-release` values a derivative carries.

These facts need a booted VM, which needs KVM, so they are recorded on a
KVM-capable host (the build server has none): one JSON file per image key in
`../images.json`, with `"recorded": false` until the probe has run on it.

## Files

One file per image the probe will cover, named after its `../images.json` key:

- `fedora-44.json`  -- the pinned Fedora 44 cloud image (recorded, booted with
  SELinux permissive as `../images.json` pins it, and again enforcing for the
  enforcing-only facts)
- `fedora-45.json`  -- Fedora 45 once its image is pinned
- `arch-boxes.json` -- the pinned Arch `arch-boxes` image (recorded)
- `arch-install.json` -- the `archinstall`-built Arch image, once hosted

Debian and Ubuntu need no probe: they are admitted and covered by the smoke
suite directly.

## Fact schema

Each file is an object:

- `image`   -- the `../images.json` key this file records.
- `osId`    -- the decoy's `/etc/os-release` ID.
- `recorded` -- `false` until a probe run has filled `facts`; a consumer must
  skip or xfail a fact file whose `recorded` is `false`.
- `facts`   -- the recorded facts, each `null`/empty until recorded:
  - `selinuxBackdoorDomain` -- the SELinux domain a backdoor-style unit runs in
    on the stock image (string, or `null` where the image has no SELinux; a
    permissive boot labels processes as an enforcing one does, so it records
    the domain too).
  - `mounts` -- the image's own mount layout: a list of
    `{ "target": ..., "fstype": ..., "options": ... }`.
  - `tools` -- the programs the NAILS sources name, mapped to their absolute
    path on the image (`{ "<tool>": "<path>" }`); an absent tool is omitted.
  - `journaldVendorConfig` -- the effective vendor `Storage=` and the files that
    set it (`{ "storage": ..., "sources": [ ... ] }`); `sources` is empty when
    no file sets it and the compiled-in default applies.
  - `failedBootUnits` -- boot-loader and early units that show as failed on a
    plain boot of the stock image (list of unit names).
  - `updatedbPrunePaths` -- the `PRUNEPATHS` the image's `updatedb` ships (list).
  - `avcs` -- AVC denials seen on a plain boot, permissive or enforcing (list of
    raw AVC lines).
  - `ninePUnderEnforcing` -- whether a 9p share mounts and reads while SELinux is
    enforcing, from the enforcing variant (`true`/`false`, or `null` where the
    image has no SELinux).
  - `derivativeOsRelease` -- for a derivative, the `ID`, `ID_LIKE` and
    `VARIANT_ID` its `os-release` carries (`{ ... }`).

## Regenerating

On a KVM-capable host, build the probe driver of the image (`../probe.nix`, the
same `nix-vm-test` seam the smoke suite uses) and run it. The driver keeps the
VM state and its sockets in `XDG_RUNTIME_DIR`, falling back to `TMPDIR`; point
both at a short directory on disk, since a Unix socket path holds at most 107
bytes and the state is several GB:

```bash
nix build .#e2e-distro.fedora-44-probe -o fedora-44-probe
mkdir -p /var/tmp/p
TMPDIR=/var/tmp/p XDG_RUNTIME_DIR=/var/tmp/p ./fedora-44-probe/bin/test-driver
```

A Fedora image also has an enforcing variant, `<image>-enforcing-probe`, which
boots the same image with SELinux enforcing; `ninePUnderEnforcing` and the
enforcing half of `avcs` come from it.

The driver prints one `=== <fact> ===` block per query. Copy what the blocks
show into the matching file and set `recorded` to `true`. Keep the key order
and the schema; a consumer in the platform or session tests reads the file by
its `image` key. The `/nix/.ro-store` 9p share and the `backdoor.service` and
`mount-store.service` units belong to the test harness, not to the image, so
they stay out of `mounts`; the domain the backdoor unit runs in is exactly what
`selinuxBackdoorDomain` records. The harness also masks some units (the
`masked-units` block lists them, for example the serial getty and SSH units,
and on Arch `systemd-boot-update.service`, `systemd-time-wait-sync.service`
and the keyring units), so `failedBootUnits` cannot show a failure of one of
those.
