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

These facts need a booted VM, which needs KVM, so recording them is a follow-up
on a KVM-capable host (the build server has none). This directory holds the
**structure** so that adding a real recording later is a drop-in: one JSON file
per image key in `../images.json`, with the fact schema already in place and
`"recorded": false` until the probe has run.

## Files

One file per image the probe will cover, named after its `../images.json` key:

- `fedora-44.json`  -- the pinned Fedora 44 cloud image
- `fedora-45.json`  -- Fedora 45 once its image is pinned
- `arch-boxes.json` -- the pinned Arch `arch-boxes` image
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
    on the stock image (string, or `null` where SELinux is not enforcing).
  - `mounts` -- the image's own mount layout: a list of
    `{ "target": ..., "fstype": ..., "options": ... }`.
  - `tools` -- host tools NAILS may spawn, mapped to their absolute path on the
    image (`{ "<tool>": "<path>" }`); an absent tool is omitted.
  - `journaldVendorConfig` -- the effective vendor `Storage=` and the files that
    set it (`{ "storage": ..., "sources": [ ... ] }`).
  - `failedBootUnits` -- boot-loader and early units that show as failed on a
    plain boot of the stock image (list of unit names).
  - `updatedbPrunePaths` -- the `PRUNEPATHS` the image's `updatedb` ships (list).
  - `avcs` -- AVC denials seen on a plain boot (list of raw AVC lines).
  - `ninePUnderEnforcing` -- whether a 9p share mounts and reads while SELinux is
    enforcing (`true`/`false`/`null`).
  - `derivativeOsRelease` -- for a derivative, the `ID`, `ID_LIKE` and
    `VARIANT_ID` its `os-release` carries (`{ ... }`).

## Regenerating

On a KVM-capable host, boot the image through the same `nix-vm-test` seam the
smoke suite uses (`../lib/distro-vm.nix`), gather the facts above on the stock
decoy before NAILS touches it, and write them into the matching file with
`recorded` set to `true`. Keep the key order and the schema; a consumer in the
platform or session tests reads the file by its `image` key.
