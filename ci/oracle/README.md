# Forensic oracle

The forensic oracle turns the output of disk-image analysis tools into one
pass/fail verdict: did a torn-down hidden session leave a trace an examiner
could find? The verdict tool is the `nails-oracle` crate; this directory holds
its two input policy files. The nightly `oracle-nightly.yml` workflow builds the
images, runs the analysis tools, and runs the verdict tool over their output.

## What it compares

Three images of one host are scanned:

- `before` — the host before any hidden session (the clean baseline).
- `control` — a clean boot cycle that ran **no** hidden session (the noise
  baseline).
- `after` — the host after a hidden session was torn down (the image under
  test).

A difference between `after` and `before` is a leak **unless** it also appears
in the `control` cycle (then it is ordinary boot noise, subtracted) or a cited
allowlist entry explains it. The verdict is `clean` only when every difference
is accounted for, the scan proved it is not blind (the positive controls), and
it proved it read the image (the canary).

## The outputs/ tree it consumes

The scan writes one subtree per tool, per image label:

```
outputs/restore/<label>/...            btrfs restore file tree
outputs/bulk_extractor/<label>/*.txt   bulk_extractor feature files
outputs/plaso/<label>.jsonl            plaso timeline, one JSON event per line
```

`<label>` is `before`, `control` or `after`. The plaso store is exported to JSON
lines (for example `psort -o json_line`) so the verdict tool can read it without
a plaso runtime. Each tool normalizes to findings keyed by `(tool, path,
field)`:

- restore — `path` is the recovered file's absolute on-image path; `field` is
  empty.
- bulk_extractor — `path` is the feature type (`email`, `url`, ...); `field` is
  the feature value. This channel still sees a deleted-but-not-overwritten
  trace in free space.
- plaso — `path` is the event's source path; `field` is the event descriptor.

## allowlist.json — the citation rule

The allowlist is the only set of `after`-vs-`before` differences, beyond
control-cycle noise, that a clean verdict tolerates. Every entry names a
specific location and **exactly one** citation:

```json
{
  "entries": [
    { "path": "/var/lib/nixos", "cite": "var-lib-nixos", "note": "optional" }
  ]
}
```

- `path` — an absolute path (covers that path and everything beneath it), or a
  bulk_extractor feature type (then `field` must give the exact value).
- `field` — optional; when set, only that exact value is covered.
- `cite` — **required**: a residue-catalog `id` (kebab-case), or a threat-model
  doc anchor `<file>.md#<anchor>`. There is no uncited form.

An entry is rejected — and a rejected allowlist can never produce a clean
verdict — when it:

- cites nothing, or cites an id or anchor that does not exist in the live
  residue catalog;
- names a whole top-level directory (`/var`, `/nix`), a whole system subtree
  (`/var/lib`, `/nix/store`), or uses a glob (`/nix/store/**`); or
- sits outside the cited row's own channel (citing `var-lib-nixos`, whose
  channel is `/var/lib/nixos`, for a `/var/log` path).

There is deliberately no wholesale `var/` or `nix/` exemption. Those trees are
exactly where residue lands — the catalog enumerates it there selectively — so
they are scanned, not skipped. The oracle prints the cited row's own risk and
mitigation text to justify each difference it keeps.

## controls.json — the scan self-checks

Two checks keep a clean verdict honest:

```json
{
  "positive_controls": [
    { "name": "wtmpdb-boot", "tool": null, "path": "/var/log/wtmp.db", "field": null }
  ],
  "canary": { "tool": "bulk_extractor", "path": "email", "field": "canary@oracle.example" }
}
```

- **Positive controls** are baseline records the scan plants on the `after`
  image (for example a wtmpdb boot row, a lastlog2 row). Each must be detected,
  or the scan is blind and the run fails — never `clean`. A run with no positive
  control also fails: it cannot prove it sees residue at all.
- The **canary** is a fixed marker planted on every image. Finding it proves the
  scan read the image's contents.

`tool` pins the channel that must surface a check (any channel when `null`).
Keep these in step with what the scan actually plants.

## Running it

```
nails-oracle <outputs-dir> [--allowlist FILE] [--controls FILE]
```

It prints the verdict as JSON to stdout and a one-line summary to stderr. Exit
codes: `0` clean, `1` fail (residue, blind, canary or a bad allowlist), `2`
usage or I/O error.
