# Forensic oracle

The forensic oracle turns the output of disk-image analysis tools into one
pass/fail verdict: did a torn-down hidden session leave a trace an examiner
could find? The verdict tool is the `nails-oracle` crate; this directory holds
its input policy files and `run-scan.sh`, the scan that feeds it.

The only oracle run in CI is `.github/workflows/oracle-real-nightly.yml`. Every
night it images real ext4 decoy roots in the `oracle-images` E2E test, runs
`run-scan.sh` over them in `ORACLE_IMAGES_DIR` mode and renders the verdict.
`oracle-nightly.yml` in this directory is a template for a run over synthetic
btrfs images. It is not installed under `.github/workflows`, so nothing runs
it, and it could not pass as it stands: plaso cannot open btrfs (see
[Proving plaso read each image](#proving-plaso-read-each-image)).

## What it compares

Three images of one host are scanned:

- `before` — the host before any hidden session (the clean baseline).
- `control` — a clean boot cycle that ran **no** hidden session (the noise
  baseline).
- `after` — the host after a hidden session was torn down (the image under
  test).

A difference between `after` and `before` is a leak **unless** the `control`
cycle shows the same change (then it is ordinary boot noise, subtracted) or a
cited allowlist entry explains it. A difference goes either way: a trace new in
`after`, a file whose content changed, and a file, record or feature that was in
`before` and in `control` but is gone from `after`. The verdict is `clean` only
when every difference it can see is accounted for, the scan proved it is not
blind (the positive controls, and every analysis channel but nix_db reporting
on every image; only a Nix decoy has a store database, so nix_db is held to the
database instead), and it proved it read the image (the canary). What it cannot
see is listed under [What it does not see](#what-it-does-not-see).

## The outputs/ tree it consumes

The scan writes one subtree per tool, per image label:

```
outputs/restore/<label>/...            restored file tree, each file emptied
outputs/restore/<label>.sha256         a SHA-256 of every restored file
outputs/nix_db/<label>.jsonl           every row of the restored Nix store database, one per line
outputs/bulk_extractor/<label>/*.txt   bulk_extractor feature files
outputs/bulk_extractor/<label>/*_carved/...  the objects its carvers saved
outputs/plaso/<label>.jsonl            plaso timeline, one JSON event per line
```

`<label>` is `before`, `control` or `after`. `run-scan.sh` hashes every restored
file (`sha256sum --zero`, run inside the tree) before it empties the file to
save disk. Before it empties a restored Nix store database
(`/nix/var/nix/db/db.sqlite`), it dumps every row of each of the database's
tables and of its schema, one JSON object per line
(`{"table": ..., "row": {...}}`), reading a copy with the write-ahead log
beside it. The plaso store is exported to JSON lines (for example `psort -o
json_line`) so the verdict tool can read it without a plaso runtime. Each tool
normalizes to findings keyed by `(tool, path, field)`:

- restore — `path` is the recovered entry's absolute on-image path; `field` is
  its kind and content: `sha256:<digest>` for a file, `dir` for a directory,
  `symlink:<target>` for a symbolic link, `other` for anything else a carver
  recovers. An empty directory or a symlink (a unit's enablement link, say) is
  a trace in its own right. The rotating journal files under `/var/log/journal`
  are left to plaso, which compares them by content; the directories that hold
  them are still reported.
- nix_db — `path` is the store database's on-image path; `field` is one of its
  rows: the table's name, then its columns as `name=value` in name order, a
  NULL left out. Every table is read, the schema (`sqlite_master`) too:
  `ValidPaths`, one row per registered store path, `Refs`, the references
  between those paths by their `ValidPaths` ids, `DerivationOutputs`, and
  `sqlite_sequence`, the highest id `ValidPaths` ever gave out. Left out are
  the columns that only order, date or place a row: a `ValidPaths` row's id
  and registration time, and the page a schema entry starts at (`rootpage`).
  The oracle's decoy VMs register their store paths at every start (the QEMU
  test module's `register-nix-paths`), which rewrites the database file, so
  the restore channel can only call it noise. Its rows do not change with
  such a start, so a store path the session registered or removed, or
  registered again with another hash, size, deriver or signature, is a change
  of its own, and so is a store path it registered and collected again: the
  sequence stays raised.
- bulk_extractor — `path` is the feature type (`email`, `url`, ...); `field` is
  the feature value. This channel reads the whole image, free space included,
  so it still sees a deleted but not yet overwritten trace, though only by the
  features it records in it: deleted content that holds none is not seen
  (`deleted_content` under [What it does not see](#what-it-does-not-see)).
  Its carvers save whole objects, named by the offset they were found at, so
  those are keyed by their content instead: a carved login record
  (`utmp_carved`) by the fields it records with its time and session left
  out, and any other carved object by its content hash. Two outputs stay out
  of the verdict: `sqlite_carved`, because the oracle's decoy VMs rewrite
  their Nix store database file at every start and the images hold live and
  stale, partly overwritten copies of it that no clean boot reproduces (the
  live database is read by its rows instead), and `duplicates`, which lists
  repeated blocks by their offsets.
- plaso — `path` is the event's source path; `field` is the event's data type,
  then, for a record, every field that says what it records (`name=value`).
  The record's timestamps, its offset, the file's inode and hash, and plaso's
  own rendering of the record as text are left out, so the same record written
  again at another time is the same finding, and a process id is kept as the
  power-of-two range it falls in (`512-1023`). A file's own `fs:` event is
  keyed by its path alone. A systemd-journal line is keyed as `journal` with
  its reporter, host and message body, where only a process id, a boot id, a
  duration, a size or an audit stamp in its known position is masked: an
  address, a port, a user or group id, a MAC or a hostname that differs from
  the decoy's own line keeps the line from subtracting.

The restore channel holds one entry per path, so it is compared path by path:
a path whose entry `after` holds differently is residue when `before` and
`control` agree on it, and noise when `control` changed it too (a file every
boot rewrites, like `/var/lib/systemd/random-seed`). Records, rows and features
are compared one by one: a login record appended to `wtmp`, which every boot
appends to, subtracts only against the same record in `control`, and so does
a row of the store database.

Every channel but nix_db must report at least one finding on every image. A
channel that reported nothing for an image (its tool was missing, failed,
timed out or read nothing) fails the run as `channel_missing` and marks it
blind, never `clean`. Only a Nix decoy has a store database, so the nix_db
channel is held to the database instead: a restored tree that holds the
database without its rows, or rows without the database, stops the verdict
tool (exit `2`), and `run-scan.sh` stops when `sqlite3` is missing or cannot
read the database.
No channel stands in for another: the restore channel leaves the journal files
to plaso, and every shipped self-check is a bulk_extractor finding.
`run-scan.sh` drops the plaso channel whole when docker is missing, its pinned
image cannot be pulled, or any image's timeline fails, runs past 20 minutes or
does not show that plaso read the image (see below), so such a run fails. There
is no switch to skip a channel; the verdict is still written, so a local run
without docker can read what the other channels found.

### Carving the restore channel

`run-scan.sh` carves the file tree with `btrfs restore` for btrfs (snapshots and
symlinks included) and `debugfs rdump` for ext{2,3,4}. An image is a bare
filesystem, or a whole-disk image with exactly one btrfs or ext{2,3,4}
partition (plaso also needs it to be the only partition: see below). A disk
with several (a separate `/boot` or `/home`) fails the run, because the root
cannot be told apart safely: scan the root filesystem's own image instead.

A carve must report no error and must hold the canary's file
(`/var/lib/nails-oracle/canary.txt` on the synthetic images,
`/var/lib/nails-oracle/canary` on the real ones), or the run fails: debugfs
exits 0 even when it cannot open the image, so its own status proves nothing. A
filesystem with no carver here (xfs, f2fs, bcachefs, zfs) stops the run with
that reason rather than leaving this channel empty, which would fail the verdict
anyway. Add a carver to `carve_restore` in `run-scan.sh` to certify such a
decoy.

### Proving plaso read each image

plaso reads the files in an image only when it can open the image's file
system. An image it cannot open, it reads as one opaque file, and it still
dates that file. Those events name the one path every image is read through, so
they collapse across the images: the plaso channel reports something on every
image, and the run could read clean, while plaso read no file in any of them.
`run-scan.sh` therefore keeps a timeline only when it has an event for the
canary's file (`timeline-has-file.sh` checks the events' `filename`), and drops
the plaso channel otherwise.

plaso opens ext{2,3,4} but not btrfs, so a btrfs image, the synthetic ones
included, fails the plaso channel and with it the run. It also opens a
whole-disk image only when the image holds a single partition: `run-scan.sh`
runs log2timeline unattended and without `--partitions`, and log2timeline then
stops rather than choose among several, an EFI system or BIOS boot partition
next to the root included. Scan the root filesystem's own image instead.

### What it does not see

The verdict accounts for every difference its keys can tell apart, and no
more. It names what it cannot see under `unseen` in the verdict, one entry per
class with its `kind`, and a clean summary line ends with the same classes
(`; not seen: ...`):

- `timestamps`: no key holds a time, so a file the session only read or
  touched reads as unchanged.
- `metadata`: the mode, owner and extended attributes of a file whose content
  stays the same.
- `process_id_range`: a process id in the same power-of-two range as the one a
  fresh boot gives that process.
- `deleted_content`: what lies outside the live tree, a file the session
  deleted or what free space holds, unless it carries a feature bulk_extractor
  records: a value (an e-mail address, a URL, a domain, ...) or an object one
  of its carvers saves. The restore channel carves only the live tree, and
  bulk_extractor reports the features it finds in free space, not the bytes
  around them.
- `skipped_carvers`: a database carved from free space (`sqlite_carved`, named
  in `feature_types`), unless its content carries an e-mail address, a URL or
  a domain the value recorders find.
- `reboot_rewritten`: a file a plain reboot rewrites too. The control cycle
  marks its path as noise, so a session's write to it is seen only where a
  channel reads the file's records: the login records of `wtmp`, through
  plaso and bulk_extractor's carver, and the rows and schema of the Nix store
  database, though not what the database's unused space keeps of rows it
  deleted.
  `paths` lists this run's other such files where `after` holds what neither
  `before` nor `control` does (on the real images,
  `/var/lib/systemd/random-seed` among them).

## allowlist.json — the citation rule

The allowlist is the only set of `after`-vs-`before` differences, beyond
control-cycle noise, that a clean verdict tolerates. Every entry names one
exact location and **exactly one** citation:

```json
{
  "entries": [
    { "path": "/var/lib/systemd/timesync/clock", "cite": "timesync-clock", "note": "optional" }
  ]
}
```

- `path` — an absolute path, which covers that path alone and never anything
  beneath it, or a locus that is not a path (a bulk_extractor feature type,
  `journal`), which must then give the exact value in `field`.
- `field` — optional; when set, only that exact value is covered. Without it the
  entry covers the restore channel's entry at `path`, whatever it holds; a
  record or a feature (plaso's own `fs:stat` of the file included) is covered
  only by naming its exact value, so no entry waves through every record of a
  file.
- `cite` — **required**: the id of a residual residue-catalog row
  (kebab-case), or a threat-model doc anchor `<file>.md#<anchor>` a residual
  row points at. There is no uncited form.
- `removed` — optional, `false` by default; `true` covers the entry's removal
  from `after` (it was in `before` and `control`) instead of its arrival or
  change, so a trace the session is expected to delete is cited apart from one
  it is expected to leave.

An entry is rejected — and a rejected allowlist can never produce a clean
verdict — when it:

- cites nothing, or cites an id or anchor that does not exist in the live
  residue catalog;
- cites a row that is not residual, or an anchor only such rows point at: those
  rows describe a trace the overlay must prevent, so that trace in `after` is a
  leak, and citing the row would print the leak's own description as its
  excuse (`var-lib-nixos` describes hidden users reaching the decoy's
  `/var/lib/nixos`);
- names a whole top-level directory (`/var`, `/nix`), a whole system subtree
  (`/var/lib`, `/nix/store`), or uses a glob (`/nix/store/**`); or
- sits outside the cited row's own channel (citing `timesync-clock`, whose
  channel is `/var/lib/systemd/timesync/clock`, for a `/var/log` path).

There is deliberately no wholesale `var/` or `nix/` exemption, and no subtree
one: those trees are exactly where residue lands, and a new entry under a
directory the catalog names (a stamp under `/var/lib/systemd/timers` for a timer
only the hidden system runs) is the leak itself. What a plain reboot changes
there is subtracted by the control cycle and needs no entry. The oracle prints
the cited row's own risk and mitigation text to justify each difference it
keeps.

## controls.json — the scan self-checks

Two checks keep a clean verdict honest:

```json
{
  "positive_controls": [
    { "name": "unallocated-1", "tool": "bulk_extractor", "path": "email", "field": "unallocated-1@oracle.example" }
  ],
  "canary": { "tool": "bulk_extractor", "path": "email", "field": "canary@oracle.example" }
}
```

Every self-check must name a **concrete planted artifact**: an exact `field`,
never a whole directory or a value-less locus. The engine rejects a self-check
whose `field` is null or that names a whole location, so neither can silently
widen into a blanket residue exemption.

- **Positive controls** are records the scan plants on the `after` image: each
  a unique, obviously-synthetic `@oracle.example` address written into
  unallocated space, so no file, path or record changes and only the carved
  address is new. On the real images `run-scan.sh` writes each into its own
  free block of a working copy of `after.raw` that holds nothing but zeros,
  byte by byte with no mount (`plant-in-free-space.sh`): a read-write mount
  would replay or restart the ext4 journal and rewrite the superblock, so the
  image scanned would no longer be the one captured. On the synthetic images
  `make-sample-images.sh` writes them past the end of the filesystem. A control
  counts as detected only when `after` carries it and `before` and `control`
  do not, so a value the baseline already holds can never stand in for the
  planted one. A control missing, or already in the baseline, makes the scan
  blind and fails the run — never `clean`. A run with no positive control also
  fails: it cannot prove it sees residue at all. (This proves that the channel
  that reads free space sees an e-mail address planted there, as it would one
  a leaked-then-deleted trace holds. It proves neither that a format-aware
  parser understood a record nor that deleted content without such a feature
  is seen.)
- The **canary** is a reserved address planted on every image at an
  otherwise-uncovered path. Finding it proves the scan read the image's
  contents. The scan may rotate it per run (`ORACLE_SEED`) and pins whatever it
  planted in a run-time copy of this file; the committed value is the default.

`tool` pins the channel that must surface a check (any channel when `null`).
Keep these in step with what `make-sample-images.sh` and `run-scan.sh` plant.

The real images also carry session data the oracle must **not** find: inside
the hidden session the e2e test (`nix/e2e-tests/tests/forensic/13-oracle-images.nix`)
writes an address and a URL under `session.oracle.example` into a file, syncs
it to disk and deletes it, then checks the bytes are still on the hidden
volume's block device. If a regression put the session's writes on the decoy
disk, bulk_extractor would carve them from `after`'s free space, and the run
would fail on them as unexplained residue.

## Running it

```
nails-oracle <outputs-dir> [--allowlist FILE] [--controls FILE]
```

It prints the verdict as JSON to stdout and a one-line summary to stderr; a
clean summary ends with what the verdict cannot see. Exit codes: `0` clean,
`1` fail (residue, a blind scan or a missing channel, canary or a bad
allowlist), `2` usage or I/O error. `run-scan.sh` passes a run only when the
tool exits `0` and the `verdict.json` it wrote says `"status": "clean"`. Run it
as a user who can read the whole outputs tree: the carved trees keep the
decoy's root-only modes (`/root`, `/etc/credstore`), so that is normally root.
An entry it cannot read, a restored file without its digest, a carved record
it cannot read as one, or a restored store database without its rows stops it
with exit `2` rather than being skipped.
