# Forensic oracle

The forensic oracle turns the output of disk-image analysis tools into one
pass/fail verdict: did a torn-down hidden session leave a trace an examiner
could find? The verdict tool is the `nails-oracle` crate; this directory holds
its input policy files and `run-scan.sh`, the scan that feeds it.

The oracle runs in CI are in `.github/workflows/oracle-real-nightly.yml`. Every
night it images real ext4 decoy roots in the `oracle-images` E2E test, runs
`run-scan.sh` over them in `ORACLE_IMAGES_DIR` mode and renders the verdict,
its `scan-btrfs` job runs `run-scan.sh` over the synthetic btrfs images
`make-sample-images.sh` builds, and its `produce-btrfs` and `scan-btrfs-real`
jobs image a real Fedora 44 btrfs decoy and scan it (see
[Real btrfs images: a Fedora 44 decoy](#real-btrfs-images-a-fedora-44-decoy)).
plaso cannot open btrfs, so a btrfs scan runs no timeline and its verdict is
`partial` at best, never `clean` (see [btrfs: no timeline](#btrfs-no-timeline)). `oracle-nightly.yml` in this
directory is a template for the synthetic run alone; it is not installed under
`.github/workflows`.

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
database instead), and it proved it read the image (the canary). A btrfs scan,
which runs no plaso timeline, is at best `partial`: everything else holds, but
it is not a full run. What it cannot see is listed under
[What it does not see](#what-it-does-not-see).

## The outputs/ tree it consumes

The scan writes one subtree per tool, per image label:

```
outputs/restore/<label>/...            restored file tree, each file but the login record files emptied
outputs/restore/<label>.sha256         a SHA-256 of every restored file
outputs/nix_db/<label>.jsonl           every row of the restored Nix store database, one per line
outputs/bulk_extractor/<label>/*.txt   bulk_extractor feature files
outputs/bulk_extractor/<label>/*_carved/...  the objects its carvers saved
outputs/plaso/<label>.jsonl            plaso timeline, one JSON event per line
outputs/plaso/not-run                  on btrfs, instead of the timelines: "btrfs"
```

`<label>` is `before`, `control` or `after`. `run-scan.sh` hashes every restored
file (`sha256sum --zero`, run inside the tree) before it empties the file to
save disk. It keeps the login record files whole (`wtmp` and `btmp` and their
rotations, such as `wtmp.1` or `wtmp-20261029`): the control image's are read
for the login records its cycle wrote (see
[Login records the control holds](#login-records-the-control-holds)). Before
it empties a restored Nix store database
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
  them are still reported. A btrfs scan runs no timeline, so there they are
  reported like any file: a journal the session left is residue, not unseen.
- nix_db — `path` is the store database's on-image path; `field` is one of its
  rows: the table's name, then its columns as `name=value` in name order, a
  NULL left out, as in `ValidPaths hash="sha256:..." narSize=1216
  path="/nix/store/..."`. Each value is written as JSON (a string in double
  quotes), and so is a name that is not a plain identifier, so two rows read
  alike only when they hold the same. Every table is read, the schema
  (`sqlite_master`) too:
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
  out, and any other carved object by its content hash. A carved login record
  new in `after` is also subtracted by a record of the same key in the control
  image's login files (see
  [Login records the control holds](#login-records-the-control-holds)). Two
  outputs stay out of the verdict: `sqlite_carved`, because the oracle's decoy
  VMs rewrite their Nix store database file at every start and the images hold
  live and stale, partly overwritten copies of it that no clean boot
  reproduces (the live database is read by its rows instead), and
  `duplicates`, which lists repeated blocks by their offsets.
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
is no switch to skip a channel: the one channel left out is the timeline of
btrfs images, by design and named in the verdict (see
[btrfs: no timeline](#btrfs-no-timeline)). The verdict is still written, so a
local run without docker can read what the other channels found.

### Carving the restore channel

`run-scan.sh` carves the file tree with `btrfs restore` for btrfs (snapshots and
symlinks included) and `debugfs rdump` for ext{2,3,4}. An image is a bare
filesystem, or a whole-disk image with exactly one btrfs or ext{2,3,4}
partition, the root. A disk with several (a separate `/boot` or `/home`) fails
the run, because the root cannot be told apart safely: scan the root
filesystem's own image instead. So does an image that holds a filesystem at
byte 0 and a partition table too, which could be either.

Of a whole-disk image, every byte outside the root filesystem is compared too,
each part at a top-level name of its own (`ci/oracle/partitions.sh`), and
each partition from its place n in the partition table:

- a vfat partition, an EFI system partition, into `/partition-<n>-vfat/`. No
  carver here reads vfat offline, so it is mounted read-only from a read-only
  loop device, through which the kernel cannot write to the image, and its
  directories and files are copied. The bytes from its start to its data
  area, its boot sector (with its label, serial and dirty flag), its other
  reserved sectors, its allocation tables and, on FAT12 and FAT16, its root
  directory, go to the file `/partition-<n>-vfat-structures`;
- a partition holding no filesystem blkid recognises, a BIOS boot partition,
  into the one file `/partition-<n>`, which holds its bytes, so the partition
  is compared whole. One larger than 64 MiB stops the run;
- every stretch no partition covers into
  `/outside-partitions/<offset>-<end>` (in bytes, the end exclusive), with its
  bytes: the protective MBR and its boot code, the GPT header and entries, the
  gaps before, between and after the partitions, the tables of a DOS extended
  partition and the backup GPT. A change to the partition table is seen, and
  so is a partition mmls does not list, such as one an entry places over the
  table itself.

A partition holding any other filesystem, one blkid cannot tell (two
signatures, say), a table mmls cannot read or that does not list the root
once, and a root that already holds one of these names each stop the run,
since a part of the disk would go uncompared while the verdict passes. What
the scan does not compare by its bytes is free space inside a filesystem and
the data area of a vfat partition beyond its files, which only bulk_extractor
reads. plaso also needs the root to be the only partition (see below), so on
ext{2,3,4} a disk with more partitions fails the plaso channel.

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

plaso opens ext{2,3,4} but not btrfs, so on btrfs images `run-scan.sh` runs
no timeline at all (next section). It also opens a whole-disk image only when
the image holds a single partition: `run-scan.sh` runs log2timeline unattended
and without `--partitions`, and log2timeline then stops rather than choose
among several, an EFI system or BIOS boot partition next to the root included.
Scan the root filesystem's own image instead.

### btrfs: no timeline

Fedora and Arch decoys are btrfs by default, and plaso cannot read btrfs. So
when the three images are btrfs, `run-scan.sh` neither pulls nor runs plaso and
writes `outputs/plaso/not-run` holding `btrfs` in place of the timelines. The
three images are one host's disk, so all three must be btrfs; some btrfs and
some not stops the run. `nails-oracle` then:

- requires the restore carve (`btrfs restore`) and bulk_extractor on every
  image, as on any scan, and compares the files, their content, the records
  bulk_extractor decodes and the rows of a Nix store database as always; a
  silent channel, a leak, a missing control or canary fails the run;
- reports the rotating journal files as restore findings (above);
- writes `"status": "partial"`, exit `3`, when nothing else is wrong, never
  `clean`, with `"not_run": [{"tool": "plaso", "channel": "timeline",
  "reason": "plaso cannot read btrfs"}]` and a summary that begins `PARTIAL, NOT
  A FULL RUN (timeline: not run, plaso cannot read btrfs)`; a failing summary
  names it too;
- stops (exit `2`) on a `not-run` marker that says anything else or sits next
  to a timeline, and fails a run in which plaso reported a finding although
  the marker says it did not run (`not_run_channel_reported`).

What a partial run does not see beyond a full one is what only plaso reads:
the records it parses out of a file, such as the login records of `wtmp`
(bulk_extractor still carves those where they are stored uncompressed: see
[Real btrfs images](#real-btrfs-images-a-fedora-44-decoy)) and the messages of
a journal (whose file the restore channel then compares whole). A file a reboot rewrites that only
plaso read records of is named under `reboot_rewritten` instead.

`run-scan.sh` passes a partial verdict only on btrfs images that ran no
timeline, and only when the verdict says `partial` and names exactly that
channel; it then prints `PARTIAL verdict, not a full run` (a warning
annotation in GitHub Actions). Anything that asks for `"status": "clean"`
does not take a partial run for one.

On a real btrfs `after` image the positive controls go into device space no
btrfs chunk is allocated in (see [controls.json](#controlsjson--the-scan-self-checks)).

### Real btrfs images: a Fedora 44 decoy

The `produce-btrfs` job of the nightly runs `fedora-44-oracle-images`, a host
driver of the distribution tests (`nix/distro-tests/oracle-images.nix`), on a
KVM runner. It boots the stock Fedora 44 Cloud image, whose root is a btrfs
filesystem compressed with zstd, with `root`, `boot`, `home` and `var`
subvolumes and a vfat ESP beside it, and keeps the whole disk four times,
powered off: before, after one plain reboot (control), after a second plain
reboot (control2), and after one more boot, a hidden session and the way back
(after). The run stays in one QEMU process, which pauses at the guest's
power-off instead of exiting, so the images are one disk's lineage: each is a
copy of the paused disk, and a reset boots it again.

Fedora is not admitted yet, so the driver runs a test-only build of the
release binary in which only the Fedora row of the family table is admitted.
That build is never released. The verdict on the images says what the
oracle's channels see of a session on a Fedora 44 Cloud decoy, with what they
do not see listed under [What it does not see](#what-it-does-not-see), not
that NAILS supports Fedora.

Before the first image the driver makes the decoy's journal volatile and masks
auditd (the posture NAILS requires), creates `/mnt/data` and writes the
coverage canary, with btrfs compression turned off for its file and its bytes
checked on the partition in clear. The hidden root is a file on a tmpfs, and
inside the session the driver writes, syncs and deletes a token whose bytes it
then finds on the hidden root's device.

`scan-btrfs-real` runs `run-scan.sh` twice: over before, control and after,
and over before, control and control2 in the place of after. No session ran
on control2, so the second scan has nothing to find: whatever it calls
residue, plain reboots made, and it fails the job as a leak would. Each scan
passes only on the partial verdict that names the timeline, as `scan-btrfs`
does. A diagnostic job, `btrfs-wtmp-extents`, shows how each of the four
images stores `/var/log/wtmp`: its size and which of its bytes btrfs keeps
inline, compressed or plain (`btrfs-file-extents.sh`, which reads the image
through a read-only loop device mounted read-only).

Three things read differently from the ext4 images:

- The disk holds three partitions, and the restore channel compares each and
  what lies outside them (see
  [Carving the restore channel](#carving-the-restore-channel)): the BIOS boot
  partition whole as `/partition-1`, the EFI system partition's files under
  `/partition-2-vfat` and its structures as `/partition-2-vfat-structures`,
  the btrfs root at `/`, and the GPT with the gaps around the partitions under
  `/outside-partitions`.
- `btrfs restore` recovers the top level of the filesystem, so a file is keyed
  by its path there: the root subvolume's `/etc/fstab` reads as
  `/root/etc/fstab`, while `/var` and `/home`, subvolumes of the same name at
  the top level, keep their paths. The canary's `/var/lib/nails-oracle/canary`
  is found where the carve check looks for it.
- Fedora mounts the filesystem with `compress=zstd:1`, and bulk_extractor reads
  the bytes on the disk: it sees nothing a compressed extent holds, nor a file
  btrfs keeps compressed inside its metadata, as it does with a file of at most
  one 4 KiB block that compresses well. The restore carve still compares such
  files whole, but what a compressed extent keeps outside the live tree is
  unseen, and the verdict names it so (`compressed_extents` under
  [What it does not see](#what-it-does-not-see)). And a file stored
  compressed in the earlier images and partly in
  plain blocks in a later one shows bulk_extractor those blocks in the later
  image alone. The decoy's `/var/log/wtmp` does this: it stays inline and
  compressed through before and control, with two boots' records, and once it
  grows past 4 KiB a write of a single block of it is stored plain, so
  bulk_extractor carves the getty, boot and shutdown records of that block
  from control2 and after, and none from before and control.

#### Login records the control holds

A carved login record is therefore also compared with the control image's
login files, read whole. `run-scan.sh` keeps `wtmp`, `btmp` and their
rotations whole when it empties the restored files, and nails-oracle reads
every whole record of the control's by the key a carved record gets: its
type, process range, terminal, id, user, host, exit status and address, with
its time and session left out. A carved login record new in `after` whose key
one of those records has is a record the control cycle wrote too, and
subtracts as noise, as if the control had carved it. The key must match
exactly: a record only `after` holds, in a later process range, of another
user or on another terminal, stays residue. The control's files only
subtract a record new in `after`: one that `before` and the control both
carved and `after` lost is residue as before. A login record file found empty
that the digest manifest recorded as holding data stops the scan, since its
records would be lost. The same holds on ext4, where whether a record is
carved also depends on where its blocks lie.

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
- `compressed_extents`, on a btrfs scan: what a compressed extent holds
  outside the live tree. bulk_extractor decodes no btrfs compression, so it
  records no feature in an extent btrfs compressed (on a filesystem mounted
  with `compress`, as Fedora's is), and content a file left there is unseen
  whatever value it carries. The restore carve reads the live tree's files
  decompressed (see
  [Real btrfs images](#real-btrfs-images-a-fedora-44-decoy)).
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
  image scanned would no longer be the one captured. On a btrfs image the free
  blocks are the device space no chunk is allocated in, found offline in the
  device tree with btrfs-progs; the first MiB and the superblock copies are
  passed over, and btrfs tracks nothing there, so the image reads the same to
  btrfs afterwards. On the synthetic images `make-sample-images.sh` writes them
  past the end of the filesystem. A control
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
allowlist), `2` usage or I/O error, `3` partial (a btrfs scan without the
timeline that passes everything else). `run-scan.sh` passes a run only when the
tool exits `0` and the `verdict.json` it wrote says `"status": "clean"`, or on
btrfs images only, when it exits `3` and the verdict says `partial` and names
the timeline as the one channel not run. Run it
as a user who can read the whole outputs tree: the carved trees keep the
decoy's root-only modes (`/root`, `/etc/credstore`), so that is normally root.
An entry it cannot read, a restored file without its digest, a carved record
it cannot read as one, or a restored store database without its rows stops it
with exit `2` rather than being skipped.
