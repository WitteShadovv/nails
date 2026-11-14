#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Plant record-level positive controls into a real Fedora btrfs decoy image:
# the changes a hidden session would make if it reached the decoy's login and
# package records, written where the decoy keeps them. The oracle nightly scans
# such a planted copy of after.raw in the place of after, and the verdict must
# fail on exactly these paths: that shows the independent collector sees a row
# added to a login database and a change to the package manager's state, which
# the free-space controls (plant-in-free-space.sh) do not show.
#
#   sudo plant-records.sh <image> <out.json>
#
# The image is a whole disk; its btrfs filesystem is mounted read-write from
# its top level (subvolid=5), noatime, through a loop device, so every
# subvolume is a folder below the mount, as the restore channel keys it. It
# plants, each with a value no image holds:
#
#   /var/lib/lastlog/lastlog2.db  a row for a user named after the seed, in
#                                 the Lastlog2 table pam_lastlog2 writes (the
#                                 table, the file and its folder made when the
#                                 image has none);
#   the wtmpdb database           a login row, where the image has one
#                                 (/var/lib/wtmpdb/wtmp.db or /var/log/wtmp.db);
#   /var/lib/dnf/<seed>.json      a file in the package manager's state folder.
#
# The values are plain words: no address, domain or URL that bulk_extractor
# would record, so the controls show the restore channel alone. It writes
# <out.json>: each path it changed or made, a folder it had to make among
# them, keyed as the oracle keys a restore finding, and the databases it
# found absent. A read-write mount
# rewrites the filesystem's own metadata, so the image is a copy for this
# scan alone, never the one captured. Exits 0 when every control was planted,
# 1 when the image holds no btrfs filesystem it can mount, 2 on a usage error.
set -euo pipefail

if [ "$#" -ne 2 ] || [ ! -f "$1" ]; then
  echo "usage: plant-records.sh <image> <out.json>" >&2
  exit 2
fi
img=$1
out=$2
seed=${ORACLE_RECORD_SEED:-oracle-record-control}

loop=$(losetup --find --show --partscan "$img")
mnt=$(mktemp -d)
cleanup() {
  umount "$mnt" 2>/dev/null || true
  rmdir "$mnt" 2>/dev/null || true
  losetup -d "$loop" 2>/dev/null || true
}
trap cleanup EXIT
udevadm settle 2>/dev/null || true

part=
for candidate in "$loop"p*; do
  [ -b "$candidate" ] || continue
  if [ "$(blkid -o value -s TYPE "$candidate" 2>/dev/null)" = btrfs ]; then
    part=$candidate
    break
  fi
done
if [ -z "$part" ]; then
  echo "plant-records: no btrfs partition in $img" >&2
  exit 1
fi
mount -o rw,noatime,subvolid=5 "$part" "$mnt"

python3 -I - "$mnt" "$seed" "$out" <<'PY'
import json
import os
import sqlite3
import sys
import time

mnt, seed, out = sys.argv[1:4]
now = int(time.time())
planted = []
absent = []


def where(path):
    return os.path.join(mnt, path.lstrip("/"))


def folder(path):
    """Make the folder of ``path`` where it is missing, each folder made a
    planted path of its own."""
    missing = []
    parent = os.path.dirname(path)
    while not os.path.isdir(where(parent)):
        missing.append(parent)
        parent = os.path.dirname(parent)
    for made in reversed(missing):
        os.mkdir(where(made))
        planted.append({"path": made, "change": "new"})


# lastlog2: the table pam_lastlog2 keeps, one row per user.
lastlog2 = "/var/lib/lastlog/lastlog2.db"
folder(lastlog2)
existed = os.path.exists(where(lastlog2))
db = sqlite3.connect(where(lastlog2))
db.execute(
    "CREATE TABLE IF NOT EXISTS Lastlog2(Name TEXT PRIMARY KEY, Time INTEGER "
    "NOT NULL, TTY TEXT, RemoteHost TEXT, Service TEXT)"
)
db.execute(
    "INSERT OR REPLACE INTO Lastlog2 VALUES (?, ?, ?, ?, ?)",
    (seed, now, "pts/9", "", "sshd"),
)
db.commit()
db.close()
planted.append({"path": lastlog2, "change": "changed" if existed else "new"})

# wtmpdb: a login row, where the image keeps a database.
for wtmpdb in ("/var/lib/wtmpdb/wtmp.db", "/var/log/wtmp.db"):
    if not os.path.exists(where(wtmpdb)):
        continue
    db = sqlite3.connect(where(wtmpdb))
    db.execute(
        "INSERT INTO wtmp (Type, User, Login, TTY, RemoteHost, Service) "
        "VALUES (3, ?, ?, ?, ?, ?)",
        (seed, now * 1000000, "pts/9", "", "sshd"),
    )
    db.commit()
    db.close()
    planted.append({"path": wtmpdb, "change": "changed"})
    break
else:
    absent.append("wtmpdb")

# dnf: a file in the package manager's state folder.
dnf = f"/var/lib/dnf/{seed}.json"
folder(dnf)
with open(where(dnf), "w", encoding="utf-8") as handle:
    json.dump({"control": seed, "time": now}, handle)
planted.append({"path": dnf, "change": "new"})

with open(out, "w", encoding="utf-8") as handle:
    json.dump({"planted": planted, "absent": absent}, handle, indent=1)
print(json.dumps({"planted": planted, "absent": absent}))
PY
sync
