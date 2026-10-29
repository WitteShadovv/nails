# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write the SQLite fixtures of nails-base/src/packages/sqlite_tests.rs and
the write-ahead log of rpm_tests.rs with SQLite itself:
``python3 make-sqlite.py <fixtures dir>``, after make-rpmdb.sh.

- ``tree.sqlite``: 512-byte pages and a table ``t (id INTEGER PRIMARY KEY,
  data BLOB)`` of 120 rows, row ``i`` holding ``blob(i)``, so the table has
  interior pages and its larger rows go on in overflow pages;
- ``rpmdb-hidden.wal``: a write-ahead log of ``rpmdb-hidden.sqlite``, named
  so that SQLite never pairs the two on its own, with two
  transactions, not checkpointed, so the database file stays as it was: the
  first adds the header of row 6 of the decoy's database (``kernel-core``
  6.17.2) as row 7, the second deletes row 1 (``kernel-core`` 6.17.1), and a byte of the last frame of the
  second is flipped afterwards, so its checksum fails and only the first
  counts.
"""

import os
import shutil
import sqlite3
import sys
import tempfile


def blob(i):
    size = (i * 137) % 1500 + 1
    return bytes((i * 7 + j) % 251 for j in range(size))


def tree(out):
    path = os.path.join(out, "tree.sqlite")
    if os.path.exists(path):
        os.remove(path)
    db = sqlite3.connect(path)
    db.execute("PRAGMA page_size = 512")
    db.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, data BLOB)")
    db.executemany("INSERT INTO t VALUES (?, ?)", [(i, blob(i)) for i in range(1, 121)])
    db.commit()
    db.execute("VACUUM")
    db.close()


def wal(out):
    with tempfile.TemporaryDirectory() as work:
        path = os.path.join(work, "rpmdb.sqlite")
        shutil.copy(os.path.join(out, "rpmdb-hidden.sqlite"), path)
        decoy = sqlite3.connect(
            "file:" + os.path.join(out, "rpmdb-decoy.sqlite") + "?immutable=1", uri=True
        )
        (header,) = decoy.execute("SELECT blob FROM Packages WHERE hnum = 6").fetchone()
        decoy.close()
        db = sqlite3.connect(path, isolation_level=None)
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("PRAGMA wal_autocheckpoint = 0")
        db.execute("BEGIN")
        db.execute("INSERT INTO Packages VALUES (7, ?)", (header,))
        db.execute("COMMIT")
        db.execute("BEGIN")
        db.execute("DELETE FROM Packages WHERE hnum = 1")
        db.execute("COMMIT")
        # Read while the connection is open: closing it checkpoints the log.
        same = open(path, "rb").read() == open(os.path.join(out, "rpmdb-hidden.sqlite"), "rb").read()
        assert same, "the transactions reached the database file"
        log = bytearray(open(path + "-wal", "rb").read())
        db.close()
    log[-1] ^= 0xFF
    open(os.path.join(out, "rpmdb-hidden.wal"), "wb").write(log)


if __name__ == "__main__":
    tree(sys.argv[1])
    wal(sys.argv[1])
