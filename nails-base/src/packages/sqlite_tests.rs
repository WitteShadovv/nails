// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The fixtures are SQLite's own files, written by `fixtures/make-sqlite.py`
//! and `fixtures/make-rpmdb.sh`.

use super::*;

/// 512-byte pages and a table `t (id INTEGER PRIMARY KEY, data BLOB)` of 120
/// rows, row `i` holding [`blob`]`(i)`.
const TREE: &[u8] = include_bytes!("fixtures/tree.sqlite");

/// rpm's database of hidden sessions in the fixtures, and a log of it with a
/// committed transaction that adds row 7, and one that deletes row 1 whose
/// last frame does not hold its checksum.
const RPMDB: &[u8] = include_bytes!("fixtures/rpmdb-hidden.sqlite");
const RPMDB_WAL: &[u8] = include_bytes!("fixtures/rpmdb-hidden.wal");

/// What `make-sqlite.py` writes into row `i` of the tree.
fn blob(i: usize) -> Vec<u8> {
    let size = (i * 137) % 1500 + 1;
    (0..size).map(|j| ((i * 7 + j) % 251) as u8).collect()
}

fn rows(file: &[u8], wal: Option<&[u8]>, table: &str) -> Result<Vec<Row>> {
    let wal = wal.map(<[u8]>::to_vec);
    let database = Database::open(&file, wal.as_ref().map(|wal| wal as &dyn Pages))?;
    let root = database.table_root(table)?.expect("the table exists");
    database.rows(root)
}

fn rowids(rows: &[Row]) -> Vec<i64> {
    rows.iter().map(|row| row.rowid).collect()
}

#[test]
fn every_row_of_a_tree_with_interior_and_overflow_pages_is_read() {
    let database = Database::open(&TREE, None).unwrap();
    assert_eq!(database.page_size, 512);
    let root = database.table_root("t").unwrap().unwrap();
    // The root of 120 rows on 512-byte pages is an interior page.
    assert_eq!(database.page(root).unwrap()[0], 0x05);
    let rows = database.rows(root).unwrap();
    assert_eq!(rows.len(), 120);
    for (i, row) in rows.iter().enumerate() {
        let id = i + 1;
        assert_eq!(row.rowid, id as i64);
        assert_eq!(
            row.values,
            vec![Value::Null, Value::Blob(blob(id))],
            "row {id}"
        );
    }
    assert_eq!(database.table_root("missing").unwrap(), None);
}

#[test]
fn the_committed_transactions_of_the_log_count_and_a_broken_frame_ends_it() {
    let alone = rows(RPMDB, None, "Packages").unwrap();
    assert_eq!(rowids(&alone), [1, 2, 3, 5, 6]);
    // The first transaction adds row 7; the second, whose last frame fails
    // its checksum, never committed.
    let logged = rows(RPMDB, Some(RPMDB_WAL), "Packages").unwrap();
    assert_eq!(rowids(&logged), [1, 2, 3, 5, 6, 7]);

    // With that frame whole again, the second transaction deletes row 1.
    let mut whole = RPMDB_WAL.to_vec();
    *whole.last_mut().unwrap() ^= 0xff;
    let logged = rows(RPMDB, Some(&whole), "Packages").unwrap();
    assert_eq!(rowids(&logged), [2, 3, 5, 6, 7]);

    // A log cut in the middle of the second transaction holds the first.
    let cut = &whole[..whole.len() - 100];
    assert_eq!(
        rowids(&rows(RPMDB, Some(cut), "Packages").unwrap()),
        [1, 2, 3, 5, 6, 7]
    );
}

#[test]
fn a_log_whose_header_does_not_hold_has_no_frame() {
    let empty: &[u8] = &[];
    for log in [empty, &RPMDB_WAL[..20]] {
        assert_eq!(
            rowids(&rows(RPMDB, Some(log), "Packages").unwrap()),
            [1, 2, 3, 5, 6]
        );
    }
    // A header checksum that fails, salts that differ from the header's, a
    // version or a page size SQLite does not write: each leaves the frames
    // out.
    for (at, what) in [
        (24, "checksum"),
        (20, "salt"),
        (4, "version"),
        (8, "page size"),
    ] {
        let mut log = RPMDB_WAL.to_vec();
        log[at + 3] ^= 0x01;
        if at == 20 {
            // The header's own checksum then covers the new salt, so only the
            // frames' salts differ.
            let sum = checksum((0, 0), &log[..24], log[3] & 1 == 1);
            log[24..28].copy_from_slice(&sum.0.to_be_bytes());
            log[28..32].copy_from_slice(&sum.1.to_be_bytes());
        }
        assert_eq!(
            rowids(&rows(RPMDB, Some(&log), "Packages").unwrap()),
            [1, 2, 3, 5, 6],
            "{what}"
        );
    }
}

#[test]
fn a_big_endian_checksum_sums_words_read_big_endian() {
    let data = [0, 0, 0, 1, 0, 0, 0, 2];
    assert_eq!(checksum((0, 0), &data, true), (1, 3));
    assert_eq!(checksum((0, 0), &data, false), (1 << 24, 3 << 24));
    assert_eq!(checksum((1, 1), &data, true), (3, 6));
}

#[test]
fn a_file_that_is_not_such_a_database_is_refused() {
    let refused = |file: &[u8]| Database::open(&file, None).unwrap_err();
    assert!(matches!(refused(b"not a database"), Error::Malformed(_)));
    assert_eq!(refused(&[]), Error::Malformed("an empty file".into()));
    let mut text = TREE[..100].to_vec();
    text[0] = b's';
    assert_eq!(refused(&text), Error::Malformed("no SQLite header".into()));

    let mut utf16 = TREE.to_vec();
    utf16[59] = 2;
    assert_eq!(
        refused(&utf16),
        Error::Malformed("text that is not UTF-8".into())
    );
    let mut size = TREE.to_vec();
    size[16..18].copy_from_slice(&1000u16.to_be_bytes());
    assert!(matches!(refused(&size), Error::Malformed(_)));
    let mut reserved = TREE.to_vec();
    reserved[20] = 100;
    assert_eq!(
        refused(&reserved),
        Error::Malformed("pages reserve too many bytes".into())
    );
}

#[test]
fn a_page_reached_twice_or_outside_the_file_is_refused() {
    let database = Database::open(&TREE, None).unwrap();
    let root = database.table_root("t").unwrap().unwrap() as usize;
    let at = (root - 1) * 512;

    // The root's rightmost child is the root again: a loop.
    let mut looped = TREE.to_vec();
    looped[at + 8..at + 12].copy_from_slice(&(root as u32).to_be_bytes());
    let database = Database::open(&looped, None).unwrap();
    let error = database.rows(root as u32).unwrap_err();
    assert!(error.to_string().contains("is reached twice"), "{error}");

    // A child past the end of the file.
    let mut past = TREE.to_vec();
    past[at + 8..at + 12].copy_from_slice(&100_000u32.to_be_bytes());
    let database = Database::open(&past, None).unwrap();
    let error = database.rows(root as u32).unwrap_err();
    assert!(error.to_string().contains("lies outside"), "{error}");

    // A page that is no table page.
    let mut kind = TREE.to_vec();
    kind[at] = 0x02;
    let database = Database::open(&kind, None).unwrap();
    let error = database.rows(root as u32).unwrap_err();
    assert!(error.to_string().contains("is no table page"), "{error}");

    // A file cut short of a page the tree needs.
    let cut = &TREE[..TREE.len() - 512 * 3 - 100];
    let database = Database::open(&cut, None).unwrap();
    assert!(database.rows(root as u32).is_err());
}

#[test]
fn a_varint_takes_seven_bits_a_byte_and_all_eight_of_the_ninth() {
    assert_eq!(varint(&[0x05], 0).unwrap(), (5, 1));
    assert_eq!(varint(&[0x81, 0x00], 0).unwrap(), (128, 2));
    assert_eq!(varint(&[0xff; 9], 0).unwrap(), (u64::MAX, 9));
    assert!(varint(&[0x81], 0).is_err());
    assert!(varint(&[], 3).is_err());
}

#[test]
fn a_record_reads_every_serial_type() {
    // Header: its size, then NULL, i8, i16, i24, i32, i48, i64, f64, 0, 1, a
    // two-byte blob and a two-byte text.
    let mut record = vec![13, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17];
    record.extend([0xff]);
    record.extend([0x01, 0x00]);
    record.extend([0x80, 0x00, 0x00]);
    record.extend(7i32.to_be_bytes());
    record.extend([0, 0, 0, 0, 1, 0]);
    record.extend((-2i64).to_be_bytes());
    record.extend(1.5f64.to_bits().to_be_bytes());
    record.extend([0xab, 0xcd]);
    record.extend(*b"hi");
    assert_eq!(
        super::record(&record).unwrap(),
        vec![
            Value::Null,
            Value::Integer(-1),
            Value::Integer(256),
            Value::Integer(-(1 << 23)),
            Value::Integer(7),
            Value::Integer(256),
            Value::Integer(-2),
            Value::Real(1.5),
            Value::Integer(0),
            Value::Integer(1),
            Value::Blob(vec![0xab, 0xcd]),
            Value::Text("hi".into()),
        ]
    );
    for broken in [
        &[2, 10][..],
        &[2, 6, 0][..],
        &[9, 1][..],
        &[2, 15, 0xff][..],
    ] {
        assert!(super::record(broken).is_err(), "{broken:?}");
    }
}

#[test]
fn a_read_past_the_end_of_bytes_fails() {
    let bytes: &[u8] = &[1, 2, 3];
    assert_eq!(Pages::read(&bytes, 1, 2).unwrap(), [2, 3]);
    assert!(Pages::read(&bytes, 2, 2).is_err());
    assert!(Pages::read(&bytes, u64::MAX, 1).is_err());
    let owned = bytes.to_vec();
    assert_eq!(Pages::len(&owned), 3);
    assert!(!Pages::is_empty(&owned));
    assert_eq!(Pages::read(&owned, 0, 3).unwrap(), bytes);
    assert_eq!(
        Error::Read("gone".into()).to_string(),
        "gone",
        "a read error says why"
    );
}

#[test]
fn two_bytes_are_read_big_endian_where_the_bytes_hold_them() {
    assert_eq!(be16(&[1, 2], 0).unwrap(), 0x0102);
    assert_eq!(be16(&[0, 1, 2], 1).unwrap(), 0x0102);
    assert!(be16(&[1], 0).is_err());
    assert_eq!(be32(&[0, 0, 1, 2], 0).unwrap(), 0x0102);
    assert!(be32(&[0, 0, 1], 0).is_err());
}

#[test]
fn a_database_shows_its_page_size_and_size() {
    let database = Database::open(&TREE, None).unwrap();
    let shown = format!("{database:?}");
    assert!(shown.starts_with("Database {"), "{shown}");
    assert!(shown.contains("page_size: 512"), "{shown}");
    assert!(
        shown.contains(&format!("pages: {}", TREE.len() / 512)),
        "{shown}"
    );
}

/// A frame of a log a test writes: its page number, the database's size
/// after it when it ends a transaction (0 when not), its salts and the page.
struct Frame {
    number: u32,
    commit: u32,
    salts: (u32, u32),
    page: Vec<u8>,
}

/// The log SQLite would write with `magic`, `version`, `page_size` and
/// `salts` in its header and `frames` after it, every checksum carried on as
/// SQLite carries it.
fn log(magic: u32, version: u32, page_size: u32, salts: (u32, u32), frames: &[Frame]) -> Vec<u8> {
    let big = magic & 1 == 1;
    let mut log = Vec::new();
    for word in [magic, version, page_size, 0, salts.0, salts.1] {
        log.extend(word.to_be_bytes());
    }
    let mut sum = checksum((0, 0), &log, big);
    log.extend(sum.0.to_be_bytes());
    log.extend(sum.1.to_be_bytes());
    for frame in frames {
        let mut header = Vec::new();
        header.extend(frame.number.to_be_bytes());
        header.extend(frame.commit.to_be_bytes());
        sum = checksum(sum, &header, big);
        sum = checksum(sum, &frame.page, big);
        for word in [frame.salts.0, frame.salts.1, sum.0, sum.1] {
            header.extend(word.to_be_bytes());
        }
        log.extend(header);
        log.extend(&frame.page);
    }
    log
}

const LE: u32 = 0x377f_0682;
const BE: u32 = 0x377f_0683;
const VERSION: u32 = 3_007_000;
const SALTS: (u32, u32) = (7, 9);

/// A frame that rewrites the tree's page 1 as it is and ends a transaction
/// that leaves the database one page long: where the log counts, the table's
/// pages lie outside the database.
fn first_page(salts: (u32, u32), number: u32) -> Frame {
    Frame {
        number,
        commit: 1,
        salts,
        page: TREE[..512].to_vec(),
    }
}

/// The rows of `t` read with `log`: an error where the log counts.
fn tree_with(log: &[u8]) -> Result<Vec<Row>> {
    rows(TREE, Some(log), "t")
}

#[test]
fn a_log_counts_only_with_sqlites_magic_version_salts_and_page_numbers() {
    let counts = |log: &[u8]| tree_with(log).is_err();
    assert!(counts(&log(
        LE,
        VERSION,
        512,
        SALTS,
        &[first_page(SALTS, 1)]
    )));
    // Checksums of big-endian words where the magic says so.
    assert!(counts(&log(
        BE,
        VERSION,
        512,
        SALTS,
        &[first_page(SALTS, 1)]
    )));

    assert!(!counts(&log(
        0x377f_0684,
        VERSION,
        512,
        SALTS,
        &[first_page(SALTS, 1)]
    )));
    assert!(!counts(&log(
        LE,
        VERSION + 1,
        512,
        SALTS,
        &[first_page(SALTS, 1)]
    )));
    // A frame with other salts than the header's, or no page number, ends
    // the log.
    assert!(!counts(&log(
        LE,
        VERSION,
        512,
        SALTS,
        &[first_page((7, 8), 1)]
    )));
    assert!(!counts(&log(
        LE,
        VERSION,
        512,
        SALTS,
        &[first_page(SALTS, 0)]
    )));
    // A frame that ends no transaction does not count.
    let pending = Frame {
        commit: 0,
        ..first_page(SALTS, 1)
    };
    assert!(!counts(&log(LE, VERSION, 512, SALTS, &[pending])));
}

#[test]
fn a_log_of_another_page_size_counts_only_without_a_frame() {
    let page = Frame {
        page: vec![0; 1024],
        ..first_page(SALTS, 1)
    };
    let error = tree_with(&log(LE, VERSION, 1024, SALTS, &[page])).unwrap_err();
    assert_eq!(
        error,
        Error::Malformed("the write-ahead log has another page size".into())
    );
    // A header alone of another page size leaves the database as it is.
    assert_eq!(
        tree_with(&log(LE, VERSION, 1024, SALTS, &[]))
            .unwrap()
            .len(),
        120
    );
}

#[test]
fn a_log_alone_holds_the_database_when_it_holds_page_1() {
    let empty: &[u8] = &[];
    let open = |log: &[u8]| Database::open(&empty, Some(&log as &dyn Pages)).map(|_| ());
    assert_eq!(
        open(&log(LE, VERSION, 512, SALTS, &[first_page(SALTS, 1)])),
        Ok(())
    );
    let zeros = Frame {
        page: vec![0; 512],
        ..first_page(SALTS, 1)
    };
    assert_eq!(
        open(&log(LE, VERSION, 512, SALTS, &[zeros])),
        Err(Error::Malformed("no SQLite header".into()))
    );
    // A header without a frame holds no page.
    assert_eq!(
        open(&log(LE, VERSION, 512, SALTS, &[])),
        Err(Error::Malformed("page 1 lies outside the database".into()))
    );
}

#[test]
fn a_record_longer_than_its_values_is_refused() {
    assert_eq!(super::record(&[2, 1, 7]).unwrap(), vec![Value::Integer(7)]);
    assert_eq!(
        super::record(&[2, 1, 7, 0]),
        Err(Error::Malformed("a record longer than its values".into()))
    );
}
