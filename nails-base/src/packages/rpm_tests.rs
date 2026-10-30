// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The databases are rpm's own, written by `fixtures/make-rpmdb.sh`: one
//! the decoy and hidden sessions shared, then changed on each side.

use super::*;
use crate::filesystem::MockFilesystem;
use std::time::{Duration, SystemTime};

const DECOY: &[u8] = include_bytes!("fixtures/rpmdb-decoy.sqlite");
const HIDDEN: &[u8] = include_bytes!("fixtures/rpmdb-hidden.sqlite");
const HIDDEN_WAL: &[u8] = include_bytes!("fixtures/rpmdb-hidden.wal");

/// Each package as `name.arch evr`, sorted.
fn names(packages: &[Package]) -> Vec<String> {
    let mut names: Vec<String> = packages
        .iter()
        .map(|package| {
            let arch = package.arch.as_deref().unwrap_or("-");
            format!("{}.{arch} {}", package.name, package.evr())
        })
        .collect();
    names.sort();
    names
}

#[test]
fn the_packages_of_rpms_own_database_are_read() {
    let decoy = parse_database(DECOY, None).unwrap();
    assert_eq!(
        names(&decoy),
        [
            "alpha.noarch 1.0-1",
            "beta.noarch 2.1-1",
            "delta.noarch 1:3.0-1",
            "kernel-core.x86_64 6.17.1-200.fc44",
            "kernel-core.x86_64 6.17.2-200.fc44",
        ]
    );
    let hidden = parse_database(HIDDEN, None).unwrap();
    assert_eq!(
        names(&hidden),
        [
            "alpha.noarch 1.1-1",
            "beta.noarch 2.0-1",
            "epsilon.noarch 0.5-1",
            "gamma.noarch 1.0-1",
            "kernel-core.x86_64 6.17.1-200.fc44",
        ]
    );
}

#[test]
fn a_packages_files_are_read_with_what_makes_them_its_own() {
    let decoy = parse_database(DECOY, None).unwrap();
    let delta = decoy
        .iter()
        .find(|package| package.name == "delta")
        .unwrap();
    assert_eq!(delta.epoch, Some(1));
    let files: Vec<(String, bool)> = delta
        .files
        .iter()
        .map(|file| (delta.path(file), file.is_own()))
        .collect();
    assert_eq!(
        files,
        [
            ("/etc/delta.conf", false),
            ("/usr/bin/delta-3.0", true),
            ("/usr/share/delta", false),
            ("/usr/share/delta/3.0", true),
            ("/var/log/delta.log", false),
        ]
        .map(|(path, own)| (path.to_string(), own))
    );
    // Each directory is kept once, for all of its files.
    assert_eq!(
        delta.dirs,
        [
            "/etc/",
            "/usr/bin/",
            "/usr/share/",
            "/usr/share/delta/",
            "/var/log/"
        ]
        .map(Box::from)
    );
    let flags = |path: &str| {
        let file = delta
            .files
            .iter()
            .find(|file| delta.path(file) == path)
            .unwrap();
        (file.flags, file.mode & S_IFMT == S_IFDIR, file.state)
    };
    assert_eq!(flags("/etc/delta.conf").0 & CONFIG, CONFIG);
    assert_eq!(flags("/var/log/delta.log").0 & GHOST, GHOST);
    assert!(flags("/usr/share/delta").1, "a directory");
    assert_eq!(flags("/usr/bin/delta-3.0"), (0, false, NORMAL));

    // A file another package replaced is no longer the package's own.
    let replaced = File {
        state: 1,
        ..delta.files[1].clone()
    };
    assert!(!replaced.is_own());
}

#[test]
fn the_committed_transactions_of_the_log_are_part_of_the_database() {
    // The log adds the decoy's kernel-core 6.17.2 to hidden sessions' copy.
    let hidden = parse_database(HIDDEN, Some(HIDDEN_WAL)).unwrap();
    let names = names(&hidden);
    assert_eq!(names.len(), 6);
    assert!(
        names.contains(&"kernel-core.x86_64 6.17.2-200.fc44".to_string()),
        "{names:?}"
    );
}

/// The header of alpha 1.0-1 in the decoy's database, as rpm exported it.
fn alpha() -> Vec<u8> {
    let file = &DECOY;
    let database = Database::open(file, None).unwrap();
    let root = database.table_root("Packages").unwrap().unwrap();
    database
        .rows(root)
        .unwrap()
        .into_iter()
        .find_map(|row| match row.values.get(1) {
            Some(Value::Blob(blob)) if parse_header(blob).unwrap().name == "alpha" => {
                Some(blob.clone())
            }
            _ => None,
        })
        .unwrap()
}

/// `header` with the 32-bit big-endian `value` at `at`.
fn with(header: &[u8], at: usize, value: u32) -> Vec<u8> {
    let mut header = header.to_vec();
    header[at..at + 4].copy_from_slice(&value.to_be_bytes());
    header
}

/// The entry index of `tag` in `header`.
fn entry_of(header: &[u8], tag: u32) -> usize {
    let il = u32::from_be_bytes(header[..4].try_into().unwrap()) as usize;
    (0..il)
        .find(|i| header[8 + 16 * i..12 + 16 * i] == tag.to_be_bytes())
        .unwrap()
}

#[test]
fn a_header_rpm_cannot_have_written_is_refused() {
    let header = alpha();
    assert_eq!(parse_header(&header).unwrap().name, "alpha");

    let size = "a header of a size rpm does not write";
    let short = "a header shorter than its sizes";
    let name = entry_of(&header, tag::NAME);
    let dirindexes = entry_of(&header, tag::DIRINDEXES);
    let basenames = entry_of(&header, tag::BASENAMES);
    let modes = entry_of(&header, tag::FILEMODES);
    let field = |entry: usize, n: usize| 8 + 16 * entry + 4 * n;
    let refused = [
        (header[..6].to_vec(), short),
        (with(&header, 0, 0), size),
        (with(&header, 0, 0x1_0000), size),
        (with(&header, 4, 0x1000_0000), size),
        (header[..header.len() - 1].to_vec(), short),
        (
            with(&header, field(name, 2), u32::MAX),
            "a header entry past its data",
        ),
        (
            with(&header, field(name, 1), kind::INT32),
            "tag 1000 is no string",
        ),
        (
            with(&header, field(dirindexes, 3), 1),
            "as many directory indexes as file names",
        ),
        (
            with(&header, field(dirindexes, 3), u32::MAX / 4),
            "tag 1116 runs past its data",
        ),
        (
            with(&header, field(basenames, 3), u32::MAX),
            // Read on through the data until a string does not hold.
            "a string of tag 1117 ",
        ),
        (
            with(&header, field(modes, 3), 1),
            "tag 1030 has not one value per file",
        ),
        // The name tag renumbered: a header without a name.
        (
            with(&header, field(name, 0), 999),
            "a header without its name",
        ),
    ];
    for (header, why) in &refused {
        let error = parse_header(header).unwrap_err();
        assert!(error.starts_with(why), "{error}, not {why}");
    }

    // An entry of a tag NAILS does not read may start where the data ends.
    let dl = u32::from_be_bytes(header[4..8].try_into().unwrap());
    let summary = entry_of(&header, 1004);
    assert_eq!(
        parse_header(&with(&header, field(summary, 2), dl))
            .unwrap()
            .name,
        "alpha"
    );
}

#[test]
fn a_directory_index_past_the_directories_is_refused() {
    let header = alpha();
    let dirindexes = entry_of(&header, tag::DIRINDEXES);
    let il = u32::from_be_bytes(header[..4].try_into().unwrap()) as usize;
    let offset = u32::from_be_bytes(
        header[8 + 16 * dirindexes + 8..8 + 16 * dirindexes + 12]
            .try_into()
            .unwrap(),
    ) as usize;
    let data = 8 + 16 * il;
    let broken = with(&header, data + offset, 1000);
    let error = parse_header(&broken).unwrap_err();
    assert!(error.contains("directory index"), "{error}");
}

#[test]
fn a_header_without_basenames_reads_its_old_file_names() {
    let header = alpha();
    let basenames = entry_of(&header, tag::BASENAMES);
    // BASENAMES renumbered to OLDFILENAMES: its strings are then the paths.
    let old = with(&header, 8 + 16 * basenames, tag::OLDFILENAMES);
    let package = parse_header(&old).unwrap();
    assert!(
        package.files.iter().any(|file| package.path(file) == "1.0"),
        "{:?}",
        package.files
    );
}

#[test]
fn a_public_key_is_known_as_one() {
    let mut package = parse_header(&alpha()).unwrap();
    assert!(!package.is_key());
    package.name = "gpg-pubkey".into();
    assert!(!package.is_key(), "a key has no architecture");
    package.arch = None;
    assert!(package.is_key());
}

const DB: &str = "/sysimage/rpm/rpmdb.sqlite";
const DB_WAL: &str = "/sysimage/rpm/rpmdb.sqlite-wal";

/// A filesystem with `database` and its log `wal`, each written at a fixed
/// time.
fn staged(database: &[u8], wal: Option<&[u8]>) -> MockFilesystem {
    let fs = MockFilesystem::new();
    let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    fs.mock_set_file_bytes(DB, database);
    fs.mock_set_modified_time(Path::new(DB), time.into());
    if let Some(wal) = wal {
        fs.mock_set_file_bytes(DB_WAL, wal);
        fs.mock_set_modified_time(Path::new(DB_WAL), time.into());
    }
    fs
}

#[test]
fn the_files_beside_a_database_are_counted_when_they_exist() {
    let fs = staged(HIDDEN, Some(HIDDEN_WAL));
    let files = Files::beside(&fs, Path::new(DB)).unwrap();
    assert_eq!(
        files,
        Files {
            database: PathBuf::from(DB),
            wal: Some(PathBuf::from(DB_WAL)),
            journal: None,
        }
    );
    let mut budget = Budget::default();
    let packages = read_packages(&fs, &files, &mut budget).unwrap();
    assert_eq!(packages.len(), 6);
    // What the packages keep is taken from the budget, a few KiB here.
    let taken = KEPT_LIMIT - budget.left();
    assert!((1000..16_000).contains(&taken), "{taken}");
    assert_eq!(packages, parse_database(HIDDEN, Some(HIDDEN_WAL)).unwrap());
}

#[test]
fn reading_through_the_filesystem_takes_the_file_in_pieces() {
    // A file over several pieces, read through a source that keeps few.
    let big: Vec<u8> = (0..(CHUNK * 3 + 5)).map(|i| (i % 253) as u8).collect();
    let fs = staged(&big, None);
    let source = Source {
        fs: &fs,
        path: Path::new(DB),
        len: big.len() as u64,
        chunks: RefCell::new(BTreeMap::new()),
    };
    let at = CHUNK as u64 - 3;
    assert_eq!(
        source.read(at, CHUNK + 6).unwrap(),
        &big[at as usize..][..CHUNK + 6]
    );
    assert_eq!(source.read(0, 4).unwrap(), &big[..4]);
    // The pieces read so far are kept: the first read took three.
    assert_eq!(source.chunks.borrow().len(), 3);
    // The last piece is as long as what is left of the file.
    let tail = big.len() as u64 - 7;
    assert_eq!(source.read(tail, 7).unwrap(), &big[tail as usize..]);
    assert_eq!(source.read(tail, 0).unwrap(), b"");
    assert!(source.read(big.len() as u64 - 1, 2).is_err());
    // A file shorter than its size said.
    let short = Source {
        fs: &fs,
        path: Path::new(DB),
        len: big.len() as u64 + 10,
        chunks: RefCell::new(BTreeMap::new()),
    };
    let error = short.read(CHUNK as u64 * 3, 10).unwrap_err();
    assert!(error.to_string().contains("shorter than it was"), "{error}");
    // Many pieces read one after the other.
    let many: Vec<u8> = vec![7; CHUNK * (CHUNKS + 2)];
    let fs = staged(&many, None);
    let source = Source {
        fs: &fs,
        path: Path::new(DB),
        len: many.len() as u64,
        chunks: RefCell::new(BTreeMap::new()),
    };
    for index in 0..(CHUNKS + 2) as u64 {
        assert_eq!(source.read(index * CHUNK as u64, 1).unwrap(), [7]);
    }
    assert!(source.chunks.borrow().len() <= CHUNKS);
}

#[test]
fn a_database_that_cannot_be_trusted_is_an_error() {
    // An empty rollback journal is none.
    let fs = staged(HIDDEN, None);
    fs.mock_set_file_bytes("/sysimage/rpm/rpmdb.sqlite-journal", b"");
    fs.mock_set_modified_time(
        Path::new("/sysimage/rpm/rpmdb.sqlite-journal"),
        (SystemTime::UNIX_EPOCH + Duration::from_secs(1)).into(),
    );
    let files = Files::beside(&fs, Path::new(DB)).unwrap();
    assert!(files.journal.is_some());
    assert_eq!(
        read_packages(&fs, &files, &mut Budget::default())
            .unwrap()
            .len(),
        5
    );

    // A rollback journal left by a transaction stopped half way.
    let fs = staged(HIDDEN, None);
    fs.mock_set_file_bytes("/sysimage/rpm/rpmdb.sqlite-journal", b"journal");
    fs.mock_set_modified_time(
        Path::new("/sysimage/rpm/rpmdb.sqlite-journal"),
        (SystemTime::UNIX_EPOCH + Duration::from_secs(1)).into(),
    );
    let files = Files::beside(&fs, Path::new(DB)).unwrap();
    let error = read_packages(&fs, &files, &mut Budget::default()).unwrap_err();
    assert!(error.to_string().contains("rollback journal"), "{error}");

    // A file that is no database.
    let fs = staged(b"not a database at all", None);
    let files = Files::beside(&fs, Path::new(DB)).unwrap();
    let error = read_packages(&fs, &files, &mut Budget::default()).unwrap_err();
    assert!(
        error.to_string().contains("not a SQLite database"),
        "{error}"
    );

    // A database without the table of packages.
    let tree = include_bytes!("fixtures/tree.sqlite");
    let fs = staged(tree, None);
    let files = Files::beside(&fs, Path::new(DB)).unwrap();
    let error = read_packages(&fs, &files, &mut Budget::default()).unwrap_err();
    assert!(error.to_string().contains("no table Packages"), "{error}");

    // A database that is gone.
    let fs = MockFilesystem::new();
    let files = Files {
        database: PathBuf::from(DB),
        wal: None,
        journal: None,
    };
    let error = read_packages(&fs, &files, &mut Budget::default()).unwrap_err();
    assert!(error.to_string().contains("no such file"), "{error}");
}

#[test]
fn a_database_written_while_it_is_read_is_an_error() {
    // The mock gives a file without a time of its own the time of each call,
    // so every look at it says it was written since the last.
    let fs = MockFilesystem::new();
    fs.mock_set_file_bytes(DB, HIDDEN);
    let files = Files::beside(&fs, Path::new(DB)).unwrap();
    let error = read_packages(&fs, &files, &mut Budget::default()).unwrap_err();
    assert!(error.to_string().contains("while it was read"), "{error}");
}

#[test]
fn a_stamp_that_cannot_be_taken_is_an_error_not_a_missing_file() {
    use crate::filesystem::RealFilesystem;
    use std::os::unix::fs::PermissionsExt;

    if rustix::process::geteuid().is_root() {
        // Root looks into any directory.
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let closed = dir.path().join("rpm");
    std::fs::create_dir(&closed).unwrap();
    std::fs::write(closed.join("rpmdb.sqlite-wal"), b"").unwrap();
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
    let stamped = stamp(&RealFilesystem, &closed.join("rpmdb.sqlite-wal"));
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(stamped.is_err(), "{stamped:?}");
    assert_eq!(
        stamp(&RealFilesystem, &dir.path().join("missing")).unwrap(),
        None
    );
}

/// A header of `entries`, each `(tag, type, count, data)`, laid out as
/// `headerExport()` lays one out: the data of each entry after the one before.
fn build(entries: &[(u32, u32, usize, Vec<u8>)]) -> Vec<u8> {
    let mut index = Vec::new();
    let mut data: Vec<u8> = Vec::new();
    for (tag, type_, count, bytes) in entries {
        for word in [*tag, *type_, data.len() as u32, *count as u32] {
            index.extend(word.to_be_bytes());
        }
        data.extend(bytes);
    }
    let mut header = Vec::new();
    header.extend((entries.len() as u32).to_be_bytes());
    header.extend((data.len() as u32).to_be_bytes());
    header.extend(index);
    header.extend(data);
    header
}

/// `strings` as the data of a string array.
fn string_data(strings: &[&str]) -> Vec<u8> {
    strings
        .iter()
        .flat_map(|text| text.bytes().chain([0]))
        .collect()
}

/// A header of a package whose `files` empty names all lie in one directory
/// of `dir` bytes, each of its files taking two bytes of the header.
fn one_long_directory(dir: usize, files: usize) -> Vec<u8> {
    let dir = format!("/{}/", "d".repeat(dir - 2));
    build(&[
        (tag::NAME, kind::STRING, 1, string_data(&["wide"])),
        (tag::VERSION, kind::STRING, 1, string_data(&["1"])),
        (tag::RELEASE, kind::STRING, 1, string_data(&["1"])),
        (
            tag::DIRNAMES,
            kind::STRING_ARRAY,
            1,
            string_data(&[dir.as_str()]),
        ),
        (tag::BASENAMES, kind::STRING_ARRAY, files, vec![0; files]),
        (tag::DIRINDEXES, kind::INT8, files, vec![0; files]),
    ])
}

#[test]
fn a_directory_is_kept_once_for_all_of_its_files() {
    // Each path joined whole would take 4000 bytes: 200 MB for a header of
    // 104 KB.
    let header = one_long_directory(4_000, 50_000);
    assert!(header.len() < 110_000, "{}", header.len());
    let package = parse_header(&header).unwrap();
    assert_eq!(package.dirs.len(), 1);
    assert_eq!(package.files.len(), 50_000);
    assert_eq!(package.path(&package.files[49_999]).len(), 4_000);
    assert!(package.files.iter().all(File::is_own));
}

#[test]
fn packages_that_need_more_than_the_budget_are_refused() {
    let header = one_long_directory(100, 50_000);
    // 50000 files take 1.6 MB, more than a budget of 1 MiB.
    let mut budget = Budget::new(1 << 20);
    let error = header::parse(&header, &mut budget).unwrap_err();
    assert_eq!(
        error,
        "packages that need more than the 1048576 bytes of memory NAILS keeps for rpm's databases"
    );
    let mut budget = Budget::new(4 << 20);
    assert!(header::parse(&header, &mut budget).is_ok());
    assert!(budget.left() < 3 << 20, "{}", budget.left());
    // A database whose packages need more is refused whole.
    let database = Database::open(&DECOY, None).unwrap();
    let error = packages(&database, &mut Budget::new(1000)).unwrap_err();
    assert!(error.contains("more than the 1000 bytes"), "{error}");
}

#[test]
fn a_database_or_a_log_larger_than_rpm_keeps_is_refused_unread() {
    for path in [DB, DB_WAL] {
        let fs = staged(HIDDEN, Some(HIDDEN_WAL));
        fs.mock_set_file_size(path, FILE_LIMIT + 1);
        let files = Files::beside(&fs, Path::new(DB)).unwrap();
        let error = read_packages(&fs, &files, &mut Budget::default()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("more than rpm keeps in its database or its log"),
            "{path}: {error}"
        );
    }
}
