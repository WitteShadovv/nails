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

/// rpm's own databases of the links fixtures: Fedora's directory links, and
/// the kernel's modules recorded through them.
const LINKS_DECOY: &[u8] = include_bytes!("fixtures/rpmdb-links-decoy.sqlite");
const LINKS_HIDDEN: &[u8] = include_bytes!("fixtures/rpmdb-links-hidden.sqlite");

/// The kernel's modules of version `version`, recorded below /lib.
fn modules(version: &str) -> String {
    format!("/lib/modules/{version}-200.fc44.x86_64/kernel/drivers/nails/")
}

#[test]
fn the_links_a_package_installed_are_read_with_their_targets() {
    let decoy = parse_database(LINKS_DECOY, None).unwrap();
    let layout = decoy
        .iter()
        .find(|package| package.name == "filesystem")
        .unwrap();
    let links: Vec<(String, &str)> = layout
        .links
        .iter()
        .map(|(index, target)| (layout.path(&layout.files[*index as usize]), &**target))
        .collect();
    assert_eq!(
        links,
        [
            ("/bin", "usr/bin"),
            ("/lib", "usr/lib"),
            ("/lib64", "usr/lib64"),
            ("/sbin", "usr/sbin"),
            ("/var/run", "../run"),
        ]
        .map(|(path, target)| (path.to_string(), target))
    );
    // A link is a file of its package's own; a directory is not.
    assert!(
        layout
            .files
            .iter()
            .filter(|file| file.is_link())
            .all(File::is_own)
    );
    let links = links_of(&decoy);
    assert_eq!(
        links.resolve(&modules("6.17.1")).as_deref(),
        Ok("/usr/lib/modules/6.17.1-200.fc44.x86_64/kernel/drivers/nails")
    );
    assert_eq!(links.resolve("/var/run/lock").as_deref(), Ok("/run/lock"));
    // The modules of hidden sessions' kernel, as rpm recorded them.
    let hidden = parse_database(LINKS_HIDDEN, None).unwrap();
    let kernel = hidden
        .iter()
        .find(|package| package.name == "kernel-modules")
        .unwrap();
    assert_eq!(kernel.version, "6.18.0");
    let paths: Vec<String> = kernel
        .files
        .iter()
        .filter(|file| file.is_own())
        .map(|file| kernel.path(file))
        .collect();
    assert_eq!(paths, [format!("{}nails.ko.xz", modules("6.18.0"))]);
}

/// A package with the symbolic links `links`, each `(path, target)`, and the
/// `flags` and `state` of each.
fn linking(links: &[(&str, &str)], flags: u32, state: u8) -> Package {
    let mut package = Package {
        name: "layout".to_string(),
        arch: Some("noarch".to_string()),
        epoch: None,
        version: "1".to_string(),
        release: "1".to_string(),
        dirs: Vec::new(),
        files: Vec::new(),
        links: Vec::new(),
    };
    for (path, target) in links {
        let (dir, name) = path.split_at(path.rfind('/').unwrap() + 1);
        package.dirs.push(dir.into());
        package
            .links
            .push((package.files.len() as u32, (*target).into()));
        package.files.push(File {
            dir: package.dirs.len() as u32 - 1,
            name: name.into(),
            flags,
            mode: 0o120_777,
            state,
        });
    }
    package
}

/// The links `packages` installed, within a budget of [`KEPT_LIMIT`].
fn links_of<'a>(packages: impl IntoIterator<Item = &'a Package>) -> Links {
    Links::of(packages, &mut Budget::default()).unwrap()
}

#[test]
fn a_path_is_resolved_through_the_links_as_the_kernel_resolves_it() {
    let links = links_of(&[linking(
        &[
            ("/sbin", "usr/sbin"),
            ("/usr/sbin", "bin"),
            ("/opt/app", "/srv/app-1.2"),
            ("/srv/app-1.2/data", "../../var/lib/app"),
        ],
        0,
        NORMAL,
    )]);
    for (path, resolved) in [
        // A relative target from the link's own directory, a chain of two.
        ("/sbin/ip", "/usr/bin/ip"),
        // An absolute target from the root, then a relative one with `..`.
        ("/opt/app/data/state", "/var/lib/app/state"),
        ("/usr/./lib/../share/", "/usr/share"),
        ("/", "/"),
        ("/../etc", "/etc"),
    ] {
        assert_eq!(links.resolve(path).as_deref(), Ok(resolved), "{path}");
    }
    // A relative path is left as it is, and links in a loop lead nowhere.
    assert_eq!(links.resolve("usr/bin").as_deref(), Ok("usr/bin"));
    let looped = links_of(&[linking(&[("/a", "b"), ("/b", "a")], 0, NORMAL)]);
    assert_eq!(looped.resolve("/a/file"), Err(Unresolved::Loop));
    // A ghost and a link rpm did not install count for nothing, and of two
    // packages that record a link at one path the first counts.
    let first = linking(&[("/lib", "usr/lib")], 0, NORMAL);
    let ghost = linking(&[("/lib", "elsewhere")], GHOST, NORMAL);
    let skipped = linking(&[("/lib", "elsewhere")], 0, 2);
    assert_eq!(
        links_of([&ghost, &skipped]).resolve("/lib/x").as_deref(),
        Ok("/lib/x")
    );
    assert_eq!(
        links_of([&first, &ghost]).resolve("/lib/x").as_deref(),
        Ok("/usr/lib/x")
    );
    let second = linking(&[("/lib", "usr/lib32")], 0, NORMAL);
    assert_eq!(
        links_of([&first, &second]).resolve("/lib/x").as_deref(),
        Ok("/usr/lib/x")
    );
}

#[test]
fn link_targets_not_one_for_each_file_are_refused() {
    let header = alpha();
    let linktos = entry_of(&header, tag::FILELINKTOS);
    let error = parse_header(&with(&header, 8 + 16 * linktos + 12, 1)).unwrap_err();
    assert_eq!(error, "tag 1036 has not one value per file");
}

#[test]
fn a_path_longer_than_a_path_can_be_is_refused() {
    let header = |dir: &str, name: &str, target: Option<&str>| {
        let mut entries = vec![
            (tag::NAME, kind::STRING, 1, string_data(&["long"])),
            (tag::VERSION, kind::STRING, 1, string_data(&["1"])),
            (tag::RELEASE, kind::STRING, 1, string_data(&["1"])),
            (tag::DIRNAMES, kind::STRING_ARRAY, 1, string_data(&[dir])),
            (tag::BASENAMES, kind::STRING_ARRAY, 1, string_data(&[name])),
            (tag::DIRINDEXES, kind::INT32, 1, 0u32.to_be_bytes().to_vec()),
        ];
        if let Some(target) = target {
            entries.push((
                tag::FILEMODES,
                kind::INT16,
                1,
                0o120_777u16.to_be_bytes().to_vec(),
            ));
            entries.push((
                tag::FILELINKTOS,
                kind::STRING_ARRAY,
                1,
                string_data(&[target]),
            ));
        }
        parse_header(&build(&entries))
    };
    let dir = |len: usize| format!("/{}/", "d".repeat(len - 2));
    // The longest a path can be, and a byte more.
    assert!(header(&dir(4000), &"n".repeat(95), None).is_ok());
    for (header, what) in [
        (header(&dir(4096), "n", None), "a directory"),
        (header(&dir(4000), &"n".repeat(96), None), "a file's path"),
        (
            header("/", "link", Some(&"t".repeat(4096))),
            "a link's target",
        ),
    ] {
        assert_eq!(
            header.unwrap_err(),
            format!("{what} of 4096 bytes or more, longer than a path can be")
        );
    }
    assert!(header("/", "link", Some(&"t".repeat(4095))).is_ok());
    // A target of a file that is no link is none NAILS keeps.
    let mut entries = vec![(tag::NAME, kind::STRING, 1, string_data(&["plain"]))];
    entries.extend([
        (tag::VERSION, kind::STRING, 1, string_data(&["1"])),
        (tag::RELEASE, kind::STRING, 1, string_data(&["1"])),
        (
            tag::OLDFILENAMES,
            kind::STRING_ARRAY,
            1,
            string_data(&[dir(4097).as_str()]),
        ),
    ]);
    assert_eq!(
        parse_header(&build(&entries)).unwrap_err(),
        "a file's path of 4096 bytes or more, longer than a path can be"
    );
}

/// A package of `links` symbolic links, each to `target`, all in one
/// directory of `dir` bytes.
fn many_links(dir: usize, links: usize, target: &str) -> Package {
    let names: Vec<String> = (0..links).map(|i| format!("{i:x}")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let dir = format!("/{}/", "d".repeat(dir - 2));
    parse_header(&build(&[
        (tag::NAME, kind::STRING, 1, string_data(&["wide"])),
        (tag::VERSION, kind::STRING, 1, string_data(&["1"])),
        (tag::RELEASE, kind::STRING, 1, string_data(&["1"])),
        (
            tag::DIRNAMES,
            kind::STRING_ARRAY,
            1,
            string_data(&[dir.as_str()]),
        ),
        (
            tag::BASENAMES,
            kind::STRING_ARRAY,
            links,
            string_data(&names),
        ),
        (tag::DIRINDEXES, kind::INT8, links, vec![0; links]),
        (
            tag::FILEMODES,
            kind::INT16,
            links,
            0o120_777u16.to_be_bytes().repeat(links),
        ),
        (
            tag::FILELINKTOS,
            kind::STRING_ARRAY,
            links,
            string_data(&vec![target; links]),
        ),
    ]))
    .unwrap()
}

#[test]
fn the_links_keep_each_name_once_within_the_budget() {
    // 50000 links in one directory of 4000 bytes: their paths whole would
    // take 200 MB, the names on their way take a few MB.
    let package = many_links(4000, 50_000, "t");
    let mut budget = Budget::default();
    let links = Links::of([&package], &mut budget).unwrap();
    let taken = KEPT_LIMIT - budget.left();
    assert!((1 << 20..16 << 20).contains(&taken), "{taken}");
    let dir = &package.dirs[0];
    assert_eq!(
        links.resolve(&format!("{dir}1f")).as_deref(),
        Ok(format!("{dir}t").as_str())
    );
    // A budget they do not fit refuses them.
    let error = Links::of([&package], &mut Budget::new(1 << 20)).unwrap_err();
    assert!(error.contains("more than the 1048576 bytes"), "{error}");
}

#[test]
fn a_path_that_grows_too_long_or_loops_through_its_links_cannot_be_resolved() {
    // A path of two thousand names, none a link.
    let deep = format!("/{}", "a/".repeat(2000));
    let none = Links::default();
    assert_eq!(
        none.resolve(&deep).as_deref(),
        Ok(deep.trim_end_matches('/'))
    );
    assert_eq!(
        none.resolve(&format!("{deep}{}", "a".repeat(100))),
        Err(Unresolved::TooLong)
    );
    // A link to itself and two thousand names more, followed again at each
    // turn: it grows past what a path can be long before it loops.
    let target = format!("/x{}", "/a".repeat(2000));
    let looped = links_of(&[linking(&[("/x", target.as_str())], 0, NORMAL)]);
    assert_eq!(looped.resolve("/x/f"), Err(Unresolved::TooLong));
    // A link to a name of 3000 bytes, below which lies one of 2000.
    let long = links_of(&[linking(&[("/l", "b".repeat(3000).as_str())], 0, NORMAL)]);
    assert!(long.resolve(&format!("/l/{}", "c".repeat(1000))).is_ok());
    assert_eq!(
        long.resolve(&format!("/l/{}", "c".repeat(2000))),
        Err(Unresolved::TooLong)
    );
    // Forty links on the way are followed, a forty-first is a loop.
    let chain: Vec<(String, String)> = (0..41)
        .map(|i| (format!("/l{i}"), format!("l{}", i + 1)))
        .collect();
    let chain: Vec<(&str, &str)> = chain
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let chained = links_of(&[linking(&chain[..40], 0, NORMAL)]);
    assert_eq!(chained.resolve("/l0/f").as_deref(), Ok("/l40/f"));
    let chained = links_of(&[linking(&chain, 0, NORMAL)]);
    assert_eq!(chained.resolve("/l0/f"), Err(Unresolved::Loop));
    assert_eq!(
        Unresolved::TooLong.to_string(),
        "the links on its way lead to a path of 4096 bytes or more"
    );
    assert_eq!(
        Unresolved::Loop.to_string(),
        "the links on its way make a loop"
    );
}

#[test]
fn a_path_resolved_holds_no_more_room_than_its_bytes() {
    // Followed through a link of 3000 bytes, the path grows to more than
    // twice what it started as; its callers keep what they are given.
    let links = links_of(&[linking(&[("/l", "b".repeat(3000).as_str())], 0, NORMAL)]);
    let resolved = links.resolve("/l/c/d/e").unwrap();
    assert_eq!(resolved.len(), 3007);
    assert_eq!(resolved.capacity(), resolved.len());
    let plain = links.resolve(&format!("/{}", "a/".repeat(1000))).unwrap();
    assert_eq!(plain.capacity(), plain.len());
}
