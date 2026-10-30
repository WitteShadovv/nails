// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `package-drift` on rpm's database, with the databases rpm wrote for
//! `nails-base/src/packages/fixtures/make-rpmdb.sh`: one the decoy and
//! hidden sessions shared, then changed on each side.

use super::*;
use crate::filesystem::{MockFilesystem, PathKind};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};

const DECOY: &[u8] = include_bytes!("../../../nails-base/src/packages/fixtures/rpmdb-decoy.sqlite");
const HIDDEN: &[u8] =
    include_bytes!("../../../nails-base/src/packages/fixtures/rpmdb-hidden.sqlite");
/// A log of [`HIDDEN`] that adds the decoy's kernel-core 6.17.2.
const HIDDEN_WAL: &[u8] =
    include_bytes!("../../../nails-base/src/packages/fixtures/rpmdb-hidden.wal");

const ROOT: &str = "/decoy";
const HIDDEN_ROOT: &str = "/mnt/data";
const UPPER: &str = "/mnt/data/root/upper";
const DB: &str = "usr/lib/sysimage/rpm/rpmdb.sqlite";

/// What the hidden session changed in the fixtures: alpha updated from 1.0
/// to 1.1, epsilon installed.
const OWN: &[&str] = &[
    "usr/bin/alpha-1.1",
    "usr/share/alpha/1.1",
    "usr/bin/epsilon-0.5",
    "usr/share/epsilon/0.5",
];
const OWN_REMOVED: &[&str] = &["usr/bin/alpha-1.0", "usr/share/alpha/1.0"];

fn check() -> PackageDriftCheck {
    PackageDriftCheck::new(PathBuf::from(ROOT), PathBuf::from(HIDDEN_ROOT)).as_privileged(true)
}

fn run(check: &PackageDriftCheck, fs: &MockFilesystem) -> CheckResult {
    PreFlightCheck::<MockFilesystem>::run(check, fs).unwrap()
}

/// `bytes` at `path`, written at a fixed time.
fn file(fs: &MockFilesystem, path: &str, bytes: &[u8]) {
    fs.mock_set_file_bytes(path, bytes);
    let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    fs.mock_set_modified_time(Path::new(path), time.into());
}

/// The upper's tree: `files` (below the upper) and the `whiteouts`, with
/// each directory on their way listing what it holds.
fn upper(fs: &MockFilesystem, files: &[&str], whiteouts: &[&str]) {
    let mut listings: BTreeMap<PathBuf, BTreeSet<PathBuf>> = BTreeMap::new();
    for (rel, whiteout) in files
        .iter()
        .map(|rel| (rel, false))
        .chain(whiteouts.iter().map(|rel| (rel, true)))
    {
        let path = Path::new(UPPER).join(rel);
        if whiteout {
            fs.mock_set_whiteout(&path.display().to_string());
        } else if !fs.path_exists(&path).unwrap() {
            fs.mock_add_file(&path.display().to_string(), "");
        }
        let mut child = path.clone();
        while let Some(parent) = child.parent() {
            if !parent.starts_with(UPPER) {
                break;
            }
            listings
                .entry(parent.to_path_buf())
                .or_default()
                .insert(child.clone());
            child = parent.to_path_buf();
        }
    }
    for (dir, entries) in listings {
        fs.mock_set_path_type(&dir.display().to_string(), PathKind::Dir);
        fs.mock_set_directory_contents(&dir, entries.into_iter().collect());
    }
}

/// A Fedora decoy with rpm's database `decoy`, and hidden sessions with
/// `hidden` as their copy in the upper, when given.
fn fedora(decoy: &[u8], hidden: Option<&[u8]>) -> MockFilesystem {
    let fs = MockFilesystem::new();
    file(&fs, &format!("{ROOT}/{DB}"), decoy);
    // Fedora keeps the old place as a link to the new one.
    fs.mock_set_path_type(&format!("{ROOT}/var/lib/rpm"), PathKind::Symlink);
    if let Some(hidden) = hidden {
        file(&fs, &format!("{UPPER}/{DB}"), hidden);
    }
    fs
}

#[test]
fn rpm_packages_the_decoy_changed_since_are_named_and_the_hidden_sessions_own_are_not() {
    let fs = fedora(DECOY, Some(HIDDEN));
    upper(&fs, &[&[DB], OWN].concat(), OWN_REMOVED);
    let result = run(&check(), &fs);
    assert!(result.is_warn(), "{result:?}");
    assert_eq!(
        result.message().lines().next().unwrap(),
        "the decoy installed, updated or removed 4 packages since hidden sessions made their \
         own copy of the rpm package database (/usr/lib/sysimage/rpm/rpmdb.sqlite), which \
         still records them as they were: beta (2.1-1 on the decoy, 2.0-1 in hidden \
         sessions), delta (1:3.0-1 on the decoy, not in hidden sessions), gamma (not on the \
         decoy, 1.0-1 in hidden sessions), kernel-core (6.17.1-200.fc44 and 6.17.2-200.fc44 \
         on the decoy, 6.17.1-200.fc44 in hidden sessions)"
    );
    assert!(
        result.message().contains("`sudo dnf upgrade --refresh`"),
        "{result:?}"
    );

    // Without the files of its own in the upper, alpha and epsilon drifted
    // too: nothing says a hidden session changed them.
    let fs = fedora(DECOY, Some(HIDDEN));
    upper(&fs, &[DB], &[]);
    let result = run(&check(), &fs);
    assert!(
        result
            .message()
            .contains("removed 6 packages since hidden sessions"),
        "{result:?}"
    );
}

#[test]
fn a_package_removed_with_its_directory_is_the_hidden_sessions_own() {
    // gamma's own directory deleted whole: its files are gone on the way.
    let fs = fedora(HIDDEN, Some(DECOY));
    upper(&fs, &[DB, "usr/share/delta/3.0", "usr/bin/delta-3.0"], &[]);
    let result = run(&check(), &fs);
    assert!(
        result.message().contains("gamma (1.0-1 on the decoy"),
        "{result:?}"
    );
    let fs = fedora(HIDDEN, Some(DECOY));
    upper(
        &fs,
        &[DB, "usr/share/delta/3.0", "usr/bin/delta-3.0"],
        &["usr/share/gamma"],
    );
    let result = run(&check(), &fs);
    assert!(!result.message().contains("gamma ("), "{result:?}");
    assert!(!result.message().contains("delta"), "{result:?}");
}

#[test]
fn an_rpm_copy_that_holds_only_the_hidden_sessions_changes_follows() {
    // The copy adds kernel-core 6.17.2 in its log, whose files the upper
    // holds: the hidden session's own change.
    let fs = fedora(HIDDEN, Some(HIDDEN));
    file(&fs, &format!("{UPPER}/{DB}-wal"), HIDDEN_WAL);
    upper(
        &fs,
        &[DB, &format!("{DB}-wal"), "usr/share/kernel-core/6.17.2"],
        &[],
    );
    let result = run(&check(), &fs);
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        result.message(),
        "hidden sessions keep their own copy of the rpm package database \
         (/usr/lib/sysimage/rpm/rpmdb.sqlite), which follows the decoy's but for the 1 package \
         they changed themselves"
    );
}

#[test]
fn a_log_of_its_own_beside_the_decoys_database_is_the_hidden_sessions_copy() {
    // rpm stopped before its checkpoint: the upper holds the log alone, which
    // hidden sessions read over the decoy's database.
    let fs = fedora(HIDDEN, None);
    file(&fs, &format!("{UPPER}/{DB}-wal"), HIDDEN_WAL);
    upper(&fs, &[&format!("{DB}-wal")], &[]);
    let result = run(&check(), &fs);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(
            "kernel-core (6.17.1-200.fc44 on the decoy, 6.17.1-200.fc44 and 6.17.2-200.fc44 in \
             hidden sessions)"
        ),
        "{result:?}"
    );
    // A log on the decoy shows through where hidden sessions keep none.
    let fs = fedora(HIDDEN, Some(HIDDEN));
    file(&fs, &format!("{ROOT}/{DB}-wal"), HIDDEN_WAL);
    upper(&fs, &[DB], &[]);
    let result = run(&check(), &fs);
    assert!(result.is_pass(), "{result:?}");
    // Unless they deleted it.
    let fs = fedora(HIDDEN, Some(HIDDEN));
    file(&fs, &format!("{ROOT}/{DB}-wal"), HIDDEN_WAL);
    upper(&fs, &[DB], &[&format!("{DB}-wal")]);
    let result = run(&check(), &fs);
    assert!(
        result.message().contains("6.17.2-200.fc44 on the decoy"),
        "{result:?}"
    );
}

#[test]
fn rpm_without_a_copy_is_shared_even_without_root_and_a_copy_needs_root() {
    let fs = fedora(DECOY, None);
    let result = run(&check().as_privileged(false), &fs);
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        result.message(),
        "hidden sessions see the decoy's own rpm package database \
         (/usr/lib/sysimage/rpm/rpmdb.sqlite)"
    );
    let fs = fedora(DECOY, Some(HIDDEN));
    let result = run(&check().as_privileged(false), &fs);
    assert!(result.is_warn(), "{result:?}");
    assert!(result.message().contains("only root reads"), "{result:?}");
    // A decoy mounted noatime is read without root.
    fs.mock_set_mount_table("1 0 8:2 / /decoy rw,noatime - btrfs /dev/vda2 rw\n");
    upper(&fs, &[&[DB], OWN].concat(), OWN_REMOVED);
    let result = run(&check().as_privileged(false), &fs);
    assert!(
        result.message().contains("removed 4 packages since"),
        "{result:?}"
    );
}

#[test]
fn an_rpm_database_that_cannot_be_read_cannot_be_judged() {
    let fs = fedora(b"not a database", Some(HIDDEN));
    let result = run(&check(), &fs);
    assert!(
        result.message().contains(
            "could not tell whether hidden sessions' copy of the rpm package database \
             (/usr/lib/sysimage/rpm/rpmdb.sqlite) follows the decoy's: \
             /usr/lib/sysimage/rpm/rpmdb.sqlite on the decoy cannot be read"
        ),
        "{result:?}"
    );
    let fs = fedora(DECOY, Some(b"not a database"));
    let result = run(&check(), &fs);
    assert!(
        result
            .message()
            .contains("hidden sessions' copy of /usr/lib/sysimage/rpm/rpmdb.sqlite cannot be read"),
        "{result:?}"
    );
    // A log on the decoy that is a link is not followed.
    let fs = fedora(DECOY, Some(HIDDEN));
    fs.mock_set_path_type(&format!("{ROOT}/{DB}-wal"), PathKind::Symlink);
    let result = run(&check(), &fs);
    assert!(
        result
            .message()
            .contains("/usr/lib/sysimage/rpm/rpmdb.sqlite-wal on the decoy is a symbolic link"),
        "{result:?}"
    );
}

#[test]
fn an_rpm_database_larger_than_rpm_keeps_cannot_be_judged() {
    // Refused unread: the check says it cannot tell, never that nothing
    // drifted.
    for path in [format!("{UPPER}/{DB}"), format!("{ROOT}/{DB}")] {
        let fs = fedora(DECOY, Some(HIDDEN));
        fs.mock_set_file_size(&path, rpm::FILE_LIMIT + 1);
        let result = run(&check(), &fs);
        assert!(result.is_warn(), "{result:?}");
        assert!(
            result.message().starts_with(
                "could not tell whether hidden sessions' copy of the rpm package database \
                 (/usr/lib/sysimage/rpm/rpmdb.sqlite) follows the decoy's"
            ),
            "{path}: {result:?}"
        );
        assert!(
            result
                .message()
                .contains("more than rpm keeps in its database or its log"),
            "{path}: {result:?}"
        );
    }
}

#[test]
fn an_rpm_database_a_hidden_session_deleted_warns_with_the_discard() {
    let fs = fedora(DECOY, None);
    upper(&fs, &[], &[DB]);
    let result = run(&check(), &fs);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .starts_with("a hidden session deleted /usr/lib/sysimage/rpm/rpmdb.sqlite"),
        "{result:?}"
    );
}

#[test]
fn an_upper_directory_that_cannot_be_listed_cannot_be_judged() {
    use crate::filesystem::RealFilesystem;
    use std::os::unix::fs::PermissionsExt;

    if rustix::process::geteuid().is_root() {
        // Root lists any directory.
        return;
    }
    let decoy = tempfile::tempdir().unwrap();
    let hidden = tempfile::tempdir().unwrap();
    let database = decoy.path().join(DB);
    std::fs::create_dir_all(database.parent().unwrap()).unwrap();
    std::fs::write(&database, DECOY).unwrap();
    let upper = hidden.path().join("root/upper");
    std::fs::create_dir_all(upper.join(DB).parent().unwrap()).unwrap();
    std::fs::write(upper.join(DB), HIDDEN).unwrap();
    let share = upper.join("usr/share");
    std::fs::create_dir_all(&share).unwrap();
    std::fs::set_permissions(&share, std::fs::Permissions::from_mode(0o000)).unwrap();

    let check = PackageDriftCheck::new(decoy.path().to_path_buf(), hidden.path().to_path_buf())
        .as_privileged(true);
    let result = PreFlightCheck::<RealFilesystem>::run(&check, &RealFilesystem).unwrap();
    std::fs::set_permissions(&share, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains("usr/share cannot be read"),
        "{result:?}"
    );
}

#[test]
fn reading_rpms_database_leaves_the_decoys_access_times_alone() {
    use crate::filesystem::RealFilesystem;
    use std::os::unix::fs::MetadataExt;

    let decoy = tempfile::tempdir().unwrap();
    let hidden = tempfile::tempdir().unwrap();
    let database = decoy.path().join(DB);
    std::fs::create_dir_all(database.parent().unwrap()).unwrap();
    std::fs::write(&database, DECOY).unwrap();
    let wal = decoy.path().join(format!("{DB}-wal"));
    std::fs::write(&wal, b"").unwrap();
    let copy = hidden.path().join("root/upper").join(DB);
    std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
    std::fs::write(&copy, HIDDEN).unwrap();
    for own in OWN {
        let path = hidden.path().join("root/upper").join(own);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"").unwrap();
    }
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    for path in [&database, &wal] {
        std::fs::File::open(path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_accessed(old))
            .unwrap();
    }
    let atime = |path: &Path| {
        let meta = std::fs::metadata(path).unwrap();
        (meta.atime(), meta.atime_nsec())
    };
    let before = (atime(&database), atime(&wal));

    let check = PackageDriftCheck::new(decoy.path().to_path_buf(), hidden.path().to_path_buf())
        .as_privileged(true);
    let result = PreFlightCheck::<RealFilesystem>::run(&check, &RealFilesystem).unwrap();
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains("removed 4 packages"),
        "{result:?}"
    );
    assert_eq!((atime(&database), atime(&wal)), before);
}

fn package(name: &str, arch: Option<&str>, version: &str) -> rpm::Package {
    rpm::Package {
        name: name.to_string(),
        arch: arch.map(str::to_string),
        epoch: None,
        version: version.to_string(),
        release: "1".to_string(),
        dirs: Vec::new(),
        files: Vec::new(),
        links: Vec::new(),
    }
}

#[test]
fn an_rpm_package_of_several_architectures_is_named_with_its_own_and_keys_are_left_out() {
    let decoy = [
        package("glibc", Some("x86_64"), "2.41"),
        package("glibc", Some("i686"), "2.41"),
        package("gpg-pubkey", None, "7fac5991"),
    ];
    let hidden = [
        package("glibc", Some("x86_64"), "2.40"),
        package("glibc", Some("i686"), "2.41"),
    ];
    assert_eq!(
        judge_rpm(&decoy, &hidden, &BTreeSet::new()),
        Verdict::Drifted(Drift::Stale(vec![Change {
            name: "glibc.x86_64".to_string(),
            decoy: Some("2.41-1".to_string()),
            hidden: Some("2.40-1".to_string()),
        }]))
    );
    // Each side's package of a key that differs, and no public key.
    let differing = rpm_differing(&decoy, &hidden);
    let key = ("glibc".to_string(), Some("x86_64".to_string()));
    assert_eq!(differing.keys().collect::<Vec<_>>(), [&key]);
    assert_eq!(differing[&key].len(), 2);
    let changed = BTreeSet::from([key]);
    assert_eq!(
        judge_rpm(&decoy, &hidden, &changed),
        Verdict::Follows { own: 1 }
    );
}

#[test]
fn files_on_a_decoy_filesystem_hidden_sessions_never_wrote_to_are_not_theirs() {
    // /usr/share is a filesystem of its own, whose upper does not exist: the
    // files there are no hidden session's, and those in /usr/bin still are.
    let fs = fedora(DECOY, Some(HIDDEN));
    upper(&fs, &[&[DB], OWN].concat(), OWN_REMOVED);
    fs.mock_set_mount_table(
        "1 0 8:2 / /decoy rw - ext4 /dev/vda2 rw\n2 1 8:3 / /decoy/usr/share rw - ext4 /dev/vda3 rw\n",
    );
    let result = run(&check(), &fs);
    assert!(
        result.message().contains("removed 4 packages since"),
        "{result:?}"
    );
}

#[test]
fn a_directory_a_hidden_session_replaced_with_a_link_makes_the_package_its_own() {
    use crate::filesystem::RealFilesystem;

    let decoy = tempfile::tempdir().unwrap();
    let hidden = tempfile::tempdir().unwrap();
    let database = decoy.path().join(DB);
    std::fs::create_dir_all(database.parent().unwrap()).unwrap();
    std::fs::write(&database, DECOY).unwrap();
    let upper = hidden.path().join("root/upper");
    std::fs::create_dir_all(upper.join(DB).parent().unwrap()).unwrap();
    std::fs::write(upper.join(DB), HIDDEN).unwrap();
    for own in OWN {
        let path = upper.join(own);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"").unwrap();
    }
    // delta's own directory, a link to another directory in hidden sessions.
    std::os::unix::fs::symlink(
        upper.join("usr/share/epsilon"),
        upper.join("usr/share/delta"),
    )
    .unwrap();

    let check = PackageDriftCheck::new(decoy.path().to_path_buf(), hidden.path().to_path_buf())
        .as_privileged(true);
    let result = PreFlightCheck::<RealFilesystem>::run(&check, &RealFilesystem).unwrap();
    assert!(
        result.message().contains("removed 3 packages since"),
        "{result:?}"
    );
    assert!(!result.message().contains("delta ("), "{result:?}");
}

/// `value` as a varint of SQLite.
fn varint(mut value: u64) -> Vec<u8> {
    let mut bytes = vec![(value & 0x7f) as u8];
    value >>= 7;
    while value > 0 {
        bytes.push((value & 0x7f) as u8 | 0x80);
        value >>= 7;
    }
    bytes.reverse();
    bytes
}

/// A cell of a table leaf: row `rowid`, whose record holds `values`, each a
/// serial type and its bytes.
fn cell(rowid: u64, values: &[(u64, &[u8])]) -> Vec<u8> {
    let serials: Vec<u8> = values
        .iter()
        .flat_map(|(serial, _)| varint(*serial))
        .collect();
    let mut record = varint(serials.len() as u64 + 1);
    record.extend(serials);
    for (_, bytes) in values {
        record.extend(*bytes);
    }
    let mut cell = varint(record.len() as u64);
    cell.extend(varint(rowid));
    cell.extend(record);
    cell
}

/// A leaf page of `cell` alone, its b-tree header at `start` of the page.
fn leaf(page: &mut [u8], start: usize, cell: &[u8]) {
    let at = page.len() - cell.len();
    page[start] = 0x0d;
    page[start + 3..start + 5].copy_from_slice(&1u16.to_be_bytes());
    page[start + 5..start + 7].copy_from_slice(&u16::try_from(at).unwrap().to_be_bytes());
    page[start + 8..start + 10].copy_from_slice(&u16::try_from(at).unwrap().to_be_bytes());
    page[at..].copy_from_slice(cell);
}

/// rpm's database of one package, the header `header`, as SQLite lays out a
/// table of one row: pages of 4096 bytes, the schema naming the table
/// `Packages` at page 2.
fn database_of(header: &[u8]) -> Vec<u8> {
    let mut file = vec![0; 8192];
    file[..16].copy_from_slice(b"SQLite format 3\0");
    file[16..18].copy_from_slice(&4096u16.to_be_bytes());
    file[56..60].copy_from_slice(&1u32.to_be_bytes());
    let sql = b"CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)";
    let text = |bytes: &[u8]| 2 * bytes.len() as u64 + 13;
    let schema: [(u64, &[u8]); 5] = [
        (text(b"table"), b"table"),
        (text(b"Packages"), b"Packages"),
        (text(b"Packages"), b"Packages"),
        (1, &[2]),
        (text(sql), sql),
    ];
    leaf(&mut file[..4096], 100, &cell(1, &schema));
    let row: [(u64, &[u8]); 2] = [(0, &[]), (2 * header.len() as u64 + 12, header)];
    let row = cell(1, &row);
    leaf(&mut file[4096..], 0, &row);
    file
}

/// rpm's header of the package `name` 1-1 of `files`, each a directory, a
/// name and, for a symbolic link, its target.
fn rpm_header(name: &str, files: &[(&str, &str, Option<&str>)]) -> Vec<u8> {
    let strings = |strings: &[&str]| -> Vec<u8> {
        strings
            .iter()
            .flat_map(|text| text.bytes().chain([0]))
            .collect()
    };
    let mut dirs: Vec<&str> = Vec::new();
    let mut indexes = Vec::new();
    for (dir, _, _) in files {
        let index = dirs
            .iter()
            .position(|known| known == dir)
            .unwrap_or_else(|| {
                dirs.push(*dir);
                dirs.len() - 1
            });
        indexes.extend(u32::try_from(index).unwrap().to_be_bytes());
    }
    let names: Vec<&str> = files.iter().map(|(_, name, _)| *name).collect();
    let modes: Vec<u8> = files
        .iter()
        .flat_map(|(_, _, target)| match target {
            Some(_) => 0o120_777u16.to_be_bytes(),
            None => 0o100_644u16.to_be_bytes(),
        })
        .collect();
    let targets: Vec<&str> = files
        .iter()
        .map(|(_, _, target)| target.unwrap_or(""))
        .collect();
    let count = files.len() as u32;
    // Tag, type, count and data of each entry, as `headerExport()` lays one
    // out.
    let entries: [(u32, u32, u32, Vec<u8>); 9] = [
        (1000, 6, 1, strings(&[name])),
        (1001, 6, 1, strings(&["1"])),
        (1002, 6, 1, strings(&["1"])),
        (1022, 6, 1, strings(&["noarch"])),
        (1030, 3, count, modes),
        (1036, 8, count, strings(&targets)),
        (1116, 4, count, indexes),
        (1117, 8, count, strings(&names)),
        (1118, 8, dirs.len() as u32, strings(&dirs)),
    ];
    let (mut index, mut data): (Vec<u8>, Vec<u8>) = (Vec::new(), Vec::new());
    for (tag, kind, count, bytes) in entries {
        for word in [tag, kind, data.len() as u32, count] {
            index.extend(word.to_be_bytes());
        }
        data.extend(bytes);
    }
    let mut header = Vec::new();
    header.extend(9u32.to_be_bytes());
    header.extend((data.len() as u32).to_be_bytes());
    header.extend(index);
    header.extend(data);
    header
}

#[test]
fn links_that_loop_on_the_way_to_a_packages_file_cannot_be_judged() {
    // Hidden sessions' copy records a package whose links /a and /b point at
    // each other, and a file of its own below /a.
    let header = rpm_header(
        "loopy",
        &[
            ("/", "a", Some("b")),
            ("/", "b", Some("a")),
            ("/a/", "x", None),
        ],
    );
    let hidden = database_of(&header);
    assert_eq!(rpm::parse_database(&hidden, None).unwrap().len(), 1);
    let fs = fedora(LINKS_DECOY, Some(&hidden));
    upper(&fs, &[DB], &[]);
    let result = run(&check(), &fs);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(
            "could not tell whether hidden sessions' copy of the rpm package database \
             (/usr/lib/sysimage/rpm/rpmdb.sqlite) follows the decoy's: rpm's records give \
             links on the way to /a/ that NAILS cannot follow: the links on its way make a \
             loop"
        ),
        "{result:?}"
    );
}

/// rpm's own databases of the links fixtures (`make-rpmdb.sh`): the decoy's
/// filesystem package links /lib to usr/lib, and its kernel's modules are
/// recorded below /lib/modules; hidden sessions installed kernel 6.18 and
/// removed 6.17.1, as dnf does at its limit of kernels.
const LINKS_DECOY: &[u8] =
    include_bytes!("../../../nails-base/src/packages/fixtures/rpmdb-links-decoy.sqlite");
const LINKS_HIDDEN: &[u8] =
    include_bytes!("../../../nails-base/src/packages/fixtures/rpmdb-links-hidden.sqlite");
const MODULES_NEW: &str = "usr/lib/modules/6.18.0-200.fc44.x86_64";
const MODULES_OLD: &str = "usr/lib/modules/6.17.1-200.fc44.x86_64";

#[test]
fn a_kernel_update_through_lib_in_a_hidden_session_is_its_own() {
    // dnf in a hidden session writes the new modules where /lib leads,
    // below usr/lib, and deletes the old tree there.
    let new = format!("{MODULES_NEW}/kernel/drivers/nails/nails.ko.xz");
    let fs = fedora(LINKS_DECOY, Some(LINKS_HIDDEN));
    upper(&fs, &[DB, &new], &[MODULES_OLD]);
    let result = run(&check(), &fs);
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        result.message(),
        "hidden sessions keep their own copy of the rpm package database \
         (/usr/lib/sysimage/rpm/rpmdb.sqlite), which follows the decoy's but for the 1 package \
         they changed themselves"
    );
    // Either change alone tells it.
    for (files, whiteouts) in [
        (vec![DB, new.as_str()], vec![]),
        (vec![DB], vec![MODULES_OLD]),
    ] {
        let fs = fedora(LINKS_DECOY, Some(LINKS_HIDDEN));
        upper(&fs, &files, &whiteouts);
        assert!(run(&check(), &fs).is_pass(), "{files:?} {whiteouts:?}");
    }
    // Without either, nothing says a hidden session changed the package.
    let fs = fedora(LINKS_DECOY, Some(LINKS_HIDDEN));
    upper(&fs, &[DB], &[]);
    let result = run(&check(), &fs);
    assert!(
        result.message().contains(
            "kernel-modules (6.17.1-200.fc44 on the decoy, 6.18.0-200.fc44 in hidden sessions)"
        ),
        "{result:?}"
    );
}

/// Without the mount table: the decoy's directories above the database and
/// the packages' files that the kernel says are no mount points.
fn without_the_mount_table(fs: &MockFilesystem, dirs: &[&str]) {
    fs.mock_set_mount_table_error("permission denied");
    for dir in ["usr", "usr/lib", "usr/lib/sysimage", "usr/lib/sysimage/rpm"]
        .iter()
        .chain(dirs)
    {
        fs.mock_set_mount_root(&format!("{ROOT}/{dir}"), false);
    }
}

#[test]
fn without_the_mount_table_a_directory_the_decoy_lacks_is_no_mount_point() {
    let fs = fedora(DECOY, Some(HIDDEN));
    upper(&fs, &[&[DB], OWN].concat(), OWN_REMOVED);
    without_the_mount_table(
        &fs,
        &[
            "usr/bin",
            "usr/share",
            "usr/share/alpha",
            "usr/share/beta",
            "usr/share/delta",
            "usr/share/kernel-core",
        ],
    );
    // The decoy removed gamma with its directory and never had epsilon's:
    // there the kernel finds nothing to say anything of.
    for dir in ["usr/share/gamma", "usr/share/epsilon"] {
        fs.mock_set_mount_root_error(&format!("{ROOT}/{dir}"), std::io::ErrorKind::NotFound);
    }
    let result = run(&check(), &fs);
    assert!(
        result.message().contains("removed 4 packages since"),
        "{result:?}"
    );
    // A directory the kernel cannot be asked about leaves the verdict open.
    fs.mock_set_mount_root_error(
        &format!("{ROOT}/usr/share/beta"),
        std::io::ErrorKind::PermissionDenied,
    );
    let result = run(&check(), &fs);
    assert!(
        result.message().contains(
            "the mount table cannot be read, nor whether /usr/share/beta is a mount point"
        ),
        "{result:?}"
    );
}

#[test]
fn without_the_mount_table_nothing_below_a_link_on_the_decoy_is_asked_about() {
    // Hidden sessions' own changes lie below /usr/share alone.
    let fs = fedora(DECOY, Some(HIDDEN));
    upper(
        &fs,
        &[DB, "usr/share/alpha/1.1", "usr/share/epsilon/0.5"],
        &["usr/share/alpha/1.0"],
    );
    without_the_mount_table(&fs, &["usr/bin"]);
    // The decoy's /usr/share is a link. Asked about what lies below it, the
    // kernel would follow the link, and here it would say each package's
    // directory is a filesystem of its own, whose upper holds nothing.
    fs.mock_set_path_type(&format!("{ROOT}/usr/share"), PathKind::Symlink);
    for name in ["alpha", "beta", "delta", "epsilon", "gamma", "kernel-core"] {
        fs.mock_set_mount_root(&format!("{ROOT}/usr/share/{name}"), true);
    }
    let result = run(&check(), &fs);
    assert!(
        result.message().contains("removed 4 packages since"),
        "{result:?}"
    );
}

#[test]
fn without_the_mount_table_nothing_below_an_automount_point_is_asked_about() {
    // As below a link: the kernel, asked about what lies below the decoy's
    // automount point, would mount it, and here it would say each package's
    // directory is a filesystem of its own, whose upper holds nothing.
    let fs = fedora(DECOY, Some(HIDDEN));
    upper(
        &fs,
        &[DB, "usr/share/alpha/1.1", "usr/share/epsilon/0.5"],
        &["usr/share/alpha/1.0"],
    );
    without_the_mount_table(&fs, &["usr/bin"]);
    fs.mock_set_automount(&format!("{ROOT}/usr/share"));
    for name in ["alpha", "beta", "delta", "epsilon", "gamma", "kernel-core"] {
        fs.mock_set_mount_root(&format!("{ROOT}/usr/share/{name}"), true);
    }
    let result = run(&check(), &fs);
    assert!(
        result.message().contains("removed 4 packages since"),
        "{result:?}"
    );
}

#[test]
fn without_the_mount_table_the_reads_follow_no_link_on_the_decoy() {
    use crate::filesystem::RealFilesystem;
    use std::os::unix::fs::MetadataExt;

    let decoy = tempfile::tempdir().unwrap();
    let hidden = tempfile::tempdir().unwrap();
    let database = decoy.path().join(DB);
    std::fs::create_dir_all(database.parent().unwrap()).unwrap();
    std::fs::write(&database, DECOY).unwrap();
    // The decoy's /usr/share is a link to a directory that holds nothing of
    // the packages'.
    std::fs::create_dir_all(decoy.path().join("usr/share-elsewhere")).unwrap();
    let link = decoy.path().join("usr/share");
    std::os::unix::fs::symlink("share-elsewhere", &link).unwrap();
    let upper = hidden.path().join("root/upper");
    std::fs::create_dir_all(upper.join(DB).parent().unwrap()).unwrap();
    std::fs::write(upper.join(DB), HIDDEN).unwrap();
    for own in OWN {
        let path = upper.join(own);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"").unwrap();
    }
    let old = rustix::fs::Timestamps {
        last_access: rustix::fs::Timespec {
            tv_sec: 1_000_000_000,
            tv_nsec: 0,
        },
        last_modification: rustix::fs::Timespec {
            tv_sec: 0,
            tv_nsec: rustix::fs::UTIME_OMIT,
        },
    };
    rustix::fs::utimensat(
        rustix::fs::CWD,
        &link,
        &old,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .unwrap();
    let atime = || {
        let meta = std::fs::symlink_metadata(&link).unwrap();
        (meta.atime(), meta.atime_nsec())
    };
    let before = atime();

    let layout = crate::session::layout::Layout::new(hidden.path());
    let verdicts = verdicts(&RealFilesystem, decoy.path(), &layout, None, true);
    assert_eq!(atime(), before, "the link was followed");
    let (_, _, rpm) = &verdicts[2];
    assert!(matches!(rpm, Verdict::Drifted(_)), "{rpm:?}");
}
