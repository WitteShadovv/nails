// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::READ_LIMIT;
use super::dpkg::{self, State, info_owner, parse_status};
use super::pacman::{self, parse_entry};
use super::rpm::{self, Stamp};
use crate::filesystem::{MockFilesystem, PathKind};
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Three stanzas as dpkg writes them on Debian 13: a library of which several
/// architectures can be installed, a tool with its configuration files and a
/// package removed with its configuration kept.
const STATUS: &str = "\
Package: libc6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 12989
Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>
Architecture: amd64
Multi-Arch: same
Source: glibc
Version: 2.41-12
Depends: libgcc-s1
Description: GNU C Library: Shared libraries
 Contains the standard libraries that are used by nearly all programs on
 the system.
 .
 This package includes shared versions of the standard C library.

Package: openssh-client
Status: install ok installed
Priority: standard
Architecture: amd64
Version: 1:10.0p1-7
Conffiles:
 /etc/ssh/ssh_config 6d1d2b4d0c5b0c4d8e3f1a2b3c4d5e6f
Description: secure shell (SSH) client
 This is the portable version of OpenSSH.

Package: oldtool
Status: deinstall ok config-files
Architecture: all
Version: 0.9-1
Conffiles:
 /etc/oldtool.conf 0123456789abcdef0123456789abcdef
";

fn package(name: &str, arch: Option<&str>, version: &str, state: State) -> dpkg::Package {
    dpkg::Package {
        name: name.to_string(),
        architecture: arch.map(str::to_string),
        version: Some(version.to_string()),
        state: Some(state),
    }
}

#[test]
fn reads_each_stanza_dpkg_writes() {
    assert_eq!(
        parse_status(STATUS),
        vec![
            package("libc6", Some("amd64"), "2.41-12", State::Installed),
            package(
                "openssh-client",
                Some("amd64"),
                "1:10.0p1-7",
                State::Installed
            ),
            package("oldtool", Some("all"), "0.9-1", State::ConfigFiles),
        ]
    );
}

#[test]
fn a_status_without_stanzas_records_nothing() {
    assert_eq!(parse_status(""), vec![]);
    assert_eq!(parse_status("\n\n\n"), vec![]);
}

#[test]
fn field_names_match_in_any_case_and_may_have_space_before_the_colon() {
    let packages = parse_status(
        "PACKAGE: libssl3t64\nstatus\t: install ok unpacked\nVERSION:3.5.4-1\narchitecture :  amd64 \n",
    );
    assert_eq!(
        packages,
        vec![package(
            "libssl3t64",
            Some("amd64"),
            "3.5.4-1",
            State::Unpacked
        )]
    );
}

#[test]
fn stanzas_end_only_at_an_empty_line() {
    // Several empty lines between and around stanzas are one boundary.
    let spread = "\n\nPackage: a\nVersion: 1\n\n\n\nPackage: b\nVersion: 2\n\n";
    let names: Vec<String> = parse_status(spread).into_iter().map(|p| p.name).collect();
    assert_eq!(names, ["a", "b"]);

    // A line of spaces continues the field before it, as dpkg reads it, so
    // the second `Package` lands in the first stanza, which dpkg refuses.
    let spaces = "Package: a\nDescription: x\n \nPackage: b\n";
    assert_eq!(parse_status(spaces), vec![]);

    // The `\r` a CRLF file leaves on its empty line does the same.
    let crlf = "Package: a\r\nVersion: 1\r\n\r\nPackage: b\r\nVersion: 2\r\n";
    assert_eq!(parse_status(crlf), vec![]);
    // A value keeps no `\r` of its line.
    let one = "Package: a\r\nVersion: 1\r\n";
    assert_eq!(parse_status(one)[0].version.as_deref(), Some("1"));
}

#[test]
fn a_stanza_dpkg_refuses_is_left_out_and_the_others_are_read() {
    for broken in [
        // A field set twice.
        "Package: x\nVersion: 1\nVersion: 2\n",
        "Package: x\npackage: y\n",
        // A line with no colon after the name, and one with no name.
        "Package: x\nVersion 1\n",
        "Package: x\n: 1\n",
        // A kept field carried over to a second line.
        "Package: x\nVersion: 1\n 2\n",
        "Package: x\n  y\n",
        // No package named.
        "Version: 1\nStatus: install ok installed\n",
        "Package:\nVersion: 1\n",
    ] {
        let status = format!("Package: before\n\n{broken}\nPackage: after\n");
        let names: Vec<String> = parse_status(&status).into_iter().map(|p| p.name).collect();
        assert_eq!(names, ["before", "after"], "{broken:?}");
    }
}

#[test]
fn white_space_on_the_next_line_adds_nothing_to_a_kept_field() {
    // dpkg warns about the blank line in the value, keeps the value trimmed,
    // and reads the next field into the same stanza.
    let status = "Package: x\nVersion: 1\n \t\x0b\nArchitecture: all\n";
    assert_eq!(
        parse_status(status),
        vec![dpkg::Package {
            name: "x".to_string(),
            architecture: Some("all".to_string()),
            version: Some("1".to_string()),
            state: None,
        }]
    );
}

#[test]
fn a_field_this_reader_does_not_keep_may_run_over_lines() {
    // Description, Conffiles and the others go on over lines that start with
    // white space; a blank field value is fine too.
    let status = "Package: x\nDepends:\nDescription: short\n long\n .\n more\nVersion: 1\n";
    assert_eq!(parse_status(status)[0].version.as_deref(), Some("1"));
}

#[test]
fn the_state_is_the_last_word_of_the_status() {
    for (state, word) in State::ALL {
        let status = format!("Package: x\nStatus: hold reinstreq {word}\n");
        assert_eq!(parse_status(&status)[0].state, Some(state), "{word}");
        assert_eq!(State::parse(word), Some(state));
        assert_eq!(state.as_str(), word);
    }
    let status = "Package: x\nStatus: install ok   installed  \t\n";
    assert_eq!(parse_status(status)[0].state, Some(State::Installed));
    // A word dpkg does not write, and no status at all.
    assert_eq!(
        parse_status("Package: x\nStatus: install ok gone\n")[0].state,
        None
    );
    assert_eq!(parse_status("Package: x\n")[0].state, None);
    assert_eq!(State::parse("Installed"), None);
}

#[test]
fn files_are_present_from_unpacked_on() {
    let present: Vec<&str> = State::ALL
        .into_iter()
        .filter(|(state, _)| state.files_present())
        .map(|(_, word)| word)
        .collect();
    assert_eq!(
        present,
        [
            "unpacked",
            "half-configured",
            "triggers-awaited",
            "triggers-pending",
            "installed"
        ]
    );
    let mut package = package("x", None, "1", State::Installed);
    assert!(package.files_present());
    package.state = None;
    assert!(!package.files_present(), "an unknown state counts as none");
}

#[test]
fn an_empty_architecture_or_version_is_none() {
    let packages = parse_status("Package: x\nArchitecture:\nVersion:   \n");
    assert_eq!(packages[0].architecture, None);
    assert_eq!(packages[0].version, None);
}

#[test]
fn an_info_file_names_its_package_and_architecture() {
    assert_eq!(
        info_owner("libc6:amd64.list"),
        Some(("libc6", Some("amd64")))
    );
    assert_eq!(
        info_owner("openssh-client.md5sums"),
        Some(("openssh-client", None))
    );
    // Names with dots keep them: only the last one ends the name.
    assert_eq!(
        info_owner("gir1.2-gtk-3.0:amd64.list"),
        Some(("gir1.2-gtk-3.0", Some("amd64")))
    );
    assert_eq!(
        info_owner("python3.13.postinst"),
        Some(("python3.13", None))
    );
    for other in [
        "format",
        "format-new",
        ".list",
        "x.",
        ":amd64.list",
        "x:.list",
        "x:a:b.list",
    ] {
        assert_eq!(info_owner(other), None, "{other}");
    }
}

#[test]
fn the_status_file_is_read_through_the_filesystem() {
    let fs = MockFilesystem::new();
    let root = Path::new("/decoy");
    assert_eq!(dpkg::read_status(&fs, root).unwrap(), None, "no file");

    fs.mock_add_file("/decoy/var/lib/dpkg/status", STATUS);
    let packages = dpkg::read_status(&fs, root).unwrap().unwrap();
    assert_eq!(packages.len(), 3);
    assert_eq!(
        dpkg::read_status_file(&fs, Path::new("/decoy/var/lib/dpkg/status"))
            .unwrap()
            .unwrap(),
        packages
    );
}

#[test]
fn a_status_file_larger_than_the_limit_is_not_read() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/var/lib/dpkg/status", STATUS);
    fs.mock_set_file_size("/var/lib/dpkg/status", READ_LIMIT + 1);
    let error = dpkg::read_status(&fs, Path::new("/")).unwrap_err();
    assert_eq!(error.io_kind(), Some(std::io::ErrorKind::InvalidData));

    fs.mock_set_file_size("/var/lib/dpkg/status", READ_LIMIT);
    assert!(dpkg::read_status(&fs, Path::new("/")).unwrap().is_some());
}

#[test]
fn bytes_that_are_not_utf8_do_not_hide_the_stanzas_around_them() {
    let dir = tempfile::tempdir().unwrap();
    let status = dir.path().join("var/lib/dpkg/status");
    std::fs::create_dir_all(status.parent().unwrap()).unwrap();
    let mut bytes = b"Package: a\nDescription: \xff\xfe\n\nPackage: b\n".to_vec();
    bytes.extend_from_slice(b"Version: 1\n");
    std::fs::write(&status, bytes).unwrap();
    let names: Vec<String> = dpkg::read_status(&crate::RealFilesystem, dir.path())
        .unwrap()
        .unwrap()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert_eq!(names, ["a", "b"]);
}

#[test]
fn an_entry_splits_at_its_last_two_hyphens() {
    for (entry, name, version) in [
        ("linux-6.17.1.arch1-1", "linux", "6.17.1.arch1-1"),
        (
            "linux-firmware-20260910.abc1234-1",
            "linux-firmware",
            "20260910.abc1234-1",
        ),
        ("python-1:3.13.7-1", "python", "1:3.13.7-1"),
        ("a-b-", "a", "b-"),
        ("a--", "a", "-"),
        ("cryptsetup-2.8.1-1/desc", "cryptsetup", "2.8.1-1"),
    ] {
        let package = parse_entry(entry).unwrap_or_else(|| panic!("{entry}"));
        assert_eq!(
            (package.name.as_str(), package.version.as_str()),
            (name, version)
        );
    }
    for other in [
        "",
        "linux",
        "linux-6.17",
        "-6.17-1",
        "--",
        "ALPM_DB_VERSION",
        "/a-b-c",
    ] {
        assert_eq!(parse_entry(other), None, "{other}");
    }
}

#[test]
fn an_entry_name_is_the_package_name_and_version_joined() {
    let package = parse_entry("linux-firmware-1:2026-1").unwrap();
    assert_eq!(package.entry(), "linux-firmware-1:2026-1");
}

#[test]
fn the_local_database_is_listed_through_the_filesystem() {
    let fs = MockFilesystem::new();
    let root = Path::new("/decoy");
    assert_eq!(pacman::read_local(&fs, root).unwrap(), None, "no directory");

    let local = root.join(pacman::LOCAL);
    fs.mock_set_directory_contents(
        &local,
        [
            "ALPM_DB_VERSION",
            "linux-6.17.1.arch1-1",
            "pacman-7.0.0.r6.gc685ae6-2",
        ]
        .iter()
        .map(|name| local.join(name))
        .collect(),
    );
    let packages = pacman::read_local(&fs, root).unwrap().unwrap();
    let entries: Vec<String> = packages.iter().map(pacman::Package::entry).collect();
    assert_eq!(
        entries,
        ["linux-6.17.1.arch1-1", "pacman-7.0.0.r6.gc685ae6-2"]
    );
}

#[test]
fn an_entry_whose_name_is_not_utf8_is_left_out() {
    use std::os::unix::ffi::OsStrExt;
    let fs = MockFilesystem::new();
    let local = Path::new("/l");
    fs.mock_set_directory_contents(
        local,
        vec![
            local.join(std::ffi::OsStr::from_bytes(b"bad\xff-1-1")),
            local.join("good-1-1"),
        ],
    );
    let packages = pacman::read_local_dir(&fs, local).unwrap().unwrap();
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "good");
}

fn at(seconds: u64) -> chrono::DateTime<chrono::Utc> {
    (SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)).into()
}

#[test]
fn rpms_database_is_found_at_its_place_since_fedora_36() {
    let fs = MockFilesystem::new();
    let root = Path::new("/decoy");
    assert_eq!(rpm::locate(&fs, root).unwrap(), None, "no database");

    let path = "/decoy/usr/lib/sysimage/rpm/rpmdb.sqlite";
    fs.mock_set_file_size(path, 4096);
    fs.mock_set_modified_time(Path::new(path), at(1_000));
    // The old place, a link to the new one as Fedora keeps it, is passed over.
    fs.mock_set_path_type("/decoy/var/lib/rpm", PathKind::Symlink);
    assert_eq!(
        rpm::locate(&fs, root).unwrap(),
        Some((
            rpm::DATABASES[0],
            Stamp {
                size: 4096,
                modified: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000)
            }
        ))
    );
}

#[test]
fn rpms_database_at_the_old_place_counts_unless_a_link_leads_there() {
    let fs = MockFilesystem::new();
    let root = Path::new("/decoy");
    let path = "/decoy/var/lib/rpm/rpmdb.sqlite";
    fs.mock_set_file_size(path, 8192);
    fs.mock_set_modified_time(Path::new(path), at(2_000));
    let (database, stamp) = rpm::locate(&fs, root).unwrap().unwrap();
    assert_eq!(database, rpm::DATABASES[1]);
    assert_eq!(stamp.size, 8192);

    for link in ["/decoy/var", "/decoy/var/lib/rpm", path] {
        let fs = MockFilesystem::new();
        fs.mock_set_file_size(path, 8192);
        fs.mock_set_path_type(link, PathKind::Symlink);
        assert_eq!(rpm::locate(&fs, root).unwrap(), None, "{link}");
    }
}

#[test]
fn a_directory_where_rpms_database_should_be_is_none() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/usr/lib/sysimage/rpm/rpmdb.sqlite", PathKind::Dir);
    assert_eq!(rpm::locate(&fs, Path::new("/")).unwrap(), None);
    assert_eq!(
        rpm::stamp(&fs, Path::new("/var/lib/rpm/rpmdb.sqlite")).unwrap(),
        None,
        "no file"
    );
}

#[test]
fn real_reads_of_a_database_leave_its_access_times_alone() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let status = root.join(dpkg::STATUS);
    let local = root.join(pacman::LOCAL);
    std::fs::create_dir_all(status.parent().unwrap()).unwrap();
    std::fs::create_dir_all(local.join("linux-6.17.1.arch1-1")).unwrap();
    std::fs::write(&status, STATUS).unwrap();
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    for path in [&status, &local] {
        std::fs::File::open(path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_accessed(old))
            .unwrap();
    }
    let atime = |path: &Path| {
        let meta = std::fs::metadata(path).unwrap();
        (meta.atime(), meta.atime_nsec())
    };
    let before = (atime(&status), atime(&local));

    let fs = crate::RealFilesystem;
    assert_eq!(dpkg::read_status(&fs, root).unwrap().unwrap().len(), 3);
    assert_eq!(pacman::read_local(&fs, root).unwrap().unwrap().len(), 1);
    assert_eq!((atime(&status), atime(&local)), before);
}

proptest::proptest! {
    /// Packages written as dpkg writes them read back the same, whatever
    /// other stanzas sit around them.
    #[test]
    fn written_stanzas_read_back(
        packages in proptest::collection::vec(
            (
                "[a-z0-9][a-z0-9+.-]{0,30}",
                proptest::option::of("(amd64|i386|all|arm64)"),
                proptest::option::of("([0-9]:)?[0-9][0-9a-z.+~]{0,12}(-[0-9a-z.+~]{1,8})?"),
                proptest::option::of(0usize..8),
            ),
            0..8,
        ),
    ) {
        let expected: Vec<dpkg::Package> = packages
            .iter()
            .map(|(name, arch, version, state)| dpkg::Package {
                name: name.clone(),
                architecture: arch.clone(),
                version: version.clone(),
                state: state.map(|i| State::ALL[i].0),
            })
            .collect();
        let text: String = expected
            .iter()
            .map(|package| {
                let mut stanza = format!("Package: {}\n", package.name);
                if let Some(state) = package.state {
                    stanza.push_str(&format!("Status: install ok {}\n", state.as_str()));
                }
                stanza.push_str("Description: a package\n with a long description\n");
                if let Some(arch) = &package.architecture {
                    stanza.push_str(&format!("Architecture: {arch}\n"));
                }
                if let Some(version) = &package.version {
                    stanza.push_str(&format!("Version: {version}\n"));
                }
                stanza
            })
            .collect::<Vec<_>>()
            .join("\n");
        proptest::prop_assert_eq!(parse_status(&text), expected);
    }

    /// Every entry name of `<name>-<version>-<release>` splits back into its
    /// parts.
    #[test]
    fn an_entry_name_splits_back_into_its_parts(
        name in "[a-z0-9@._+][a-z0-9@._+-]{0,30}",
        version in "([0-9]{1,2}:)?[a-z0-9._+]{1,12}",
        release in "[0-9]{1,3}(\\.[0-9])?",
    ) {
        let package = parse_entry(&format!("{name}-{version}-{release}"));
        proptest::prop_assert_eq!(
            package,
            Some(pacman::Package { name, version: format!("{version}-{release}") })
        );
    }
}
