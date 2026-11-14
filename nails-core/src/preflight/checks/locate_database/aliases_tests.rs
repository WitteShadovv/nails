// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::super::super::systemd_conf::Assignment;
use super::super::unit::{SYSTEM_UNIT_PATH, UnitSection, unit_section};
use super::*;
use crate::filesystem::MockFilesystem;
use std::cell::RefCell;
use std::collections::BTreeMap;

/// An in-memory decoy whose directories list what is added below them.
struct Tree {
    fs: MockFilesystem,
    listings: RefCell<BTreeMap<PathBuf, Vec<PathBuf>>>,
}

impl Tree {
    fn new() -> Self {
        Self {
            fs: MockFilesystem::new(),
            listings: RefCell::new(BTreeMap::new()),
        }
    }

    fn list(&self, path: &Path) {
        let mut listings = self.listings.borrow_mut();
        let mut child = path.to_path_buf();
        while let Some(parent) = child.parent().map(Path::to_path_buf) {
            let entries = listings.entry(parent.clone()).or_default();
            if !entries.contains(&child) {
                entries.push(child.clone());
                self.fs
                    .mock_set_directory_contents(&parent, entries.clone());
            }
            child = parent;
        }
    }

    fn file(&self, path: &str, text: &str) -> &Self {
        self.fs.mock_add_file(path, text);
        self.list(Path::new(path));
        self
    }

    fn link(&self, path: &str, target: &str) -> &Self {
        self.fs
            .create_symlink(Path::new(target), Path::new(path))
            .unwrap();
        self.list(Path::new(path));
        self
    }

    fn dirs() -> Vec<PathBuf> {
        SYSTEM_UNIT_PATH
            .iter()
            .map(|dir| Path::new("/").join(dir))
            .collect()
    }

    fn section(&self, unit: &str) -> UnitSection {
        let files = DecoyFiles::new(&self.fs, Path::new("/"), &[]);
        unit_section(&files, &Self::dirs(), unit, "Service")
    }

    fn aliases(&self, unit: &str) -> Vec<String> {
        let files = DecoyFiles::new(&self.fs, Path::new("/"), &[]);
        let dirs = Self::dirs();
        let entries = Entries::read(&files, &dirs).unwrap();
        aliases(&files, &dirs, &entries, unit).unwrap()
    }
}

/// The value of `key` the section's assignments end with.
fn last(section: &UnitSection, key: &str) -> Option<String> {
    match section {
        UnitSection::Assignments(assignments) => assignments
            .iter()
            .rev()
            .find(|assignment: &&Assignment| assignment.key == key)
            .map(|assignment| assignment.value.clone()),
        other => panic!("no assignments: {other:?}"),
    }
}

const FIREWALLD: &str = "[Service]\nExecStart=/usr/bin/firewalld --nofork --nopid\n\
                         [Install]\nAlias=dbus-org.fedoraproject.FirewallD1.service\n";
const ALIAS: &str = "/etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service";

#[test]
fn a_drop_in_of_an_alias_is_read_for_its_unit() {
    let tree = Tree::new();
    tree.file("/usr/lib/systemd/system/firewalld.service", FIREWALLD)
        // `systemctl enable` links the unit's Alias=.
        .link(ALIAS, "/usr/lib/systemd/system/firewalld.service");
    assert!(tree.aliases("firewalld.service").is_empty(), "no drop-ins");
    tree.file(
        "/etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service.d/50-file.conf",
        "[Service]\nExecStart=\nExecStart=/usr/bin/firewalld --log-target=file\n",
    );
    assert_eq!(
        tree.aliases("firewalld.service"),
        ["dbus-org.fedoraproject.FirewallD1.service"]
    );
    assert_eq!(
        last(&tree.section("firewalld.service"), "ExecStart").as_deref(),
        Some("/usr/bin/firewalld --log-target=file")
    );
    // The directory of a dash prefix of the alias counts too.
    let tree = Tree::new();
    tree.file("/usr/lib/systemd/system/firewalld.service", FIREWALLD)
        .link(ALIAS, "../../../usr/lib/systemd/system/firewalld.service")
        .file(
            "/usr/lib/systemd/system/dbus-.service.d/50-out.conf",
            "[Service]\nStandardOutput=append:/var/log/dbus.log\n",
        );
    assert_eq!(
        last(&tree.section("firewalld.service"), "StandardOutput").as_deref(),
        Some("append:/var/log/dbus.log")
    );
}

#[test]
fn only_a_link_into_the_unit_directories_is_an_alias() {
    let tree = Tree::new();
    tree.file("/usr/lib/systemd/system/firewalld.service", FIREWALLD)
        // A unit file linked from elsewhere is a unit of its own.
        .file("/opt/units/other.service", FIREWALLD)
        .link(
            "/etc/systemd/system/other.service",
            "/opt/units/other.service",
        )
        .file(
            "/etc/systemd/system/other.service.d/50-x.conf",
            "[Service]\nStandardOutput=append:/var/log/x.log\n",
        )
        // A regular file is no alias, nor a link to another unit, nor one of
        // another type.
        .file("/etc/systemd/system/plain.service", FIREWALLD)
        .file(
            "/etc/systemd/system/plain.service.d/50-x.conf",
            "[Service]\n",
        )
        .link(
            "/etc/systemd/system/sshd.service",
            "/usr/lib/systemd/system/ssh.service",
        )
        .file("/usr/lib/systemd/system/ssh.service", "[Service]\n")
        .file(
            "/etc/systemd/system/sshd.service.d/50-x.conf",
            "[Service]\n",
        )
        .link(
            "/etc/systemd/system/firewalld.socket",
            "/usr/lib/systemd/system/firewalld.service",
        )
        .file(
            "/etc/systemd/system/firewalld.socket.d/50-x.conf",
            "[Socket]\n",
        );
    assert!(tree.aliases("firewalld.service").is_empty());
    assert_eq!(
        last(&tree.section("firewalld.service"), "StandardOutput"),
        None
    );
}

#[test]
fn a_unit_read_by_an_alias_takes_the_drop_ins_of_its_unit_file() {
    // syslog.service names the syslog daemon that is enabled.
    let tree = Tree::new();
    tree.file(
        "/usr/lib/systemd/system/rsyslog.service",
        "[Service]\nExecStart=/usr/sbin/rsyslogd -n\n",
    )
    .link(
        "/etc/systemd/system/syslog.service",
        "/usr/lib/systemd/system/rsyslog.service",
    )
    .file(
        "/etc/systemd/system/rsyslog.service.d/50-x.conf",
        "[Service]\nExecStart=\nExecStart=/usr/sbin/rsyslogd -n -iNONE\n",
    );
    assert_eq!(tree.aliases("syslog.service"), ["rsyslog.service"]);
    assert_eq!(tree.aliases("rsyslog.service"), Vec::<String>::new());
}

#[test]
fn an_instance_takes_the_aliases_of_its_template() {
    let tree = Tree::new();
    tree.file(
        "/usr/lib/systemd/system/foo@.service",
        "[Service]\nExecStart=/usr/bin/foo %i\n",
    )
    .link(
        "/etc/systemd/system/bar@.service",
        "/usr/lib/systemd/system/foo@.service",
    )
    .file(
        "/etc/systemd/system/bar@.service.d/50-x.conf",
        "[Service]\nStandardError=append:/var/log/bar.log\n",
    );
    assert_eq!(tree.aliases("foo@one.service"), ["bar@one.service"]);
    assert_eq!(
        last(&tree.section("foo@one.service"), "StandardError").as_deref(),
        Some("append:/var/log/bar.log")
    );
    // A chain of aliases is followed.
    tree.link(
        "/etc/systemd/system/baz@.service",
        "/etc/systemd/system/bar@.service",
    )
    .file(
        "/etc/systemd/system/baz@.service.d/60-x.conf",
        "[Service]\n",
    );
    assert_eq!(
        tree.aliases("foo@one.service"),
        ["bar@one.service", "baz@one.service"]
    );
}

#[test]
fn a_drop_in_name_two_names_hold_leaves_the_section_unknown() {
    let tree = Tree::new();
    tree.file("/usr/lib/systemd/system/firewalld.service", FIREWALLD)
        .link(ALIAS, "/usr/lib/systemd/system/firewalld.service")
        .file(
            "/etc/systemd/system/firewalld.service.d/50-x.conf",
            "[Service]\nStandardOutput=null\n",
        )
        .file(
            "/etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service.d/50-x.conf",
            "[Service]\nStandardOutput=append:/var/log/fw.log\n",
        );
    match tree.section("firewalld.service") {
        UnitSection::Unknown(why) => assert!(
            why.starts_with(
                "NAILS cannot tell which of /etc/systemd/system/firewalld.service.d/50-x.conf \
                 and /etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service.d/50-x.conf \
                 the service manager reads for firewalld.service"
            ),
            "{why}"
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_alias_is_one_of_the_same_kind() {
    for (link, target) in [
        ("a.service", "b.service"),
        ("a@.service", "b@.service"),
        ("a@x.service", "b@x.service"),
        ("a@x.service", "b@.service"),
    ] {
        assert!(valid_alias(link, target), "{link} -> {target}");
    }
    for (link, target) in [
        ("a.service", "a.service"),
        ("a.service", "b.socket"),
        ("a.service", "b@.service"),
        ("a@.service", "b.service"),
        ("a@x.service", "b@y.service"),
        ("a@.service", "b@x.service"),
        ("a", "b"),
    ] {
        assert!(!valid_alias(link, target), "{link} -> {target}");
    }
    assert_eq!(
        simplified(Path::new("/etc/systemd/system/../../../usr/./lib/x")),
        Path::new("/usr/lib/x")
    );
}
