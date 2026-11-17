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

    /// A link at `path` to `target`, which holds `text`. The mock reads no
    /// file through a link, so the link holds the text as well.
    fn linked(&self, path: &str, target: &str, text: &str) -> &Self {
        self.link(path, target);
        self.fs.mock_set_file_content(path, text);
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

    fn names(&self, unit: &str) -> Names {
        let files = DecoyFiles::new(&self.fs, Path::new("/"), &[]);
        let dirs = Self::dirs();
        let entries = Entries::read(&files, &dirs).unwrap();
        names(&files, &dirs, &entries, unit).unwrap()
    }

    fn aliases(&self, unit: &str) -> Vec<String> {
        self.names(unit).aliases
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
    .linked(
        "/etc/systemd/system/syslog.service",
        "/usr/lib/systemd/system/rsyslog.service",
        "[Service]\nExecStart=/usr/sbin/rsyslogd -n\n",
    )
    .file(
        "/etc/systemd/system/rsyslog.service.d/50-x.conf",
        "[Service]\nExecStart=\nExecStart=/usr/sbin/rsyslogd -n -iNONE\n",
    );
    // The unit file's name is its id, and syslog.service, which has no
    // drop-in directory, no alias that adds one.
    assert_eq!(
        tree.names("syslog.service"),
        Names {
            id: "rsyslog.service".to_string(),
            aliases: Vec::new()
        }
    );
    assert_eq!(tree.names("rsyslog.service").id, "rsyslog.service");
    assert_eq!(
        last(&tree.section("syslog.service"), "ExecStart").as_deref(),
        Some("/usr/sbin/rsyslogd -n -iNONE")
    );
    tree.file(
        "/etc/systemd/system/syslog.service.d/60-x.conf",
        "[Service]\n",
    );
    assert_eq!(tree.aliases("syslog.service"), ["syslog.service"]);
    assert_eq!(tree.aliases("rsyslog.service"), ["syslog.service"]);
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
fn a_drop_in_of_the_id_shadows_one_of_the_same_name_of_an_alias() {
    // systemd lists the drop-in directories of the unit's id before those of
    // its aliases, and takes the first file of a name.
    let tree = Tree::new();
    tree.file("/usr/lib/systemd/system/firewalld.service", FIREWALLD)
        .linked(
            ALIAS,
            "/usr/lib/systemd/system/firewalld.service",
            FIREWALLD,
        )
        .file(
            "/usr/lib/systemd/system/firewalld.service.d/50-x.conf",
            "[Service]\nStandardOutput=null\n",
        )
        .file(
            "/etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service.d/50-x.conf",
            "[Service]\nStandardOutput=append:/var/log/fw.log\n",
        );
    for name in [
        "firewalld.service",
        "dbus-org.fedoraproject.FirewallD1.service",
    ] {
        assert_eq!(
            last(&tree.section(name), "StandardOutput").as_deref(),
            Some("null"),
            "{name}"
        );
    }
}

/// A unit with two aliases, `a.service` and `b.service`, that hold a
/// drop-in of the same name, `a_text` and `b_text`, which its id does not.
fn two_aliases(a_text: &str, b_text: &str) -> Tree {
    let tree = Tree::new();
    tree.file(
        "/usr/lib/systemd/system/unit.service",
        "[Service]\nExecStart=/usr/bin/unit\n",
    )
    .linked(
        "/etc/systemd/system/a.service",
        "/usr/lib/systemd/system/unit.service",
        "[Service]\nExecStart=/usr/bin/unit\n",
    )
    .linked(
        "/etc/systemd/system/b.service",
        "/usr/lib/systemd/system/unit.service",
        "[Service]\nExecStart=/usr/bin/unit\n",
    )
    .file("/etc/systemd/system/a.service.d/50-x.conf", a_text)
    .file("/run/systemd/system/b.service.d/50-x.conf", b_text);
    tree
}

#[test]
fn a_drop_in_name_two_aliases_hold_counts_only_where_they_differ() {
    // systemd takes the aliases in an order NAILS cannot tell, so it reads
    // either file, and what both give alike is known.
    let same = "[Service]\nStandardOutput=null\n";
    let tree = two_aliases(same, same);
    assert_eq!(tree.aliases("unit.service"), ["a.service", "b.service"]);
    assert_eq!(
        last(&tree.section("unit.service"), "StandardOutput").as_deref(),
        Some("null")
    );
    // Files that differ only in a section the check does not read.
    let tree = two_aliases(
        "[Unit]\nDescription=a\n[Service]\nStandardOutput=null\n",
        "[Unit]\nDescription=b\n\n[Service]\nStandardOutput=null\n",
    );
    assert_eq!(
        last(&tree.section("unit.service"), "StandardOutput").as_deref(),
        Some("null")
    );
    let files = DecoyFiles::new(&tree.fs, Path::new("/"), &[]);
    assert!(matches!(
        unit_section(&files, &Tree::dirs(), "unit.service", "Unit"),
        UnitSection::Unknown(_)
    ));
    // Files that set what the check reads apart.
    let tree = two_aliases(same, "[Service]\nStandardOutput=append:/var/log/unit.log\n");
    match tree.section("unit.service") {
        UnitSection::Unknown(why) => assert_eq!(
            why,
            "NAILS cannot tell which of /etc/systemd/system/a.service.d/50-x.conf and \
             /run/systemd/system/b.service.d/50-x.conf the service manager reads for \
             unit.service: both are drop-ins of its aliases a.service and b.service, which it \
             takes in an order of its own, and they differ in [Service]"
        ),
        other => panic!("{other:?}"),
    }
    // A drop-in of the id shadows both.
    tree.file(
        "/usr/lib/systemd/system/unit.service.d/50-x.conf",
        "[Service]\nStandardOutput=journal\n",
    );
    assert_eq!(
        last(&tree.section("unit.service"), "StandardOutput").as_deref(),
        Some("journal")
    );
}

/// `/etc/systemd/system` of NixOS with dbus-broker, as the systemd module of
/// the nixpkgs this repository pins writes it (its `system-units`): the unit
/// files, the alias `dbus.service` that `systemd.services.dbus-broker.aliases`
/// makes, and the `overrides.conf` drop-ins of `systemd.services.dbus-broker`
/// and of `systemd.services.dbus`, which the dbus module sets in either
/// implementation, each given to `add` as a link, its target and the text
/// it leads to, in a file of the store.
fn nixos_dbus_broker(add: impl Fn(&str, &str, &str)) {
    const BROKER: &str = "/nix/store/2lg1d4zbpykbvma2s7wgsb4wnwyz8x6q-dbus-broker-37"; // pragma: allowlist secret
    let broker = format!(
        "[Unit]\n\
             Description=D-Bus System Message Bus\n\
             Documentation=man:dbus-broker-launch(1)\n\
             DefaultDependencies=false\n\
             After=dbus.socket\n\
             Before=basic.target shutdown.target\n\
             Requires=dbus.socket\n\
             Conflicts=shutdown.target\n\
             \n\
             [Service]\n\
             Type=notify-reload\n\
             Sockets=dbus.socket\n\
             OOMScoreAdjust=-900\n\
             LimitNOFILE=16384\n\
             ProtectSystem=full\n\
             PrivateTmp=true\n\
             PrivateDevices=true\n\
             ExecStart={BROKER}/bin/dbus-broker-launch --scope system --audit\n\
             \n\
             [Install]\n\
             Alias=dbus.service\n"
    );
    add(
        "/etc/systemd/system/dbus-broker.service",
        &format!("{BROKER}/lib/systemd/system/dbus-broker.service"),
        &broker,
    );
    add(
        "/etc/systemd/system/dbus.service",
        "dbus-broker.service",
        &broker,
    );
    const ENVIRONMENT: &str = "Environment=\"LOCALE_ARCHIVE=/nix/store/\
         1m9dlscbzj1ma5xjsbfw2kk0gwfq3qb7-glibc-locales-2.44-25/lib/locale/locale-archive\"\n\
         Environment=\"PATH=/nix/store/2gfxiwls9hbgwdwcy43mprchwsq36mg6-coreutils-9.11/bin:\
         /nix/store/ycrbcy9sg4knpnik6a01dk70l0m673x7-findutils-4.11.0/bin:\
         /nix/store/3668q0d9zhc5n9l2pnyvpd44kz9bjsjm-gnugrep-3.12/bin:\
         /nix/store/1ggxndc1gd5061j5hqprhnhx9p30yilv-gnused-4.10/bin:\
         /nix/store/l5hiab3932k2n4d6nirh09mk6xgxp61w-systemd-261.3/bin:\
         /nix/store/2gfxiwls9hbgwdwcy43mprchwsq36mg6-coreutils-9.11/sbin:\
         /nix/store/ycrbcy9sg4knpnik6a01dk70l0m673x7-findutils-4.11.0/sbin:\
         /nix/store/3668q0d9zhc5n9l2pnyvpd44kz9bjsjm-gnugrep-3.12/sbin:\
         /nix/store/1ggxndc1gd5061j5hqprhnhx9p30yilv-gnused-4.10/sbin:\
         /nix/store/l5hiab3932k2n4d6nirh09mk6xgxp61w-systemd-261.3/sbin\"\n\
         Environment=\"TZDIR=/nix/store/n8fqcpnr5ni28l3i9svqa70wz46798v9-tzdata-2026d/share/\
         zoneinfo\"\n\
         X-ReloadIfChanged=true\n";
    add(
        "/etc/systemd/system/dbus-broker.service.d/overrides.conf",
        "/nix/store/xdnczrcy9mfbqqalv1y8lgs2bs6lasdw-unit-dbus-broker.service/dbus-broker.service",
        &format!(
            "[Unit]\n\
             RequiresMountsFor=/tmp\n\
             X-Restart-Triggers=/nix/store/agrdrisp98v7ylpy4pir4vgfh9ax44wz-X-Restart-Triggers-\
             dbus-broker\n\
             \n\
             [Service]\n\
             Environment=\"LD_LIBRARY_PATH=/nix/store/l5hiab3932k2n4d6nirh09mk6xgxp61w-systemd-\
             261.3/lib\"\n\
             {ENVIRONMENT}"
        ),
    );
    add(
        "/etc/systemd/system/dbus.service.d/overrides.conf",
        "/nix/store/1wh8ikszcnfyrpp202vv8ydwwn9b0i8k-unit-dbus.service/dbus.service",
        &format!("[Unit]\n\n[Service]\n{ENVIRONMENT}"),
    );
}

#[test]
fn nixos_reads_the_drop_in_of_dbus_broker_and_not_that_of_its_alias() {
    // The two overrides.conf differ in [Service], and systemd reads the one
    // of the id, dbus-broker.service, whose unit file the link leads to
    // outside the unit directories.
    let tree = Tree::new();
    nixos_dbus_broker(|path, target, text| {
        if target.starts_with('/') {
            tree.file(target, text);
        }
        tree.linked(path, target, text);
    });
    for name in ["dbus-broker.service", "dbus.service"] {
        assert_eq!(tree.names(name).id, "dbus-broker.service", "{name}");
        let section = tree.section(name);
        assert_eq!(
            last(&section, "ExecStart").as_deref(),
            Some(
                "/nix/store/2lg1d4zbpykbvma2s7wgsb4wnwyz8x6q-dbus-broker-37/bin/\
                 dbus-broker-launch --scope system --audit"
            ),
            "{name}"
        );
        let UnitSection::Assignments(assignments) = section else {
            panic!("{name}");
        };
        assert!(
            assignments
                .iter()
                .any(|assignment| assignment.key == "Environment"
                    && assignment.value.starts_with("\"LD_LIBRARY_PATH=")),
            "{name}: {assignments:?}"
        );
    }
    assert_eq!(tree.aliases("dbus-broker.service"), ["dbus.service"]);
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

#[test]
fn nixos_with_dbus_broker_and_its_fix_passes_the_locate_check() {
    // The stock NixOS layout, with services.locate and its fix: dbus-broker
    // runs no updatedb, and NAILS reads its drop-ins as systemd does.
    use super::super::tests::{NIXOS_PRUNEPATHS, nixos};
    let mut pruned = NIXOS_PRUNEPATHS.to_vec();
    pruned.push("/mnt");
    let decoy = nixos(&pruned, &[]);
    nixos_dbus_broker(|path, target, text| {
        if target.starts_with('/') {
            decoy.file(target, text);
        }
        // The mock reads no file through a link.
        decoy.link(path, target);
        decoy.fs.mock_set_file_content(path, text);
    });
    let result = decoy.check(true);
    assert!(result.is_pass(), "{result:?}");
}
