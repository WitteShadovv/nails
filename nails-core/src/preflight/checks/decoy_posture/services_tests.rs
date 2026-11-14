// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! tuned, tuned-ppd, firewalld and ABRT on the decoy, on the units Fedora 44
//! installs: the Fedora 44 probe's Cloud image has none of them, while
//! Fedora enables all four by preset wherever they are installed
//! (`fedora-release-common`'s `90-default.preset`).

use super::super::{CORE_PATTERN, DecoyPersistenceCheck, MOUNTINFO};
use super::*;
use crate::filesystem::MockFilesystem;
use crate::preflight::{CheckResult, PreFlightCheck};
use std::cell::RefCell;

/// `/usr/lib/systemd/system/tuned.service` of Fedora 44's tuned-2.27.0-1.fc44.
const TUNED_UNIT: &str = include_str!("fixtures/fedora-44-tuned.service");
/// `/usr/lib/systemd/system/tuned-ppd.service` of Fedora 44's
/// tuned-ppd-2.27.0-1.fc44.
const PPD_UNIT: &str = include_str!("fixtures/fedora-44-tuned-ppd.service");
/// `/usr/lib/systemd/system/firewalld.service` of Fedora 44's
/// firewalld-2.4.0-2.fc44.
const FIREWALLD_UNIT: &str = include_str!("fixtures/fedora-44-firewalld.service");
/// `/etc/sysconfig/firewalld` of the same package.
const FIREWALLD_SYSCONFIG: &str = include_str!("fixtures/fedora-44-firewalld.sysconfig");
/// `/usr/lib/systemd/system/abrtd.service` of Fedora 44's abrt-2.17.8-3.fc44.
const ABRTD_UNIT_FILE: &str = include_str!("fixtures/fedora-44-abrtd.service");

/// What the module finds, as the tests compare it: the blockers by their
/// sentences.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Findings {
    blockers: Vec<String>,
    units: Vec<&'static str>,
    programs: Vec<&'static str>,
    warnings: Vec<String>,
}

/// [`blockers`] and [`warnings`] of the decoy under `root`, with the fixes of
/// a NixOS decoy when `is_nixos`.
fn findings<F: Filesystem>(fs: &F, root: &Path, hidden: &[PathBuf], is_nixos: bool) -> Findings {
    let tuned = blockers(fs, root, hidden);
    Findings {
        blockers: tuned
            .blockers
            .into_iter()
            .map(|finding| finding.sentence)
            .collect(),
        units: tuned.units,
        programs: tuned.programs,
        warnings: warnings(fs, root, hidden, is_nixos),
    }
}

/// An invocation id as systemd writes it.
const INVOCATION_ID: &str = "8028a17235414b4e80c950b24a7487d7";

/// The command lines Fedora 44's daemons run with: Python programs, whose
/// `comm` is the script's name.
const TUNED_ARGV: &[&str] = &["/usr/bin/python3", "-Es", "/usr/sbin/tuned", "-l", "-P"];
const PPD_ARGV: &[&str] = &["/usr/bin/python3", "-Es", "/usr/sbin/tuned-ppd", "-l"];
const FIREWALLD_ARGV: &[&str] = &[
    "/usr/bin/python3",
    "-sP",
    "/usr/bin/firewalld",
    "--nofork",
    "--nopid",
];

/// An in-memory decoy with a volatile journal and a noatime root, whose
/// directories list what is added below them.
struct Decoy {
    fs: MockFilesystem,
    listings: RefCell<BTreeMap<PathBuf, Vec<PathBuf>>>,
}

impl Decoy {
    fn new() -> Self {
        let decoy = Self {
            fs: MockFilesystem::new(),
            listings: RefCell::new(BTreeMap::new()),
        };
        decoy
            .file(
                "/etc/systemd/journald.conf",
                "[Journal]\nStorage=volatile\n",
            )
            .file(
                MOUNTINFO,
                "36 35 0:32 / / rw,noatime shared:1 - btrfs /dev/vda3 rw\n",
            );
        decoy
    }

    /// List `path` in its directory, and each directory in its own.
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

    /// Install `unit` with the text `text`, as its package does.
    fn unit(&self, unit: &str, text: &str) -> &Self {
        self.file(&format!("/usr/lib/systemd/system/{unit}"), text)
    }

    /// Enable `unit` for `target`, as `systemctl enable` and a preset do.
    fn enable(&self, target: &str, unit: &str) -> &Self {
        self.link(
            &format!("/etc/systemd/system/{target}.wants/{unit}"),
            &format!("/usr/lib/systemd/system/{unit}"),
        )
    }

    /// Mark `unit` active, as systemd's invocation marker does.
    fn active(&self, unit: &str) -> &Self {
        self.link(
            &format!("/run/systemd/units/invocation:{unit}"),
            INVOCATION_ID,
        )
    }

    /// Make every lookup of `path` fail with `kind`, as one in a directory
    /// NAILS may not search fails.
    fn lookup_error(&self, path: &str, kind: std::io::ErrorKind) -> &Self {
        self.fs.mock_set_lookup_error(path, kind);
        self
    }

    /// Mask `unit` in /etc/systemd/system.
    fn mask(&self, unit: &str) -> &Self {
        self.link(&format!("/etc/systemd/system/{unit}"), "/dev/null")
    }

    /// Run a process `pid` named `comm` with the command line `argv`.
    fn process(&self, pid: u32, comm: &str, argv: &[&str]) -> &Self {
        self.file(&format!("/proc/{pid}/comm"), &format!("{comm}\n"));
        let cmdline: String = argv.iter().map(|arg| format!("{arg}\0")).collect();
        self.file(&format!("/proc/{pid}/cmdline"), &cmdline)
    }

    /// Fedora's tuned and tuned-ppd, installed, enabled by preset and
    /// running, as on Workstation.
    fn fedora_tuned(&self) -> &Self {
        self.unit("tuned.service", TUNED_UNIT)
            .unit("tuned-ppd.service", PPD_UNIT)
            .enable("multi-user.target", "tuned.service")
            .enable("graphical.target", "tuned-ppd.service")
            .active("tuned.service")
            .active("tuned-ppd.service")
            .process(812, "tuned", TUNED_ARGV)
            .process(900, "tuned-ppd", PPD_ARGV)
    }

    /// Fedora's firewalld, installed with its sysconfig file, enabled by
    /// preset and running.
    fn fedora_firewalld(&self) -> &Self {
        self.unit("firewalld.service", FIREWALLD_UNIT)
            .file("/etc/sysconfig/firewalld", FIREWALLD_SYSCONFIG)
            .enable("multi-user.target", "firewalld.service")
            .active("firewalld.service")
            .process(700, "firewalld", FIREWALLD_ARGV)
    }

    fn findings(&self) -> Findings {
        findings(&self.fs, Path::new("/"), &[], false)
    }

    fn check(&self, allow: bool) -> CheckResult {
        DecoyPersistenceCheck::new(allow, false)
            .run(&self.fs)
            .unwrap()
    }
}

/// The finding of tuned's or tuned-ppd's log file `path`, shown by
/// `sources`: tuned logs its stop and its start, tuned-ppd what it does then.
fn logs_to(program: &str, path: &str, sources: &str) -> String {
    let around = match program {
        "tuned" => {
            "it logs there, on the decoy disk, when it stops or starts around a switch, with the \
             time"
        }
        _ => {
            "what it logs as it stops for a switch or starts again after the way back, a power \
             profile it sets or a hold it releases, stays there, on the decoy disk, with the time"
        }
    };
    format!("{program} writes its log to {path} ({sources}): {around}")
}

#[test]
fn fedora_tuned_and_tuned_ppd_refuse_with_their_log_files() {
    let decoy = Decoy::new();
    decoy.fedora_tuned();
    let found = decoy.findings();
    assert_eq!(
        found.blockers,
        [
            logs_to(
                "tuned",
                "/var/log/tuned/tuned.log",
                "tuned.service is enabled and active, with -l; process 812 runs with -l"
            ),
            logs_to(
                "tuned-ppd",
                "/var/log/tuned/tuned-ppd.log",
                "tuned-ppd.service is enabled and active, with -l; process 900 runs with -l"
            ),
        ]
    );
    assert_eq!(found.units, ["tuned.service", "tuned-ppd.service"]);
    assert!(found.warnings.is_empty(), "{found:?}");

    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        result.allowable(),
        Some(nails_api::Allowable::PersistentDecoy)
    );
    assert!(result.message().contains(&found.blockers[0]), "{result:?}");
    let remediation = result.remediation().unwrap();
    for part in [
        "Make tuned log to the journal: for each of tuned.service tuned-ppd.service, add a \
         drop-in (such as /etc/systemd/system/tuned.service.d/50-journal.conf) that clears \
         ExecStart= and sets it again without -l and -d",
        "Fedora's tuned.service: ExecStart=/usr/sbin/tuned -P",
        "systemctl restart tuned.service tuned-ppd.service",
        "systemctl mask --now tuned.service tuned-ppd.service",
        "or pass --allow-persistent-decoy",
    ] {
        assert!(remediation.contains(part), "{part}: {remediation}");
    }

    // The override lets it go on, and says what it lets happen.
    let allowed = decoy.check(true);
    assert!(allowed.is_warn(), "{allowed:?}");
    assert!(
        allowed.message().contains(
            "What tuned or tuned-ppd logs around a switch stays on the decoy disk, with the time."
        ),
        "{allowed:?}"
    );
}

#[test]
fn the_override_says_tuned_may_log_where_nails_cannot_tell() {
    // A program NAILS does not follow: it cannot tell where tuned logs.
    let decoy = Decoy::new();
    decoy
        .unit("tuned.service", TUNED_UNIT)
        .enable("multi-user.target", "tuned.service")
        .file(
            "/etc/systemd/system/tuned.service.d/50-wrap.conf",
            "[Service]\nExecStart=\nExecStart=/usr/local/bin/run-tuned\nStandardError=journal\n",
        );
    let message = decoy.check(true).message().to_string();
    assert!(
        message.contains("NAILS cannot tell whether tuned writes a log file"),
        "{message}"
    );
    assert!(
        message.contains(
            "What tuned or tuned-ppd logs around a switch may stay on the decoy disk, with the \
             time."
        ),
        "{message}"
    );
    assert!(!message.contains("stays on the decoy disk"), "{message}");
}

#[test]
fn the_fix_names_a_process_that_still_logs_beside_a_unit_that_does() {
    // tuned's unit is fixed but tuned still runs with -l; tuned-ppd's unit
    // is not fixed yet.
    let decoy = Decoy::new();
    decoy.fedora_tuned().file(
        "/etc/systemd/system/tuned.service.d/50-journal.conf",
        TUNED_DROPIN,
    );
    let found = decoy.findings();
    assert_eq!(found.units, ["tuned-ppd.service"], "{found:?}");
    assert_eq!(found.programs, ["tuned"], "{found:?}");
    let result = decoy.check(false);
    let remediation = result.remediation().unwrap();
    for part in [
        "for each of tuned-ppd.service, add a drop-in",
        "systemctl restart tuned-ppd.service;",
        "and stop each tuned process that logs to a file and start it again without -l and -d, \
         its standard error sent to no file, as systemctl restart tuned.service does",
    ] {
        assert!(remediation.contains(part), "{part}: {remediation}");
    }
}

/// The drop-ins docs/decoy-requirements.md gives for tuned and tuned-ppd.
const TUNED_DROPIN: &str =
    "[Service]\nExecStart=\nExecStart=/usr/sbin/tuned -P\nStandardError=journal\n";
const PPD_DROPIN: &str =
    "[Service]\nExecStart=\nExecStart=/usr/sbin/tuned-ppd\nStandardError=journal\n";

#[test]
fn the_documented_drop_ins_clear_the_refusal_once_tuned_runs_again() {
    let decoy = Decoy::new();
    decoy
        .fedora_tuned()
        .file(
            "/etc/systemd/system/tuned.service.d/50-journal.conf",
            TUNED_DROPIN,
        )
        .file(
            "/etc/systemd/system/tuned-ppd.service.d/50-journal.conf",
            PPD_DROPIN,
        )
        // A drop-in that sends every service's standard output to a file
        // changes nothing: the standard error goes to the journal.
        .file(
            "/etc/systemd/system/service.d/50-log.conf",
            "[Service]\nStandardOutput=append:/var/log/daemons.log\n",
        );
    // Still running as started, with -l: the stop at the switch logs.
    let found = decoy.findings();
    assert_eq!(
        found.blockers,
        [
            logs_to(
                "tuned",
                "/var/log/tuned/tuned.log",
                "process 812 runs with -l"
            ),
            logs_to(
                "tuned-ppd",
                "/var/log/tuned/tuned-ppd.log",
                "process 900 runs with -l"
            ),
        ]
    );
    assert!(found.units.is_empty(), "{found:?}");
    assert_eq!(found.programs, ["tuned", "tuned-ppd"]);
    assert!(
        decoy.check(false).remediation().unwrap().starts_with(
            "Stop each tuned and tuned-ppd process that logs to a file and start it again \
             without -l and -d, its standard error sent to no file, as systemctl restart \
             tuned.service tuned-ppd.service does once its unit no longer makes it log to one"
        ),
        "{found:?}"
    );

    // Restarted, as `systemctl restart` does: their standard error is a
    // stream to the journal.
    decoy
        .process(
            812,
            "tuned",
            &["/usr/bin/python3", "-Es", "/usr/sbin/tuned", "-P"],
        )
        .link("/proc/812/fd/2", "socket:[24680]")
        .process(
            900,
            "tuned-ppd",
            &["/usr/bin/python3", "-Es", "/usr/sbin/tuned-ppd"],
        )
        .link("/proc/900/fd/2", "socket:[24681]");
    assert_eq!(decoy.findings(), Findings::default());
    assert!(decoy.check(false).is_pass(), "{:?}", decoy.check(false));
}

#[test]
fn tuned_without_a_log_file_refuses_where_its_standard_error_goes_to_one() {
    // Without -l or -d tuned logs every line to its standard error.
    let decoy = Decoy::new();
    decoy
        .unit("tuned.service", TUNED_UNIT)
        .enable("multi-user.target", "tuned.service")
        .file(
            "/etc/systemd/system/tuned.service.d/50-journal.conf",
            "[Service]\nExecStart=\nExecStart=/usr/sbin/tuned -P\n\
             StandardError=append:/var/log/tuned/tuned.log\n",
        );
    let found = decoy.findings();
    assert_eq!(
        found.blockers,
        [logs_to(
            "tuned",
            "/var/log/tuned/tuned.log",
            "tuned.service is enabled, with neither -l nor -d and \
             StandardError=append:/var/log/tuned/tuned.log"
        )]
    );
    assert_eq!(found.units, ["tuned.service"]);
    assert!(decoy.check(false).is_fail());

    // StandardError= left as systemd's default, inherit, follows a standard
    // output that a drop-in for every service sends to a file.
    let decoy = Decoy::new();
    decoy
        .unit("tuned.service", TUNED_UNIT)
        .unit("tuned-ppd.service", PPD_UNIT)
        .enable("multi-user.target", "tuned.service")
        .file(
            "/etc/systemd/system/service.d/50-log.conf",
            "[Service]\nStandardOutput=append:/var/log/daemons.log\n",
        )
        .file(
            "/etc/systemd/system/tuned.service.d/50-journal.conf",
            "[Service]\nExecStart=\nExecStart=/usr/sbin/tuned -P\n",
        )
        .file(
            "/etc/systemd/system/tuned-ppd.service.d/50-journal.conf",
            "[Service]\nExecStart=\nExecStart=/usr/sbin/tuned-ppd\n",
        );
    let found = decoy.findings();
    assert_eq!(
        found.blockers,
        [
            logs_to(
                "tuned",
                "/var/log/daemons.log",
                "tuned.service is enabled, with neither -l nor -d, StandardError= not set \
                 (inherit) and StandardOutput=append:/var/log/daemons.log"
            ),
            logs_to(
                "tuned-ppd",
                "/var/log/daemons.log",
                "tuned-ppd.service can start, as D-Bus starts it whenever a program asks for \
                 power profiles, with no -l, StandardError= not set (inherit) and \
                 StandardOutput=append:/var/log/daemons.log"
            ),
        ]
    );
    // The documented drop-ins send it to the journal.
    decoy
        .file(
            "/etc/systemd/system/tuned.service.d/50-journal.conf",
            TUNED_DROPIN,
        )
        .file(
            "/etc/systemd/system/tuned-ppd.service.d/50-journal.conf",
            PPD_DROPIN,
        );
    assert_eq!(decoy.findings(), Findings::default());

    // A tuned started by hand, its standard error a file.
    let decoy = Decoy::new();
    decoy
        .process(
            812,
            "tuned",
            &["/usr/bin/python3", "-Es", "/usr/sbin/tuned", "-P"],
        )
        .link("/proc/812/fd/1", "/dev/null")
        .link("/proc/812/fd/2", "/var/log/tuned/by-hand.log");
    let found = decoy.findings();
    assert_eq!(
        found.blockers,
        [logs_to(
            "tuned",
            "/var/log/tuned/by-hand.log",
            "process 812 runs with neither -l nor -d, its standard error being that file"
        )]
    );
    assert_eq!(found.programs, ["tuned"]);
    assert!(
        decoy
            .check(false)
            .remediation()
            .unwrap()
            .starts_with("Stop each tuned process that logs to a file"),
        "{found:?}"
    );
}

#[test]
fn a_disabled_tuned_still_starts_through_tuned_ppd_and_d_bus() {
    // Neither unit is enabled nor running: D-Bus starts tuned-ppd whenever a
    // desktop asks for power profiles, and tuned-ppd's unit needs tuned's.
    let decoy = Decoy::new();
    decoy
        .unit("tuned.service", TUNED_UNIT)
        .unit("tuned-ppd.service", PPD_UNIT);
    let found = decoy.findings();
    assert_eq!(
        found.blockers,
        [
            logs_to(
                "tuned",
                "/var/log/tuned/tuned.log",
                "tuned.service can start, as tuned-ppd.service needs it and D-Bus starts \
                 tuned-ppd.service whenever a program asks for power profiles, with -l"
            ),
            logs_to(
                "tuned-ppd",
                "/var/log/tuned/tuned-ppd.log",
                "tuned-ppd.service can start, as D-Bus starts it whenever a program asks for \
                 power profiles, with -l"
            ),
        ]
    );

    // A masked tuned-ppd leaves tuned to its own state: installed alone and
    // disabled, nothing starts it.
    decoy.mask("tuned-ppd.service");
    assert_eq!(decoy.findings(), Findings::default());
}

#[test]
fn a_masked_tuned_starts_by_no_route() {
    // `systemctl mask` without `disable` leaves the preset's links.
    let decoy = Decoy::new();
    decoy
        .unit("tuned.service", TUNED_UNIT)
        .unit("tuned-ppd.service", PPD_UNIT)
        .enable("multi-user.target", "tuned.service")
        .enable("graphical.target", "tuned-ppd.service")
        .mask("tuned.service")
        .mask("tuned-ppd.service");
    assert_eq!(decoy.findings(), Findings::default());
    // tuned-ppd needs tuned: with tuned masked, it cannot start either.
    let decoy = Decoy::new();
    decoy
        .unit("tuned.service", TUNED_UNIT)
        .unit("tuned-ppd.service", PPD_UNIT)
        .enable("graphical.target", "tuned-ppd.service")
        .mask("tuned.service");
    assert_eq!(decoy.findings(), Findings::default());
}

#[test]
fn what_nails_cannot_read_of_tuned_counts_as_a_log_file() {
    let decoy = Decoy::new();
    decoy
        .unit("tuned.service", TUNED_UNIT)
        .enable("multi-user.target", "tuned.service")
        .file(
            "/etc/systemd/system/tuned.service.d/50-wrapper.conf",
            "[Service]\nExecStart=\nExecStart=/usr/local/bin/start-tuned\n",
        );
    assert_eq!(
        decoy.findings().blockers,
        [
            "NAILS cannot tell whether tuned writes a log file on the decoy disk, so it counts as \
          one that does (tuned.service is enabled: its ExecStart= runs \
          /usr/local/bin/start-tuned, which is no tuned)"
        ]
    );

    let decoy = Decoy::new();
    decoy
        .unit("tuned.service", TUNED_UNIT)
        .active("tuned.service");
    decoy
        .fs
        .mock_set_unreadable_dir("/etc/systemd/system/tuned.service.d");
    let blockers = decoy.findings().blockers;
    assert_eq!(blockers.len(), 1, "{blockers:?}");
    assert!(
        blockers[0].starts_with(
            "NAILS cannot tell whether tuned writes a log file on the decoy disk, so it counts \
             as one that does (tuned.service is active: NAILS cannot list \
             /etc/systemd/system/tuned.service.d"
        ),
        "{blockers:?}"
    );

    // A process whose options NAILS cannot read.
    let decoy = Decoy::new();
    decoy.process(77, "tuned", &["/usr/bin/python3", "/usr/sbin/tuned", "--d"]);
    assert_eq!(
        decoy.findings().blockers,
        [
            "NAILS cannot tell whether tuned writes a log file on the decoy disk, so it counts as \
          one that does (process 77 runs: NAILS does not know its option --d)"
        ]
    );
}

#[test]
fn a_tuned_started_by_hand_is_seen_by_its_process() {
    let decoy = Decoy::new();
    decoy.process(
        4242,
        "tuned",
        &["/usr/bin/python3", "-Es", "/usr/sbin/tuned", "-d"],
    );
    let found = decoy.findings();
    assert_eq!(
        found.blockers,
        [logs_to(
            "tuned",
            "/var/log/tuned/tuned.log",
            "process 4242 runs with -d, which logs to a file as -l does"
        )]
    );
    assert!(found.units.is_empty());
    // A process of another name is not tuned's.
    let decoy = Decoy::new();
    decoy.process(
        4243,
        "tuned-adm",
        &["/usr/bin/python3", "/usr/sbin/tuned-adm", "-l"],
    );
    assert_eq!(decoy.findings(), Findings::default());
}

#[test]
fn tuned_on_nixos_is_fixed_in_the_configuration() {
    assert_eq!(
        tuned_fix(&["tuned.service"], &[], true),
        "make tuned log to the journal: set services.tuned.enable = false in the decoy \
         configuration, or there clear ExecStart= of systemd.services.tuned (and of \
         systemd.services.tuned-ppd) and set it again without -l, with StandardError= set to \
         journal, then run nixos-rebuild switch"
    );
    // A tuned-ppd only its process shows has no -d to drop.
    assert_eq!(
        tuned_fix(&[], &["tuned-ppd"], false),
        "stop each tuned-ppd process that logs to a file and start it again without -l, its \
         standard error sent to no file, as systemctl restart tuned-ppd.service does once its \
         unit no longer makes it log to one"
    );
}

/// firewalld's warning of its default log target, shown by `sources`.
fn firewalld_logs(sources: &str, fix: &str) -> String {
    format!(
        "firewalld writes its warnings and errors to /var/log/firewalld ({sources}), so what it \
         logs when it stops or starts around a switch stays on the decoy disk with the time; \
         make it log to the journal: {fix}, then restart it (systemctl restart \
         firewalld.service)"
    )
}

#[test]
fn fedora_firewalld_warns_of_its_log_file_and_names_its_sysconfig() {
    let decoy = Decoy::new();
    decoy.fedora_firewalld();
    let found = decoy.findings();
    assert_eq!(
        found.warnings,
        [firewalld_logs(
            "firewalld.service is enabled and active, with the log target mixed, the default; \
             process 700 runs with the log target mixed, the default",
            "add --log-target=syslog to FIREWALLD_ARGS in /etc/sysconfig/firewalld"
        )]
    );
    assert!(found.blockers.is_empty(), "{found:?}");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(result.message().contains(&found.warnings[0]), "{result:?}");
}

#[test]
fn a_drop_in_under_the_alias_systemctl_enable_links_counts() {
    // Fedora's firewalld.service has Alias=dbus-org.fedoraproject.FirewallD1.service,
    // which `systemctl enable` and the preset link, and the service manager
    // reads the drop-ins of every name of a unit.
    let decoy = Decoy::new();
    decoy
        .unit("firewalld.service", FIREWALLD_UNIT)
        .file(
            "/etc/sysconfig/firewalld",
            "FIREWALLD_ARGS=--log-target=syslog\n",
        )
        .enable("multi-user.target", "firewalld.service")
        .link(
            "/etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service",
            "/usr/lib/systemd/system/firewalld.service",
        );
    assert_eq!(decoy.findings(), Findings::default());
    decoy.file(
        "/etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service.d/50-file.conf",
        "[Service]\nExecStart=\nExecStart=/usr/bin/firewalld --nofork --nopid --log-target=file\n",
    );
    let warnings = decoy.findings().warnings;
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].starts_with(
            "firewalld writes every message it logs to /var/log/firewalld (firewalld.service is \
             enabled, with --log-target=file)"
        ),
        "{warnings:?}"
    );
}

#[test]
fn firewalld_on_nixos_is_fixed_in_the_configuration() {
    // NixOS's firewalld module writes /etc/sysconfig/firewalld from
    // services.firewalld.extraArgs.
    let decoy = Decoy::new();
    decoy.fedora_firewalld();
    assert_eq!(
        findings(&decoy.fs, Path::new("/"), &[], true).warnings,
        [firewalld_logs(
            "firewalld.service is enabled and active, with the log target mixed, the default; \
             process 700 runs with the log target mixed, the default",
            "set services.firewalld.extraArgs = [ \"--log-target=syslog\" ] in the decoy \
             configuration and run nixos-rebuild switch"
        )]
    );
}

#[test]
fn firewalld_logging_to_syslog_passes_once_it_runs_so() {
    let decoy = Decoy::new();
    decoy.fedora_firewalld().file(
        "/etc/sysconfig/firewalld",
        "# firewalld command line args\nFIREWALLD_ARGS=\"--log-target=syslog\"\n",
    );
    // Still running as started.
    assert_eq!(
        decoy.findings().warnings,
        [firewalld_logs(
            "process 700 runs with the log target mixed, the default",
            "add --log-target=syslog to FIREWALLD_ARGS in /etc/sysconfig/firewalld"
        )]
    );
    let mut argv = FIREWALLD_ARGV.to_vec();
    argv.push("--log-target=syslog");
    decoy.process(700, "firewalld", &argv);
    assert_eq!(decoy.findings(), Findings::default());
    assert!(decoy.check(false).is_pass(), "{:?}", decoy.check(false));
}

#[test]
fn firewalld_without_its_sysconfig_cannot_be_told_but_warns() {
    let decoy = Decoy::new();
    decoy
        .unit("firewalld.service", FIREWALLD_UNIT)
        .enable("multi-user.target", "firewalld.service");
    assert_eq!(
        decoy.findings().warnings,
        [
            "NAILS cannot tell whether firewalld writes a log file on the decoy disk \
          (firewalld.service is enabled: NAILS cannot read its ExecStart=/usr/bin/firewalld \
          --nofork --nopid $FIREWALLD_ARGS (it takes an argument from $FIREWALLD_ARGS, which the \
          unit itself does not set)), so what it logs when it stops or starts around a switch \
          stays on the decoy disk with the time; make it log to the journal: add \
          --log-target=syslog to its ExecStart= in a drop-in, then restart it (systemctl restart \
          firewalld.service)"
        ]
    );
    // Disabled and stopped, it starts by nothing NAILS reads.
    let decoy = Decoy::new();
    decoy.unit("firewalld.service", FIREWALLD_UNIT);
    assert_eq!(decoy.findings(), Findings::default());
}

#[test]
fn firewalld_logging_to_its_standard_output_is_judged_by_where_it_goes() {
    let decoy = Decoy::new();
    decoy
        .unit("firewalld.service", FIREWALLD_UNIT)
        .file(
            "/etc/sysconfig/firewalld",
            "FIREWALLD_ARGS=--log-target=console\n",
        )
        .enable("multi-user.target", "firewalld.service");
    // Its unit sends the standard output to /dev/null.
    assert_eq!(decoy.findings(), Findings::default());
    decoy.file(
        "/etc/systemd/system/firewalld.service.d/50-out.conf",
        "[Service]\nStandardOutput=append:/var/log/fw.log\n",
    );
    let warnings = decoy.findings().warnings;
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].starts_with(
            "firewalld writes its log to /var/log/fw.log (firewalld.service is enabled, with the \
             log target console and StandardOutput=append:/var/log/fw.log)"
        ),
        "{warnings:?}"
    );

    // A process: where its standard output leads.
    let decoy = Decoy::new();
    let mut argv = FIREWALLD_ARGV.to_vec();
    argv.push("--log-target=console");
    decoy
        .process(701, "firewalld", &argv)
        .link("/proc/701/fd/1", "/dev/null");
    assert_eq!(decoy.findings(), Findings::default());
    decoy
        .process(702, "firewalld", &argv)
        .link("/proc/702/fd/1", "/var/log/fw-out.log");
    let warnings = decoy.findings().warnings;
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].starts_with(
            "firewalld writes its log to /var/log/fw-out.log (process 702 runs with the log \
             target console, its standard output being that file)"
        ),
        "{warnings:?}"
    );
}

/// ABRT's warning, shown by `signs`.
fn abrt_in_use(signs: &str) -> String {
    format!(
        "ABRT is in use on the decoy ({signs}): it keeps crash reports in its dump location \
         (/var/spool/abrt unless DumpLocation in /etc/abrt/abrt.conf names another) on the \
         decoy disk, made from the core dumps systemd-coredump keeps of the programs packages \
         install, the kernel oops messages in the journal and, each time it starts, the crash \
         records pstore holds, so a crash on the decoy around a switch, dated then, or a crash \
         record of the hidden session that pstore kept lands there; turn it off with systemctl \
         disable --now abrtd.service, which the other ABRT units need"
    )
}

#[test]
fn abrt_in_use_warns() {
    let decoy = Decoy::new();
    decoy
        .unit("abrtd.service", ABRTD_UNIT_FILE)
        .enable("multi-user.target", "abrtd.service")
        .active("abrtd.service")
        .process(655, "abrtd", &["/usr/sbin/abrtd", "-d", "-s"]);
    assert_eq!(
        decoy.findings().warnings,
        [abrt_in_use(
            "abrtd.service is enabled and active; process 655 is abrtd"
        )]
    );
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");

    // A unit that runs no abrtd, and a disabled one, show none.
    let decoy = Decoy::new();
    decoy
        .unit("abrtd.service", ABRTD_UNIT_FILE)
        .enable("multi-user.target", "abrtd.service")
        .file(
            "/etc/systemd/system/abrtd.service.d/50-off.conf",
            "[Service]\nExecStart=\nExecStart=/bin/true\n",
        );
    assert_eq!(decoy.findings(), Findings::default());
    let decoy = Decoy::new();
    decoy.unit("abrtd.service", ABRTD_UNIT_FILE);
    assert_eq!(decoy.findings(), Findings::default());
}

/// The drop-in Ubuntu's apport package installs as
/// `/usr/lib/systemd/system/systemd-coredump@.service.d/apport-coredump-hook.conf`
/// (apport 2.28.3 in 24.04, 2.34.1 in 26.04), comments left out.
const APPORT_HOOK_DROPIN: &str = "[Unit]\nOnSuccess=apport-coredump-hook@%i.service\n";

/// The warning of a unit systemd-coredump starts for each crash, as `hooks`
/// and `masks` name it.
fn hook_warning(hooks: &str, masks: &str) -> String {
    format!(
        "systemd-coredump starts {hooks} for each crash, which NAILS does not judge: such a \
         unit can read every crash from the journal, where systemd-coredump logs it even with \
         Storage=none and ProcessSizeMax=0, and Ubuntu's apport-coredump-hook@.service does, \
         logging the path and the command line of each program that crashed to \
         /var/log/apport.log, with the time, and for a program a package installed writing a \
         report of the crash to /var/crash, on the decoy disk; mask it (systemctl mask {masks})"
    )
}

#[test]
fn a_unit_systemd_coredump_starts_for_each_crash_warns_until_it_is_masked() {
    // Ubuntu with systemd-coredump installed: the kernel pipes to it, and
    // its settings keep nothing.
    let decoy = Decoy::new();
    decoy
        .file(
            CORE_PATTERN,
            "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %d\n",
        )
        .file(
            "/etc/systemd/coredump.conf.d/50-discard.conf",
            "[Coredump]\nStorage=none\nProcessSizeMax=0\n",
        )
        .unit(
            "systemd-coredump@.service",
            "[Unit]\nDescription=Process Core Dump\n\n[Service]\n\
             ExecStart=-/usr/lib/systemd/systemd-coredump\n",
        );
    assert!(decoy.check(false).is_pass(), "{:?}", decoy.check(false));

    // apport's hook reads each crash from the journal, whether apport.service
    // runs or not.
    decoy
        .file(
            "/usr/lib/systemd/system/systemd-coredump@.service.d/apport-coredump-hook.conf",
            APPORT_HOOK_DROPIN,
        )
        .unit(
            "apport-coredump-hook@.service",
            "[Service]\nType=oneshot\nExecStart=/usr/share/apport/apport \
             --from-systemd-coredump %i\n",
        );
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    let warning = hook_warning(
        "apport-coredump-hook@%i.service (OnSuccess=)",
        "apport-coredump-hook@.service",
    );
    assert!(result.message().contains(&warning), "{result:?}");
    // The hook alone warns: coredump.conf keeps nothing.
    assert!(
        !result.message().contains("/var/lib/systemd/coredump"),
        "{result:?}"
    );

    // Masked by its template, the hook never starts.
    decoy.mask("apport-coredump-hook@.service");
    assert!(decoy.check(false).is_pass(), "{:?}", decoy.check(false));

    // A drop-in left behind by a hook that is not installed starts nothing,
    // while one NAILS cannot resolve, a unit named with a specifier other
    // than the instance, still counts.
    let decoy = Decoy::new();
    decoy
        .file(CORE_PATTERN, "|/usr/lib/systemd/systemd-coredump %P\n")
        .file(
            "/etc/systemd/coredump.conf",
            "[Coredump]\nStorage=none\nProcessSizeMax=0\n",
        )
        .unit("systemd-coredump@.service", "[Unit]\nDescription=x\n")
        .file(
            "/etc/systemd/system/systemd-coredump@.service.d/50-hook.conf",
            "[Unit]\nOnSuccess=gone@%i.service\nOnFailure=\nOnFailure=%N-notify.service\n",
        );
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(&hook_warning(
            "%N-notify.service (OnFailure=)",
            "%N-notify.service"
        )),
        "{result:?}"
    );
    assert!(!result.message().contains("gone@"), "{result:?}");

    // A section NAILS cannot read warns too.
    let decoy = Decoy::new();
    decoy
        .file(CORE_PATTERN, "|/usr/lib/systemd/systemd-coredump %P\n")
        .file(
            "/etc/systemd/coredump.conf",
            "[Coredump]\nStorage=none\nProcessSizeMax=0\n",
        )
        .unit("systemd-coredump@.service", "[Unit]\nDescription=x\n");
    decoy
        .fs
        .mock_set_unreadable_dir("/etc/systemd/system/systemd-coredump@.service.d");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(
            "NAILS cannot tell which units systemd-coredump starts for each crash (NAILS cannot \
             list /etc/systemd/system/systemd-coredump@.service.d"
        ),
        "{result:?}"
    );

    // A pattern to another handler leaves systemd-coredump's units unread.
    let decoy = Decoy::new();
    decoy
        .file(CORE_PATTERN, "core\n")
        .unit("systemd-coredump@.service", "[Unit]\nDescription=x\n")
        .file(
            "/usr/lib/systemd/system/systemd-coredump@.service.d/apport-coredump-hook.conf",
            APPORT_HOOK_DROPIN,
        )
        .unit(
            "apport-coredump-hook@.service",
            "[Service]\nType=oneshot\nExecStart=/bin/true\n",
        );
    assert!(decoy.check(false).is_pass(), "{:?}", decoy.check(false));
}

/// A decoy whose kernel pipes core dumps to systemd-coredump, set to keep
/// nothing, with its stock unit.
fn coredump_decoy() -> Decoy {
    let decoy = Decoy::new();
    decoy
        .file(
            CORE_PATTERN,
            "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %d\n",
        )
        .file(
            "/etc/systemd/coredump.conf.d/50-discard.conf",
            "[Coredump]\nStorage=none\nProcessSizeMax=0\n",
        )
        .unit(
            "systemd-coredump@.service",
            "[Unit]\nDescription=Process Core Dump\nRequires=systemd-journald.socket\n\n\
             [Service]\nExecStart=-/usr/lib/systemd/systemd-coredump\n",
        );
    decoy
}

#[test]
fn a_unit_systemd_coredump_pulls_in_for_each_crash_warns_too() {
    // The socket the stock unit requires is no hook.
    let decoy = coredump_decoy();
    assert!(decoy.check(false).is_pass(), "{:?}", decoy.check(false));

    // KDE's DrKonqi links its processor into systemd-coredump@.service.wants.
    decoy
        .unit(
            "drkonqi-coredump-processor@.service",
            "[Service]\nExecStart=/usr/libexec/drkonqi-coredump-processor --boot-id %b \
             --instance %i\n\n[Install]\nWantedBy=systemd-coredump@.service\n",
        )
        .link(
            "/usr/lib/systemd/system/systemd-coredump@.service.wants/\
             drkonqi-coredump-processor@.service",
            "/usr/lib/systemd/system/drkonqi-coredump-processor@.service",
        );
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(&hook_warning(
            "drkonqi-coredump-processor@.service in systemd-coredump@.service.wants",
            "drkonqi-coredump-processor@.service"
        )),
        "{result:?}"
    );
    decoy.mask("drkonqi-coredump-processor@.service");
    assert!(decoy.check(false).is_pass(), "{:?}", decoy.check(false));

    // A link to /dev/null in the directory masks that dependency alone; a
    // service a drop-in wants with it counts.
    let decoy = coredump_decoy();
    decoy
        .link(
            "/etc/systemd/system/systemd-.service.wants/drkonqi-coredump-processor@.service",
            "/dev/null",
        )
        .unit(
            "drkonqi-coredump-processor@.service",
            "[Service]\nExecStart=/bin/true\n",
        )
        .unit("crash-mailer.service", "[Service]\nExecStart=/bin/true\n")
        .file(
            "/etc/systemd/system/systemd-coredump@.service.d/50-mail.conf",
            "[Unit]\nWants=crash-mailer.service network.target\n",
        );
    let result = decoy.check(false);
    assert!(
        result.message().contains(&hook_warning(
            "crash-mailer.service (Wants=)",
            "crash-mailer.service"
        )),
        "{result:?}"
    );
    assert!(!result.message().contains("drkonqi"), "{result:?}");
    assert!(!result.message().contains("network.target"), "{result:?}");
}

/// apport.service of Ubuntu 26.04's apport-core-dump-handler 2.34.1 and of
/// 24.04's apport 2.28.3, which are the same.
const APPORT_UNIT: &str = "[Unit]\nDescription=automatic crash report generation\n\
                           After=remote-fs.target\nConditionVirtualization=!container\n\n\
                           [Service]\nType=oneshot\nRemainAfterExit=yes\n\
                           ExecStart=/usr/share/apport/apport --start\n\
                           ExecStop=/usr/share/apport/apport --stop\n\n\
                           [Install]\nWantedBy=multi-user.target\n";

/// The pattern `apport --start` sets.
const APPORT_PATTERN: &str =
    "|/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -F%F -- %E\n";

#[test]
fn an_enabled_apport_warns_though_it_is_stopped() {
    // `systemctl stop apport.service` sets the pattern back to core and
    // leaves the unit enabled: the decoy starts it again after the way back.
    let decoy = Decoy::new();
    decoy
        .file(CORE_PATTERN, "core\n")
        .unit("apport.service", APPORT_UNIT)
        .enable("multi-user.target", "apport.service");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(
            "apport.service is enabled, though kernel.core_pattern does not name apport now: \
             when the decoy starts after the way back, it sets the pattern to apport's pipe \
             again, and apport logs the path and the command line of each program that crashes \
             from then on to /var/log/apport.log on the decoy disk; turn it off with systemctl \
             disable --now apport.service"
        ),
        "{result:?}"
    );
    // Running, it is named once, by the pattern.
    decoy.file(CORE_PATTERN, APPORT_PATTERN);
    let result = decoy.check(false);
    assert!(
        result
            .message()
            .contains("kernel.core_pattern hands core dumps to a handler other than"),
        "{result:?}"
    );
    assert!(
        !result.message().contains("apport.service is enabled"),
        "{result:?}"
    );
    // Disabled, masked or not installed, it starts nothing.
    let decoy = Decoy::new();
    decoy
        .file(CORE_PATTERN, "core\n")
        .unit("apport.service", APPORT_UNIT);
    assert!(decoy.check(false).is_pass(), "{:?}", decoy.check(false));
    decoy
        .enable("multi-user.target", "apport.service")
        .link("/run/systemd/system/apport.service", "/dev/null");
    assert!(decoy.check(false).is_pass(), "{:?}", decoy.check(false));
    let decoy = Decoy::new();
    decoy
        .file(CORE_PATTERN, "core\n")
        .enable("multi-user.target", "apport.service");
    assert!(decoy.check(false).is_pass(), "{:?}", decoy.check(false));
}

#[test]
fn a_pattern_sysctl_d_sets_again_at_the_way_back_warns() {
    // systemd-sysctl applies sysctl.d again when the decoy starts after the
    // way back; here the pattern in force was set to core by hand.
    let decoy = Decoy::new();
    decoy.file(CORE_PATTERN, "core\n").file(
        "/etc/sysctl.d/90-crash.conf",
        "kernel.core_pattern=/var/crash/core.%e.%p.%t\n",
    );
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(
            "/etc/sysctl.d/90-crash.conf sets kernel.core_pattern to /var/crash/core.%e.%p.%t \
             when the decoy starts again after the way back, though another pattern is in force \
             now: kernel.core_pattern writes core dumps to the decoy disk \
             (/var/crash/core.%e.%p.%t)"
        ),
        "{result:?}"
    );
    // The pattern in force is judged once, where the files set it too, as
    // Fedora's systemd does.
    let decoy = coredump_decoy();
    decoy.file(
        "/usr/lib/sysctl.d/50-coredump.conf",
        "kernel.core_pattern=|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %d\n",
    );
    assert!(decoy.check(false).is_pass(), "{:?}", decoy.check(false));
    decoy.file(
        "/etc/systemd/coredump.conf.d/50-discard.conf",
        "[Coredump]\nStorage=none\n",
    );
    let result = decoy.check(false);
    assert_eq!(
        result
            .message()
            .matches("systemd-coredump still writes")
            .count(),
        1,
        "{result:?}"
    );
}

#[test]
fn the_fedora_44_cloud_decoy_the_probe_recorded_refuses_for_auditd_alone() {
    // nix/distro-tests/probe/fedora-44.json: auditd enabled and active, its
    // unit refusing a manual stop; tuned, firewalld and abrtd not found. The
    // journal made volatile, as the docs ask.
    let decoy = Decoy::new();
    decoy
        .unit(
            "auditd.service",
            "[Unit]\nRefuseManualStop=yes\n[Service]\nType=forking\nExecStart=/usr/bin/auditd\n",
        )
        .enable("multi-user.target", "auditd.service")
        .active("auditd.service");
    assert_eq!(decoy.findings(), Findings::default());
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        result.message(),
        "decoy keeps a persistent record of the hidden session: auditd is active and writes \
         audit records to the decoy disk."
    );
    assert!(
        result.remediation().unwrap().starts_with(
            "Turn auditd off for good, without a reboot (systemctl disable auditd.service and \
             systemctl mask auditd.service, then auditctl --signal stop"
        ),
        "{result:?}"
    );
}

#[test]
fn processes_are_read_in_the_order_of_their_numbers_and_only_by_their_names() {
    let decoy = Decoy::new();
    decoy
        .process(1000, "firewalld", &["/usr/bin/firewalld"])
        .process(99, "abrtd", &["/usr/sbin/abrtd"])
        .process(5, "bash", &["/bin/bash"])
        .file("/proc/self/comm", "abrtd\n")
        // Run through its interpreter, by hand or by a unit of another name.
        .process(
            4242,
            "python3",
            &["/usr/bin/python3", "-Es", "/usr/sbin/tuned", "-l", "-P"],
        )
        // Other Python programs are not read.
        .process(4243, "python3", &["/usr/bin/python3", "/usr/bin/dnf", "-y"])
        .process(4244, "python3.14", &["/usr/bin/python3.14", "-m", "tuned"])
        // NixOS's wrapper names the script .tuned-wrapped, and the kernel cuts
        // .tuned-ppd-wrapped to 15 bytes.
        .process(
            300,
            ".tuned-wrapped",
            &[
                "/nix/store/abc-python3-3.13.9/bin/python3.13",
                "/nix/store/def-tuned-2.27.0/bin/.tuned-wrapped",
                "-l",
                "-P",
            ],
        )
        .process(
            301,
            ".tuned-ppd-wrap",
            &[
                "/nix/store/abc-python3-3.13.9/bin/python3.13",
                "/nix/store/def-tuned-2.27.0/bin/.tuned-ppd-wrapped",
            ],
        )
        .link("/proc/301/fd/2", "socket:[24682]");
    let processes = processes::processes(&decoy.fs, Path::new("/"), PROCESS_NAMES, PYTHON_SCRIPTS);
    assert_eq!(processes.unread, None);
    let found = processes.found;
    let names: Vec<(&str, &str)> = found
        .iter()
        .map(|process| (process.pid.as_str(), process.name))
        .collect();
    assert_eq!(
        names,
        [
            ("99", "abrtd"),
            ("300", "tuned"),
            ("301", "tuned-ppd"),
            ("1000", "firewalld"),
            ("4242", "tuned"),
        ]
    );
    assert_eq!(
        decoy.findings().blockers,
        [logs_to(
            "tuned",
            "/var/log/tuned/tuned.log",
            "process 300 runs with -l; process 4242 runs with -l"
        )]
    );
    assert_eq!(
        found[0].argv,
        Ok(vec![b"/usr/sbin/abrtd".to_vec()]),
        "the NUL that ends the last word is no word"
    );
}

/// The link that would enable `unit` for multi-user.target, in a directory
/// that holds another unit's link, so that the directory is listed.
fn unseen_link(decoy: &Decoy, unit: &str) -> String {
    decoy.enable("multi-user.target", "sshd.service");
    let link = format!("/etc/systemd/system/multi-user.target.wants/{unit}");
    decoy.lookup_error(&link, std::io::ErrorKind::PermissionDenied);
    link
}

/// Why NAILS cannot tell whether `unit` is enabled, its link `link` being
/// one it may not look up.
fn untold_enabled(unit: &str, link: &str) -> String {
    format!(
        "NAILS cannot tell whether {unit} is enabled: NAILS cannot look up {link}; run the command \
         again with sudo"
    )
}

#[test]
fn a_tuned_nails_cannot_tell_is_enabled_refuses_where_it_would_log_to_a_file() {
    let decoy = Decoy::new();
    decoy.unit("tuned.service", TUNED_UNIT);
    let link = unseen_link(&decoy, "tuned.service");
    let found = decoy.findings();
    assert_eq!(
        found.blockers,
        [format!(
            "NAILS cannot tell whether tuned writes a log file on the decoy disk, so it counts as \
             one that does (tuned.service would start it with -l, which logs to \
             /var/log/tuned/tuned.log, and {})",
            untold_enabled("tuned.service", &link)
        )]
    );
    assert_eq!(found.units, ["tuned.service"]);
    let tuned = blockers(&decoy.fs, Path::new("/"), &[]);
    assert!(
        tuned
            .blockers
            .iter()
            .all(|finding| finding.untold.is_some()),
        "{tuned:?}"
    );
    let result = decoy.check(false);
    assert!(
        result
            .message()
            .starts_with("decoy keeps, or may keep, a persistent record"),
        "{result:?}"
    );
    assert_eq!(
        result.allowable(),
        Some(nails_api::Allowable::PersistentDecoy)
    );
    // Started without -l and with its standard error sent to the journal, it
    // would log to no file, so whether it starts decides nothing.
    decoy.file(
        "/etc/systemd/system/tuned.service.d/50-journal.conf",
        TUNED_DROPIN,
    );
    assert_eq!(decoy.findings(), Findings::default());
}

#[test]
fn a_daemon_nails_cannot_tell_starts_counts_only_where_it_is_installed() {
    // The same link NAILS may not look up, for daemons that are not there.
    let decoy = Decoy::new();
    for unit in [
        "tuned.service",
        "tuned-ppd.service",
        "firewalld.service",
        "abrtd.service",
        "apport.service",
    ] {
        unseen_link(&decoy, unit);
    }
    assert_eq!(decoy.findings(), Findings::default());
    assert!(decoy.check(false).is_pass(), "{:?}", decoy.check(false));
}

#[test]
fn a_tuned_nails_cannot_tell_runs_refuses_where_it_would_log_to_a_file() {
    let decoy = Decoy::new();
    decoy.unit("tuned.service", TUNED_UNIT).lookup_error(
        "/run/systemd/units/invocation:tuned.service",
        std::io::ErrorKind::PermissionDenied,
    );
    assert_eq!(
        decoy.findings().blockers,
        [
            "NAILS cannot tell whether tuned writes a log file on the decoy disk, so it counts as \
          one that does (tuned.service would start it with -l, which logs to \
          /var/log/tuned/tuned.log, and NAILS cannot tell whether tuned.service runs: NAILS \
          cannot look up /run/systemd/units/invocation:tuned.service; run the command again \
          with sudo)"
        ]
    );
}

#[test]
fn a_firewalld_or_abrt_nails_cannot_tell_is_enabled_warns() {
    let decoy = Decoy::new();
    decoy
        .unit("firewalld.service", FIREWALLD_UNIT)
        .file("/etc/sysconfig/firewalld", FIREWALLD_SYSCONFIG)
        .unit("abrtd.service", ABRTD_UNIT_FILE);
    let firewalld = unseen_link(&decoy, "firewalld.service");
    let abrtd = unseen_link(&decoy, "abrtd.service");
    let warnings = decoy.findings().warnings;
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(
        warnings[0].starts_with(&format!(
            "NAILS cannot tell whether firewalld writes a log file on the decoy disk \
             (firewalld.service would start it with the log target mixed, the default, which \
             logs to /var/log/firewalld, and {}), so ",
            untold_enabled("firewalld.service", &firewalld)
        )),
        "{warnings:?}"
    );
    assert!(
        warnings[0]
            .contains("add --log-target=syslog to FIREWALLD_ARGS in /etc/sysconfig/firewalld"),
        "{warnings:?}"
    );
    assert!(
        warnings[1].starts_with(&format!(
            "ABRT may be in use on the decoy ({}): it keeps crash reports",
            untold_enabled("abrtd.service", &abrtd)
        )),
        "{warnings:?}"
    );
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
}

#[test]
fn an_apport_nails_cannot_tell_is_enabled_warns() {
    let decoy = Decoy::new();
    decoy
        .file(CORE_PATTERN, "core\n")
        .unit("apport.service", APPORT_UNIT);
    let link = unseen_link(&decoy, "apport.service");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(&format!(
            "apport.service may be enabled ({}), though kernel.core_pattern does not name apport \
             now",
            untold_enabled("apport.service", &link)
        )),
        "{result:?}"
    );
}

#[test]
fn a_program_that_runs_tuned_or_firewalld_in_turn_counts_against_the_decoy() {
    // e2fsprogs' logsave and util-linux's script copy what the command
    // writes to its standard output and standard error into a file.
    for (exec, program) in [
        (
            "/usr/sbin/logsave -a /var/log/tuned/tuned.log /usr/sbin/tuned -P",
            "/usr/sbin/logsave",
        ),
        (
            "/usr/bin/script -q -a /var/log/tuned/typescript -c /usr/sbin/tuned",
            "/usr/bin/script",
        ),
    ] {
        let decoy = Decoy::new();
        decoy
            .unit("tuned.service", TUNED_UNIT)
            .enable("multi-user.target", "tuned.service")
            .file(
                "/etc/systemd/system/tuned.service.d/50-wrap.conf",
                &format!("[Service]\nExecStart=\nExecStart={exec}\nStandardError=journal\n"),
            );
        assert_eq!(
            decoy.findings().blockers,
            [format!(
                "NAILS cannot tell whether tuned writes a log file on the decoy disk, so it \
                 counts as one that does (tuned.service is enabled: its ExecStart= runs \
                 {program}, which is no tuned)"
            )],
            "{exec}"
        );
    }

    let decoy = Decoy::new();
    decoy
        .unit("firewalld.service", FIREWALLD_UNIT)
        .file("/etc/sysconfig/firewalld", FIREWALLD_SYSCONFIG)
        .enable("multi-user.target", "firewalld.service")
        .file(
            "/etc/systemd/system/firewalld.service.d/50-logsave.conf",
            "[Service]\nExecStart=\nExecStart=/usr/sbin/logsave -a /var/log/firewalld.log \
             /usr/bin/firewalld --nofork --nopid --log-target=console\n",
        );
    let warnings = decoy.findings().warnings;
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].starts_with(
            "NAILS cannot tell whether firewalld writes a log file on the decoy disk \
             (firewalld.service is enabled: its ExecStart= runs /usr/sbin/logsave, which is no \
             firewalld)"
        ),
        "{warnings:?}"
    );
}

#[test]
fn a_tuned_whose_standard_error_is_a_pipe_counts_against_the_decoy() {
    // Started by hand as `tuned -P 2>&1 | tee -a /var/log/tuned-run.log`,
    // its units set to log to the journal.
    let decoy = Decoy::new();
    decoy
        .fedora_tuned()
        .file(
            "/etc/systemd/system/tuned.service.d/50-journal.conf",
            TUNED_DROPIN,
        )
        .file(
            "/etc/systemd/system/tuned-ppd.service.d/50-journal.conf",
            PPD_DROPIN,
        )
        .process(
            812,
            "tuned",
            &["/usr/bin/python3", "-Es", "/usr/sbin/tuned", "-P"],
        )
        .link("/proc/812/fd/2", "pipe:[4242]")
        .process(813, "tee", &["tee", "-a", "/var/log/tuned-run.log"])
        .link("/proc/813/fd/0", "pipe:[4242]")
        .link("/proc/813/fd/3", "/var/log/tuned-run.log")
        .process(
            900,
            "tuned-ppd",
            &["/usr/bin/python3", "-Es", "/usr/sbin/tuned-ppd"],
        )
        .link("/proc/900/fd/2", "socket:[24681]");
    let found = decoy.findings();
    assert_eq!(
        found.blockers,
        [
            "NAILS cannot tell whether tuned writes a log file on the decoy disk, so it counts as \
          one that does (process 812 runs: it logs to its standard error, a pipe, which NAILS \
          cannot follow past the process that reads it)"
        ]
    );
    assert_eq!(found.programs, ["tuned"]);
    assert!(decoy.check(false).is_fail(), "{:?}", decoy.check(false));
}

#[test]
fn a_tuned_that_logs_to_the_null_device_logs_to_no_file() {
    for dropin in [
        "[Service]\nExecStart=\nExecStart=/usr/sbin/tuned -P\nStandardError=file:/dev/null\n",
        "[Service]\nExecStart=\nExecStart=/usr/sbin/tuned -l /dev/null -P\n",
    ] {
        let decoy = Decoy::new();
        decoy
            .unit("tuned.service", TUNED_UNIT)
            .enable("multi-user.target", "tuned.service")
            .file("/etc/systemd/system/tuned.service.d/50-null.conf", dropin);
        assert_eq!(decoy.findings(), Findings::default(), "{dropin}");
        assert!(decoy.check(false).is_pass(), "{dropin}");
    }
}

#[test]
fn a_process_nails_cannot_read_counts_where_the_daemon_is_installed() {
    // /proc mounted with hidepid=1 lists other users' processes but lets
    // no one else read them.
    let decoy = Decoy::new();
    decoy
        .process(812, "tuned", TUNED_ARGV)
        .process(813, "sshd", &["/usr/sbin/sshd", "-D"])
        .lookup_error("/proc/812/comm", std::io::ErrorKind::PermissionDenied)
        .lookup_error("/proc/813/comm", std::io::ErrorKind::PermissionDenied);
    // No daemon is installed: nothing counts.
    assert_eq!(decoy.findings(), Findings::default());
    let why = "a process NAILS cannot read may run tuned: NAILS cannot read /proc/812/comm, nor \
               the name of 1 more process; run the command again with sudo";
    decoy
        .unit("tuned.service", TUNED_UNIT)
        .mask("tuned.service");
    assert_eq!(
        decoy.findings().blockers,
        [format!(
            "NAILS cannot tell whether tuned writes a log file on the decoy disk, so it counts as \
             one that does ({why})"
        )]
    );
    decoy
        .unit("firewalld.service", FIREWALLD_UNIT)
        .unit("abrtd.service", ABRTD_UNIT_FILE)
        .mask("firewalld.service")
        .mask("abrtd.service");
    let warnings = decoy.findings().warnings;
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(
        warnings[0].starts_with(
            "NAILS cannot tell whether firewalld writes a log file on the decoy disk (a process \
             NAILS cannot read may run firewalld: "
        ),
        "{warnings:?}"
    );
    assert!(
        warnings[1].starts_with(
            "ABRT may be in use on the decoy (a process NAILS cannot read may be abrtd: NAILS \
             cannot read /proc/812/comm"
        ),
        "{warnings:?}"
    );
}

#[test]
fn a_hook_link_nails_cannot_look_up_warns() {
    // A dependency directory NAILS may list but not search, as a 0644 one
    // is to anyone but root.
    let link = "/usr/lib/systemd/system/systemd-coredump@.service.wants/\
                drkonqi-coredump-processor@.service";
    let decoy = coredump_decoy();
    decoy
        .unit(
            "drkonqi-coredump-processor@.service",
            "[Service]\nExecStart=/usr/libexec/drkonqi-coredump-processor\n",
        )
        .link(
            link,
            "/usr/lib/systemd/system/drkonqi-coredump-processor@.service",
        )
        .lookup_error(link, std::io::ErrorKind::PermissionDenied);
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().contains(&format!(
            "NAILS cannot tell which units systemd-coredump starts for each crash (NAILS cannot \
             look up {link}; run the command again with sudo)"
        )),
        "{result:?}"
    );
}

#[test]
fn a_hook_in_the_directory_of_an_instance_prefix_warns() {
    // systemd reads systemd-@0.service.d and systemd-@.service.d for the
    // instance systemd-coredump@0.service too.
    for dir in [
        "systemd-.service.d",
        "systemd-@.service.d",
        "systemd-@0.service.d",
    ] {
        let decoy = coredump_decoy();
        decoy
            .unit(
                "crash-hook@.service",
                "[Service]\nType=oneshot\nExecStart=/usr/local/bin/crash-hook %i\n",
            )
            .file(
                &format!("/etc/systemd/system/{dir}/50-hook.conf"),
                "[Unit]\nOnSuccess=crash-hook@%i.service\n",
            );
        let result = decoy.check(false);
        assert!(result.is_warn(), "{dir}: {result:?}");
        assert!(
            result
                .message()
                .contains("systemd-coredump starts crash-hook@%i.service (OnSuccess=)"),
            "{dir}: {result:?}"
        );
    }
}
