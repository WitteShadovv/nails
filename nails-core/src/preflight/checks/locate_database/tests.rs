// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The check on decoys laid out as the distributions lay out their locate
//! packages, with the files they ship copied unchanged into `fixtures/`, and
//! one test for each way updatedb may run.

use super::scan::names_updatedb;
use super::*;
use crate::filesystem::automount::mount_fix;
use crate::filesystem::{MockFilesystem, PathKind};
use crate::preflight::checks::automount_fixture::{direct, reached};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::ErrorKind;

/// Debian 13's `/usr/lib/systemd/system/plocate-updatedb.service`, from
/// plocate 1.1.23-1, as
/// <https://deb.debian.org/debian/pool/main/p/plocate/plocate_1.1.23-1_amd64.deb>
/// installs it. Ubuntu 26.04's plocate ships the same unit.
const DEBIAN_SERVICE: &str = include_str!("fixtures/debian-13-plocate-updatedb.service");

/// Debian 13's `/etc/cron.daily/plocate`, from the same package. It ends at
/// once where systemd runs, but names updatedb, so it counts.
const DEBIAN_CRON: &str = include_str!("fixtures/debian-13-cron.daily-plocate");

/// Fedora 44's `/usr/lib/systemd/system/plocate-updatedb.service`, from
/// plocate 1.1.24-1.fc44. Arch Linux's plocate 1.1.25-1 ships the same unit.
const FEDORA_SERVICE: &str = include_str!("fixtures/fedora-44-plocate-updatedb.service");

/// What plocate's and mlocate's timers say: run daily, and catch a missed
/// run up after boot.
const TIMER: &str = "[Unit]\nDescription=Update the plocate database daily\n\n\
                     [Timer]\nOnCalendar=daily\nPersistent=true\n";

/// The hidden root every test checks.
const HIDDEN_ROOT: &str = "/mnt/data";

/// A btrfs root, and the hidden volume, ext4, at `/mnt/data`.
const MOUNTS: &str = "22 1 0:31 / / rw,relatime shared:1 - btrfs /dev/vda2 rw\n\
                      40 22 254:16 / /mnt/data rw,relatime shared:20 - ext4 /dev/mapper/data rw\n";

/// What `systemctl show` gives of a system manager that runs nothing that
/// names updatedb.
const QUIET: &str = "Id=init.scope\nNames=init.scope\nLoadState=loaded\nActiveState=active\n\n\
                     Id=sshd.service\nNames=sshd.service\nLoadState=loaded\nActiveState=active\n\
                     ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; }\n";

/// An in-memory decoy whose directories list what is added below them: a
/// running system, whose /proc shows its init.
struct Decoy {
    fs: MockFilesystem,
    listings: RefCell<BTreeMap<PathBuf, Vec<PathBuf>>>,
    shown: RefCell<std::result::Result<String, String>>,
}

impl Decoy {
    fn new() -> Self {
        let fs = MockFilesystem::new();
        fs.mock_set_mount_table(MOUNTS);
        let decoy = Self {
            fs,
            listings: RefCell::new(BTreeMap::new()),
            shown: RefCell::new(Ok(QUIET.to_string())),
        };
        decoy.process(1, "systemd");
        decoy
    }

    /// List `path` in its directory, and each directory in its own.
    fn list(&self, path: &Path) {
        let mut listings = self.listings.borrow_mut();
        let mut child = path.to_path_buf();
        while let Some(parent) = child.parent().map(Path::to_path_buf) {
            self.fs
                .mock_set_path_type(&parent.display().to_string(), PathKind::Dir);
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

    /// Enable `unit` with a link in `dir`'s `timers.target.wants` to its
    /// file. The mock reads no file through a link, so the link holds the
    /// file's text.
    fn enable(&self, dir: &str, unit: &str) -> &Self {
        self.wants(&format!("{dir}/timers.target.wants/{unit}"), unit)
    }

    /// A dependency entry at `path` for `unit`, as `systemctl enable` makes
    /// it.
    fn wants(&self, path: &str, unit: &str) -> &Self {
        let target = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
        ]
        .iter()
        .map(|dir| format!("{dir}/{unit}"))
        .find(|target| self.fs.read_file_content(Path::new(target)).is_ok())
        .expect("the unit's file");
        let text = self.fs.read_file_content(Path::new(&target)).unwrap();
        self.link(path, &target);
        self.fs.mock_set_file_content(path, &text);
        self
    }

    /// Mask `unit` in /etc/systemd/system, as `systemctl mask` does.
    fn mask(&self, unit: &str) -> &Self {
        self.link(&format!("/etc/systemd/system/{unit}"), "/dev/null")
    }

    /// Run a process `pid` named `comm`.
    fn process(&self, pid: u32, comm: &str) -> &Self {
        self.file(&format!("/proc/{pid}/comm"), &format!("{comm}\n"))
    }

    /// Have `systemctl show` give `shown`.
    fn shows(&self, shown: std::result::Result<String, String>) -> &Self {
        *self.shown.borrow_mut() = shown;
        self
    }

    fn check(&self, nixos: bool) -> CheckResult {
        LocateDatabaseCheck::new(PathBuf::from(HIDDEN_ROOT), nixos)
            .with_shown(self.shown.borrow().clone())
            .run(&self.fs)
            .unwrap()
    }
}

/// Debian 13 or Ubuntu 26.04 with plocate installed: its unit, its timer,
/// which `deb-systemd-helper` enables, its cron job and its program.
fn debian() -> Decoy {
    let decoy = Decoy::new();
    decoy
        .file(
            "/usr/lib/systemd/system/plocate-updatedb.service",
            DEBIAN_SERVICE,
        )
        .file("/usr/lib/systemd/system/plocate-updatedb.timer", TIMER)
        .file("/etc/cron.daily/plocate", DEBIAN_CRON)
        .file("/etc/updatedb.conf", "PRUNEPATHS=\"/mnt /tmp\"\n")
        .file("/usr/sbin/updatedb.plocate", "")
        .enable("/etc/systemd/system", "plocate-updatedb.timer");
    decoy
}

/// NixOS with `services.locate.enable = true`: the service runs a script
/// named for it, whose path is all its unit names of updatedb.
fn nixos() -> Decoy {
    let decoy = Decoy::new();
    decoy
        .file(
            "/etc/systemd/system/update-locatedb.service",
            "[Unit]\nDescription=Update Locate Database\n\n[Service]\nExecStart=\
             /nix/store/0000-unit-script-update-locatedb-start/bin/update-locatedb-start\n",
        )
        .file(
            "/etc/systemd/system/update-locatedb.timer",
            "[Timer]\nOnCalendar=02:15\nPersistent=true\n",
        )
        .enable("/etc/systemd/system", "update-locatedb.timer");
    decoy
}

fn fails_naming(result: &CheckResult, parts: &[&str]) {
    assert!(result.is_fail(), "{result:?}");
    for part in parts {
        assert!(result.message().contains(part), "{part}: {result:?}");
    }
}

#[test]
fn a_decoy_without_updatedb_passes() {
    let result = Decoy::new().check(false);
    assert!(result.is_pass(), "{result:?}");
    assert!(
        result
            .message()
            .contains("nothing on the decoy schedules or runs updatedb")
    );
}

#[test]
fn the_words_that_name_updatedb() {
    for named in [
        "updatedb",
        "/usr/sbin/updatedb.plocate",
        "plocate-updatedb.timer",
        "UpdateDB",
        "update-locatedb.service",
        "/var/cache/locatedb",
    ] {
        assert!(names_updatedb(named.as_bytes()), "{named}");
    }
    for other in ["plocate", "locate", "update-db", "mandb", "update", ""] {
        assert!(!names_updatedb(other.as_bytes()), "{other}");
    }
}

/// Debian and Ubuntu: the timer, the service and the cron job each count,
/// whatever updatedb.conf prunes, and the fix names the package and each
/// one.
#[test]
fn debian_with_plocate_fails_naming_each_way_it_runs() {
    let result = debian().check(false);
    fails_naming(
        &result,
        &[
            "/usr/lib/systemd/system/plocate-updatedb.timer names updatedb, and \
             plocate-updatedb.timer is not masked",
            "/usr/lib/systemd/system/plocate-updatedb.service names updatedb, and \
             plocate-updatedb.service is not masked",
            "/etc/systemd/system/timers.target.wants/plocate-updatedb.timer names updatedb",
            "/etc/cron.daily/plocate names updatedb",
        ],
    );
    let remediation = result.remediation().unwrap();
    for part in [
        "Lock the hidden volume now: unmount /mnt/data and close it.",
        "long before you use it again",
        "`sudo apt purge plocate`",
        "`sudo systemctl mask --now plocate-updatedb.timer`",
        "`sudo systemctl mask --now plocate-updatedb.service`",
        "remove /etc/cron.daily/plocate",
        "does not lift this refusal",
        DOC,
    ] {
        assert!(remediation.contains(part), "{part}: {remediation}");
    }
}

/// The package's own hook: Debian's and Ubuntu's postinst restarts
/// plocate-updatedb.service at every upgrade, which a masked timer does not
/// stop. The service alone still refuses.
#[test]
fn a_masked_timer_leaves_the_service_the_package_restarts() {
    let decoy = debian();
    decoy.mask("plocate-updatedb.timer");
    decoy
        .fs
        .remove_file(Path::new("/etc/cron.daily/plocate"))
        .unwrap();
    decoy
        .fs
        .mock_set_directory_contents(Path::new("/etc/cron.daily"), Vec::new());
    let result = decoy.check(false);
    fails_naming(&result, &["plocate-updatedb.service is not masked"]);
    assert!(
        !result
            .message()
            .contains("plocate-updatedb.timer is not masked")
    );
}

/// Both units masked and the cron job gone: only a run by hand is left,
/// which warns.
#[test]
fn every_unit_masked_and_the_cron_job_gone_warns_of_a_run_by_hand() {
    let decoy = debian();
    decoy
        .mask("plocate-updatedb.timer")
        .mask("plocate-updatedb.service");
    decoy
        .fs
        .remove_file(Path::new("/etc/cron.daily/plocate"))
        .unwrap();
    decoy
        .fs
        .mock_set_directory_contents(Path::new("/etc/cron.daily"), Vec::new());
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .contains("updatedb is installed on the decoy (/usr/sbin/updatedb.plocate)"),
        "{result:?}"
    );
}

/// The cron script a removed (not purged) package leaves still counts.
#[test]
fn the_cron_script_a_removed_package_leaves_still_refuses() {
    let decoy = Decoy::new();
    decoy.file("/etc/cron.daily/plocate", DEBIAN_CRON);
    fails_naming(
        &decoy.check(false),
        &["/etc/cron.daily/plocate names updatedb"],
    );
}

/// Debian's mlocate (0.26-5): neither mlocate.timer's name nor its text
/// names updatedb, but the service it starts does, and masking that service
/// stops the timer's run too. Its cron job counts as plocate's does.
#[test]
fn mlocate_fails_by_its_service_and_cron_job() {
    let decoy = Decoy::new();
    decoy
        .file(
            "/lib/systemd/system/mlocate.service",
            "[Unit]\nDescription=Update a database for mlocate\n\n[Service]\n\
             ExecStart=/usr/bin/updatedb.mlocate\nNice=19\n",
        )
        .file(
            "/lib/systemd/system/mlocate.timer",
            "[Unit]\nDescription=Updates mlocate database every day\n\n[Timer]\n\
             OnCalendar=daily\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
        )
        .file(
            "/etc/cron.daily/mlocate",
            "#! /bin/bash\nset -e\n[ -x /usr/bin/updatedb.mlocate ] || exit 0\n",
        )
        .enable("/etc/systemd/system", "mlocate.timer");
    let result = decoy.check(false);
    fails_naming(
        &result,
        &[
            "/lib/systemd/system/mlocate.service names updatedb",
            "/etc/cron.daily/mlocate names updatedb",
        ],
    );
    assert!(
        !result.message().contains("mlocate.timer names"),
        "{result:?}"
    );
}

/// Fedora: the preset enables the timer in /etc, the program is
/// /usr/bin/updatedb.
#[test]
fn fedora_with_plocate_fails_and_masking_both_units_leaves_a_warning() {
    let decoy = Decoy::new();
    decoy
        .file(
            "/usr/lib/systemd/system/plocate-updatedb.service",
            FEDORA_SERVICE,
        )
        .file("/usr/lib/systemd/system/plocate-updatedb.timer", TIMER)
        .file("/usr/bin/updatedb", "")
        .enable("/etc/systemd/system", "plocate-updatedb.timer");
    let result = decoy.check(false);
    fails_naming(&result, &["plocate-updatedb.timer is not masked"]);
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("`sudo dnf remove plocate`")
    );
    decoy
        .mask("plocate-updatedb.timer")
        .mask("plocate-updatedb.service");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
}

/// Arch Linux enables the timer with a link in /usr/lib, which a mask in
/// /etc still masks.
#[test]
fn arch_with_plocate_enables_its_timer_in_usr_lib() {
    let decoy = Decoy::new();
    decoy
        .file(
            "/usr/lib/systemd/system/plocate-updatedb.service",
            FEDORA_SERVICE,
        )
        .file("/usr/lib/systemd/system/plocate-updatedb.timer", TIMER)
        .file("/usr/bin/updatedb", "")
        .enable("/usr/lib/systemd/system", "plocate-updatedb.timer");
    let result = decoy.check(false);
    fails_naming(
        &result,
        &["/usr/lib/systemd/system/timers.target.wants/plocate-updatedb.timer names updatedb"],
    );
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("`sudo pacman -Rns plocate`")
    );
    decoy
        .mask("plocate-updatedb.timer")
        .mask("plocate-updatedb.service");
    assert!(decoy.check(false).is_warn());
}

/// NixOS's services.locate: its unit names locatedb only. The fix is the
/// option, since /etc/systemd/system is the configuration's.
#[test]
fn nixos_services_locate_fails_with_the_option_as_its_fix() {
    let result = nixos().check(true);
    fails_naming(
        &result,
        &[
            "/etc/systemd/system/update-locatedb.service names updatedb",
            "/etc/systemd/system/update-locatedb.timer names updatedb",
        ],
    );
    let remediation = result.remediation().unwrap();
    assert!(
        remediation.contains("set `services.locate.enable = false;`"),
        "{remediation}"
    );
    assert!(!remediation.contains("systemctl mask"), "{remediation}");
}

/// A unit of the decoy's own that runs updatedb counts whether or not
/// anything starts it: another unit, a socket or `systemctl start` may.
#[test]
fn a_unit_of_its_own_that_nothing_enables_refuses() {
    let decoy = Decoy::new();
    decoy.file(
        "/etc/systemd/system/reindex.service",
        "[Service]\nExecStart=/usr/bin/nice /usr/bin/updatedb --prunepaths /tmp\n",
    );
    let result = decoy.check(false);
    fails_naming(
        &result,
        &["/etc/systemd/system/reindex.service names updatedb"],
    );
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("`sudo systemctl mask --now reindex.service`")
    );
    // An empty file masks it too.
    decoy.file("/etc/systemd/system.control/reindex.service", "");
    assert!(decoy.check(false).is_pass());
}

/// A drop-in that adds updatedb to another unit refuses until it is removed
/// or that unit is masked; one for every service can be masked by none.
#[test]
fn a_drop_in_that_runs_updatedb_refuses() {
    let decoy = Decoy::new();
    decoy.file(
        "/etc/systemd/system/backup.service.d/index.conf",
        "[Service]\nExecStartPost=/usr/bin/updatedb\n",
    );
    let result = decoy.check(false);
    fails_naming(
        &result,
        &[
            "/etc/systemd/system/backup.service.d/index.conf names updatedb, and backup.service \
           is not masked",
        ],
    );
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("remove /etc/systemd/system/backup.service.d/index.conf")
    );
    decoy.mask("backup.service");
    assert!(decoy.check(false).is_pass());

    let every = Decoy::new();
    every.file(
        "/usr/lib/systemd/system/service.d/index.conf",
        "[Service]\nExecStartPost=updatedb\n",
    );
    fails_naming(
        &every.check(false),
        &["service.d/index.conf names updatedb"],
    );
}

/// A template masks its instances; an instance's own file counts on its own.
#[test]
fn a_masked_template_masks_its_instances() {
    let decoy = Decoy::new();
    decoy
        .file(
            "/etc/systemd/system/index@.service",
            "[Service]\nExecStart=/usr/bin/updatedb -U %I\n",
        )
        .wants(
            "/etc/systemd/system/multi-user.target.wants/index@home.service",
            "index@.service",
        );
    fails_naming(&decoy.check(false), &["index@.service is not masked"]);
    decoy.link("/run/systemd/system.control/index@.service", "/dev/null");
    assert!(decoy.check(false).is_pass());
}

/// systemd-run's transient units, and what a generator writes (systemd-cron
/// turns crontabs into units there), are units too.
#[test]
fn transient_and_generated_units_refuse() {
    let decoy = Decoy::new();
    decoy.file(
        "/run/systemd/transient/run-r1.service",
        "[Service]\nExecStart=\"/usr/bin/updatedb\"\n",
    );
    fails_naming(
        &decoy.check(false),
        &["/run/systemd/transient/run-r1.service"],
    );
    let generated = Decoy::new();
    generated.file(
        "/run/systemd/generator/cron-index.service",
        "[Service]\nExecStart=/bin/sh -c 'updatedb'\n",
    );
    fails_naming(
        &generated.check(false),
        &["/run/systemd/generator/cron-index.service"],
    );
}

/// A user's own unit refuses until it is removed; one in a directory every
/// user shares until it is masked for every user.
#[test]
fn users_units_refuse() {
    let decoy = Decoy::new();
    decoy
        .file(
            "/etc/passwd",
            "root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/bash\n",
        )
        .file(
            "/home/alice/.config/systemd/user/index.timer",
            "[Timer]\nOnCalendar=daily\n",
        )
        .file(
            "/home/alice/.config/systemd/user/index.service",
            "[Service]\nExecStart=/usr/bin/updatedb -o %h/.locate.db\n",
        );
    let result = decoy.check(false);
    fails_naming(
        &result,
        &["/home/alice/.config/systemd/user/index.service names updatedb"],
    );
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("remove /home/alice/.config/systemd/user/index.service")
    );

    let shared = Decoy::new();
    shared.file(
        "/usr/lib/systemd/user/index.service",
        "[Service]\nExecStart=/usr/bin/updatedb\n",
    );
    let result = shared.check(false);
    fails_naming(
        &result,
        &["/usr/lib/systemd/user/index.service names updatedb"],
    );
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("`sudo systemctl --global mask index.service`")
    );
    shared.link("/etc/systemd/user/index.service", "/dev/null");
    assert!(shared.check(false).is_pass());
}

/// A user's runtime units, `systemd-run --user` among them.
#[test]
fn a_users_transient_unit_refuses() {
    let decoy = Decoy::new();
    decoy.file(
        "/run/user/1000/systemd/transient/run-u7.service",
        "[Service]\nExecStart=/usr/bin/updatedb\n",
    );
    fails_naming(
        &decoy.check(false),
        &["/run/user/1000/systemd/transient/run-u7.service names updatedb"],
    );
}

/// What the system manager has loaded: a timer masked without `--now` still
/// runs, a unit whose file is gone is still loaded. A unit masked and
/// stopped, and one with no file, start nothing.
#[test]
fn units_the_system_manager_has_loaded() {
    let running = format!(
        "{QUIET}\nId=plocate-updatedb.timer\nNames=plocate-updatedb.timer\nLoadState=masked\n\
         ActiveState=active\n"
    );
    fails_naming(
        &Decoy::new().shows(Ok(running)).check(false),
        &["the system manager runs plocate-updatedb.timer"],
    );
    let gone = format!(
        "{QUIET}\nId=reindex.service\nNames=reindex.service\nLoadState=loaded\n\
         ActiveState=inactive\nExecStart={{ path=/usr/bin/updatedb ; argv[]=/usr/bin/updatedb ; }}\n"
    );
    fails_naming(
        &Decoy::new().shows(Ok(gone)).check(false),
        &["the system manager has reindex.service loaded"],
    );
    for (load, active) in [
        ("masked", "inactive"),
        ("not-found", "inactive"),
        ("masked", "failed"),
    ] {
        let idle = format!(
            "{QUIET}\nId=plocate-updatedb.timer\nNames=plocate-updatedb.timer\nLoadState={load}\n\
             ActiveState={active}\n"
        );
        assert!(
            Decoy::new().shows(Ok(idle)).check(false).is_pass(),
            "{load} {active}"
        );
    }
}

/// A system manager NAILS cannot ask, or an answer it cannot read, may run
/// anything.
#[test]
fn a_system_manager_nails_cannot_ask_refuses() {
    fails_naming(
        &Decoy::new()
            .shows(Err("NAILS cannot run systemctl (no such file)".to_string()))
            .check(false),
        &[
            "NAILS cannot tell whether a unit the system manager has loaded runs updatedb: NAILS \
           cannot run systemctl",
        ],
    );
    fails_naming(
        &Decoy::new().shows(Ok(String::new())).check(false),
        &["`systemctl show` lists no init.scope"],
    );
    // A decoy read under another root has no manager to ask.
    let decoy = Decoy::new();
    let result = LocateDatabaseCheck::new(PathBuf::from(HIDDEN_ROOT), false)
        .with_root(Path::new("/image"))
        .run(&decoy.fs)
        .unwrap();
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().contains("the decoy is read under /image"),
        "{result:?}"
    );
}

/// Every cron and at table: the system crontab, cron.d, anacron, the
/// run-parts directories, root's and the users' crontabs as Debian and
/// cronie keep them, and at jobs as Debian and Fedora keep them.
#[test]
fn every_cron_and_at_table_refuses() {
    for (path, text) in [
        ("/etc/crontab", "17 3 * * * root /usr/bin/updatedb\n"),
        ("/etc/cron.d/index", "@daily root updatedb\n"),
        ("/etc/anacrontab", "1 5 index nice updatedb\n"),
        (
            "/etc/cron.hourly/index",
            "#!/bin/sh\nexec /usr/bin/updatedb\n",
        ),
        ("/etc/cron.weekly/index", "#!/bin/sh\nupdatedb\n"),
        ("/etc/cron.monthly/index", "#!/bin/sh\nupdatedb\n"),
        ("/var/spool/cron/crontabs/root", "@reboot updatedb\n"),
        ("/var/spool/cron/alice", "0 * * * * updatedb -o ~/.db\n"),
        (
            "/var/spool/cron/atjobs/a0000101c4e5a0",
            "#!/bin/sh\nupdatedb\n",
        ),
        ("/var/spool/at/a0000101c4e5a0", "#!/bin/sh\nupdatedb\n"),
    ] {
        let decoy = Decoy::new();
        decoy.file(path, text);
        let result = decoy.check(false);
        fails_naming(&result, &[&format!("{path} names updatedb")]);
        assert!(
            result
                .remediation()
                .unwrap()
                .contains(&format!("remove {path}")),
            "{result:?}"
        );
    }
    // A job that names no updatedb is none.
    let decoy = Decoy::new();
    decoy.file(
        "/etc/cron.daily/logrotate",
        "#!/bin/sh\nlogrotate /etc/logrotate.conf\n",
    );
    assert!(decoy.check(false).is_pass());
}

/// An updatedb that runs now, plocate's whose name the kernel cuts to 15
/// bytes and NixOS's script among them.
#[test]
fn an_updatedb_that_runs_now_refuses() {
    for comm in ["updatedb", "updatedb.plocat", "update-locatedb"] {
        let decoy = Decoy::new();
        decoy.process(4242, comm);
        fails_naming(&decoy.check(false), &["an updatedb runs now (process 4242"]);
    }
}

/// A /proc that hides process 1, and a process NAILS cannot read, may hide
/// an updatedb.
#[test]
fn processes_nails_cannot_see_refuse() {
    let hidden = Decoy::new();
    hidden.fs.remove_file(Path::new("/proc/1/comm")).unwrap();
    hidden
        .fs
        .mock_set_directory_contents(Path::new("/proc"), Vec::new());
    fails_naming(&hidden.check(false), &["/proc hides process 1 from NAILS"]);

    let unread = Decoy::new();
    unread.process(77, "x");
    unread
        .fs
        .mock_set_lookup_error("/proc/77/comm", ErrorKind::PermissionDenied);
    fails_naming(&unread.check(false), &["NAILS cannot read /proc/77/comm"]);
}

/// A unit directory, a cron directory or an /etc/passwd NAILS cannot read
/// may hold an updatedb.
#[test]
fn what_nails_cannot_read_refuses() {
    for dir in ["/etc/systemd/system", "/var/spool/cron", "/home"] {
        let decoy = Decoy::new();
        decoy.file(&format!("{dir}/x"), "");
        decoy.fs.mock_set_unreadable_dir(dir);
        let result = decoy.check(false);
        fails_naming(&result, &["NAILS cannot tell whether", "runs updatedb"]);
        assert!(result.message().contains("sudo"), "{dir}: {result:?}");
    }
    let decoy = Decoy::new();
    decoy.file("/etc/passwd", "root:x:0:0::/root:/bin/sh\n");
    decoy
        .fs
        .mock_set_lookup_error("/etc/passwd", ErrorKind::PermissionDenied);
    fails_naming(&decoy.check(false), &["a user's unit runs updatedb"]);
}

/// Without a mount table NAILS looks up nothing, and refuses.
#[test]
fn without_a_mount_table_it_refuses() {
    let decoy = Decoy::new();
    decoy.fs.mock_set_mount_table_error("no mount table");
    let result = decoy.check(false);
    fails_naming(&result, &["it cannot read the mount table"]);
}

/// A cron directory behind an automount point nothing is mounted on yet is
/// not looked up, and the check refuses, naming the point once.
#[test]
fn a_directory_behind_an_automount_point_refuses_without_a_lookup() {
    let decoy = Decoy::new();
    decoy
        .fs
        .mock_set_mount_table(&format!("{MOUNTS}{}", direct("/var/spool/cron", 0, 22)));
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    let fix = mount_fix(&[Path::new("/var/spool/cron")]);
    assert!(
        result.message().contains(fix.as_str())
            || result
                .remediation()
                .is_some_and(|text| text.contains(fix.as_str())),
        "{result:?}"
    );
    assert!(
        !reached(&decoy.fs, "/var/spool/cron"),
        "{:?}",
        decoy.fs.mock_lookups()
    );
}

/// An updatedb a person may start, in each place a program is installed,
/// warns.
#[test]
fn an_updatedb_only_a_person_starts_warns() {
    for path in [
        "/usr/bin/updatedb",
        "/usr/local/bin/updatedb",
        "/run/current-system/sw/bin/updatedb",
        "/usr/bin/updatedb.findutils",
    ] {
        let decoy = Decoy::new();
        decoy.file(path, "");
        let result = decoy.check(false);
        assert!(result.is_warn(), "{path}: {result:?}");
        assert!(result.message().contains(path), "{result:?}");
    }
}
