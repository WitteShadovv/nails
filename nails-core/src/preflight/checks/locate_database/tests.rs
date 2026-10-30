// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The check on decoys laid out as the distributions lay them out, with the
//! files they ship copied unchanged into `fixtures/`.

use super::*;
use crate::filesystem::MockFilesystem;
use std::cell::RefCell;
use std::collections::BTreeMap;

/// Debian 13's `/etc/updatedb.conf`, from plocate 1.1.23-1:
/// <https://sources.debian.org/src/plocate/1.1.23-1/debian/updatedb.conf/>, as
/// <https://deb.debian.org/debian/pool/main/p/plocate/plocate_1.1.23-1_amd64.deb>
/// installs it.
pub(super) const DEBIAN: &str = include_str!("fixtures/debian-13-updatedb.conf");

/// Debian 13's `/usr/lib/systemd/system/plocate-updatedb.service`, from the
/// same package.
const DEBIAN_SERVICE: &str = include_str!("fixtures/debian-13-plocate-updatedb.service");

/// Debian 13's `/etc/cron.daily/plocate`, from the same package:
/// <https://sources.debian.org/src/plocate/1.1.23-1/debian/cron.daily/plocate/>.
const DEBIAN_CRON: &str = include_str!("fixtures/debian-13-cron.daily-plocate");

/// Ubuntu 26.04's `/etc/updatedb.conf`, from plocate 1.1.23-1ubuntu3:
/// `debian/updatedb.conf` of
/// <http://archive.ubuntu.com/ubuntu/pool/universe/p/plocate/plocate_1.1.23-1ubuntu3.debian.tar.xz>.
pub(super) const UBUNTU: &str = include_str!("fixtures/ubuntu-26.04-updatedb.conf");

/// Fedora 44's `/etc/updatedb.conf`, which
/// <https://src.fedoraproject.org/rpms/plocate/blob/f44/f/plocate.spec> writes,
/// as
/// <https://mirrors.kernel.org/fedora/updates/44/Everything/x86_64/Packages/p/plocate-1.1.25-2.fc44.x86_64.rpm>
/// installs it.
pub(super) const FEDORA: &str = include_str!("fixtures/fedora-44-updatedb.conf");

/// Fedora 44's `/usr/lib/systemd/system/plocate-updatedb.service`, from the
/// same package.
const FEDORA_SERVICE: &str = include_str!("fixtures/fedora-44-plocate-updatedb.service");

/// Arch Linux's `/etc/updatedb.conf`:
/// <https://gitlab.archlinux.org/archlinux/packaging/packages/plocate/-/blob/main/updatedb.conf>,
/// as plocate 1.1.25-1 installs it (its PKGBUILD lists the sha256
/// `d00796741e2194032d0185b40de70ff5c8a11fda416a70434eb0aa2020981f91`).
pub(super) const ARCH: &str = include_str!("fixtures/arch-updatedb.conf");

/// The default `pruneFS` of NixOS's `services.locate`
/// (nixos/modules/misc/locate.nix).
const NIXOS_PRUNEFS: &str = "afs anon_inodefs auto autofs bdev binfmt binfmt_misc ceph cgroup \
     cgroup2 cifs coda configfs cramfs cpuset curlftpfs debugfs devfs devpts devtmpfs eventpollfs \
     exofs futexfs ftpfs fuse fusectl fusesmb fuse.ceph fuse.glusterfs fuse.gvfsd-fuse fuse.mfs \
     fuse.rclone fuse.rozofs fuse.sshfs gfs gfs2 hostfs hugetlbfs inotifyfs iso9660 jffs2 lustre \
     lustre_lite misc mfs mqueue ncpfs nfs NFS nfs4 nfsd nnpfs ocfs ocfs2 pipefs proc ramfs \
     rpc_pipefs securityfs selinuxfs sfs shfs smbfs sockfs spufs sshfs subfs supermount sysfs \
     tmpfs tracefs ubifs udev udf usbfs vboxsf vperfctrfs";

/// Its default `pruneNames`.
const NIXOS_PRUNENAMES: &str = ".bzr .cache .git .hg .svn";

/// Its default `prunePaths`.
const NIXOS_PRUNEPATHS: &[&str] = &[
    "/tmp",
    "/var/tmp",
    "/var/cache",
    "/var/lock",
    "/var/run",
    "/var/spool",
    "/nix/store",
    "/nix/var/log/nix",
];

/// The updatedb of the plocate package in the store.
const NIXOS_UPDATEDB: &str =
    "/nix/store/0000000000000000000000000000000-plocate-1.1.25/bin/updatedb";

/// The `/etc/updatedb.conf` NixOS writes for `prune_paths`.
fn nixos_conf(prune_paths: &[&str]) -> String {
    format!(
        "PRUNEFS=\"{NIXOS_PRUNEFS}\"\nPRUNENAMES=\"{NIXOS_PRUNENAMES}\"\n\
         PRUNEPATHS=\"{}\"\nPRUNE_BIND_MOUNTS=\"no\"\n",
        prune_paths.join(" ")
    )
}

/// The `update-locatedb.service` NixOS writes for `prune_paths` and
/// `extra_flags`: every argument quoted by `utils.escapeSystemdExecArgs`.
fn nixos_service(prune_paths: &[&str], extra_flags: &[&str]) -> String {
    let mut args = vec![
        NIXOS_UPDATEDB.to_string(),
        "--output".to_string(),
        "/var/cache/locatedb".to_string(),
        "--prune-bind-mounts".to_string(),
        "no".to_string(),
        "--prunefs".to_string(),
        NIXOS_PRUNEFS.to_string(),
        "--prunenames".to_string(),
        NIXOS_PRUNENAMES.to_string(),
        "--prunepaths".to_string(),
        prune_paths.join(" "),
    ];
    args.extend(extra_flags.iter().map(ToString::to_string));
    let quoted: Vec<String> = args.iter().map(|arg| format!("\"{arg}\"")).collect();
    format!(
        "[Unit]\nDescription=Update Locate Database\n\n[Service]\nExecStart={}\nNice=19\n\
         ReadOnlyPaths=/\nReadWritePaths=/var/cache\n",
        quoted.join(" ")
    )
}

/// The hidden root every test checks.
const HIDDEN_ROOT: &str = "/mnt/data";

/// A btrfs root, and the hidden volume, ext4, at `/mnt/data`.
const MOUNTS: &str = "22 1 0:31 / / rw,relatime shared:1 - btrfs /dev/vda2 rw\n\
                      40 22 254:16 / /mnt/data rw,relatime shared:20 - ext4 /dev/mapper/data rw\n";

/// An invocation id as systemd writes it.
const INVOCATION_ID: &str = "8028a17235414b4e80c950b24a7487d7";

/// An in-memory decoy whose directories list what is added below them.
struct Decoy {
    fs: MockFilesystem,
    listings: RefCell<BTreeMap<PathBuf, Vec<PathBuf>>>,
}

impl Decoy {
    fn new() -> Self {
        let fs = MockFilesystem::new();
        fs.mock_set_mount_table(MOUNTS);
        Self {
            fs,
            listings: RefCell::new(BTreeMap::new()),
        }
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

    /// Mark `unit` active, as systemd's invocation marker does.
    fn active(&self, unit: &str) -> &Self {
        self.link(
            &format!("/run/systemd/units/invocation:{unit}"),
            INVOCATION_ID,
        )
    }

    /// Enable `timer` with a link in `dir`'s `timers.target.wants`.
    fn enable(&self, dir: &str, timer: &str) -> &Self {
        self.link(
            &format!("{dir}/timers.target.wants/{timer}"),
            &format!("../{timer}"),
        )
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

    fn check(&self, nixos: bool) -> CheckResult {
        LocateDatabaseCheck::new(PathBuf::from(HIDDEN_ROOT), nixos)
            .run(&self.fs)
            .unwrap()
    }
}

/// Debian 13 with plocate installed: its file, its unit, its cron job, and
/// the timer `deb-systemd-helper` enables.
fn debian(conf: &str) -> Decoy {
    let decoy = Decoy::new();
    decoy
        .file("/etc/updatedb.conf", conf)
        .file(
            "/usr/lib/systemd/system/plocate-updatedb.service",
            DEBIAN_SERVICE,
        )
        .file(
            "/usr/lib/systemd/system/plocate-updatedb.timer",
            "[Timer]\nOnCalendar=daily\nPersistent=true\n",
        )
        .file("/etc/cron.daily/plocate", DEBIAN_CRON)
        .file("/usr/sbin/updatedb.plocate", "")
        .link("/usr/bin/updatedb", "/etc/alternatives/updatedb")
        .link("/etc/alternatives/updatedb", "/usr/sbin/updatedb.plocate")
        .enable("/etc/systemd/system", "plocate-updatedb.timer");
    decoy
}

/// `conf` with `/mnt` added to its PRUNEPATHS.
fn pruning_mnt(conf: &str) -> String {
    conf.replace("PRUNEPATHS=\"/tmp", "PRUNEPATHS=\"/mnt /tmp")
        .replace("PRUNEPATHS = \"/tmp", "PRUNEPATHS = \"/mnt /tmp")
}

fn message(result: &CheckResult) -> &str {
    result.message()
}

#[test]
fn a_decoy_without_updatedb_passes() {
    let result = Decoy::new().check(false);
    assert!(result.is_pass(), "{result:?}");
    assert!(message(&result).contains("no updatedb"), "{result:?}");
}

#[test]
fn debian_with_its_timer_enabled_fails_and_names_the_way_out() {
    let result = debian(DEBIAN).check(false);
    assert!(result.is_fail(), "{result:?}");
    let message = message(&result);
    for part in [
        "plocate-updatedb.timer schedules updatedb",
        "does not skip the hidden volume at /mnt/data",
        "into /var/lib/plocate/plocate.db on the decoy disk",
    ] {
        assert!(message.contains(part), "{part}: {message}");
    }
    // Debian's cron job ends at once under systemd and is no finding.
    assert!(!message.contains("cron"), "{message}");
    let remediation = result.remediation().unwrap();
    for part in [
        "Lock the hidden volume now: unmount /mnt/data and close it.",
        "long before you use it again",
        "add /mnt to PRUNEPATHS in /etc/updatedb.conf",
        "`sudo systemctl mask plocate-updatedb.timer`",
        DOC,
    ] {
        assert!(remediation.contains(part), "{part}: {remediation}");
    }
    assert!(
        !remediation.contains("/mnt/data to PRUNEPATHS"),
        "{remediation}"
    );
}

#[test]
fn ubuntu_and_fedora_with_their_timers_enabled_fail() {
    let ubuntu = debian(UBUNTU).check(false);
    assert!(ubuntu.is_fail(), "{ubuntu:?}");

    // Fedora enables the timer by preset and runs /usr/bin/updatedb.
    let fedora = Decoy::new();
    fedora
        .file("/etc/updatedb.conf", FEDORA)
        .file(
            "/usr/lib/systemd/system/plocate-updatedb.service",
            FEDORA_SERVICE,
        )
        .file("/usr/bin/updatedb", "")
        .enable("/etc/systemd/system", "plocate-updatedb.timer");
    let result = fedora.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(message(&result).contains("/var/lib/plocate/plocate.db"));
}

#[test]
fn prunepaths_with_the_mount_points_parent_or_itself_passes_and_names_the_rule() {
    for (conf, entry) in [
        (pruning_mnt(DEBIAN), "/mnt"),
        (DEBIAN.replace("/tmp", "/mnt/data"), "/mnt/data"),
        (pruning_mnt(FEDORA), "/mnt"),
    ] {
        let result = debian(&conf).check(false);
        assert!(result.is_pass(), "{entry}: {result:?}");
        assert_eq!(
            message(&result),
            format!(
                "updatedb skips the hidden volume: PRUNEPATHS in /etc/updatedb.conf lists {entry}"
            )
        );
    }
    // updatedb compares the path exactly: a trailing slash skips nothing.
    let result = debian(&DEBIAN.replace("/tmp", "/mnt/")).check(false);
    assert!(result.is_fail(), "{result:?}");
}

#[test]
fn prunenames_naming_a_directory_on_the_way_passes() {
    let conf = DEBIAN.replace("# PRUNENAMES=\".git", "PRUNENAMES=\"data .git");
    let result = debian(&conf).check(false);
    assert!(result.is_pass(), "{result:?}");
    assert!(
        message(&result).contains("PRUNENAMES in /etc/updatedb.conf lists data"),
        "{result:?}"
    );
}

#[test]
fn prunefs_naming_the_volumes_type_passes() {
    // The type is read from the mount table; PRUNEFS ignores ASCII case.
    let conf = DEBIAN.replace("PRUNEFS=\"NFS", "PRUNEFS=\"EXT4 NFS");
    let result = debian(&conf).check(false);
    assert!(result.is_pass(), "{result:?}");
    assert!(
        message(&result).contains("lists EXT4, the type of the filesystem mounted at /mnt/data"),
        "{result:?}"
    );
    // Without a mount table the type is not known, so it covers nothing.
    let decoy = debian(&conf);
    decoy.fs.mock_set_mount_table_error("no mount table");
    assert!(decoy.check(false).is_fail());
}

#[test]
fn a_masked_timer_leaves_a_run_by_hand_and_warns() {
    let decoy = debian(DEBIAN);
    decoy.mask("plocate-updatedb.timer");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    let message = message(&result);
    assert!(
        message.contains("updatedb can be started by hand (/usr/bin/updatedb)"),
        "{message}"
    );
    assert!(
        message.contains("systemctl start plocate-updatedb.service"),
        "{message}"
    );
    // A mask is no fix to name again.
    assert!(!message.contains("systemctl mask"), "{message}");
}

#[test]
fn a_masked_timer_does_not_cover_a_run_in_progress() {
    let by_unit = debian(DEBIAN);
    by_unit
        .mask("plocate-updatedb.timer")
        .active("plocate-updatedb.service");
    let result = by_unit.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains("an updatedb runs now (plocate-updatedb.service is active)"),
        "{result:?}"
    );
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("lists its files until updatedb runs again with the volume locked"),
        "{result:?}"
    );

    // One a person started is seen by its process, under its cut comm.
    let by_hand = debian(DEBIAN);
    by_hand.mask("plocate-updatedb.timer").process(
        4242,
        "updatedb.plocat",
        &["/usr/sbin/updatedb.plocate"],
    );
    let result = by_hand.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains("updatedb runs as process 4242"),
        "{result:?}"
    );
}

#[test]
fn a_run_in_progress_that_skips_the_volume_passes() {
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .active("plocate-updatedb.service")
        .process(77, "updatedb", &["/usr/bin/updatedb"]);
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn a_process_is_judged_by_its_own_command_line() {
    // The file skips /mnt, the running process replaces the list.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy.mask("plocate-updatedb.timer").process(
        9,
        "updatedb",
        &["updatedb", "--prunepaths", "/tmp"],
    );
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    // One that adds /mnt itself skips the volume on an unpruned file: only
    // the runs by hand are left to warn about.
    let decoy = debian(DEBIAN);
    decoy
        .mask("plocate-updatedb.timer")
        .process(9, "updatedb", &["updatedb", "-e", "/mnt"]);
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(!message(&result).contains("process 9"), "{result:?}");
}

#[test]
fn arch_prunes_mnt_by_default_and_passes() {
    let decoy = Decoy::new();
    decoy
        .file("/etc/updatedb.conf", ARCH)
        .file(
            "/usr/lib/systemd/system/plocate-updatedb.service",
            FEDORA_SERVICE,
        )
        .file("/usr/bin/updatedb", "")
        // Arch's package enables the timer with a link of its own.
        .enable("/usr/lib/systemd/system", "plocate-updatedb.timer");
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");
    assert!(
        message(&result).contains("PRUNEPATHS in /etc/updatedb.conf lists /mnt"),
        "{result:?}"
    );
}

/// NixOS with `services.locate.enable`: the file and the unit it writes for
/// `prune_paths` and `extra_flags`, and the timer `wantedBy` enables.
fn nixos(prune_paths: &[&str], extra_flags: &[&str]) -> Decoy {
    let decoy = Decoy::new();
    decoy
        .file("/etc/updatedb.conf", &nixos_conf(prune_paths))
        .file(
            "/etc/systemd/system/update-locatedb.service",
            &nixos_service(prune_paths, extra_flags),
        )
        .file(NIXOS_UPDATEDB, "")
        .link("/run/current-system/sw/bin/updatedb", NIXOS_UPDATEDB)
        .enable("/etc/systemd/system", "update-locatedb.timer");
    decoy
}

#[test]
fn nixos_defaults_fail_and_the_fix_keeps_the_default_list() {
    let result = nixos(NIXOS_PRUNEPATHS, &[]).check(true);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains("into /var/cache/locatedb on the decoy disk"),
        "{result:?}"
    );
    let remediation = result.remediation().unwrap();
    assert!(
        remediation.contains("`services.locate.prunePaths = lib.mkOptionDefault [ \"/mnt\" ];`"),
        "{remediation}"
    );
    assert!(!remediation.contains("/etc/updatedb.conf"), "{remediation}");

    // lib.mkOptionDefault adds /mnt to the default list, in the file and in
    // the unit alike.
    let mut pruned = NIXOS_PRUNEPATHS.to_vec();
    pruned.push("/mnt");
    let result = nixos(&pruned, &[]).check(true);
    assert!(result.is_pass(), "{result:?}");
    assert!(
        message(&result)
            .contains("--prunepaths in the ExecStart of update-locatedb.service lists /mnt"),
        "{result:?}"
    );
    assert!(
        message(&result).contains("PRUNEPATHS in /etc/updatedb.conf lists /mnt"),
        "{result:?}"
    );
}

#[test]
fn nixos_flags_replace_or_add_to_the_files_lists() {
    // The unit's --prunepaths replaces the file's list: a /mnt in the file
    // alone leaves the timer's run indexing the volume.
    let decoy = nixos(NIXOS_PRUNEPATHS, &[]);
    let mut pruned = NIXOS_PRUNEPATHS.to_vec();
    pruned.push("/mnt");
    decoy
        .fs
        .mock_set_file_content("/etc/updatedb.conf", &nixos_conf(&pruned));
    let result = decoy.check(true);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains("update-locatedb.timer schedules updatedb"),
        "{result:?}"
    );

    // --add-prunepaths in extraFlags adds to it: the timer's run skips the
    // volume, a run by hand reads the file alone and does not.
    let result = nixos(NIXOS_PRUNEPATHS, &["--add-prunepaths", "/mnt"]).check(true);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result)
            .contains("updatedb can be started by hand (/run/current-system/sw/bin/updatedb)"),
        "{result:?}"
    );
}

#[test]
fn the_nixos_fix_passes_the_check_of_the_decoys_own_configuration() {
    use nails_platform::nixos::verify_base_config_clean;
    let remediation = nixos(NIXOS_PRUNEPATHS, &[])
        .check(true)
        .remediation()
        .unwrap()
        .to_string();
    let line = remediation
        .split('`')
        .find(|part| part.starts_with("services.locate.prunePaths"))
        .expect("the remediation names the line to add");
    let scan = |text: &str| {
        let fs = MockFilesystem::new();
        fs.mock_set_mount_table(MOUNTS);
        fs.mock_set_file_content("/etc/nixos/configuration.nix", text);
        fs.mock_set_files_with_pattern(
            "/etc/nixos",
            ".nix",
            &[Path::new("/etc/nixos/configuration.nix")],
        );
        verify_base_config_clean(&fs, Path::new(HIDDEN_ROOT)).unwrap()
    };
    assert!(
        scan(&format!("{{ lib, ... }}: {{\n  {line}\n}}\n")).is_clean(),
        "{line}"
    );
    // Naming the mount point itself would trip that check.
    assert!(
        !scan("{ lib, ... }: {\n  services.locate.prunePaths = lib.mkOptionDefault [ \"/mnt/data\" ];\n}\n")
            .is_clean()
    );
}

#[test]
fn a_volume_right_below_the_root_gets_a_fix_that_names_no_mount_point() {
    let decoy = nixos(NIXOS_PRUNEPATHS, &[]);
    let result = LocateDatabaseCheck::new(PathBuf::from("/data"), true)
        .run(&decoy.fs)
        .unwrap();
    assert!(result.is_fail(), "{result:?}");
    let remediation = result.remediation().unwrap();
    assert!(
        remediation.contains("disable services.locate in the decoy's configuration"),
        "{remediation}"
    );
    assert!(!remediation.contains("prunePaths ="), "{remediation}");

    let result = LocateDatabaseCheck::new(PathBuf::from("/data"), false)
        .run(&debian(DEBIAN).fs)
        .unwrap();
    let remediation = result.remediation().unwrap();
    assert!(
        remediation
            .contains("mask plocate-updatedb.timer (`sudo systemctl mask plocate-updatedb.timer`)"),
        "{remediation}"
    );
    assert!(
        remediation.contains(
            "adding the mount point to PRUNEPATHS in /etc/updatedb.conf would name it there"
        ),
        "{remediation}"
    );
}

#[test]
fn a_malformed_or_unreadable_file_warns() {
    let malformed = debian("PRUNEPATHS = \"/mnt\"\nPRUNEPATHS = \"/tmp\"\n").check(false);
    assert!(malformed.is_warn(), "{malformed:?}");
    assert!(
        message(&malformed).contains(
            "updatedb stops before it scans, because in /etc/updatedb.conf line 2 sets \
             PRUNEPATHS a second time"
        ),
        "{malformed:?}"
    );

    let unreadable = debian(DEBIAN);
    unreadable
        .fs
        .mock_set_path_type("/etc/updatedb.conf", crate::filesystem::PathKind::Dir);
    let result = unreadable.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains("/etc/updatedb.conf is not a regular file"),
        "{result:?}"
    );
}

#[test]
fn a_file_that_leads_onto_the_hidden_volume_is_not_read() {
    let onto = Decoy::new();
    onto.file("/mnt/data/updatedb.conf", &pruning_mnt(DEBIAN))
        .link("/etc/updatedb.conf", "/mnt/data/updatedb.conf")
        .file(
            "/usr/lib/systemd/system/plocate-updatedb.service",
            DEBIAN_SERVICE,
        )
        .file("/usr/sbin/updatedb.plocate", "")
        .enable("/etc/systemd/system", "plocate-updatedb.timer");
    let result = onto.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains("/etc/updatedb.conf leads onto the hidden volume"),
        "{result:?}"
    );
}

#[test]
fn a_missing_file_prunes_nothing_and_a_null_one_reads_empty() {
    let missing = debian(DEBIAN);
    missing.fs.mock_set_path_exists("/etc/updatedb.conf", false);
    assert!(missing.check(false).is_fail());

    let null = Decoy::new();
    null.link("/etc/updatedb.conf", "/dev/null")
        .file(
            "/usr/lib/systemd/system/plocate-updatedb.service",
            DEBIAN_SERVICE,
        )
        .enable("/etc/systemd/system", "plocate-updatedb.timer");
    assert!(null.check(false).is_fail());
}

#[test]
fn a_cron_job_schedules_a_run_unless_it_ends_under_systemd() {
    // Debian's job without its first test runs under systemd too.
    let unguarded = DEBIAN_CRON.replace("if [ -d /run/systemd/system ]; then", "if false; then");
    let decoy = debian(DEBIAN);
    decoy
        .mask("plocate-updatedb.timer")
        .fs
        .mock_set_file_content("/etc/cron.daily/plocate", &unguarded);
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains("the cron job /etc/cron.daily/plocate runs updatedb"),
        "{result:?}"
    );
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("remove the cron job /etc/cron.daily/plocate"),
        "{result:?}"
    );

    // A command before the test runs before it.
    let early = DEBIAN_CRON.replace("set -e", "set -e\nFOO=1 updatedb");
    let decoy = debian(DEBIAN);
    decoy
        .mask("plocate-updatedb.timer")
        .fs
        .mock_set_file_content("/etc/cron.daily/plocate", &early);
    assert!(decoy.check(false).is_fail());
}

#[test]
fn a_cron_job_whose_options_are_not_read_warns() {
    for (path, text, why) in [
        (
            "/etc/cron.daily/locate",
            "#!/bin/sh\nupdatedb.findutils\n",
            "runs findutils' updatedb",
        ),
        (
            "/etc/cron.d/locate-index",
            "0 3 * * * root updatedb --prunepaths /tmp\n",
            "passes updatedb options of its own",
        ),
    ] {
        let decoy = Decoy::new();
        decoy.file("/etc/updatedb.conf", DEBIAN).file(path, text);
        let result = decoy.check(false);
        assert!(result.is_warn(), "{path}: {result:?}");
        assert!(message(&result).contains(why), "{path}: {result:?}");
    }
    // A crontab line without options reads the file.
    let decoy = Decoy::new();
    decoy
        .file("/etc/updatedb.conf", &pruning_mnt(DEBIAN))
        .file("/etc/crontab", "15 2 * * * root updatedb\n");
    assert!(decoy.check(false).is_pass());
}

#[test]
fn every_mount_of_the_volume_must_be_skipped() {
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy.fs.mock_set_mount_table(&format!(
        "{MOUNTS}41 22 254:16 / /srv/copy rw,relatime shared:21 - ext4 /dev/mapper/data rw\n"
    ));
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains("does not skip the hidden volume at /srv/copy"),
        "{result:?}"
    );
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("unmount /mnt/data and /srv/copy"),
        "{result:?}"
    );
}

#[test]
fn the_hidden_root_is_judged_where_its_links_lead() {
    // Debian prunes /media: a root that is a link to a volume there passes.
    let decoy = debian(DEBIAN);
    decoy
        .fs
        .create_symlink(Path::new("/media/vol"), Path::new(HIDDEN_ROOT))
        .unwrap();
    decoy.fs.mock_set_mount_table(
        "22 1 0:31 / / rw,relatime shared:1 - btrfs /dev/vda2 rw\n\
         40 22 254:16 / /media/vol rw,relatime shared:20 - ext4 /dev/mapper/data rw\n",
    );
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");
    assert!(
        message(&result).contains("PRUNEPATHS in /etc/updatedb.conf lists /media"),
        "{result:?}"
    );
}

#[test]
fn a_masked_service_runs_nothing() {
    let decoy = Decoy::new();
    decoy
        .file("/etc/updatedb.conf", DEBIAN)
        .file(
            "/usr/lib/systemd/system/plocate-updatedb.service",
            DEBIAN_SERVICE,
        )
        .mask("plocate-updatedb.service")
        .enable("/etc/systemd/system", "plocate-updatedb.timer");
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");
    assert!(
        message(&result).contains("nothing can start it"),
        "{result:?}"
    );
}

#[test]
fn a_service_dropin_changes_what_the_timer_runs() {
    // `systemctl edit` writes a drop-in that empties ExecStart and sets it
    // anew; the drop-in's options decide.
    let decoy = debian(DEBIAN);
    decoy.file(
        "/etc/systemd/system/plocate-updatedb.service.d/override.conf",
        "[Service]\nExecStart=\nExecStart=/usr/sbin/updatedb.plocate --add-prunepaths /mnt\n",
    );
    let result = decoy.check(false);
    // The timer's run skips the volume; a run by hand does not.
    assert!(result.is_warn(), "{result:?}");
    assert!(
        !message(&result).contains("plocate-updatedb.timer schedules"),
        "{result:?}"
    );
    // A drop-in that runs something else cannot be told about.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy.file(
        "/etc/systemd/system/service.d/zz-wrap.conf",
        "[Service]\nExecStart=\nExecStart=/bin/sh -c updatedb\n",
    );
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains("runs /bin/sh, which NAILS does not read as updatedb"),
        "{result:?}"
    );
}

#[test]
fn the_check_writes_nothing() {
    let decoy = debian(DEBIAN);
    decoy
        .active("plocate-updatedb.service")
        .process(5, "updatedb", &["updatedb"]);
    let before = decoy.fs.mock_ops().len();
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        decoy.fs.mock_ops().len(),
        before,
        "the check writes nothing"
    );
    assert!(decoy.fs.mock_written_paths().is_empty());
}

#[test]
fn the_reader_works_under_a_root_on_real_files() {
    use crate::RealFilesystem;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let write = |rel: &str, text: &str| {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    // No PRUNEFS, so that the host's own mounts cannot cover anything, and
    // no path the scratch directory may lie below.
    write("etc/updatedb.conf", "PRUNEPATHS=\"/var/spool\"\n");
    write(
        "usr/lib/systemd/system/plocate-updatedb.service",
        DEBIAN_SERVICE,
    );
    write("usr/sbin/updatedb.plocate", "");
    let wants = root.join("etc/systemd/system/timers.target.wants");
    std::fs::create_dir_all(&wants).unwrap();
    std::os::unix::fs::symlink(
        "/usr/lib/systemd/system/plocate-updatedb.timer",
        wants.join("plocate-updatedb.timer"),
    )
    .unwrap();
    let hidden = root.join("mnt/data");
    std::fs::create_dir_all(&hidden).unwrap();
    let check = LocateDatabaseCheck::new(hidden.clone(), false).with_root(root);
    let result = check.run(&RealFilesystem).unwrap();
    assert!(result.is_fail(), "{result:?}");

    // Pruning the volume's parent fixes it.
    let parent = hidden
        .canonicalize()
        .unwrap()
        .parent()
        .unwrap()
        .display()
        .to_string();
    write(
        "etc/updatedb.conf",
        &format!("PRUNEPATHS=\"/var/spool {parent}\"\n"),
    );
    let result = check.run(&RealFilesystem).unwrap();
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn the_check_has_a_stable_name() {
    let check = LocateDatabaseCheck::new(PathBuf::from(HIDDEN_ROOT), false);
    assert_eq!(
        <LocateDatabaseCheck as PreFlightCheck<MockFilesystem>>::name(&check),
        "locate-database"
    );
    assert!(
        <LocateDatabaseCheck as PreFlightCheck<MockFilesystem>>::description(&check)
            .contains("locate database")
    );
}

#[test]
fn the_dropin_directories_go_from_the_unit_to_its_type() {
    use super::unit::dropin_dir_names;
    assert_eq!(
        dropin_dir_names("plocate-updatedb.service"),
        [
            "plocate-updatedb.service.d",
            "plocate-.service.d",
            "service.d"
        ]
    );
    assert_eq!(
        dropin_dir_names("a-b-c.timer"),
        ["a-b-c.timer.d", "a-b-.timer.d", "a-.timer.d", "timer.d"]
    );
    assert_eq!(dropin_dir_names("plain"), ["plain.d"]);
}
