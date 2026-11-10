// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::RealFilesystem;
use crate::filesystem::MockFilesystem;
use crate::test_support::{CHILD_ENV, Outcome, Rerun};

/// The lock file under both of its names.
const LOCK: &str = "/run/unattended-upgrades.lock";
const VAR_LOCK: &str = "/var/run/unattended-upgrades.lock";

/// `/run` as a tmpfs gives it: device 0:25.
const RUN_DEV: u64 = 25;
const LOCK_INODE: u64 = 1234;

/// A decoy whose lock file exists, under both of its names, with `holder`
/// holding a lock on it as the kernel's F_GETLK names one: a PID, or none.
fn decoy_with_lock(holder: Option<i32>) -> MockFilesystem {
    let fs = MockFilesystem::new();
    for path in [LOCK, VAR_LOCK] {
        fs.mock_add_file(path, "");
        fs.mock_set_inode(Path::new(path), LOCK_INODE);
        fs.mock_set_device_id(Path::new(path), RUN_DEV);
        fs.mock_set_record_lock_holder(Path::new(path), holder);
    }
    fs
}

fn check(fs: &MockFilesystem) -> CheckResult {
    PreFlightCheck::<MockFilesystem>::run(&UpgradeRunCheck::new(), fs).unwrap()
}

#[test]
fn a_decoy_with_no_run_passes_without_asking_about_a_lock() {
    // No lock file: no run took the lock since the boot, and nothing is
    // opened. The mock answers a query of a path it lacks with an error,
    // which a pass therefore did not make.
    let result = check(&MockFilesystem::new());
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn an_active_daily_upgrade_unit_refuses_until_it_ends() {
    let fs = MockFilesystem::new();
    fs.create_symlink(
        Path::new("8028a17235414b4e80c950b24a7487d7"), // pragma: allowlist secret
        Path::new("/run/systemd/units/invocation:apt-daily-upgrade.service"),
    )
    .unwrap();
    let result = check(&fs);
    assert!(result.is_fail(), "{result:?}");
    let message = result.message();
    assert!(
        message.contains("apt-daily-upgrade.service is active"),
        "{message}"
    );
    // The unit is apt's, and its run may not hold the lock yet: the line is
    // what the helper writes when it runs and finds the lock held.
    assert!(
        message.contains(
            "the shutdown helper of unattended-upgrades, if it runs, stops a run that holds the \
             lock and writes `Unattended-upgrade in progress during shutdown` to its log on the \
             decoy disk"
        ),
        "{message}"
    );
    assert_eq!(result.remediation(), Some(RETRY));
    // apt-daily.service takes the lock for its download, too.
    assert!(
        RETRY.contains("`systemctl status apt-daily.service apt-daily-upgrade.service`"),
        "{RETRY}"
    );
    // No flag lifts it.
    assert!(
        !matches!(
            result,
            CheckResult::Fail {
                allowable: Some(_),
                ..
            }
        ),
        "{result:?}"
    );
}

#[test]
fn an_active_daily_download_unit_refuses_before_it_takes_the_lock() {
    // apt-daily.service runs apt-get update, and only then its run of
    // unattended-upgrade takes the lock: a switch made before that meets the
    // lock when the helper looks for it.
    let fs = MockFilesystem::new();
    fs.create_symlink(
        Path::new("8028a17235414b4e80c950b24a7487d7"), // pragma: allowlist secret
        Path::new("/run/systemd/units/invocation:apt-daily.service"),
    )
    .unwrap();
    let result = check(&fs);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .contains("apt-daily.service is active, whose download run takes the lock"),
        "{result:?}"
    );
    assert_eq!(result.remediation(), Some(RETRY));
    // Seen in the cgroup tree too, and with the lock taken both signs show.
    let fs = decoy_with_lock(Some(812));
    fs.mock_add_file(
        "/sys/fs/cgroup/system.slice/apt-daily.service/cgroup.events",
        "populated 1\nfrozen 0\n",
    );
    assert_eq!(
        upgrade_run(&fs, Path::new("/")),
        UpgradeRun::InProgress(vec![
            "apt-daily.service is active, whose download run takes the lock".to_string(),
            "PID 812 holds /run/unattended-upgrades.lock".to_string(),
        ])
    );
    // Once its run ended the unit is inactive, and the row passes.
    let fs = MockFilesystem::new();
    fs.mock_add_file(
        "/sys/fs/cgroup/system.slice/apt-daily.service/cgroup.events",
        "populated 0\nfrozen 0\n",
    );
    assert!(check(&fs).is_pass());
}

#[test]
fn a_held_lock_refuses_and_names_its_holder_once() {
    let fs = decoy_with_lock(Some(812));
    let result = check(&fs);
    assert!(result.is_fail(), "{result:?}");
    let message = result.message();
    assert!(
        message.contains("PID 812 holds /run/unattended-upgrades.lock"),
        "{message}"
    );
    // /var/run/unattended-upgrades.lock is the same file.
    assert_eq!(message.matches(" holds /").count(), 1, "{message}");
    assert_eq!(result.remediation(), Some(RETRY));
}

#[test]
fn a_lock_file_no_process_holds_passes() {
    let result = check(&decoy_with_lock(None));
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn a_holder_with_no_pid_here_is_a_process() {
    // An open file description lock has no process (-1), and the kernel
    // gives 0 for a holder outside the caller's PID namespace.
    for holder in [-1, 0] {
        let fs = decoy_with_lock(Some(holder));
        assert_eq!(
            upgrade_run(&fs, Path::new("/")),
            UpgradeRun::InProgress(vec![
                "a process holds /run/unattended-upgrades.lock".to_string()
            ]),
            "{holder}"
        );
    }
    let fs = decoy_with_lock(Some(1));
    assert_eq!(
        upgrade_run(&fs, Path::new("/")),
        UpgradeRun::InProgress(vec![
            "PID 1 holds /run/unattended-upgrades.lock".to_string()
        ])
    );
}

#[test]
fn a_lock_held_under_the_var_run_name_alone_refuses() {
    // A decoy whose /var/run is a directory of its own.
    let fs = MockFilesystem::new();
    fs.mock_add_file(VAR_LOCK, "");
    fs.mock_set_inode(Path::new(VAR_LOCK), LOCK_INODE);
    fs.mock_set_device_id(Path::new(VAR_LOCK), RUN_DEV);
    fs.mock_set_record_lock_holder(Path::new(VAR_LOCK), Some(812));
    let result = check(&fs);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .contains("PID 812 holds /var/run/unattended-upgrades.lock"),
        "{result:?}"
    );
}

#[test]
fn what_cannot_be_read_refuses_as_unknown() {
    // The lock file is there, and the kernel cannot be asked about it.
    let fs = MockFilesystem::new();
    fs.mock_add_file(LOCK, "");
    fs.mock_set_record_lock_error(Path::new(LOCK), std::io::ErrorKind::InvalidData);
    let unknown = upgrade_run(&fs, Path::new("/"));
    assert!(
        matches!(&unknown, UpgradeRun::Unknown(why)
            if why.starts_with(&format!("{LOCK} cannot be asked about its locks: "))),
        "{unknown:?}"
    );
    let result = check(&fs);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().starts_with("NAILS cannot tell"),
        "{result:?}"
    );
    assert_eq!(result.remediation(), Some(UNREAD));

    // The lock file cannot be looked up.
    let fs = MockFilesystem::new();
    fs.mock_set_inode_error(Path::new(LOCK), std::io::ErrorKind::PermissionDenied);
    let unknown = upgrade_run(&fs, Path::new("/"));
    assert!(
        matches!(&unknown, UpgradeRun::Unknown(why) if why.contains(LOCK)),
        "{unknown:?}"
    );
}

#[test]
fn a_lock_file_only_root_can_open_says_to_run_as_root() {
    // unattended-upgrade makes its lock file with mode 0640: a check run
    // without root may not open it, and one run as root can.
    let fs = MockFilesystem::new();
    fs.mock_add_file(LOCK, "");
    fs.mock_set_record_lock_error(Path::new(LOCK), std::io::ErrorKind::PermissionDenied);
    let without_root = upgrade_run_as(&fs, Path::new("/"), false);
    assert!(
        matches!(&without_root, UpgradeRun::UnknownWithoutRoot(why)
            if why.ends_with("; only root can open it")),
        "{without_root:?}"
    );
    let refusal = without_root.refusal().expect("a refusal");
    assert!(
        refusal.starts_with(
            "NAILS cannot tell without root whether a daily unattended-upgrade run is in progress \
             (/run/unattended-upgrades.lock cannot be asked about its locks: "
        ),
        "{refusal}"
    );
    let fix = without_root.fix();
    assert!(fix.starts_with("Run the check as root (`sudo "), "{fix}");
    assert!(fix.contains(" check`)"), "{fix}");
    // Refused as root, as by a security module, it is no matter of root.
    let as_root = upgrade_run_as(&fs, Path::new("/"), true);
    assert!(
        matches!(&as_root, UpgradeRun::Unknown(why) if !why.contains("only root")),
        "{as_root:?}"
    );
    assert_eq!(as_root.fix(), UNREAD);
    // Any other error is no matter of root either.
    fs.mock_set_record_lock_error(Path::new(LOCK), std::io::ErrorKind::NotFound);
    assert!(matches!(
        upgrade_run_as(&fs, Path::new("/"), false),
        UpgradeRun::Unknown(_)
    ));
}

#[test]
fn a_lock_file_that_is_no_plain_file_refuses_as_unknown() {
    // The helper opens the lock file without following a link and takes
    // one it cannot open for a held lock, which no lock shows.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::create_dir_all(root.join("run")).unwrap();
    std::fs::create_dir_all(root.join("srv")).unwrap();
    std::fs::write(root.join("srv/lock"), "").unwrap();
    let lock = root.join("run/unattended-upgrades.lock");
    let check = UpgradeRunCheck::with_root(root);
    const LINK: &str = "/run/unattended-upgrades.lock is a symbolic link, not a plain file";
    for (kind, why) in [
        ("a link that leads nowhere", LINK),
        ("a link to a plain file", LINK),
        (
            "a directory",
            "/run/unattended-upgrades.lock is not a plain file",
        ),
    ] {
        match kind {
            "a link that leads nowhere" => {
                std::os::unix::fs::symlink("/nonexistent/lock", &lock).unwrap();
            }
            "a link to a plain file" => {
                std::os::unix::fs::symlink(root.join("srv/lock"), &lock).unwrap();
            }
            _ => std::fs::create_dir(&lock).unwrap(),
        }
        let result = PreFlightCheck::<RealFilesystem>::run(&check, &RealFilesystem).unwrap();
        assert!(result.is_fail(), "{kind}: {result:?}");
        let message = result.message();
        assert!(
            message.starts_with(&format!(
                "NAILS cannot tell whether a daily unattended-upgrade run is in progress ({why})"
            )),
            "{kind}: {message}"
        );
        assert_eq!(result.remediation(), Some(UNREAD), "{kind}");
        if lock.is_dir() {
            std::fs::remove_dir(&lock).unwrap();
        } else {
            std::fs::remove_file(&lock).unwrap();
        }
    }
    // A plain file nobody locks passes.
    std::fs::write(&lock, "").unwrap();
    let result = PreFlightCheck::<RealFilesystem>::run(&check, &RealFilesystem).unwrap();
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn a_lock_another_process_holds_on_a_scratch_tree_refuses() {
    // The lock unattended-upgrade takes (apt's GetLock(): fcntl F_SETLK,
    // a write lock over the whole file), held by this process on the lock
    // file of a scratch tree while a child process runs the check on it,
    // with the kernel's own answers. The parent's pid names the tree.
    fn root_of(pid: u32) -> PathBuf {
        std::env::temp_dir().join(format!("nails-upgrade-run-{pid}"))
    }
    let in_child = std::env::var_os(CHILD_ENV).is_some();
    let held = (!in_child).then(|| {
        let root = root_of(std::process::id());
        std::fs::create_dir_all(root.join("run")).unwrap();
        let file = std::fs::File::create(root.join("run/unattended-upgrades.lock")).unwrap();
        rustix::fs::fcntl_lock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .unwrap();
        (root, file)
    });
    let outcome = Rerun::new(crate::test_path!(
        a_lock_another_process_holds_on_a_scratch_tree_refuses
    ))
    .run(|| {
        let parent = std::os::unix::process::parent_id();
        let check = UpgradeRunCheck::with_root(&root_of(parent));
        let result = PreFlightCheck::<RealFilesystem>::run(&check, &RealFilesystem).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert_eq!(
            result.message(),
            format!(
                "a daily unattended-upgrade run is in progress (PID {parent} holds \
                 /run/unattended-upgrades.lock): {AT_THE_SWITCH}"
            )
        );
    });
    if let Some((root, file)) = held {
        // With the lock released the same tree passes.
        drop(file);
        let check = UpgradeRunCheck::with_root(&root);
        let result = PreFlightCheck::<RealFilesystem>::run(&check, &RealFilesystem).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        assert!(result.is_pass(), "{result:?}");
    }
    assert_eq!(outcome, Outcome::Ran);
}

#[test]
fn an_open_file_description_lock_on_a_scratch_tree_refuses() {
    // An open file description owns its lock, not the process, so the
    // check meets it in the process that holds it, with no PID to name.
    use nix::fcntl::{FcntlArg, fcntl};
    use nix::libc;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::create_dir_all(root.join("run")).unwrap();
    let file = std::fs::File::create(root.join("run/unattended-upgrades.lock")).unwrap();
    let lock = libc::flock {
        l_type: libc::F_WRLCK as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    fcntl(&file, FcntlArg::F_OFD_SETLK(&lock)).unwrap();
    assert_eq!(
        upgrade_run(&RealFilesystem, root),
        UpgradeRun::InProgress(vec![
            "a process holds /run/unattended-upgrades.lock".to_string()
        ])
    );
    drop(file);
    assert_eq!(upgrade_run(&RealFilesystem, root), UpgradeRun::Idle);
}

#[test]
fn the_check_names_itself() {
    assert_eq!(
        PreFlightCheck::<MockFilesystem>::name(&UpgradeRunCheck::new()),
        "unattended-upgrade-run"
    );
    assert!(
        PreFlightCheck::<MockFilesystem>::description(&UpgradeRunCheck::new())
            .contains("unattended-upgrade run")
    );
}

#[test]
fn the_probe_writes_nothing() {
    let fs = decoy_with_lock(Some(812));
    let before = fs.mock_ops().len();
    let _ = upgrade_run(&fs, Path::new("/"));
    assert!(fs.mock_written_paths().is_empty());
    assert_eq!(fs.mock_ops().len(), before);
}

/// A lock file whose lookup fails for another reason than that nothing is
/// there may be held: NAILS cannot tell, and refuses, naming the path.
#[test]
fn a_lock_file_that_cannot_be_looked_up_refuses() {
    for (path, kind) in [
        (LOCK, std::io::ErrorKind::PermissionDenied),
        (VAR_LOCK, std::io::ErrorKind::Other),
    ] {
        let fs = MockFilesystem::new();
        fs.mock_set_lookup_error(path, kind);
        let unknown = upgrade_run(&fs, Path::new("/"));
        assert!(
            matches!(&unknown, UpgradeRun::Unknown(why)
                if why.starts_with(&format!("{path} cannot be looked up: "))),
            "{unknown:?}"
        );
        let result = check(&fs);
        assert!(result.is_fail(), "{result:?}");
        assert_eq!(result.remediation(), Some(UNREAD));
    }
    // A lock file that is not there was not taken since the boot.
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error(LOCK, std::io::ErrorKind::NotFound);
    assert_eq!(upgrade_run(&fs, Path::new("/")), UpgradeRun::Idle);
}

/// A daily run's unit whose marker cannot be looked up, and that no other
/// route shows running, may run: NAILS cannot tell, and refuses, unless
/// another sign shows a run.
#[test]
fn a_daily_unit_nails_cannot_tell_runs_refuses() {
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error(
        "/run/systemd/units/invocation:apt-daily.service",
        std::io::ErrorKind::PermissionDenied,
    );
    let unknown = upgrade_run(&fs, Path::new("/"));
    assert!(
        matches!(&unknown, UpgradeRun::Unknown(why)
            if why.starts_with("NAILS cannot tell whether apt-daily.service runs: NAILS cannot \
                                look up /run/systemd/units/invocation:apt-daily.service")),
        "{unknown:?}"
    );
    assert!(check(&fs).is_fail());
    // A sign of a run says more.
    fs.create_symlink(
        Path::new("8028a17235414b4e80c950b24a7487d7"), // pragma: allowlist secret
        Path::new("/run/systemd/units/invocation:apt-daily-upgrade.service"),
    )
    .unwrap();
    assert_eq!(
        upgrade_run(&fs, Path::new("/")),
        UpgradeRun::InProgress(vec!["apt-daily-upgrade.service is active".to_string()])
    );
}
