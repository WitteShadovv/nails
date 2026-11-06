// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::RealFilesystem;
use crate::filesystem::MockFilesystem;

/// The lock file under both of its names.
const LOCK: &str = "/run/unattended-upgrades.lock";
const VAR_LOCK: &str = "/var/run/unattended-upgrades.lock";

/// `/run` as a tmpfs gives it: device 0:25 (`00:19` in `/proc/locks`).
const RUN_DEV: u64 = 25;
const LOCK_INODE: u64 = 1234;

/// /proc/locks as the kernel writes it (fs/locks.c, lock_get_status()): a
/// run's lock on the lock file, among others.
const HELD: &str = "\
1: POSIX  ADVISORY  WRITE 812 00:19:1234 0 EOF
2: FLOCK  ADVISORY  WRITE 691 00:19:977 0 EOF
3: OFDLCK ADVISORY  READ  -1 00:06:88 0 EOF
";

/// /proc/locks once the run has ended: other locks only, a flock() of the
/// lock file's inode on another device among them.
const FREE: &str = "\
1: FLOCK  ADVISORY  WRITE 691 00:19:977 0 EOF
2: POSIX  ADVISORY  WRITE 500 08:01:1234 0 EOF
";

/// A decoy whose lock file exists, with /proc/locks holding `locks`.
fn decoy_with_lock(locks: &str) -> MockFilesystem {
    let fs = MockFilesystem::new();
    for path in [LOCK, VAR_LOCK] {
        fs.mock_add_file(path, "");
        fs.mock_set_inode(Path::new(path), LOCK_INODE);
        fs.mock_set_device_id(Path::new(path), RUN_DEV);
    }
    fs.mock_add_file("/proc/locks", locks);
    fs
}

fn check(fs: &MockFilesystem) -> CheckResult {
    PreFlightCheck::<MockFilesystem>::run(&UpgradeRunCheck::new(), fs).unwrap()
}

#[test]
fn a_decoy_with_no_run_passes_without_reading_the_lock_list() {
    // No lock file: no run took the lock since the boot. The mock has no
    // /proc/locks either, which a pass therefore did not read.
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
    let fs = decoy_with_lock(HELD);
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
    let fs = decoy_with_lock(HELD);
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
    let result = check(&decoy_with_lock(FREE));
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn a_lock_held_under_the_var_run_name_alone_refuses() {
    // A decoy whose /var/run is a directory of its own.
    let fs = MockFilesystem::new();
    fs.mock_add_file(VAR_LOCK, "");
    fs.mock_set_inode(Path::new(VAR_LOCK), LOCK_INODE);
    fs.mock_set_device_id(Path::new(VAR_LOCK), RUN_DEV);
    fs.mock_add_file("/proc/locks", HELD);
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
    // The lock file is there, the lock list cannot be read.
    let fs = MockFilesystem::new();
    fs.mock_add_file(LOCK, "");
    let unknown = upgrade_run(&fs, Path::new("/"));
    assert!(
        matches!(&unknown, UpgradeRun::Unknown(why) if why.contains("/proc/locks")),
        "{unknown:?}"
    );
    let result = check(&fs);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().starts_with("NAILS cannot tell"),
        "{result:?}"
    );

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
fn a_lock_file_that_is_no_plain_file_refuses_as_unknown() {
    // The helper opens the lock file without following a link and takes
    // one it cannot open for a held lock, which /proc/locks does not show.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::create_dir_all(root.join("run")).unwrap();
    std::fs::create_dir_all(root.join("srv")).unwrap();
    std::fs::write(root.join("srv/lock"), "").unwrap();
    std::fs::create_dir_all(root.join("proc")).unwrap();
    std::fs::write(root.join("proc/locks"), "").unwrap();
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
fn the_lock_list_is_read_as_the_kernel_writes_it() {
    // A waiter, a flock() and a lease on the file are no lock its lock
    // conflicts with; an open file description lock has no process.
    let locks = "\
1: POSIX  ADVISORY  WRITE 812 00:19:1234 0 EOF
1: -> POSIX  ADVISORY  WRITE 900 00:19:1234 0 EOF
2: FLOCK  ADVISORY  WRITE 691 00:19:1234 0 EOF
3: LEASE  ACTIVE    READ  44 00:19:1234 0 EOF
4: OFDLCK ADVISORY  WRITE -1 00:19:1234 0 EOF
5: POSIX  ADVISORY  READ  77 103:1a5:1234 0 EOF
6: POSIX  ADVISORY  WRITE 78 00:19:12345 0 EOF
";
    assert_eq!(lock_holders(locks, (0, 25, 1234)), [812, -1]);
    assert_eq!(lock_holders(locks, (0x103, 0x1a5, 1234)), [77]);
    assert!(lock_holders(locks, (0, 25, 99)).is_empty());
    assert!(lock_holders("", (0, 25, 1234)).is_empty());
}

#[test]
fn device_numbers_decode_as_glibc_decodes_them() {
    // 259:5 (an NVMe partition), 8:0x12345 (a minor past 255), 0:25 (tmpfs),
    // and the most of each that glibc's makedev() keeps, 32 bits.
    for (major_number, minor_number) in [
        (259u64, 5u64),
        (8, 0x12345),
        (0, 25),
        (0xfff, 0xfffff),
        (0x1234_5678, 0x9abc_def0),
        (0xffff_ffff, 0xffff_ffff),
    ] {
        let dev = (minor_number & 0xff)
            | ((major_number & 0xfff) << 8)
            | ((minor_number & !0xff) << 12)
            | ((major_number & !0xfff) << 32);
        assert_eq!(
            (major(dev), minor(dev)),
            (major_number, minor_number),
            "{dev:#x}"
        );
    }
}

#[test]
fn a_real_record_lock_is_found_in_the_kernels_list() {
    // The kind of lock unattended-upgrade takes (fcntl F_SETLK over the
    // whole file), held by this process on a scratch file.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("unattended-upgrades.lock");
    let file = std::fs::File::create(&path).unwrap();
    let fs = RealFilesystem;
    let inode = fs.inode(&path).unwrap().unwrap();
    let dev = fs.device_id(&path).unwrap();
    let file_id = (major(dev), minor(dev), inode);
    let pid = i64::from(std::process::id());

    let before = std::fs::read_to_string("/proc/locks").unwrap();
    assert!(!lock_holders(&before, file_id).contains(&pid));

    rustix::fs::fcntl_lock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let held = std::fs::read_to_string("/proc/locks").unwrap();
    assert!(
        lock_holders(&held, file_id).contains(&pid),
        "{file_id:?} in\n{held}"
    );
    drop(file);
    let after = std::fs::read_to_string("/proc/locks").unwrap();
    assert!(!lock_holders(&after, file_id).contains(&pid));
}

#[test]
fn a_held_lock_on_a_scratch_tree_refuses() {
    // The check's own reads, on a real tree: the lock file under the root,
    // and the kernel's list copied there with the scratch file's lock in it.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::create_dir_all(root.join("run")).unwrap();
    std::fs::create_dir_all(root.join("proc")).unwrap();
    let lock = root.join("run/unattended-upgrades.lock");
    let file = std::fs::File::create(&lock).unwrap();
    rustix::fs::fcntl_lock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    std::fs::write(
        root.join("proc/locks"),
        std::fs::read_to_string("/proc/locks").unwrap(),
    )
    .unwrap();

    let check = UpgradeRunCheck::with_root(root);
    let result = PreFlightCheck::<RealFilesystem>::run(&check, &RealFilesystem).unwrap();
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().contains(&format!(
            "PID {} holds /run/unattended-upgrades.lock",
            std::process::id()
        )),
        "{result:?}"
    );
    drop(file);
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
    let fs = decoy_with_lock(HELD);
    let before = fs.mock_ops().len();
    let _ = upgrade_run(&fs, Path::new("/"));
    assert!(fs.mock_written_paths().is_empty());
    assert_eq!(fs.mock_ops().len(), before);
}
