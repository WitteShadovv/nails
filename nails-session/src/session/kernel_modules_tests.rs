// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the judge of the running kernel's modules, its readers and
//! the `kernel-modules` row.

use super::*;
use crate::filesystem::MockFilesystem;
use std::time::Duration;

const RELEASE: &str = "6.17.1-arch1-1";

fn release() -> OsString {
    OsString::from(RELEASE)
}

/// A decoy whose index was rebuilt at `secs` after the epoch.
fn decoy_at(secs: u64) -> Decoy {
    Decoy::Release {
        index: Some(at(secs)),
    }
}

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

const MERGED: Held = Held::Dir(Opacity::Merged);
const OPAQUE: Held = Held::Dir(Opacity::Opaque);

fn doubt() -> Held {
    Held::Dir(Opacity::Unknown(Doubt::NeedsRoot))
}

fn hidden(at: Step, how: Hiding) -> Verdict {
    Verdict::Hidden { at, how }
}

/// What the upper holds for a release directory merged with the decoy's: the
/// four directories on the way, then the `text` and `binary` index files.
fn merged(text: Held, binary: Held) -> [Held; 6] {
    [MERGED, MERGED, MERGED, MERGED, text, binary]
}

#[test]
fn the_decoys_side_decides_first() {
    // A whiteout cannot hide what the decoy does not have: a NixOS decoy keeps
    // its modules in the store, and a decoy updated without a reboot lacks them
    // itself.
    let whiteout = [MERGED, MERGED, MERGED, Held::Whiteout];
    assert_eq!(judge(&Decoy::NoModuleDir, &whiteout), Verdict::NoModuleDir);
    assert_eq!(judge(&Decoy::NoRelease, &whiteout), Verdict::MissingOnDecoy);
    assert_eq!(
        judge(&Decoy::Unknown("why".into()), &whiteout),
        Verdict::Unknown(Doubt::Other("why".into()))
    );
}

#[test]
fn nothing_in_the_upper_leaves_the_tree_intact() {
    let decoy = decoy_at(10);
    assert_eq!(judge(&decoy, &[Held::Nothing]), Verdict::Intact);
    assert_eq!(judge(&decoy, &[]), Verdict::Intact);
    // A session that changed something next to the tree copied the
    // directories above it up, merged.
    assert_eq!(
        judge(&decoy, &[MERGED, MERGED, MERGED, Held::Nothing]),
        Verdict::Intact
    );
    // One that changed something inside it holds the release directory, but
    // not the index.
    assert_eq!(
        judge(&decoy, &[MERGED, MERGED, MERGED, MERGED, Held::Nothing]),
        Verdict::Intact
    );
}

#[test]
fn a_whiteout_on_the_way_deletes_the_tree() {
    let decoy = decoy_at(10);
    assert_eq!(
        judge(&decoy, &[MERGED, MERGED, MERGED, Held::Whiteout]),
        hidden(Step::Release, Hiding::Deleted)
    );
    assert_eq!(
        judge(&decoy, &[MERGED, MERGED, Held::Whiteout]),
        hidden(Step::ModuleDir, Hiding::Deleted)
    );
    assert_eq!(
        judge(&decoy, &[Held::Whiteout]),
        hidden(Step::Usr, Hiding::Deleted)
    );
}

#[test]
fn anything_but_a_directory_on_the_way_replaces_the_tree() {
    let decoy = decoy_at(10);
    assert_eq!(
        judge(&decoy, &[MERGED, Held::Other]),
        hidden(Step::UsrLib, Hiding::Replaced)
    );
    assert_eq!(
        judge(&decoy, &[MERGED, MERGED, MERGED, Held::File(at(5))]),
        hidden(Step::Release, Hiding::Replaced)
    );
}

#[test]
fn an_opaque_directory_without_the_release_covers_it() {
    let decoy = decoy_at(10);
    // `rm -rf /usr/lib/modules`, then a new kernel's tree: the new directory is
    // opaque and has another release only.
    assert_eq!(
        judge(&decoy, &[MERGED, MERGED, OPAQUE, Held::Nothing]),
        hidden(Step::ModuleDir, Hiding::Covered)
    );
    // Below an opaque directory the directory itself keeps the tree away, so
    // the fix deletes it, not what lies below it.
    assert_eq!(
        judge(&decoy, &[MERGED, MERGED, OPAQUE, Held::Whiteout]),
        hidden(Step::ModuleDir, Hiding::Covered)
    );
    assert_eq!(
        judge(&decoy, &[MERGED, OPAQUE, MERGED, Held::Other]),
        hidden(Step::UsrLib, Hiding::Covered)
    );
}

#[test]
fn an_opaque_directory_with_the_release_is_the_sessions_own_copy() {
    let decoy = decoy_at(10);
    // The release deleted and installed again.
    assert_eq!(
        judge(
            &decoy,
            &[MERGED, MERGED, MERGED, OPAQUE, Held::File(at(20))]
        ),
        hidden(Step::Release, Hiding::OwnCopy)
    );
    // The first opaque directory on the way is the one to delete.
    assert_eq!(
        judge(
            &decoy,
            &[MERGED, OPAQUE, MERGED, OPAQUE, Held::File(at(20))]
        ),
        hidden(Step::UsrLib, Hiding::OwnCopy)
    );
    // A copy without an index loads nothing by name.
    assert_eq!(
        judge(&decoy, &[MERGED, MERGED, MERGED, OPAQUE, Held::Nothing]),
        hidden(Step::Release, Hiding::CopyWithoutIndex)
    );
    assert_eq!(
        judge(&decoy, &[MERGED, MERGED, OPAQUE, MERGED, Held::Nothing]),
        hidden(Step::ModuleDir, Hiding::CopyWithoutIndex)
    );
}

#[test]
fn a_deleted_or_replaced_index_is_found_in_a_merged_tree() {
    let decoy = decoy_at(10);
    // A kernel update that could not delete the directory itself (a module
    // some other package left there) still deletes the index.
    assert_eq!(
        judge(&decoy, &merged(Held::Whiteout, Held::Whiteout)),
        hidden(Step::Release, Hiding::IndexDeleted(Step::Index))
    );
    assert_eq!(
        judge(&decoy, &[MERGED, MERGED, MERGED, MERGED, Held::Other]),
        hidden(Step::Release, Hiding::IndexReplaced(Step::Index))
    );
    assert_eq!(
        judge(&decoy, &[MERGED, MERGED, MERGED, MERGED, MERGED]),
        hidden(Step::Release, Hiding::IndexReplaced(Step::Index))
    );
    // In a copy below an opaque directory, the copy goes as a whole.
    assert_eq!(
        judge(&decoy, &[MERGED, MERGED, OPAQUE, MERGED, Held::Whiteout]),
        hidden(Step::ModuleDir, Hiding::IndexDeleted(Step::Index))
    );
}

#[test]
fn the_binary_index_modprobe_reads_counts_on_its_own() {
    let decoy = decoy_at(10);
    // `modprobe` finds a module by name through the binary form alone.
    assert_eq!(
        judge(&decoy, &merged(Held::Nothing, Held::Whiteout)),
        hidden(Step::Release, Hiding::IndexDeleted(Step::BinaryIndex))
    );
    assert_eq!(
        judge(&decoy, &merged(Held::File(at(20)), Held::Other)),
        hidden(Step::Release, Hiding::IndexReplaced(Step::BinaryIndex))
    );
    assert_eq!(
        judge(&decoy, &merged(Held::Nothing, MERGED)),
        hidden(Step::Release, Hiding::IndexReplaced(Step::BinaryIndex))
    );
    assert_eq!(
        judge(
            &decoy,
            &merged(Held::Nothing, Held::Unreadable("no".into()))
        ),
        Verdict::Unknown(Doubt::Other("no".into()))
    );
    // Below an opaque directory, the copy goes as a whole.
    assert_eq!(
        judge(
            &decoy,
            &[
                MERGED,
                MERGED,
                MERGED,
                OPAQUE,
                Held::File(at(20)),
                Held::Whiteout
            ]
        ),
        hidden(Step::Release, Hiding::IndexDeleted(Step::BinaryIndex))
    );
    // Whether the upper has an index of its own, and how old it is, the text
    // form tells.
    assert_eq!(
        judge(&decoy, &merged(Held::Nothing, Held::File(at(5)))),
        Verdict::Intact
    );
    assert_eq!(
        judge(&decoy, &merged(Held::File(at(20)), Held::File(at(5)))),
        Verdict::OwnIndex
    );
}

#[test]
fn an_own_index_older_than_the_decoys_is_stale() {
    let own = |secs| [MERGED, MERGED, MERGED, MERGED, Held::File(at(secs))];
    // Written after (or with) the decoy's last rebuild: it covers the
    // decoy's modules as they are.
    assert_eq!(judge(&decoy_at(10), &own(20)), Verdict::OwnIndex);
    assert_eq!(judge(&decoy_at(10), &own(10)), Verdict::OwnIndex);
    assert_eq!(
        judge(&Decoy::Release { index: None }, &own(20)),
        Verdict::OwnIndex
    );
    // Written before it: modules the decoy added since are missing from it.
    assert_eq!(
        judge(&decoy_at(30), &own(20)),
        hidden(Step::Release, Hiding::StaleIndex)
    );
}

#[test]
fn an_unknown_opacity_is_a_doubt_unless_something_below_settles_it() {
    let decoy = decoy_at(10);
    let needs_root = Verdict::Unknown(Doubt::NeedsRoot);
    // Merged, the tree shows through; opaque, it is covered: no verdict.
    assert_eq!(judge(&decoy, &[doubt(), Held::Nothing]), needs_root);
    assert_eq!(
        judge(&decoy, &[doubt(), doubt(), doubt(), doubt(), Held::Nothing]),
        needs_root
    );
    assert_eq!(
        judge(
            &decoy,
            &[doubt(), doubt(), doubt(), doubt(), Held::File(at(20))]
        ),
        needs_root
    );
    // A whiteout hides whatever lies above it.
    assert_eq!(
        judge(&decoy, &[doubt(), doubt(), doubt(), Held::Whiteout]),
        hidden(Step::Release, Hiding::Deleted)
    );
    assert_eq!(
        judge(
            &decoy,
            &[doubt(), doubt(), doubt(), doubt(), Held::Whiteout]
        ),
        hidden(Step::Release, Hiding::IndexDeleted(Step::Index))
    );
    // A known opaque directory above settles it.
    assert_eq!(
        judge(&decoy, &[doubt(), OPAQUE, Held::Nothing]),
        hidden(Step::UsrLib, Hiding::Covered)
    );
}

#[test]
fn an_unreadable_entry_is_a_doubt() {
    let decoy = decoy_at(10);
    let unreadable = Held::Unreadable("no".into());
    let expected = Verdict::Unknown(Doubt::Other("no".into()));
    assert_eq!(judge(&decoy, &[MERGED, unreadable.clone()]), expected);
    assert_eq!(
        judge(&decoy, &[MERGED, MERGED, MERGED, MERGED, unreadable]),
        expected
    );
}

/// Make `rel` below `root` a directory.
fn mkdir(root: &Path, rel: &str) -> PathBuf {
    let path = root.join(rel);
    std::fs::create_dir_all(&path).unwrap();
    path
}

/// The 0:0 character device overlayfs leaves for a deleted path, or `false`
/// on a host that forbids making one (a device cgroup); Linux lets an
/// unprivileged process make it since 5.8.
fn whiteout(path: &Path) -> bool {
    use rustix::fs::{CWD, FileType, Mode, mknodat};
    match mknodat(
        CWD,
        path,
        FileType::CharacterDevice,
        Mode::from_raw_mode(0o600),
        0,
    ) {
        Ok(()) => true,
        Err(rustix::io::Errno::PERM) => false,
        Err(e) => panic!("mknod a whiteout: {e}"),
    }
}

/// A decoy with the running kernel's tree and its index.
fn decoy_with_tree() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    let tree = mkdir(root.path(), &format!("usr/lib/modules/{RELEASE}"));
    mkdir(&tree, "kernel/fs");
    std::fs::write(tree.join("modules.dep"), "kernel/fs/ext4.ko:\n").unwrap();
    root
}

fn set_modified(path: &Path, secs: u64) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(at(secs)))
        .unwrap();
}

#[test]
fn the_decoy_reader_finds_the_tree_and_its_index() {
    let root = tempfile::tempdir().unwrap();
    // A NixOS decoy has a /usr, but no /usr/lib.
    mkdir(root.path(), "usr/bin");
    assert_eq!(read_decoy(root.path(), &release()), Decoy::NoModuleDir);

    mkdir(root.path(), "usr/lib/modules/6.16.0-arch1-1");
    assert_eq!(read_decoy(root.path(), &release()), Decoy::NoRelease);

    let tree = mkdir(root.path(), &format!("usr/lib/modules/{RELEASE}"));
    assert_eq!(
        read_decoy(root.path(), &release()),
        Decoy::Release { index: None }
    );

    std::fs::write(tree.join("modules.dep"), "").unwrap();
    set_modified(&tree.join("modules.dep"), 1_000);
    assert_eq!(read_decoy(root.path(), &release()), decoy_at(1_000));

    // An index that is no file has no time to compare with.
    std::fs::remove_file(tree.join("modules.dep")).unwrap();
    mkdir(&tree, "modules.dep");
    assert_eq!(
        read_decoy(root.path(), &release()),
        Decoy::Release { index: None }
    );
}

#[test]
fn the_decoy_reader_never_follows_a_link_on_the_way() {
    let root = tempfile::tempdir().unwrap();
    mkdir(root.path(), &format!("srv/modules/{RELEASE}"));
    mkdir(root.path(), "usr/lib");
    std::os::unix::fs::symlink("/srv/modules", root.path().join("usr/lib/modules")).unwrap();
    let Decoy::Unknown(reason) = read_decoy(root.path(), &release()) else {
        panic!("a link on the way must leave the decoy's side unknown");
    };
    assert_eq!(reason, "/usr/lib/modules on the decoy is a symbolic link");

    // A file where a directory belongs holds no modules.
    let root = tempfile::tempdir().unwrap();
    mkdir(root.path(), "usr/lib");
    std::fs::write(root.path().join("usr/lib/modules"), "").unwrap();
    assert_eq!(read_decoy(root.path(), &release()), Decoy::NoModuleDir);
}

#[test]
fn the_upper_reader_stops_at_the_first_entry_that_is_no_directory() {
    let upper = tempfile::tempdir().unwrap();
    let read = |xattrs| read_upper(upper.path(), &release(), xattrs);
    assert_eq!(read(TrustedXattrs::Visible), vec![Held::Nothing]);

    // Without an opaque marker a directory is merged for a process that sees
    // the markers, and a doubt for one that does not.
    let tree = mkdir(upper.path(), &format!("usr/lib/modules/{RELEASE}"));
    assert_eq!(
        read(TrustedXattrs::Visible),
        merged(Held::Nothing, Held::Nothing)
    );
    assert_eq!(
        read(TrustedXattrs::Invisible),
        vec![
            doubt(),
            doubt(),
            doubt(),
            doubt(),
            Held::Nothing,
            Held::Nothing
        ]
    );

    // Past the directories it reads both index files.
    std::fs::write(tree.join("modules.dep"), "").unwrap();
    set_modified(&tree.join("modules.dep"), 2_000);
    std::fs::write(tree.join("modules.dep.bin"), "").unwrap();
    set_modified(&tree.join("modules.dep.bin"), 3_000);
    assert_eq!(
        read(TrustedXattrs::Visible),
        merged(Held::File(at(2_000)), Held::File(at(3_000)))
    );

    // A directory where an index file belongs is no index.
    std::fs::remove_file(tree.join("modules.dep")).unwrap();
    mkdir(&tree, "modules.dep");
    std::fs::remove_file(tree.join("modules.dep.bin")).unwrap();
    mkdir(&tree, "modules.dep.bin");
    assert_eq!(
        read(TrustedXattrs::Visible),
        merged(Held::Other, Held::Other)
    );

    // A link on the way ends the walk there.
    std::fs::remove_dir_all(upper.path().join("usr/lib")).unwrap();
    std::os::unix::fs::symlink("/elsewhere", upper.path().join("usr/lib")).unwrap();
    assert_eq!(read(TrustedXattrs::Visible), vec![MERGED, Held::Other]);
}

/// overlayfs reads the marker one byte long and takes `y` alone as opaque;
/// only root sees it, and anyone else is told it is missing.
#[test]
fn the_opaque_marker_is_exactly_one_byte_y() {
    use rustix::io::Errno;
    let rel = Path::new("usr/lib/modules");
    let visible = |read| read::marker(read, rel, TrustedXattrs::Visible);
    assert_eq!(visible(Ok(b"y")), Opacity::Opaque);
    // `x` marks a lower directory with whiteouts in files, never an upper's.
    assert_eq!(visible(Ok(b"x")), Opacity::Merged);
    assert_eq!(visible(Ok(b"")), Opacity::Merged);
    // A value longer than the byte overlayfs reads.
    assert_eq!(visible(Err(Errno::RANGE)), Opacity::Merged);
    assert_eq!(visible(Err(Errno::NOTSUP)), Opacity::Merged);
    assert_eq!(visible(Err(Errno::NODATA)), Opacity::Merged);
    assert_eq!(
        read::marker(Err(Errno::NODATA), rel, TrustedXattrs::Invisible),
        Opacity::Unknown(Doubt::NeedsRoot)
    );
    let Opacity::Unknown(Doubt::Other(reason)) = visible(Err(Errno::ACCESS)) else {
        panic!("a refused read is a doubt");
    };
    assert!(
        reason.starts_with(
            "whether a hidden session replaced /usr/lib/modules with a new directory cannot be \
             read ("
        ),
        "{reason}"
    );
}

#[test]
fn the_upper_reader_sees_a_whiteout() {
    let upper = tempfile::tempdir().unwrap();
    let modules = mkdir(upper.path(), "usr/lib/modules");
    if !whiteout(&modules.join(RELEASE)) {
        return;
    }
    assert_eq!(
        read_upper(upper.path(), &release(), TrustedXattrs::Visible),
        vec![MERGED, MERGED, MERGED, Held::Whiteout]
    );

    // Of each index file, too.
    std::fs::remove_file(modules.join(RELEASE)).unwrap();
    let tree = mkdir(&modules, RELEASE);
    assert!(whiteout(&tree.join("modules.dep")));
    assert!(whiteout(&tree.join("modules.dep.bin")));
    assert_eq!(
        read_upper(upper.path(), &release(), TrustedXattrs::Visible),
        merged(Held::Whiteout, Held::Whiteout)
    );
}

#[test]
fn an_unreadable_upper_entry_names_the_path_as_hidden_sessions_see_it() {
    use std::os::unix::fs::PermissionsExt;
    if rustix::process::geteuid().is_root() {
        // Root reads through any mode.
        return;
    }
    let upper = tempfile::tempdir().unwrap();
    let usr = mkdir(upper.path(), "usr/lib");
    let usr = usr.parent().unwrap();
    std::fs::set_permissions(usr, std::fs::Permissions::from_mode(0o000)).unwrap();
    let held = read_upper(upper.path(), &release(), TrustedXattrs::Visible);
    std::fs::set_permissions(usr, std::fs::Permissions::from_mode(0o755)).unwrap();

    let [_, Held::Unreadable(reason)] = held.as_slice() else {
        panic!("{held:?}");
    };
    assert!(
        reason.starts_with("what hidden sessions keep at /usr/lib cannot be read"),
        "{reason}"
    );
    let upper_path = upper.path().to_string_lossy().into_owned();
    assert!(!reason.contains(&upper_path), "{reason}");
}

#[test]
fn an_unreadable_decoy_path_leaves_the_decoys_side_unknown() {
    use std::os::unix::fs::PermissionsExt;
    if rustix::process::geteuid().is_root() {
        // Root reads through any mode.
        return;
    }
    let root = decoy_with_tree();
    let usr = root.path().join("usr");
    std::fs::set_permissions(&usr, std::fs::Permissions::from_mode(0o000)).unwrap();
    let decoy = read_decoy(root.path(), &release());
    std::fs::set_permissions(&usr, std::fs::Permissions::from_mode(0o755)).unwrap();
    let Decoy::Unknown(reason) = decoy else {
        panic!("{decoy:?}");
    };
    assert!(
        reason.starts_with("/usr/lib on the decoy cannot be read"),
        "{reason}"
    );

    // The tree itself readable, its index not.
    let tree = root.path().join(Step::Release.path(&release()));
    std::fs::set_permissions(&tree, std::fs::Permissions::from_mode(0o000)).unwrap();
    let decoy = read_decoy(root.path(), &release());
    std::fs::set_permissions(&tree, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        decoy,
        Decoy::Unknown(format!(
            "/usr/lib/modules/{RELEASE}/modules.dep on the decoy cannot be read \
             (Permission denied (os error 13))"
        ))
    );
}

#[test]
fn the_running_release_is_the_one_the_kernel_reports() {
    let reported = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    assert_eq!(running_release(), OsStr::new(reported.trim_end()));
}

#[test]
fn a_release_is_one_plain_directory_name() {
    assert!(plain_name(OsStr::new(RELEASE)));
    assert!(plain_name(OsStr::new("6.12.48+deb13-amd64")));
    for odd in ["", ".", "..", "6.1/x", "/"] {
        assert!(!plain_name(OsStr::new(odd)), "{odd:?}");
    }
    // The running kernel's own release is one.
    assert!(plain_name(&running_release()));
}

#[test]
fn the_same_filesystem_holds_a_tree_below_its_root() {
    let root = decoy_with_tree();
    assert_eq!(
        read::same_mount(
            root.path(),
            &root.path().join(Step::Release.path(&release()))
        ),
        Some(true)
    );
}

#[test]
fn the_same_filesystem_test_never_follows_a_final_link() {
    // /proc is a mount of its own: followed, the link would lead there.
    let root = tempfile::tempdir().unwrap();
    let link = root.path().join("link");
    std::os::unix::fs::symlink("/proc", &link).unwrap();
    assert_eq!(read::same_mount(root.path(), &link), Some(true));
    assert_eq!(
        read::same_mount(root.path(), Path::new("/proc")),
        Some(false)
    );
}

#[test]
fn a_process_without_root_sees_no_trusted_attributes() {
    if !rustix::process::geteuid().is_root() {
        assert_eq!(TrustedXattrs::of_this_process(), TrustedXattrs::Invisible);
    }
}

/// The check over the decoy `root` with the upper `upper`.
fn check(root: &Path, upper: &Path) -> KernelModulesCheck {
    KernelModulesCheck::new(root.to_path_buf(), upper.to_path_buf(), release())
}

fn tree() -> String {
    format!("/usr/lib/modules/{RELEASE}")
}

#[test]
fn the_check_reports_its_name_and_needs_the_hidden_volume() {
    let check = check(Path::new("/"), Path::new("/mnt/hidden/root/upper"));
    // The id is a status contract `check --json` rows are keyed on.
    assert_eq!(
        PreFlightCheck::<MockFilesystem>::name(&check),
        "kernel-modules"
    );
    let description = PreFlightCheck::<MockFilesystem>::description(&check);
    assert!(description.contains("kernel's modules"), "{description}");
    // It reads the upper, so a missing hidden volume skips it.
    assert!(PreFlightCheck::<MockFilesystem>::requires_hidden_volume(
        &check
    ));
}

#[test]
fn a_decoy_without_module_directory_passes_without_reading_the_upper() {
    let root = tempfile::tempdir().unwrap();
    let upper = tempfile::tempdir().unwrap();
    // Whatever the upper holds, the decoy has nothing there to hide.
    mkdir(upper.path(), "usr/lib/modules");
    let result = check(root.path(), upper.path()).result(TrustedXattrs::Invisible);
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        result.message(),
        "the decoy keeps no kernel modules in /usr/lib/modules"
    );
}

#[test]
fn a_decoy_without_the_running_kernels_tree_warns_to_reboot() {
    let root = tempfile::tempdir().unwrap();
    mkdir(root.path(), "usr/lib/modules/6.16.0-arch1-1");
    let upper = tempfile::tempdir().unwrap();
    let result = check(root.path(), upper.path()).result(TrustedXattrs::Visible);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .starts_with(&format!("the decoy has no {}", tree())),
        "{result:?}"
    );
    assert!(
        result
            .message()
            .contains("Reboot the decoy into the kernel it has installed"),
        "{result:?}"
    );
}

#[test]
fn an_untouched_tree_passes() {
    let root = decoy_with_tree();
    let upper = tempfile::tempdir().unwrap();
    let result = check(root.path(), upper.path()).result(TrustedXattrs::Invisible);
    assert!(result.is_pass(), "{result:?}");
    assert!(result.message().contains(&tree()), "{result:?}");
    // The upper of a first entry does not exist yet.
    let result =
        check(root.path(), &upper.path().join("root/upper")).result(TrustedXattrs::Invisible);
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn a_deleted_tree_warns_with_both_fixes_and_never_names_the_upper() {
    let root = decoy_with_tree();
    let upper = tempfile::tempdir().unwrap();
    let modules = mkdir(upper.path(), "usr/lib/modules");
    if !whiteout(&modules.join(RELEASE)) {
        return;
    }
    let result = check(root.path(), upper.path()).result(TrustedXattrs::Invisible);
    assert!(result.is_warn(), "{result:?}");
    let text = result.message();
    assert!(
        text.starts_with(&format!(
            "a hidden session deleted {}, the running kernel's modules",
            tree()
        )),
        "{text}"
    );
    assert!(
        text.contains("Update the decoy's kernel and reboot the decoy into it"),
        "{text}"
    );
    let discard = sudo_line_for(NextStep::Discard, &tree());
    assert!(text.contains(&format!("`{discard}`")), "{text}");
    assert!(
        text.contains("(it lists what it deletes and asks first)"),
        "{text}"
    );
    let upper_path = upper.path().to_string_lossy().into_owned();
    assert!(!text.contains(&upper_path), "{text}");
}

#[test]
fn on_a_root_accepted_as_decoy_storage_the_discard_takes_the_override() {
    let root = decoy_with_tree();
    let upper = tempfile::tempdir().unwrap();
    let modules = mkdir(upper.path(), "usr/lib/modules");
    if !whiteout(&modules.join(RELEASE)) {
        return;
    }
    let accepted = check(root.path(), upper.path())
        .allowing_decoy_storage(true)
        .result(TrustedXattrs::Invisible);
    let line = sudo_line_for(
        NextStep::Discard,
        &format!("--allow-decoy-storage {}", tree()),
    );
    assert!(
        accepted.message().contains(&format!("`{line}`")),
        "{accepted:?}"
    );
    let plain = check(root.path(), upper.path()).result(TrustedXattrs::Invisible);
    assert!(
        !plain.message().contains("--allow-decoy-storage"),
        "{plain:?}"
    );
}

#[test]
fn a_directory_an_unprivileged_run_cannot_judge_names_the_sudo_line() {
    let root = decoy_with_tree();
    let upper = tempfile::tempdir().unwrap();
    mkdir(upper.path(), &format!("usr/lib/modules/{RELEASE}"));
    let result = check(root.path(), upper.path()).result(TrustedXattrs::Invisible);
    assert!(result.is_warn(), "never a silent pass: {result:?}");
    let text = result.message();
    assert!(
        text.starts_with(&format!(
            "could not tell whether a hidden session hid the running kernel's modules ({})",
            tree()
        )),
        "{text}"
    );
    assert!(text.contains("only root can see"), "{text}");
    assert!(
        text.contains(&format!("`{}`", sudo_line(NextStep::Check))),
        "{text}"
    );
    // A process that sees the markers finds the directories merged.
    let result = check(root.path(), upper.path()).result(TrustedXattrs::Visible);
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn an_index_a_session_wrote_passes_unless_the_decoy_rebuilt_its_own_since() {
    let root = decoy_with_tree();
    let decoy_index = root
        .path()
        .join(format!("usr/lib/modules/{RELEASE}/modules.dep"));
    set_modified(&decoy_index, 5_000);
    let upper = tempfile::tempdir().unwrap();
    let tree_copy = mkdir(upper.path(), &format!("usr/lib/modules/{RELEASE}"));
    let own_index = tree_copy.join("modules.dep");
    std::fs::write(&own_index, "kernel/fs/ext4.ko:\nupdates/dkms/vboxdrv.ko:\n").unwrap();

    set_modified(&own_index, 6_000);
    let newer = check(root.path(), upper.path()).result(TrustedXattrs::Visible);
    assert!(newer.is_pass(), "{newer:?}");
    assert!(
        newer
            .message()
            .contains("their index (modules.dep) is one a hidden session wrote"),
        "{newer:?}"
    );

    set_modified(&own_index, 4_000);
    let older = check(root.path(), upper.path()).result(TrustedXattrs::Visible);
    assert!(older.is_warn(), "{older:?}");
    let text = older.message();
    assert!(
        text.contains("before the decoy last rebuilt its own"),
        "{text}"
    );
    assert!(text.contains(&format!("`sudo depmod {RELEASE}`")), "{text}");
    assert!(
        text.contains(&format!("`{}`", sudo_line_for(NextStep::Discard, &tree()))),
        "{text}"
    );
    assert!(text.contains("the modules they added included"), "{text}");
}

#[test]
fn a_release_that_is_no_plain_name_cannot_be_judged() {
    let root = decoy_with_tree();
    let upper = tempfile::tempdir().unwrap();
    for odd in ["", "..", "6.1/x"] {
        let result = KernelModulesCheck::new(
            root.path().to_path_buf(),
            upper.path().to_path_buf(),
            OsString::from(odd),
        )
        .result(TrustedXattrs::Visible);
        assert!(result.is_warn(), "{odd:?}: {result:?}");
        assert!(
            result.message().contains("is not a plain directory name"),
            "{odd:?}: {result:?}"
        );
    }
}

#[test]
fn every_hiding_has_its_own_message_and_a_fix() {
    let check = check(Path::new("/"), Path::new("/mnt/hidden/root/upper"));
    let tree = tree();
    let modules = format!("{tree}, the running kernel's modules");
    let all = [
        (Step::Release, Hiding::Deleted, format!("deleted {modules}")),
        (
            Step::ModuleDir,
            Hiding::Deleted,
            format!("deleted /usr/lib/modules, and with it {modules}"),
        ),
        (
            Step::Release,
            Hiding::Replaced,
            format!("replaced {modules}, with something other than a directory"),
        ),
        (
            Step::UsrLib,
            Hiding::Replaced,
            format!("replaced /usr/lib with something other than a directory, which hides {tree}"),
        ),
        (
            Step::ModuleDir,
            Hiding::Covered,
            format!("replaced the decoy's /usr/lib/modules with a new directory without {tree}"),
        ),
        (
            Step::Release,
            Hiding::OwnCopy,
            format!("replaced the decoy's {modules}, with a copy of its own, and"),
        ),
        (
            Step::UsrLib,
            Hiding::OwnCopy,
            "replaced the decoy's /usr/lib with a new directory, and".to_string(),
        ),
        (
            Step::Release,
            Hiding::CopyWithoutIndex,
            format!("replaced the decoy's {modules}, with a copy of its own that has no index"),
        ),
        (
            Step::ModuleDir,
            Hiding::CopyWithoutIndex,
            "replaced the decoy's /usr/lib/modules with a new directory whose copy".to_string(),
        ),
        (
            Step::Release,
            Hiding::IndexDeleted(Step::Index),
            format!("deleted {tree}/modules.dep, the index"),
        ),
        (
            Step::Release,
            Hiding::IndexDeleted(Step::BinaryIndex),
            format!("deleted {tree}/modules.dep.bin, the index"),
        ),
        (
            Step::Release,
            Hiding::IndexReplaced(Step::Index),
            format!("replaced {tree}/modules.dep, the index"),
        ),
        (
            Step::Release,
            Hiding::IndexReplaced(Step::BinaryIndex),
            format!("replaced {tree}/modules.dep.bin, the index"),
        ),
        (
            Step::Release,
            Hiding::StaleIndex,
            format!(
                "({tree}/modules.dep) is one a hidden session wrote before the decoy last rebuilt"
            ),
        ),
    ];
    let mut messages = std::collections::BTreeSet::new();
    for (at, how, phrase) in all {
        let result = check.report(&Verdict::Hidden { at, how });
        assert!(result.is_warn(), "{how:?}: {result:?}");
        let (message, fix) = result.message().split_once('\n').unwrap();
        assert!(message.contains(&phrase), "{how:?}: {message}");
        assert!(messages.insert(message.to_string()), "{how:?} repeats");
        // The fix deletes the hidden sessions' copy of the step that holds
        // the change; only a stale index has a fix of its own first, and only
        // a copy of the decoy's own tree may still load.
        let place = format!("/{}", at.path(&release()).display());
        let restore = format!(
            "bring the decoy's {place} back with `{}`",
            sudo_line_for(NextStep::Discard, &place)
        );
        let opening = match how {
            Hiding::OwnCopy => "If modules fail to load in hidden sessions, ".to_string(),
            Hiding::StaleIndex => {
                format!("Rebuild the index in a hidden session with `sudo depmod {RELEASE}`, or ")
            }
            _ => "Update the decoy's kernel and reboot the decoy into it, or ".to_string(),
        };
        assert!(
            fix.starts_with(&format!("{opening}{restore}")),
            "{how:?}: {fix}"
        );
    }
}

/// The row against the real kernel, in a user + mount namespace.
mod kernel_tests {
    use super::*;
    use nails_base::test_support::{Rerun, ScratchTmpfs};

    /// The namespace's root holds `CAP_SYS_ADMIN` in its own namespace only:
    /// the kernel shows it no `trusted.*` attribute, so a directory in the
    /// upper, opaque or not, is a doubt and never a pass.
    #[test]
    fn a_namespaced_root_cannot_see_an_opaque_marker_and_never_passes_on_it() {
        let _ = Rerun::new(nails_base::test_path!(
            a_namespaced_root_cannot_see_an_opaque_marker_and_never_passes_on_it
        ))
        .in_user_mount_ns()
        .run(|| {
            assert!(rustix::process::geteuid().is_root());
            assert_eq!(TrustedXattrs::of_this_process(), TrustedXattrs::Invisible);
            let decoy = ScratchTmpfs::new("");
            decoy.mkdir(&format!("usr/lib/modules/{RELEASE}/kernel"));
            let hidden = ScratchTmpfs::new("");
            let upper = hidden.mkdir("root/upper");
            std::fs::create_dir_all(upper.join("usr/lib/modules")).unwrap();

            let result = check(decoy.path(), &upper).result(TrustedXattrs::of_this_process());
            assert!(result.is_warn(), "{result:?}");
            assert!(result.message().contains("only root can see"), "{result:?}");
        });
    }

    /// The upper of the root overlay holds nothing of a decoy filesystem
    /// mounted below the root: the check says so instead of passing.
    #[test]
    fn a_tree_on_a_filesystem_of_its_own_cannot_be_judged() {
        let _ = Rerun::new(nails_base::test_path!(
            a_tree_on_a_filesystem_of_its_own_cannot_be_judged
        ))
        .in_user_mount_ns()
        .run(|| {
            let decoy = ScratchTmpfs::new("");
            let usr = decoy.mkdir("usr");
            rustix::mount::mount(
                "tmpfs",
                &usr,
                "tmpfs",
                rustix::mount::MountFlags::empty(),
                c"mode=0755",
            )
            .expect("a separate /usr");
            std::fs::create_dir_all(usr.join(format!("lib/modules/{RELEASE}"))).unwrap();
            let hidden = ScratchTmpfs::new("");

            let Decoy::Unknown(reason) = read_decoy(decoy.path(), &release()) else {
                panic!("a separate /usr must leave the decoy's side unknown");
            };
            assert!(reason.contains("on a filesystem of its own"), "{reason}");
            let result = check(decoy.path(), hidden.path()).result(TrustedXattrs::Visible);
            assert!(result.is_warn(), "{result:?}");
        });
    }
}
