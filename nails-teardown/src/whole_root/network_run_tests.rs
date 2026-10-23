// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use std::fs;

/// A `/run` with the decoy's NetworkManager and resolved per-link state, and
/// one profile NetworkManager holds in memory.
fn run_with_state() -> tempfile::TempDir {
    let run = tempfile::tempdir().unwrap();
    let r = run.path();
    fs::create_dir_all(r.join("NetworkManager/devices")).unwrap();
    fs::write(
        r.join("NetworkManager/devices/2"),
        "[device]\nmanaged=true\n",
    )
    .unwrap();
    fs::create_dir_all(r.join("NetworkManager/system-connections")).unwrap();
    fs::write(
        r.join("NetworkManager/system-connections/lo.nmconnection"),
        "[connection]\nid=lo\n",
    )
    .unwrap();
    fs::create_dir_all(r.join("systemd/resolve/netif")).unwrap();
    fs::write(r.join("systemd/resolve/netif/2"), "DNS=10.0.2.3\n").unwrap();
    run
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & PERMISSION_BITS
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn paths(entries: &[RunEntry]) -> Vec<&Path> {
    entries.iter().map(|entry| entry.path.as_path()).collect()
}

#[test]
fn the_copy_holds_each_entry_with_its_owner_and_mode_parents_first() {
    let run = run_with_state();
    let r = run.path();
    set_mode(&r.join("systemd/resolve/netif"), 0o700);
    set_mode(&r.join("systemd/resolve/netif/2"), 0o644);
    let copy = snapshot(r).unwrap();
    assert_eq!(
        paths(&copy),
        [
            Path::new("NetworkManager/devices"),
            Path::new("NetworkManager/devices/2"),
            Path::new("NetworkManager/system-connections"),
            Path::new("NetworkManager/system-connections/lo.nmconnection"),
            Path::new("systemd/resolve/netif"),
            Path::new("systemd/resolve/netif/2"),
        ]
    );
    let netif = &copy[4];
    let meta = fs::metadata(r.join("systemd/resolve/netif")).unwrap();
    assert_eq!((netif.uid, netif.gid), (meta.uid(), meta.gid()));
    assert_eq!(netif.mode, 0o700);
    assert_eq!(netif.kind, Kind::Dir);
    assert_eq!(copy[5].mode, 0o644);
    assert_eq!(copy[5].kind, Kind::File(b"DNS=10.0.2.3\n".to_vec()));
}

#[test]
fn the_state_comes_back_in_place_with_its_owner_and_mode() {
    let run = run_with_state();
    let r = run.path();
    let netif = r.join("systemd/resolve/netif");
    set_mode(&netif, 0o700);
    set_mode(&netif.join("2"), 0o644);
    let copy = snapshot(r).unwrap();
    let dir_inode = fs::metadata(&netif).unwrap().ino();
    let file_inode = fs::metadata(netif.join("2")).unwrap().ino();

    // The hidden session: resolved rewrites the decoy link's state and adds a
    // link of its own, NetworkManager changes a device file, removes another
    // and keeps a profile in memory, and something opens a file up.
    fs::write(
        netif.join("2"),
        "DNS=10.213.77.53\nDOMAINS=hidden.example\n",
    )
    .unwrap();
    set_mode(&netif.join("2"), 0o600);
    fs::write(netif.join("9"), "DNS=10.213.77.53\n").unwrap();
    fs::remove_file(r.join("NetworkManager/devices/2")).unwrap();
    fs::write(r.join("NetworkManager/devices/9"), "[device]\n").unwrap();
    fs::write(
        r.join("NetworkManager/system-connections/hidden.nmconnection"),
        "[connection]\nid=hidden\n",
    )
    .unwrap();
    fs::create_dir_all(r.join("NetworkManager/devices/extra/deep")).unwrap();
    set_mode(&netif, 0o755);

    restore(r, &copy);

    assert_eq!(
        fs::read_to_string(netif.join("2")).unwrap(),
        "DNS=10.0.2.3\n"
    );
    assert_eq!(
        fs::metadata(netif.join("2")).unwrap().ino(),
        file_inode,
        "rewritten in place"
    );
    assert_eq!(
        fs::metadata(&netif).unwrap().ino(),
        dir_inode,
        "the directory stays"
    );
    assert_eq!(mode(&netif), 0o700, "the directory's mode is back");
    assert_eq!(mode(&netif.join("2")), 0o644, "the file's mode is back");
    for gone in [
        "systemd/resolve/netif/9",
        "NetworkManager/devices/9",
        "NetworkManager/devices/extra",
        "NetworkManager/system-connections/hidden.nmconnection",
    ] {
        assert!(fs::symlink_metadata(r.join(gone)).is_err(), "{gone}");
    }
    assert_eq!(
        fs::read_to_string(r.join("NetworkManager/devices/2")).unwrap(),
        "[device]\nmanaged=true\n",
        "a removed file is made again"
    );
    assert_eq!(snapshot(r).unwrap(), copy, "entry's state, entry for entry");
}

#[test]
fn a_removed_entry_is_made_again_with_its_recorded_mode() {
    let run = run_with_state();
    let r = run.path();
    let netif = r.join("systemd/resolve/netif");
    set_mode(&netif, 0o711);
    set_mode(&netif.join("2"), 0o640);
    std::os::unix::fs::symlink("2", netif.join("eth0")).unwrap();
    let copy = snapshot(r).unwrap();
    // The session's resolved removed the whole directory.
    fs::remove_dir_all(&netif).unwrap();

    restore(r, &copy);

    assert_eq!(mode(&netif), 0o711);
    assert_eq!(mode(&netif.join("2")), 0o640);
    assert_eq!(fs::read_link(netif.join("eth0")).unwrap(), Path::new("2"));
    assert_eq!(snapshot(r).unwrap(), copy);
}

#[test]
fn a_link_pointing_elsewhere_is_made_again_and_one_of_another_kind_replaced() {
    let run = run_with_state();
    let r = run.path();
    let devices = r.join("NetworkManager/devices");
    std::os::unix::fs::symlink("2", devices.join("eth0")).unwrap();
    fs::create_dir(devices.join("state")).unwrap();
    let copy = snapshot(r).unwrap();
    fs::remove_file(devices.join("eth0")).unwrap();
    std::os::unix::fs::symlink("9", devices.join("eth0")).unwrap();
    // A file where the decoy had a directory.
    fs::remove_dir(devices.join("state")).unwrap();
    fs::write(devices.join("state"), "hidden\n").unwrap();

    restore(r, &copy);

    assert_eq!(fs::read_link(devices.join("eth0")).unwrap(), Path::new("2"));
    assert!(devices.join("state").is_dir());
    assert_eq!(snapshot(r).unwrap(), copy);
}

#[test]
fn a_runtime_directory_the_decoy_did_not_have_is_removed() {
    let run = tempfile::tempdir().unwrap();
    let r = run.path();
    // The decoy ran neither service: nothing to copy.
    let copy = snapshot(r).unwrap();
    assert!(copy.is_empty());
    // The hidden session's NetworkManager wrote a device file and kept a
    // profile in memory.
    fs::create_dir_all(r.join("NetworkManager/devices")).unwrap();
    fs::write(r.join("NetworkManager/devices/3"), "[device]\n").unwrap();
    fs::create_dir_all(r.join("NetworkManager/system-connections")).unwrap();
    fs::write(
        r.join("NetworkManager/system-connections/hidden.nmconnection"),
        "[wireguard]\n",
    )
    .unwrap();
    restore(r, &copy);
    assert!(!r.join("NetworkManager/devices").exists());
    assert!(!r.join("NetworkManager/system-connections").exists());
}

#[test]
fn a_socket_is_never_copied_or_touched() {
    let run = tempfile::tempdir().unwrap();
    let r = run.path();
    fs::create_dir_all(r.join("NetworkManager/devices")).unwrap();
    let socket = r.join("NetworkManager/devices/control.sock");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &socket,
        rustix::fs::FileType::Socket,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let copy = snapshot(r).unwrap();
    assert_eq!(paths(&copy), [Path::new("NetworkManager/devices")]);
    restore(r, &copy);
    assert!(
        fs::symlink_metadata(&socket)
            .unwrap()
            .file_type()
            .is_socket()
    );
}

#[test]
fn an_absent_runtime_directory_is_skipped_while_a_present_one_is_still_copied() {
    // NetworkManager state is present; systemd/resolve/netif does not exist.
    let run = tempfile::tempdir().unwrap();
    let r = run.path();
    fs::create_dir_all(r.join("NetworkManager/devices")).unwrap();
    fs::write(r.join("NetworkManager/devices/2"), "[device]\n").unwrap();
    // The absent directory reads as NotFound and is simply skipped, so the
    // present directory's state still makes it into the copy. A guard that
    // does not recognise NotFound would give no copy at all.
    let copy = snapshot(r).unwrap();
    assert!(
        paths(&copy).contains(&Path::new("NetworkManager/devices/2")),
        "{copy:?}"
    );
}

#[test]
fn state_that_cannot_be_read_gives_no_copy_rather_than_an_empty_one() {
    // NetworkManager is a plain file, so reading NetworkManager/devices below
    // it fails with a not-a-directory error, which is not NotFound. The
    // systemd state is present and would be copied if that error were wrongly
    // swallowed as a missing directory.
    let run = tempfile::tempdir().unwrap();
    let r = run.path();
    fs::write(r.join("NetworkManager"), "not a directory").unwrap();
    fs::create_dir_all(r.join("systemd/resolve/netif")).unwrap();
    fs::write(r.join("systemd/resolve/netif/2"), "DNS=10.0.2.3\n").unwrap();
    // An empty copy would read as a decoy without this state, and the way
    // back would delete the decoy's.
    assert_eq!(snapshot(r), None);
}

#[test]
fn a_copy_that_fails_is_tried_again_and_given_up_after_the_last_attempt() {
    let mut calls = 0;
    let copy = retry(ATTEMPTS, || {
        calls += 1;
        if calls < ATTEMPTS {
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        } else {
            Ok(calls)
        }
    });
    assert_eq!(copy, Some(ATTEMPTS), "the last attempt succeeds");

    let mut calls = 0;
    let copy: Option<()> = retry(ATTEMPTS, || {
        calls += 1;
        Err(std::io::Error::other("still renaming"))
    });
    assert_eq!(copy, None);
    assert_eq!(calls, ATTEMPTS);
}

#[test]
fn the_copy_stops_at_the_maximum_depth() {
    let run = tempfile::tempdir().unwrap();
    let r = run.path();
    // NetworkManager/devices is depth 0; a/b/c/d descends to MAX_DEPTH, and
    // `e` sits one level below that, past the limit.
    let at_limit = r.join("NetworkManager/devices/a/b/c/d");
    fs::create_dir_all(&at_limit).unwrap();
    fs::write(at_limit.join("e"), "too deep\n").unwrap();

    let copy = snapshot(r).unwrap();
    let copied = paths(&copy);
    assert!(
        copied.contains(&Path::new("NetworkManager/devices/a/b/c/d")),
        "the directory at the maximum depth is still copied: {copy:?}"
    );
    assert!(
        !copied.contains(&Path::new("NetworkManager/devices/a/b/c/d/e")),
        "nothing below the maximum depth is copied: {copy:?}"
    );
    // The way back looks no deeper either: what lies below is left.
    restore(r, &copy);
    assert!(at_limit.join("e").is_file());
}

#[test]
fn state_at_the_size_limit_is_copied_but_past_it_gives_no_copy() {
    // A file of exactly MAX_BYTES is within budget and is copied.
    let at = tempfile::tempdir().unwrap();
    let a = at.path();
    fs::create_dir_all(a.join("NetworkManager/devices")).unwrap();
    fs::write(
        a.join("NetworkManager/devices/at_limit"),
        vec![b'x'; MAX_BYTES],
    )
    .unwrap();
    let copy = snapshot(a).unwrap();
    assert!(
        paths(&copy).contains(&Path::new("NetworkManager/devices/at_limit")),
        "a file at exactly the limit is kept"
    );

    // One byte past the budget gives no copy.
    let over = tempfile::tempdir().unwrap();
    let o = over.path();
    fs::create_dir_all(o.join("NetworkManager/devices")).unwrap();
    fs::write(
        o.join("NetworkManager/devices/over"),
        vec![b'x'; MAX_BYTES + 1],
    )
    .unwrap();
    assert_eq!(snapshot(o), None);
}

#[test]
fn a_restored_file_gets_its_parent_directory_created() {
    let run = tempfile::tempdir().unwrap();
    let r = run.path();
    // A record that lists a file without first listing its parent directory:
    // restoring it must create the parent before writing the file, so the
    // write does not fail and silently drop the state.
    let entries = [RunEntry {
        path: PathBuf::from("NetworkManager/devices/2"),
        kind: Kind::File(b"[device]\n".to_vec()),
        uid: rustix::process::geteuid().as_raw(),
        gid: rustix::process::getegid().as_raw(),
        mode: 0o644,
    }];
    restore(r, &entries);
    assert_eq!(
        fs::read(r.join("NetworkManager/devices/2")).unwrap(),
        b"[device]\n",
        "the file is written, its parent having been created first"
    );
    assert_eq!(mode(&r.join("NetworkManager/devices/2")), 0o644);
}

#[test]
fn only_paths_below_the_runtime_directories_are_valid() {
    let entry = |path: &str| RunEntry {
        path: PathBuf::from(path),
        kind: Kind::Dir,
        uid: 0,
        gid: 0,
        mode: 0o755,
    };
    assert!(is_valid(&[
        entry("NetworkManager/devices/2"),
        entry("NetworkManager/system-connections"),
        entry("systemd/resolve/netif"),
    ]));
    for bad in [
        "NetworkManager/../../etc",
        "/run/NetworkManager/devices",
        "systemd/system",
        "NetworkManager",
        "",
    ] {
        assert!(!is_valid(&[entry(bad)]), "{bad}");
    }
}
