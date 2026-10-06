// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the post-mount writer rescan merge/classification core.

use super::*;

/// A `ProcessInfo` with every reference flag cleared, so a test sets only the
/// ones it wants to exercise.
fn proc(pid: u32, name: &str) -> ProcessInfo {
    ProcessInfo {
        pid,
        name: name.to_string(),
        cmdline: name.to_string(),
        cwd: PathBuf::from("/"),
        has_cwd_in_target: false,
        has_open_fds_in_target: false,
        has_writable_fd_in_target: false,
        has_dir_fd_in_target: false,
        has_mmap_in_target: false,
        has_shared_write_map_in_target: false,
        has_root_in_target: false,
        is_unverifiable_writer: false,
        service_name: None,
        is_interactive: false,
    }
}

#[test]
fn read_only_consumer_is_not_recorded() {
    let mut writers = Vec::new();
    let mut reader = proc(100, "less");
    reader.has_open_fds_in_target = true; // read-only fd only
    merge_target_writers(&mut writers, Path::new("/var"), &[reader], &|_| true);
    assert!(writers.is_empty(), "{writers:?}");
}

#[test]
fn writable_fd_holder_is_recorded_as_stale_lower() {
    let mut writers = Vec::new();
    let mut writer = proc(200, "tail");
    writer.has_open_fds_in_target = true;
    writer.has_writable_fd_in_target = true;
    merge_target_writers(&mut writers, Path::new("/var"), &[writer], &|_| true);
    assert_eq!(writers.len(), 1);
    assert_eq!(writers[0].pid, 200);
    assert_eq!(writers[0].kind, WriterKind::StaleLower);
    assert_eq!(writers[0].targets, vec![PathBuf::from("/var")]);
}

#[test]
fn cwd_directory_fd_and_shared_map_all_block() {
    for mutate in [
        (|p: &mut ProcessInfo| p.has_cwd_in_target = true) as fn(&mut ProcessInfo),
        |p: &mut ProcessInfo| p.has_dir_fd_in_target = true,
        |p: &mut ProcessInfo| p.has_shared_write_map_in_target = true,
        |p: &mut ProcessInfo| p.has_root_in_target = true,
    ] {
        let mut writers = Vec::new();
        let mut holder = proc(300, "proc");
        mutate(&mut holder);
        merge_target_writers(&mut writers, Path::new("/home"), &[holder], &|_| true);
        assert_eq!(writers.len(), 1, "blocking reference was not recorded");
        assert_eq!(writers[0].kind, WriterKind::StaleLower);
    }
}

#[test]
fn foreign_namespace_holder_is_unverifiable() {
    let mut writers = Vec::new();
    let mut holder = proc(400, "unknown");
    holder.is_unverifiable_writer = true;
    merge_target_writers(&mut writers, Path::new("/etc"), &[holder], &|_| true);
    assert_eq!(writers.len(), 1);
    assert_eq!(writers[0].kind, WriterKind::Unverifiable);
}

#[test]
fn an_existing_surviving_pid_keeps_its_kind_and_gains_the_target() {
    let mut writers = vec![DecoyWriter {
        pid: 500,
        name: "NetworkManager".to_string(),
        service: Some("NetworkManager".to_string()),
        targets: vec![PathBuf::from("/etc")],
        kind: WriterKind::Surviving,
    }];
    let mut holder = proc(500, "NetworkManager");
    holder.has_writable_fd_in_target = true;
    merge_target_writers(&mut writers, Path::new("/var"), &[holder], &|_| true);
    assert_eq!(writers.len(), 1, "the PID was duplicated");
    assert_eq!(
        writers[0].kind,
        WriterKind::Surviving,
        "kind was downgraded"
    );
    assert_eq!(
        writers[0].targets,
        vec![PathBuf::from("/etc"), PathBuf::from("/var")]
    );
}

#[test]
fn integrity_verified_targets_are_exempt() {
    assert!(is_integrity_verified(Path::new("/boot")));
    assert!(!is_integrity_verified(Path::new("/var")));
    assert!(!is_integrity_verified(Path::new("/boot2")));
}

#[test]
fn an_empty_snapshot_adds_no_writers() {
    let mut writers = Vec::new();
    rescan_post_mount_writers(
        &mut writers,
        &[PathBuf::from("/var"), PathBuf::from("/home")],
    );
    assert!(
        writers.is_empty(),
        "capture() is empty in test builds, so nothing should be added"
    );
}

#[test]
fn a_holder_whose_references_are_all_on_the_overlay_is_not_a_writer() {
    // A process that opened its files through the new overlay uses the hidden
    // session; flagging it StaleLower would be a false alarm.
    let mut writers = Vec::new();
    let mut holder = proc(500, "journald");
    holder.has_writable_fd_in_target = true;
    merge_target_writers(&mut writers, Path::new("/var"), &[holder.clone()], &|_| {
        false
    });
    assert!(writers.is_empty(), "{writers:?}");

    // An unverifiable holder is still recorded: its mount ids prove nothing.
    holder.is_unverifiable_writer = true;
    merge_target_writers(&mut writers, Path::new("/var"), &[holder], &|_| false);
    assert_eq!(writers.len(), 1);
    assert_eq!(writers[0].kind, WriterKind::Unverifiable);
}
