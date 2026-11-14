// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What counts as a change since the decoy's helper started, where no file
//! sets the setting: a link among apt's files that leads to no file now, the
//! directory that holds the file the helper's `APT_CONFIG` names, and a
//! lookup that fails of when the helper started or of what it read.

use super::*;

/// A link among apt's parts: what NAILS says of it where no file sets the
/// setting.
const LINKED: &str = "is reached through a symbolic link, so NAILS cannot tell whether what it \
                      leads to changed after the helper started";

/// The mock of [`mock_times`] where every file and directory changed long
/// before the helper started, with `99linked` among the parts.
fn mock_with_linked_part() -> MockFilesystem {
    let fs = mock_times(2_000_000_000, 2_000_000_000, 1_000, "/etc/apt", 1_000);
    fs.mock_set_directory_contents(
        Path::new("/etc/apt/apt.conf.d"),
        vec![
            PathBuf::from("/etc/apt/apt.conf.d/50unattended-upgrades"),
            PathBuf::from("/etc/apt/apt.conf.d/99linked"),
        ],
    );
    fs
}

#[test]
fn a_link_among_the_parts_that_leads_to_no_file_counts_as_a_change() {
    // A part that links outside /etc/apt to a file that is gone now: apt
    // skips it at the signal, with a notice, not an error, while the helper
    // read what it led to when it started, which may have turned the setting
    // on.
    let fs = mock_with_linked_part();
    fs.create_symlink(
        Path::new("/srv/99linked"),
        Path::new("/etc/apt/apt.conf.d/99linked"),
    )
    .unwrap();
    let dangling = finding(&fs, &fs, Path::new("/"), None);
    assert!(
        blocker(&dangling).contains(&format!("but /etc/apt/apt.conf.d/99linked {LINKED}")),
        "{dangling:?}"
    );
    // As is the same link with its target there.
    fs.mock_add_file("/srv/99linked", "");
    fs.mock_set_file_bytes("/etc/apt/apt.conf.d/99linked", b"// nothing set here\n");
    let resolved = finding(&fs, &fs, Path::new("/"), None);
    assert!(
        blocker(&resolved).contains(&format!("but /etc/apt/apt.conf.d/99linked {LINKED}")),
        "{resolved:?}"
    );
}

#[test]
fn a_main_file_that_links_to_no_file_counts_as_a_change() {
    let fs = mock_times(2_000_000_000, 2_000_000_000, 1_000, "/etc/apt", 1_000);
    assert_eq!(finding(&fs, &fs, Path::new("/"), None).blocker, None);
    fs.create_symlink(Path::new("/srv/apt.conf"), Path::new("/etc/apt/apt.conf"))
        .unwrap();
    let found = finding(&fs, &fs, Path::new("/"), None);
    assert!(
        blocker(&found).contains(&format!("but /etc/apt/apt.conf {LINKED}")),
        "{found:?}"
    );
}

#[test]
fn links_to_no_file_on_the_decoy_count_as_changes_where_apt_reads_their_names() {
    // On the real filesystem, the helper started after every file: a link
    // that leads nowhere, and one to a directory, which apt skips too.
    for (rel, target) in [
        (
            "etc/apt/apt.conf.d/99linked",
            "/nonexistent-nails-test/99linked",
        ),
        ("etc/apt/apt.conf.d/99dir", ".."),
        ("etc/apt/apt.conf", "/nonexistent-nails-test/apt.conf"),
    ] {
        let tmp = stock(DEBIAN_13);
        assert_eq!(find(tmp.path()).blocker, None, "{rel}");
        link(tmp.path(), rel, target);
        let found = find(tmp.path());
        let refusal = found.blocker.as_ref().expect("a refusal");
        assert!(
            refusal.finding.contains(&format!("but /{rel} {LINKED}")),
            "{rel}: {}",
            refusal.finding
        );
        assert_eq!(refusal.at_the_switch, AtTheSwitch::Unknown);
        // A false in a file apt reads at the signal wins over what the
        // helper holds, the link skipped.
        write(tmp.path(), "etc/apt/apt.conf.d/99zz-off", OFF.as_bytes());
        assert_eq!(find(tmp.path()).blocker, None, "{rel}");
    }
    // A link of a name apt skips at its start too counts for nothing.
    let tmp = stock(DEBIAN_13);
    link(
        tmp.path(),
        "etc/apt/apt.conf.d/99linked.bak",
        "/nonexistent-nails-test/99linked",
    );
    assert_eq!(find(tmp.path()).blocker, None);
}

/// The mock of [`mock_times`] whose helper, started at 2_000_000_000, runs
/// with `APT_CONFIG` naming `apt_config`, a file that sets nothing: every
/// file and directory changed before the start but `late`, which changed at
/// `late_at`.
fn mock_with_apt_config(apt_config: &str, late: &str, late_at: u64) -> MockFilesystem {
    use std::time::{Duration, UNIX_EPOCH};
    let t = 2_000_000_000;
    let fs = mock_times(t, t, t - 100, "/etc/apt", t - 100);
    fs.mock_set_file_bytes(
        &format!("/proc/{PID}/environ"),
        &environ(&[&format!("APT_CONFIG={apt_config}")]),
    );
    fs.mock_add_file(apt_config, "// nothing set here\n");
    fs.mock_set_change_time(apt_config, UNIX_EPOCH + Duration::from_secs(t - 100));
    fs.mock_set_change_time(late, UNIX_EPOCH + Duration::from_secs(late_at));
    fs
}

#[test]
fn the_directory_that_holds_the_apt_config_file_is_compared() {
    let t = 2_000_000_000;
    // Nothing changed after the start.
    let fs = mock_with_apt_config("/etc/nails/apt.conf", "/etc/nails", t - 100);
    assert_eq!(finding(&fs, &fs, Path::new("/"), None).blocker, None);
    // The directory, as one swapped into place shows.
    let fs = mock_with_apt_config("/etc/nails/apt.conf", "/etc/nails", t + 1);
    assert!(
        blocker(&finding(&fs, &fs, Path::new("/"), None))
            .contains("but /etc/nails changed after the helper started"),
        "{:?}",
        finding(&fs, &fs, Path::new("/"), None)
    );
    // The file itself.
    let fs = mock_with_apt_config("/etc/nails/apt.conf", "/etc/nails/apt.conf", t + 1);
    assert!(
        blocker(&finding(&fs, &fs, Path::new("/"), None))
            .contains("but /etc/nails/apt.conf changed after the helper started"),
        "{:?}",
        finding(&fs, &fs, Path::new("/"), None)
    );
    // A file in the root: the root is not compared, as it cannot be swapped.
    let fs = mock_with_apt_config("/apt.conf", "/", t + 1);
    assert_eq!(finding(&fs, &fs, Path::new("/"), None).blocker, None);
}

#[test]
fn a_directory_swapped_on_the_way_to_the_apt_config_file_counts_as_a_change() {
    // What the helper reads at its start, and a replacement made before it
    // started, on the real filesystem: the swap renames the directories, so
    // the file at the path is the replacement, whose own change time is
    // older than the start, while the directory renamed into place has a
    // change time of the swap.
    let tmp = stock(DEBIAN_13);
    let root = tmp.path();
    write(root, "etc/nails/apt.conf", ON.as_bytes());
    write(root, "etc/nails.new/apt.conf", b"// nothing set here\n");
    let start = now() + 1;
    while now() < start {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    // The kernel stamps a change with its coarse clock, which can lag the
    // one now() reads by up to a tick: a rename made right after the second
    // began could still be stamped with the second before. A pause longer
    // than any tick keeps the swap's change time in the start's second.
    std::thread::sleep(std::time::Duration::from_millis(50));
    run_helper_since(
        root,
        start - 3600,
        &environ(&["APT_CONFIG=/etc/nails/apt.conf"]),
    );
    let before = find(root);
    assert!(
        blocker(&before).contains("is on in the helper's APT_CONFIG file /etc/nails/apt.conf:1"),
        "{before:?}"
    );
    std::fs::rename(root.join("etc/nails"), root.join("etc/nails.old")).unwrap();
    std::fs::rename(root.join("etc/nails.new"), root.join("etc/nails")).unwrap();
    let after = find(root);
    let refusal = after.blocker.as_ref().expect("a refusal");
    assert!(
        refusal.finding.contains(
            "no file of apt's configuration sets it now, but /etc/nails changed after the \
             helper started"
        ),
        "{}",
        refusal.finding
    );
    assert_eq!(refusal.at_the_switch, AtTheSwitch::Unknown);
}

#[test]
fn a_directory_on_the_way_reached_through_a_link_counts_as_a_change() {
    // /etc is a link: /etc/apt is no link itself, but the decoy's helper
    // reads it through one, whose target's change NAILS does not follow.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(
        root,
        "real-etc/apt/apt.conf.d/50unattended-upgrades",
        DEBIAN_13,
    );
    link(root, "etc", "real-etc");
    enable_helper(root);
    install_gi(root);
    run_helper(root);
    let found = find(root);
    assert!(
        blocker(&found).contains(&format!("but /etc/apt {LINKED}")),
        "{found:?}"
    );
    // A false in a file apt reads wins, link or not.
    write(root, "real-etc/apt/apt.conf.d/99local", OFF.as_bytes());
    assert_eq!(find(root).blocker, None);
}

/// The marker of the helper's unit, whose link lookup fails, may have come
/// to be before the helper's process started: NAILS cannot tell when the
/// helper read apt's configuration, so a setting no file sets is unknown,
/// refused as if on, where the marker was passed over and the process's
/// start taken alone.
#[test]
fn a_marker_whose_lookup_fails_leaves_when_the_helper_started_unknown() {
    let t = 2_000_000_000;
    let fs = mock_times(t, t, t - 100, "/etc/apt", t - 100);
    // Its unit's cgroup still shows the helper running.
    fs.mock_add_file(&format!("/{CGROUP}/cgroup.events"), "populated 1\n");
    assert_eq!(finding(&fs, &fs, Path::new("/"), None).blocker, None);
    fs.mock_set_lookup_error(
        "/run/systemd/units/invocation:unattended-upgrades.service",
        std::io::ErrorKind::PermissionDenied,
    );
    let found = finding(&fs, &fs, Path::new("/"), None);
    let refusal = found.blocker.as_ref().expect("a refusal");
    assert_eq!(refusal.at_the_switch, AtTheSwitch::Unknown);
    assert!(
        refusal.finding.contains(
            "when unattended-upgrades.service started cannot be read: \
             /run/systemd/units/invocation:unattended-upgrades.service ("
        ),
        "{}",
        refusal.finding
    );
}

/// One of apt's directories, or a file the helper reads, whose link lookup
/// fails may be reached through a link whose target changed after the
/// helper started: a setting no file sets is unknown, refused as if on,
/// where it read as no link.
#[test]
fn a_link_lookup_that_fails_of_what_the_helper_read_leaves_a_setting_no_file_sets_unknown() {
    use crate::filesystem::{MockFailure, MockLookup};
    let t = 2_000_000_000;
    for path in ["/etc/apt", "/etc/apt/apt.conf.d/50unattended-upgrades"] {
        let fs = mock_times(t, t, t - 100, "/etc/apt", t - 100);
        fs.mock_fail_only(
            Path::new(path),
            MockLookup::IsSymlink,
            MockFailure::Io(std::io::ErrorKind::Other),
        );
        let found = finding(&fs, &fs, Path::new("/"), None);
        let refusal = found.blocker.as_ref().expect("a refusal");
        assert_eq!(refusal.at_the_switch, AtTheSwitch::Unknown, "{path}");
        assert!(
            refusal
                .finding
                .contains(&format!("{path} cannot be looked up (")),
            "{path}: {}",
            refusal.finding
        );
    }
}
