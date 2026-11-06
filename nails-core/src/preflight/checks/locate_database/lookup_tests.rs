// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What locate-database says where a lookup fails or the automount guard
//! does not make it: an updatedb it cannot tell is there, one it cannot tell
//! is findutils', and a cron directory behind an automount point warn, and
//! nothing at or below the point is looked up.

use super::tests::{DEBIAN, Decoy, MOUNTS, message, pruning_mnt};
use crate::filesystem::automount::mount_fix;
use crate::preflight::checks::automount_fixture::{direct, reached};
use std::io::ErrorKind;
use std::path::Path;

/// `decoy` with a direct automount point at `point` that nothing is mounted
/// on yet, beside its root, mount 22, and its hidden volume.
fn with_automount(decoy: &Decoy, point: &str) {
    decoy
        .fs
        .mock_set_mount_table(&format!("{MOUNTS}{}", direct(point, 0, 22)));
}

/// An updatedb in /usr/local, whose lookup fails, was passed over, and the
/// check passed as on a decoy without updatedb. It may be one a person
/// starts, and NAILS cannot tell: a warning that names it.
#[test]
fn an_updatedb_nails_cannot_tell_is_there_warns() {
    let decoy = Decoy::new();
    decoy
        .fs
        .mock_set_lookup_error("/usr/local/bin/updatedb", ErrorKind::PermissionDenied);
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "/usr/local/bin/updatedb may start updatedb, which NAILS cannot tell: NAILS cannot \
             look up /usr/local/bin/updatedb; run the command again with sudo"
        ),
        "{result:?}"
    );
}

/// An updatedb behind an automount point that nothing is mounted on yet is
/// not looked up: the warning names the path and the point, says once how to
/// mount it, and nothing at or below the point is looked up.
#[test]
fn an_updatedb_behind_an_automount_point_warns_without_a_lookup() {
    let decoy = Decoy::new();
    decoy.file("/etc/updatedb.conf", &pruning_mnt(DEBIAN));
    with_automount(&decoy, "/usr/local");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    let message = message(&result);
    assert!(
        message.contains(
            "/usr/local/bin/updatedb may start updatedb, which NAILS cannot tell: NAILS does not \
             look up /usr/local/bin/updatedb, since the lookup would mount the automount point \
             /usr/local"
        ),
        "{message}"
    );
    let fix = mount_fix(&[Path::new("/usr/local")]);
    assert_eq!(message.matches(fix.as_str()).count(), 1, "{message}");
    assert!(
        !reached(&decoy.fs, "/usr/local"),
        "{:?}",
        decoy.fs.mock_lookups()
    );
}

/// A bare `updatedb` is findutils' where the decoy's leads to it. Where it
/// leads behind an automount point the guard does not let NAILS resolve, the
/// run's prune lists cannot be told, never taken for plocate's: a cron job
/// that runs it warns, though updatedb.conf skips the volume. So does one
/// that names such a path.
#[test]
fn an_updatedb_nails_cannot_tell_is_findutils_has_lists_it_cannot_tell() {
    let decoy = Decoy::new();
    decoy
        .file("/etc/updatedb.conf", &pruning_mnt(DEBIAN))
        .file("/usr/sbin/updatedb.plocate", "")
        .link("/usr/bin/updatedb", "/usr/local/libexec/updatedb.findutils")
        .file(
            "/etc/crontab",
            "0 3 * * * root updatedb\n0 4 * * * root /usr/local/bin/updatedb\n",
        );
    with_automount(&decoy, "/usr/local");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    let message = message(&result);
    for part in [
        "the cron job at line 1 of /etc/crontab runs updatedb, and NAILS cannot tell whether it \
         skips the hidden volume: NAILS cannot tell whether /usr/bin/updatedb is findutils' \
         updatedb, whose prune options NAILS does not read: NAILS does not look up \
         /usr/bin/updatedb, since the lookup would mount the automount point /usr/local (line \
         1 of /etc/crontab)",
        "NAILS cannot tell whether /usr/local/bin/updatedb is findutils' updatedb, whose prune \
         options NAILS does not read: NAILS does not look up /usr/local/bin/updatedb, since the \
         lookup would mount the automount point /usr/local (line 2 of /etc/crontab)",
    ] {
        assert!(message.contains(part), "{part}: {message}");
    }
    assert!(
        !reached(&decoy.fs, "/usr/local"),
        "{:?}",
        decoy.fs.mock_lookups()
    );

    // Mounted, the bare updatedb leads to findutils' as it did.
    decoy.fs.mock_set_mount_table(MOUNTS);
    let result = decoy.check(false);
    assert!(
        message_of(&result).contains("line 1 of /etc/crontab runs findutils' updatedb"),
        "{result:?}"
    );
}

/// The message of `result`.
fn message_of(result: &crate::preflight::CheckResult) -> String {
    message(result).to_string()
}

/// A directory of crontabs behind an automount point is not listed: the
/// jobs it may hold are ones NAILS cannot tell about, and the warning names
/// the point.
#[test]
fn a_crontab_directory_behind_an_automount_point_warns() {
    let decoy = Decoy::new();
    decoy.file("/etc/updatedb.conf", &pruning_mnt(DEBIAN));
    decoy.file("/usr/sbin/updatedb.plocate", "");
    with_automount(&decoy, "/var/spool");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "the crontabs in /var/spool/cron may start updatedb, which NAILS cannot tell: NAILS \
             does not look up /var/spool/cron, since the lookup would mount the automount point \
             /var/spool"
        ),
        "{result:?}"
    );
    assert!(
        !reached(&decoy.fs, "/var/spool"),
        "{:?}",
        decoy.fs.mock_lookups()
    );
}

/// An entry of a cron directory whose lookup fails is read as a crontab,
/// which says why NAILS cannot read it, never passed over as a directory.
#[test]
fn a_cron_entry_nails_cannot_look_up_is_read_and_warns() {
    let decoy = Decoy::new();
    decoy
        .file("/etc/updatedb.conf", &pruning_mnt(DEBIAN))
        .file("/usr/sbin/updatedb.plocate", "")
        .file("/etc/cron.d/nightly", "0 3 * * * root updatedb\n");
    decoy
        .fs
        .mock_set_lookup_error("/etc/cron.d/nightly", ErrorKind::PermissionDenied);
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "the crontab /etc/cron.d/nightly may start updatedb, which NAILS cannot tell: NAILS \
             cannot look up /etc/cron.d/nightly; run the command again with sudo"
        ),
        "{result:?}"
    );
}
