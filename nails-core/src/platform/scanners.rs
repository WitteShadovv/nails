//! Platform-specific, read-only scans for system-state drift that a generic
//! artifact-path check cannot see.
//!
//! A clean `verify` over the shared artifact registry proves only that none of
//! the *known* files are present. It cannot, on its own, tell that a hidden
//! session installed a package, because the package manager's own databases are
//! not NAILS files. Each platform therefore contributes an
//! [`ArtifactScanner`]: on Debian/Ubuntu it diffs the apt/dpkg databases against
//! a baseline captured on the hidden root at activation; on NixOS it records
//! that the expected `/var/lib/nixos` drift is deliberately not treated as a
//! leak. Every scanner is read-only — it opens files, it never writes one.

use crate::Result;
use crate::filesystem::Filesystem;
use crate::verify::{Finding, Severity};
use std::path::{Path, PathBuf};

/// Directory on the hidden root under which an activation stores the package
/// baselines this scanner diffs against. A single definition, shared by the
/// scanner here and the activation path that writes the files.
pub const PACKAGE_BASELINE_DIR: &str = "reports/package-baseline";

/// The apt/dpkg databases a Debian-family host is compared against its baseline.
///
/// Each entry is `(absolute live path, baseline file name under
/// [`PACKAGE_BASELINE_DIR`], human label)`. `/var/lib/dpkg/status` is the
/// authoritative installed-package set; the two logs capture the actions that
/// changed it.
const DEBIAN_PACKAGE_DBS: &[(&str, &str, &str)] = &[
    (
        "/var/lib/dpkg/status",
        "dpkg-status",
        "the dpkg installed-package database",
    ),
    (
        "/var/log/apt/history.log",
        "apt-history.log",
        "the apt action history",
    ),
    ("/var/log/dpkg.log", "dpkg.log", "the dpkg action log"),
];

/// The outcome of one [`ArtifactScanner`] run.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ArtifactScan {
    /// Findings the scanner produced.
    pub findings: Vec<Finding>,
    /// Human descriptions of what the scanner could *not* inspect (for example,
    /// no activation baseline was stored), surfaced in verify's
    /// areas-not-checked list so a clean result never overclaims.
    pub not_checked: Vec<String>,
}

/// A read-only, platform-specific drift scan.
///
/// Generic over the [`Filesystem`] so it can run against a `MockFilesystem` in
/// tests and the live host in production. `rebase` maps an absolute host path to
/// where it should actually be read — the identity on the live host, and under
/// the mounted image root in an offline scan — so a scanner never needs to know
/// which context it runs in. `hidden_root` is the configured hidden volume root,
/// where an activation baseline would have been stored.
pub trait ArtifactScanner<F: Filesystem>: Send + Sync {
    /// Run the read-only scan.
    fn scan(
        &self,
        fs: &F,
        rebase: &dyn Fn(&Path) -> PathBuf,
        hidden_root: Option<&Path>,
    ) -> Result<ArtifactScan>;
}

/// Debian/Ubuntu package-database drift scanner.
///
/// Diffs `/var/lib/dpkg/status` and the apt/dpkg logs against the baseline the
/// activation captured on the hidden root. A difference means packages were
/// installed, removed or upgraded while a hidden session was active — a change
/// to the decoy that outlives deactivation. Without a baseline (no hidden
/// session ran, or an older activation did not capture one) the databases are
/// reported as not checked rather than flagged, because there is nothing to
/// compare them against.
#[derive(Debug, Clone, Copy, Default)]
pub struct DebianPackageDriftScanner;

impl<F: Filesystem> ArtifactScanner<F> for DebianPackageDriftScanner {
    fn scan(
        &self,
        fs: &F,
        rebase: &dyn Fn(&Path) -> PathBuf,
        hidden_root: Option<&Path>,
    ) -> Result<ArtifactScan> {
        let mut scan = ArtifactScan::default();

        let Some(hidden_root) = hidden_root else {
            scan.not_checked.push(
                "apt/dpkg package drift (no configured hidden root to find a baseline under)"
                    .to_string(),
            );
            return Ok(scan);
        };
        let baseline_dir = hidden_root.join(PACKAGE_BASELINE_DIR);

        for (live_path, baseline_name, label) in DEBIAN_PACKAGE_DBS {
            let live = rebase(Path::new(live_path));
            // Only compare databases that exist on the host; a host without apt
            // logs is not a Debian host and has nothing to drift.
            if !fs.path_exists(&live)? {
                continue;
            }
            let baseline = baseline_dir.join(baseline_name);
            if !fs.path_exists(&baseline)? {
                scan.not_checked.push(format!(
                    "apt/dpkg drift for {live_path} (no activation baseline at {})",
                    baseline.display()
                ));
                continue;
            }

            // Reads only: compare the live database with the stored baseline.
            // An unreadable file (permissions) is reported, not treated as a
            // match or an error exit.
            let (Ok(live_content), Ok(baseline_content)) =
                (fs.read_file_content(&live), fs.read_file_content(&baseline))
            else {
                scan.not_checked.push(format!(
                    "apt/dpkg drift for {live_path} (database unreadable)"
                ));
                continue;
            };

            if live_content != baseline_content {
                scan.findings.push(
                    Finding::new(
                        Severity::Warn,
                        "package-drift",
                        format!(
                            "{label} changed since activation ({live_path} differs from its baseline)"
                        ),
                    )
                    .with_fix_guidance(format!(
                        "Review and undo package changes made during the hidden session: diff {} against {live_path}",
                        baseline.display()
                    )),
                );
            }
        }

        Ok(scan)
    }
}

/// NixOS state-drift note.
///
/// On NixOS the `/var/lib/nixos` uid/gid map legitimately changes across
/// generations, so it is *expected* drift, not a leak. This scanner produces no
/// finding; it records the fact in areas-not-checked so an operator knows verify
/// deliberately does not treat that path as residue.
#[derive(Debug, Clone, Copy, Default)]
pub struct NixOsStateNoteScanner;

impl<F: Filesystem> ArtifactScanner<F> for NixOsStateNoteScanner {
    fn scan(
        &self,
        _fs: &F,
        _rebase: &dyn Fn(&Path) -> PathBuf,
        _hidden_root: Option<&Path>,
    ) -> Result<ArtifactScan> {
        Ok(ArtifactScan {
            findings: Vec::new(),
            not_checked: vec![
                "/var/lib/nixos drift (expected across NixOS generations, not a leak)".to_string(),
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;

    fn identity(path: &Path) -> PathBuf {
        path.to_path_buf()
    }

    #[test]
    fn debian_scanner_flags_changed_dpkg_status_and_writes_nothing() {
        let fs = MockFilesystem::new();
        let hidden = Path::new("/mnt/hidden");
        let baseline = hidden.join(PACKAGE_BASELINE_DIR);

        // Live database and a baseline that disagree.
        fs.mock_set_path_exists("/var/lib/dpkg/status", true);
        fs.mock_set_file_content("/var/lib/dpkg/status", "Package: nmap\nStatus: installed\n");
        fs.mock_set_path_exists(baseline.join("dpkg-status").to_str().unwrap(), true);
        fs.mock_set_file_content(baseline.join("dpkg-status").to_str().unwrap(), "");

        let scan = DebianPackageDriftScanner
            .scan(&fs, &identity, Some(hidden))
            .unwrap();

        assert_eq!(scan.findings.len(), 1, "{:?}", scan);
        assert_eq!(scan.findings[0].severity, Severity::Warn);
        assert_eq!(scan.findings[0].category, "package-drift");
        // The scanner is read-only: it must not have written the live database,
        // the baseline, or any file it touched while comparing them.
        assert!(
            fs.get_written_content(Path::new("/var/lib/dpkg/status"))
                .is_none(),
            "scanner wrote the live database"
        );
        assert!(
            fs.get_written_content(&baseline.join("dpkg-status"))
                .is_none(),
            "scanner wrote the baseline"
        );
    }

    #[test]
    fn debian_scanner_is_quiet_when_database_matches_baseline() {
        let fs = MockFilesystem::new();
        let hidden = Path::new("/mnt/hidden");
        let baseline = hidden.join(PACKAGE_BASELINE_DIR);

        fs.mock_set_path_exists("/var/lib/dpkg/status", true);
        fs.mock_set_file_content("/var/lib/dpkg/status", "Package: bash\n");
        fs.mock_set_path_exists(baseline.join("dpkg-status").to_str().unwrap(), true);
        fs.mock_set_file_content(
            baseline.join("dpkg-status").to_str().unwrap(),
            "Package: bash\n",
        );

        let scan = DebianPackageDriftScanner
            .scan(&fs, &identity, Some(hidden))
            .unwrap();

        assert!(scan.findings.is_empty(), "{:?}", scan);
    }

    #[test]
    fn debian_scanner_reports_missing_baseline_as_not_checked() {
        let fs = MockFilesystem::new();
        let hidden = Path::new("/mnt/hidden");

        // Live database exists but no baseline was captured.
        fs.mock_set_path_exists("/var/lib/dpkg/status", true);
        fs.mock_set_file_content("/var/lib/dpkg/status", "Package: bash\n");

        let scan = DebianPackageDriftScanner
            .scan(&fs, &identity, Some(hidden))
            .unwrap();

        assert!(scan.findings.is_empty());
        assert!(
            scan.not_checked
                .iter()
                .any(|note| note.contains("baseline")),
            "{:?}",
            scan
        );
    }

    #[test]
    fn nixos_note_scanner_adds_expected_drift_note_without_findings() {
        let fs = MockFilesystem::new();
        let scan = NixOsStateNoteScanner
            .scan(&fs, &identity, Some(Path::new("/mnt/hidden")))
            .unwrap();
        assert!(scan.findings.is_empty());
        assert_eq!(scan.not_checked.len(), 1);
        assert!(scan.not_checked[0].contains("/var/lib/nixos"));
    }
}
