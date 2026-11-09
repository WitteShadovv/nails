// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The examiner's view: setup traces on a mounted decoy image, and on its raw
//! disk when one is given.
//!
//! `verify` looks for residue of a session. An examiner also looks for the
//! setup: encryption headers and random-looking space, container files,
//! configuration that opens encrypted storage, LVM metadata, the tooling and
//! its access times, and history that names a container. This module reports
//! those, grouped by the conclusion an examiner would draw (the catalog's
//! [`ResidueClass::conclusion`](crate::residue_catalog::ResidueClass::conclusion)).
//!
//! It reports only. Every read is read-only and `O_NOATIME` (see
//! [`crate::forensic`]), and every path is looked up inside the root
//! ([`in_root`]), so no link in the image leads to the files of the machine
//! running verify; nothing is changed, removed or mounted. Its findings
//! never change verify's status: a decoy with full-disk encryption always has
//! a LUKS header, and only the operator can say which traces are explained.

mod disk;
mod files;

#[cfg(test)]
mod tests;

use crate::Filesystem;
use crate::residue_catalog::{self, Probe, ProbeHit, ResidueKind};
use crate::verify::Severity;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Options for the examiner audit.
#[derive(Debug, Clone)]
pub struct ExaminerOptions {
    /// The raw disk or image behind the mounted root, for the partition-level
    /// checks. Without it those checks are reported as not run.
    pub disk: Option<PathBuf>,
    /// Smallest file the container heuristic considers.
    pub container_min_size: u64,
    /// Entry budget for the container walk.
    pub max_walk_entries: usize,
    /// Samples taken per region for the entropy checks.
    pub samples_per_region: usize,
}

impl Default for ExaminerOptions {
    fn default() -> Self {
        Self {
            disk: None,
            container_min_size: 1 << 20,
            max_walk_entries: 500_000,
            samples_per_region: 8,
        }
    }
}

/// One setup trace.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExaminerFinding {
    /// The catalog row this trace belongs to.
    pub catalog_id: &'static str,
    /// How strongly it points at hidden storage.
    pub severity: Severity,
    /// Where it was found (a path, a partition, a byte range).
    pub location: String,
    /// What was found there.
    pub evidence: String,
}

/// The traces that support one conclusion.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExaminerGroup {
    /// What an examiner would conclude.
    pub conclusion: &'static str,
    /// The traces.
    pub findings: Vec<ExaminerFinding>,
}

/// The examiner audit's result.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ExaminerReport {
    /// Traces grouped by conclusion, in catalog order. Empty for a clean image.
    pub groups: Vec<ExaminerGroup>,
    /// The verify check ids the audit ran.
    pub checks_run: Vec<&'static str>,
    /// What the audit could not cover (beyond the catalog's own gaps).
    pub not_checked: Vec<String>,
}

impl ExaminerReport {
    /// Total number of traces.
    pub fn finding_count(&self) -> usize {
        self.groups.iter().map(|group| group.findings.len()).sum()
    }

    /// Every trace, flattened.
    pub fn findings(&self) -> impl Iterator<Item = &ExaminerFinding> {
        self.groups.iter().flat_map(|group| group.findings.iter())
    }
}

/// Run the audit against the decoy mounted at `root`.
pub fn examine(root: &Path, options: &ExaminerOptions) -> ExaminerReport {
    let mut findings = Vec::new();
    let mut checks_run = Vec::new();
    let mut not_checked = Vec::new();

    findings.extend(catalog_paths(
        &crate::RealFilesystem,
        root,
        &mut not_checked,
    ));
    checks_run.push("examiner-catalog-paths");

    findings.extend(files::config_entries(root, &mut not_checked));
    checks_run.push("examiner-config");

    findings.extend(files::lvm_metadata(root));
    checks_run.push("examiner-lvm");

    findings.extend(files::tooling(root));
    checks_run.push("examiner-tooling");
    if files::store_unread(root) {
        not_checked.push(
            "encryption tooling in the decoy's Nix store (/nix/store is missing or empty under \
             the root, so the tool check had nothing to read: mount the decoy's /nix there)"
                .to_string(),
        );
    }

    let containers = files::containers(root, options);
    findings.extend(containers.findings);
    not_checked.extend(containers.not_checked);
    checks_run.push("examiner-containers");

    findings.extend(files::history(
        root,
        &containers.candidates,
        &mut not_checked,
    ));
    checks_run.push("examiner-history");

    if let Some(disk) = &options.disk {
        match disk::audit(disk, options) {
            Ok(disk_findings) => {
                findings.extend(disk_findings);
                checks_run.push("examiner-disk");
            }
            Err(err) => not_checked.push(format!(
                "the raw disk {} (could not be read: {err})",
                disk.display()
            )),
        }
    }

    ExaminerReport {
        groups: group(findings),
        checks_run,
        not_checked,
    }
}

/// The setup rows' data-driven path probes, read under `root` through `fs`.
/// A path that does not resolve inside the root is not probed, and goes to
/// `not_checked`, as does one whose lookup fails for another reason than
/// that nothing is there, with the error.
fn catalog_paths<F: Filesystem>(
    fs: &F,
    root: &Path,
    not_checked: &mut Vec<String>,
) -> Vec<ExaminerFinding> {
    let mut out = Vec::new();
    for row in residue_catalog::catalog() {
        if row.kind != ResidueKind::Setup {
            continue;
        }
        let Probe::Paths { paths, severity } = row.verify else {
            continue;
        };
        for path in paths {
            let Some(probe) = in_root_of(fs, root, Path::new(path)) else {
                not_checked.push(format!("{path}, probed for {} ({NOT_RESOLVED})", row.title));
                continue;
            };
            match residue_catalog::path_probe_hit(fs, &probe) {
                ProbeHit::Hit => out.push(ExaminerFinding {
                    catalog_id: row.id,
                    severity: match severity {
                        crate::residue_catalog::ProbeSeverity::Info => Severity::Info,
                        crate::residue_catalog::ProbeSeverity::Warn => Severity::Warn,
                        crate::residue_catalog::ProbeSeverity::Critical => Severity::Critical,
                    },
                    location: (*path).to_string(),
                    evidence: format!("{} is present and not empty", row.title),
                }),
                ProbeHit::NoHit => {}
                ProbeHit::CannotTell(error) => not_checked.push(format!(
                    "{path}, probed for {} (it could not be looked up: {error})",
                    row.title
                )),
            }
        }
    }
    out
}

/// Group findings by their catalog row's conclusion, in catalog order.
fn group(findings: Vec<ExaminerFinding>) -> Vec<ExaminerGroup> {
    let mut groups: Vec<ExaminerGroup> = Vec::new();
    for row in residue_catalog::catalog() {
        let Some(conclusion) = row.conclusion else {
            continue;
        };
        let mine: Vec<ExaminerFinding> = findings
            .iter()
            .filter(|finding| finding.catalog_id == row.id)
            .cloned()
            .collect();
        if mine.is_empty() {
            continue;
        }
        match groups.iter_mut().find(|g| g.conclusion == conclusion) {
            Some(existing) => existing.findings.extend(mine),
            None => groups.push(ExaminerGroup {
                conclusion,
                findings: mine,
            }),
        }
    }
    groups
}

/// Why the audit read nothing at a decoy path that does not resolve inside
/// the root.
pub(crate) const NOT_RESOLVED: &str = "it does not resolve inside the root";

/// The decoy's `path` (absolute on the decoy) under the image root `root`,
/// its links followed inside the root as the decoy itself follows them
/// (`openat2` with `RESOLVE_IN_ROOT`): an absolute link in the image resolves
/// in the image, never on the machine running verify. For the files the audit
/// reads and the folders it lists or probes. `None` where `path` does not
/// resolve inside the root, through a loop of links or where the kernel
/// refuses the lookup: the root joined with `path` would follow the image's
/// links out of it on this machine, so nothing is read there.
pub(crate) fn in_root(root: &Path, path: impl AsRef<Path>) -> Option<PathBuf> {
    in_root_of(&crate::RealFilesystem, root, path.as_ref())
}

/// [`in_root`], resolved through `fs`.
fn in_root_of<F: Filesystem>(fs: &F, root: &Path, path: &Path) -> Option<PathBuf> {
    let inside = fs.resolve_in_root(root, path)?;
    Some(root.join(inside.strip_prefix("/").unwrap_or(&inside)))
}

/// The entry the decoy's `path` names under `root`: its folder resolved
/// inside the root as [`in_root`] resolves it, its last part as it is, so a
/// link there is seen, and counts, as a link.
pub(crate) fn in_root_entry(root: &Path, path: impl AsRef<Path>) -> Option<PathBuf> {
    let path = path.as_ref();
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => Some(in_root(root, parent)?.join(name)),
        _ => in_root(root, path),
    }
}
