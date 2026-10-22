// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Invariants of the residue catalog: every row has a detector and a VM test
//! (or says why not), every name it uses exists, and the generated docs match.

use super::*;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The repository root, above this crate.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("nails-forensics has a parent workspace directory")
        .to_path_buf()
}

/// Every NixOS VM test `name` under `nix/e2e-tests/tests`.
fn e2e_test_names() -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut stack = vec![repo_root().join("nix/e2e-tests/tests")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "nix") {
                let text = std::fs::read_to_string(&path).unwrap();
                if let Some(name) = text
                    .lines()
                    .map(str::trim)
                    .find_map(|line| line.strip_prefix("name = \""))
                    .and_then(|rest| rest.split('"').next())
                {
                    names.insert(name.to_string());
                }
            }
        }
    }
    names
}

/// GitHub's heading anchor for a Markdown heading line.
fn slug(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// Every heading anchor in a doc under `docs/`.
fn anchors(doc: &str) -> BTreeSet<String> {
    let text = std::fs::read_to_string(repo_root().join("docs").join(doc))
        .unwrap_or_else(|err| panic!("cannot read docs/{doc}: {err}"));
    let mut in_fence = false;
    let mut out = BTreeSet::new();
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence && line.starts_with('#') {
            out.insert(slug(line.trim_start_matches('#')));
        }
    }
    out
}

#[test]
fn ids_are_unique_kebab_case_and_rows_are_complete() {
    let mut seen = BTreeSet::new();
    for row in catalog() {
        assert!(seen.insert(row.id), "duplicate catalog id {}", row.id);
        assert!(
            !row.id.is_empty()
                && row
                    .id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "catalog id {} is not kebab-case",
            row.id
        );
        for (field, value) in [
            ("title", row.title),
            ("risk", row.risk),
            ("mitigation", row.mitigation),
            ("doc_anchor", row.doc_anchor),
        ] {
            assert!(!value.trim().is_empty(), "{}: empty {field}", row.id);
            assert!(
                !value.contains('|'),
                "{}: a | in {field} breaks the doc table",
                row.id
            );
        }
        match row.channel {
            Channel::Paths(paths) => {
                assert!(!paths.is_empty(), "{}: empty channel paths", row.id);
                for path in paths {
                    assert!(
                        path.starts_with('/') || path.starts_with("~/"),
                        "{}: channel path {path} is neither absolute nor home-relative",
                        row.id
                    );
                }
            }
            Channel::Mechanism(text) => assert!(!text.trim().is_empty(), "{}", row.id),
        }
    }
}

#[test]
fn every_row_has_a_detector_or_is_a_declared_residual_channel() {
    for row in catalog() {
        for probe in [row.preflight, row.verify] {
            match probe {
                Probe::None(reason) => {
                    assert!(
                        !reason.trim().is_empty(),
                        "{}: a probe gap needs a reason",
                        row.id
                    );
                }
                Probe::Paths { paths, .. } => {
                    assert!(!paths.is_empty(), "{}: empty probe paths", row.id);
                    assert!(
                        paths.iter().all(|path| path.starts_with('/')),
                        "{}: probe paths must be absolute",
                        row.id
                    );
                }
                Probe::Check(name) => assert!(!name.is_empty(), "{}", row.id),
            }
        }
        // A class nothing can detect is acceptable only as a residual channel:
        // it is then listed in the threat model and in verify's areas not
        // checked, never silently.
        if !row.preflight.detects() && !row.verify.detects() {
            assert!(
                row.residual,
                "{} has no detector; give it one, or mark it a residual channel with reasons",
                row.id
            );
        }
        assert!(
            !row.preflight_blocks || matches!(row.preflight, Probe::Check(_)),
            "{}: only a named check can refuse activation",
            row.id
        );
    }
}

#[test]
fn every_row_names_a_vm_test_that_exists_or_says_why_not() {
    let names = e2e_test_names();
    assert!(
        names.contains("snapshot-diff"),
        "the test-name scan found nothing"
    );
    for row in catalog() {
        let named: &[&str] = match &row.e2e {
            E2e::Test(name) => std::slice::from_ref(name),
            E2e::Tests(several) => {
                assert!(
                    several.len() > 1,
                    "{}: name one VM test as E2e::Test",
                    row.id
                );
                several
            }
            E2e::None(reason) => {
                assert!(
                    !reason.trim().is_empty(),
                    "{} has no VM test and no reason",
                    row.id
                );
                &[]
            }
        };
        for name in named {
            assert!(
                names.contains(*name),
                "{} names VM test {name}, which does not exist under nix/e2e-tests/tests",
                row.id
            );
        }
    }
}

#[test]
fn verify_probes_name_verify_checks() {
    let ids: BTreeSet<&str> = crate::verify::VERIFY_CHECK_IDS.iter().copied().collect();
    for row in catalog() {
        if let Probe::Check(id) = row.verify {
            assert!(
                ids.contains(id),
                "{} names verify check {id}, which does not exist",
                row.id
            );
        }
    }
}

#[test]
fn doc_anchors_resolve_to_headings() {
    for row in catalog() {
        let (doc, anchor) = row
            .doc_anchor
            .split_once('#')
            .unwrap_or_else(|| panic!("{}: doc anchor needs a #section", row.id));
        assert!(
            anchors(doc).contains(anchor),
            "{}: docs/{doc} has no heading #{anchor}",
            row.id
        );
    }
}

#[test]
fn setup_traces_carry_an_examiner_conclusion() {
    for row in catalog() {
        match row.kind {
            ResidueKind::Setup => assert!(
                row.conclusion.is_some_and(|text| !text.trim().is_empty()),
                "setup trace {} needs a conclusion",
                row.id
            ),
            ResidueKind::Session => {
                assert!(
                    row.conclusion.is_none(),
                    "{}: only setup traces conclude",
                    row.id
                )
            }
        }
    }
}

#[test]
fn the_new_research_classes_are_catalogued() {
    for id in [
        "sudo-io-log",
        "lvm-metadata-archive",
        "udisks2-state",
        "timesync-clock",
        "timer-stamps",
        "smart-power-on-hours",
        "decoy-filesystems",
        "run-carry-over",
        "kmsg-import",
        "soft-reboot-counter",
        "runtime-journal-reset",
    ] {
        assert!(class(id).is_some(), "catalog row {id} is missing");
    }
}

#[test]
fn sync_rewrites_only_marked_blocks() {
    let text = "intro\n<!-- residue-catalog:begin residual -->\nstale\n\
                <!-- residue-catalog:end residual -->\noutro\n";
    let synced = docs::sync_document(text, "threat-model.md").unwrap();
    assert!(synced.starts_with("intro\n<!-- residue-catalog:begin residual -->\n| Channel"));
    assert!(synced.ends_with("<!-- residue-catalog:end residual -->\noutro\n"));
    assert!(!synced.contains("stale"));
    // Idempotent.
    assert_eq!(
        docs::sync_document(&synced, "threat-model.md").unwrap(),
        synced
    );
}

#[test]
fn sync_rejects_broken_markers() {
    assert_eq!(
        docs::sync_document("<!-- residue-catalog:begin residual -->\n", "x.md"),
        Err(docs::SyncError::Unterminated("residual".to_string()))
    );
    assert_eq!(
        docs::sync_document(
            "<!-- residue-catalog:begin nope -->\n<!-- residue-catalog:end nope -->",
            "x.md"
        ),
        Err(docs::SyncError::UnknownBlock("nope".to_string()))
    );
}

#[test]
fn links_to_the_same_doc_become_bare_anchors() {
    let block = docs::render_block("fail-closed", "decoy-requirements.md").unwrap();
    assert!(
        block.contains("](#fail-closed-activation-is-refused)"),
        "{block}"
    );
    let block = docs::render_block("residual", "decoy-requirements.md").unwrap();
    assert!(
        block.contains("](threat-model.md#residual-channels)"),
        "{block}"
    );
}

/// The `Platforms` bitset: how families compose, which host each class applies
/// to, and how the set reads in the docs.
mod platforms {
    use super::super::Platforms;
    use crate::platform::{FakePlatform, HostProfile, PlatformKind};
    use nails_base::Family;

    /// A detected host of the given kind and family.
    fn host(kind: PlatformKind, family: Option<Family>) -> HostProfile {
        let mut profile = FakePlatform::fhs().host_profile();
        profile.kind = kind;
        profile.family = family;
        profile
    }

    #[test]
    fn all_is_every_family_and_fhs_is_the_three_fhs_families() {
        let all = Platforms::NIXOS | Platforms::DEBIAN | Platforms::FEDORA | Platforms::ARCH;
        assert_eq!(all, Platforms::ALL);
        let fhs = Platforms::DEBIAN | Platforms::FEDORA | Platforms::ARCH;
        assert_eq!(fhs, Platforms::FHS);
        assert_eq!(Platforms::NIXOS | Platforms::FHS, Platforms::ALL);
    }

    #[test]
    fn bitor_takes_the_union_of_overlapping_families() {
        // `|` is a set union: combining a set with a subset it already contains
        // leaves it unchanged, and combining a family with itself is idempotent.
        // A symmetric-difference would instead clear the shared bits and drop
        // those families.
        assert_eq!(Platforms::FHS | Platforms::DEBIAN, Platforms::FHS);
        assert_eq!(
            (Platforms::FHS | Platforms::DEBIAN).label(),
            "Debian, Fedora, Arch"
        );
        assert_eq!(Platforms::NIXOS | Platforms::NIXOS, Platforms::NIXOS);
        assert_eq!(Platforms::ALL | Platforms::DEBIAN, Platforms::ALL);
    }

    #[test]
    fn for_host_maps_each_live_host_to_its_family() {
        assert_eq!(
            Platforms::for_host(&host(PlatformKind::NixOs, None)),
            Some(Platforms::NIXOS)
        );
        assert_eq!(
            Platforms::for_host(&host(PlatformKind::Fhs, Some(Family::Debian))),
            Some(Platforms::DEBIAN)
        );
        // A refused Fedora or Arch host still carries its family.
        assert_eq!(
            Platforms::for_host(&host(PlatformKind::Unsupported, Some(Family::Fedora))),
            Some(Platforms::FEDORA)
        );
        assert_eq!(
            Platforms::for_host(&host(PlatformKind::Unsupported, Some(Family::Arch))),
            Some(Platforms::ARCH)
        );
    }

    #[test]
    fn a_host_detection_cannot_place_reads_as_undetected() {
        // A refused host with no family (ostree, non-systemd, unknown id).
        assert_eq!(
            Platforms::for_host(&host(PlatformKind::Unsupported, None)),
            None
        );
    }

    #[test]
    fn a_class_applies_to_a_host_its_families_overlap() {
        let nixos = Platforms::for_host(&host(PlatformKind::NixOs, None));
        let debian = Platforms::for_host(&host(PlatformKind::Fhs, Some(Family::Debian)));
        let fedora = Platforms::for_host(&host(PlatformKind::Unsupported, Some(Family::Fedora)));

        // `All` applies everywhere; an undetected host takes every class.
        for h in [nixos, debian, fedora, None] {
            assert!(Platforms::ALL.applies_to(h), "{h:?}");
        }

        // A NixOS-only class is NixOS-only; an FHS class spans the FHS families.
        assert!(Platforms::NIXOS.applies_to(nixos));
        assert!(!Platforms::NIXOS.applies_to(debian));
        assert!(!Platforms::NIXOS.applies_to(fedora));
        assert!(Platforms::FHS.applies_to(debian));
        assert!(Platforms::FHS.applies_to(fedora));
        assert!(!Platforms::FHS.applies_to(nixos));
        assert!(Platforms::DEBIAN.applies_to(debian));
        assert!(!Platforms::DEBIAN.applies_to(fedora));

        // An undetected host is never skipped, even for a scoped class.
        assert!(Platforms::NIXOS.applies_to(None));
    }

    #[test]
    fn the_cross_distro_rows_reach_the_right_families() {
        use crate::residue_catalog::class;
        let nixos = Platforms::for_host(&host(PlatformKind::NixOs, None));
        let debian = Platforms::for_host(&host(PlatformKind::Fhs, Some(Family::Debian)));
        let fedora = Platforms::for_host(&host(PlatformKind::Fhs, Some(Family::Fedora)));
        let arch = Platforms::for_host(&host(PlatformKind::Fhs, Some(Family::Arch)));

        let reaches = |id: &str, h| class(id).expect(id).platforms.applies_to(h);

        // Fedora's GRUB boot-success flag is a single-family class.
        assert!(reaches("grubenv-boot-success", fedora));
        for other in [debian, arch, nixos] {
            assert!(!reaches("grubenv-boot-success", other), "{other:?}");
        }

        // chrony, Plymouth's boot log and snapper belong to the FHS families,
        // not to NixOS.
        for id in ["chrony-drift", "plymouth-boot-log", "snapper-timeline"] {
            for fhs in [debian, fedora, arch] {
                assert!(reaches(id, fhs), "{id} on {fhs:?}");
            }
            assert!(!reaches(id, nixos), "{id} on NixOS");
        }

        // The copy-on-write and NetworkManager classes span every family.
        for id in ["btrfs-cow-history", "networkmanager-connection-records"] {
            for h in [nixos, debian, fedora, arch] {
                assert!(reaches(id, h), "{id} on {h:?}");
            }
        }
    }

    #[test]
    fn label_reads_all_a_single_family_or_a_list() {
        assert_eq!(Platforms::ALL.label(), "all");
        assert_eq!(Platforms::NIXOS.label(), "NixOS");
        assert_eq!(Platforms::DEBIAN.label(), "Debian");
        assert_eq!(Platforms::FHS.label(), "Debian, Fedora, Arch");
        assert_eq!(
            (Platforms::NIXOS | Platforms::DEBIAN).label(),
            "NixOS, Debian"
        );
    }
}

/// The committed docs carry the tables the catalog generates. Regenerate with
/// `REGENERATE_CATALOG_DOCS=1 cargo test -p nails-forensics residue_catalog`.
#[test]
fn generated_doc_tables_match_the_catalog() {
    let regenerate = std::env::var_os("REGENERATE_CATALOG_DOCS").is_some();
    for doc in docs::GENERATED_DOCS {
        let path = repo_root().join("docs").join(doc);
        let committed = std::fs::read_to_string(&path).unwrap();
        assert!(
            committed.contains("<!-- residue-catalog:begin "),
            "docs/{doc} has no generated block"
        );
        let synced = docs::sync_document(&committed, doc).unwrap();
        if regenerate {
            std::fs::write(&path, &synced).unwrap();
            continue;
        }
        assert!(
            committed == synced,
            "docs/{doc} has drifted from the residue catalog. Regenerate it with \
             `REGENERATE_CATALOG_DOCS=1 cargo test -p nails-forensics residue_catalog`"
        );
    }
}
