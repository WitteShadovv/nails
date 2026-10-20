// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the family table and its classification.

use super::*;

/// The verdict for a host with this `ID`, `ID_LIKE` and `VERSION_ID`.
fn classify_of(id: Option<&str>, id_like: &[&str], version_id: Option<&str>) -> Classification {
    let like: Vec<String> = id_like.iter().map(|t| t.to_string()).collect();
    classify(id, &like, version_id)
}

// --- DistroVersion -------------------------------------------------------

#[test]
fn version_parses_major_and_minor() {
    assert_eq!(DistroVersion::parse("12"), Some(DistroVersion::new(12, 0)));
    assert_eq!(
        DistroVersion::parse("24.04"),
        Some(DistroVersion::new(24, 4))
    );
    assert_eq!(
        DistroVersion::parse(" 13 "),
        Some(DistroVersion::new(13, 0))
    );
}

#[test]
fn version_rejects_malformed() {
    assert_eq!(DistroVersion::parse("rolling"), None);
    assert_eq!(DistroVersion::parse(""), None);
    // A non-numeric minor degrades to zero rather than failing the parse.
    assert_eq!(
        DistroVersion::parse("24.lts"),
        Some(DistroVersion::new(24, 0))
    );
}

#[test]
fn version_orders_releases() {
    assert!(DistroVersion::new(12, 0) < DistroVersion::new(13, 0));
    assert!(DistroVersion::new(24, 4) > DistroVersion::new(22, 4));
    assert!(DistroVersion::new(24, 4) == DistroVersion::new(24, 4));
    assert!(DistroVersion::new(24, 10) > DistroVersion::new(24, 4));
}

#[test]
fn version_is_written_as_the_distribution_writes_it() {
    assert_eq!(DistroVersion::new(13, 0).to_string(), "13");
    assert_eq!(DistroVersion::new(24, 4).to_string(), "24.04");
    assert_eq!(DistroVersion::new(26, 10).to_string(), "26.10");
}

#[test]
fn releases_are_listed_as_in_a_sentence() {
    let v = DistroVersion::new;
    assert_eq!(releases(&[]), "");
    assert_eq!(releases(&[v(13, 0)]), "13");
    assert_eq!(releases(&[v(24, 4), v(26, 4)]), "24.04 and 26.04");
    assert_eq!(
        releases(&[v(22, 4), v(24, 4), v(26, 4)]),
        "22.04, 24.04 and 26.04"
    );
}

// --- The generated supported-platform sentence ---------------------------

#[test]
fn the_supported_sentence_is_generated_from_the_admitted_rows() {
    assert_eq!(
        supported_platforms(),
        "Debian 13, Ubuntu 24.04, 26.04 and 26.10"
    );
}

#[test]
fn refusals_name_the_generated_supported_platforms() {
    // The refusal text should carry the generated list, not a hard-coded one.
    let FamilySupport::Refused(reason) = classify_of(Some("fedora"), &[], Some("44")).support
    else {
        panic!("Fedora should be refused");
    };
    assert!(reason.contains(&supported_platforms()), "{reason}");
}

// --- label ---------------------------------------------------------------

#[test]
fn label_names_table_and_named_refusal_rows() {
    assert_eq!(label("ubuntu"), Some("Ubuntu"));
    assert_eq!(label("debian"), Some("Debian"));
    assert_eq!(label("fedora"), Some("Fedora"));
    assert_eq!(label("arch"), Some("Arch"));
    assert_eq!(label("endeavouros"), Some("EndeavourOS"));
    assert_eq!(label("rhel"), Some("Red Hat Enterprise Linux"));
    assert_eq!(label("steamos"), Some("SteamOS"));
    assert_eq!(label("linuxmint"), None);
}

// --- Admitted base families ---------------------------------------------

#[test]
fn debian_13_is_supported_and_12_is_refused() {
    let supported = classify_of(Some("debian"), &[], Some("13"));
    assert_eq!(supported.family, Some(Family::Debian));
    assert_eq!(supported.support, FamilySupport::Supported);

    assert!(matches!(
        classify_of(Some("debian"), &[], Some("12")).support,
        FamilySupport::Refused(_)
    ));
}

#[test]
fn ubuntu_tested_releases_are_supported() {
    for release in ["24.04", "26.04", "26.10"] {
        let c = classify_of(Some("ubuntu"), &["debian"], Some(release));
        assert_eq!(c.family, Some(Family::Debian), "{release}");
        assert_eq!(c.support, FamilySupport::Supported, "{release}");
    }
}

#[test]
fn an_untested_ubuntu_release_is_admitted_with_a_warning() {
    for release in ["28.04", "24.10", "25.04"] {
        match classify_of(Some("ubuntu"), &["debian"], Some(release)).support {
            FamilySupport::Untested(warning) => {
                assert!(
                    warning.starts_with(&format!(
                        "Ubuntu {release} is not a release NAILS has been tested on \
                         (tested: Ubuntu 24.04, 26.04 and 26.10)."
                    )),
                    "{warning}"
                );
                assert!(warning.contains("nails rehearse"), "{warning}");
            }
            other => panic!("{release}: expected an untested release, got {other:?}"),
        }
    }
}

#[test]
fn a_debian_release_after_the_tested_one_is_admitted_with_a_warning() {
    match classify_of(Some("debian"), &[], Some("14")).support {
        FamilySupport::Untested(warning) => assert!(
            warning.starts_with(
                "Debian 14 is not a release NAILS has been tested on (tested: Debian 13)."
            ),
            "{warning}"
        ),
        other => panic!("expected an untested release, got {other:?}"),
    }
}

#[test]
fn a_release_below_the_minimum_is_refused_naming_the_minimum() {
    let FamilySupport::Refused(reason) =
        classify_of(Some("ubuntu"), &["debian"], Some("22.04")).support
    else {
        panic!("22.04 should be refused");
    };
    assert!(reason.contains("(Ubuntu 24.04)"), "{reason}");
    assert!(reason.contains("minimum"), "{reason}");
}

#[test]
fn an_admitted_family_without_a_version_is_refused() {
    let FamilySupport::Refused(reason) = classify_of(Some("debian"), &[], None).support else {
        panic!("a Debian host with no VERSION_ID should be refused");
    };
    assert!(reason.contains("VERSION_ID"), "{reason}");
}

#[test]
fn an_unparseable_version_is_refused() {
    assert!(matches!(
        classify_of(Some("debian"), &[], Some("sid")).support,
        FamilySupport::Refused(_)
    ));
}

// --- Fedora and Arch: in the table, refused as product data --------------

#[test]
fn fedora_is_refused_as_an_unvalidated_family() {
    for version in ["44", "45", "40"] {
        let c = classify_of(Some("fedora"), &[], Some(version));
        assert_eq!(c.family, Some(Family::Fedora), "{version}");
        match c.support {
            FamilySupport::Refused(reason) => {
                assert!(
                    reason.starts_with("Fedora is not yet a validated platform"),
                    "{reason}"
                );
            }
            other => panic!("{version}: expected a refusal, got {other:?}"),
        }
    }
}

#[test]
fn arch_is_refused_as_an_unvalidated_family() {
    let c = classify_of(Some("arch"), &[], None);
    assert_eq!(c.family, Some(Family::Arch));
    match c.support {
        FamilySupport::Refused(reason) => {
            assert!(
                reason.starts_with("Arch is not yet a validated platform"),
                "{reason}"
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// --- Derivatives of non-admitted families --------------------------------

#[test]
fn an_arch_derivative_is_refused_naming_its_base() {
    for (id, label) in [
        ("endeavouros", "EndeavourOS"),
        ("cachyos", "CachyOS"),
        ("manjaro", "Manjaro"),
    ] {
        let c = classify_of(Some(id), &["arch"], None);
        assert_eq!(c.family, Some(Family::Arch), "{id}");
        match c.support {
            FamilySupport::Refused(reason) => {
                assert!(
                    reason.starts_with(&format!("{label} is based on Arch")),
                    "{reason}"
                );
                assert!(
                    reason.contains("Arch support has been verified"),
                    "{reason}"
                );
            }
            other => panic!("{id}: expected a refusal, got {other:?}"),
        }
    }
}

#[test]
fn a_fedora_derivative_is_refused_naming_its_base() {
    for id in ["nobara", "ultramarine"] {
        let c = classify_of(Some(id), &["fedora"], Some("44"));
        assert_eq!(c.family, Some(Family::Fedora), "{id}");
        assert!(
            matches!(&c.support, FamilySupport::Refused(reason) if reason.contains("based on Fedora")),
            "{id}: {:?}",
            c.support
        );
    }
}

// --- Refused by name -----------------------------------------------------

#[test]
fn enterprise_linux_is_refused_by_name() {
    for (id, label) in [
        ("rhel", "Red Hat Enterprise Linux"),
        ("centos", "CentOS"),
        ("almalinux", "AlmaLinux"),
        ("rocky", "Rocky Linux"),
        ("ol", "Oracle Linux"),
    ] {
        let c = classify_of(Some(id), &["fedora", "rhel"], Some("9"));
        assert_eq!(c.family, None, "{id}");
        match c.support {
            FamilySupport::Refused(reason) => {
                assert!(reason.starts_with(label), "{reason}");
                assert!(reason.contains("enterprise Linux"), "{reason}");
            }
            other => panic!("{id}: expected a refusal, got {other:?}"),
        }
    }
}

#[test]
fn steamos_is_refused_by_name() {
    let c = classify_of(Some("steamos"), &["arch"], Some("3.5"));
    assert_eq!(c.family, None);
    match c.support {
        FamilySupport::Refused(reason) => {
            assert!(
                reason.starts_with("SteamOS is not a supported platform"),
                "{reason}"
            );
            assert!(reason.contains("immutable"), "{reason}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// --- ID_LIKE paths -------------------------------------------------------

#[test]
fn a_debian_like_derivative_is_accepted_with_a_warning() {
    // Linux Mint declares ID_LIKE=ubuntu debian; accepted provisionally, now
    // with an untested-derivative warning rather than silently.
    let c = classify_of(Some("linuxmint"), &["ubuntu", "debian"], Some("22"));
    assert_eq!(c.family, Some(Family::Debian));
    match c.support {
        FamilySupport::Untested(warning) => {
            assert!(
                warning.contains("derivative of the Debian family"),
                "{warning}"
            );
            assert!(warning.contains("nails rehearse"), "{warning}");
        }
        other => panic!("expected an untested derivative, got {other:?}"),
    }
}

#[test]
fn a_fedora_like_unknown_id_is_refused_naming_the_family() {
    let c = classify_of(Some("bazzite"), &["fedora"], Some("40"));
    assert_eq!(c.family, Some(Family::Fedora));
    assert!(
        matches!(&c.support, FamilySupport::Refused(reason) if reason.contains("Fedora family")),
        "{:?}",
        c.support
    );
}

#[test]
fn an_arch_like_unknown_id_is_refused_naming_the_family() {
    let c = classify_of(Some("artix"), &["arch"], None);
    assert_eq!(c.family, Some(Family::Arch));
    assert!(matches!(c.support, FamilySupport::Refused(_)));
}

#[test]
fn an_unknown_host_is_refused() {
    let c = classify_of(Some("voidlinux"), &["musl"], Some("rolling"));
    assert_eq!(c.family, None);
    assert!(matches!(c.support, FamilySupport::Refused(_)));

    let missing = classify_of(None, &[], None);
    assert_eq!(missing.family, None);
    match missing.support {
        FamilySupport::Refused(reason) => assert!(reason.contains("no os-release ID"), "{reason}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// --- Table consistency ---------------------------------------------------

#[test]
fn every_tested_release_of_an_admitted_family_is_supported() {
    for row in TABLE {
        let Gate::Versioned { min, validated } = row.gate else {
            continue;
        };
        if !(row.kind == Kind::Base && row.admitted) {
            continue;
        }
        assert!(!validated.is_empty(), "{} lists no release", row.id);
        for version in validated {
            assert!(*version >= min, "{} {version}", row.id);
            assert_eq!(
                classify_of(Some(row.id), &[], Some(&version.to_string())).support,
                FamilySupport::Supported,
                "{} {version}",
                row.id
            );
        }
    }
}

#[test]
fn a_derivative_rows_family_has_a_base_in_the_table() {
    for row in TABLE {
        if row.kind == Kind::Derivative {
            assert!(
                TABLE
                    .iter()
                    .any(|base| base.kind == Kind::Base && base.family == row.family),
                "{} names a family with no base row",
                row.id
            );
        }
    }
}

// --- Properties ----------------------------------------------------------

proptest::proptest! {
    /// An unknown `ID` whose `ID_LIKE` names an unvalidated family is always
    /// refused, whatever the rest of the tokens or the version say.
    #[test]
    fn an_unknown_id_like_an_unvalidated_family_is_always_refused(
        id in "[a-z][a-z0-9_-]{0,12}",
        family in proptest::sample::select(vec!["fedora", "rhel", "centos", "arch"]),
        extra in proptest::collection::vec("[a-z]{1,6}", 0..3),
        version in proptest::option::of("[0-9][0-9.]{0,6}"),
    ) {
        // Skip ids the table or named-refusal lists claim directly.
        proptest::prop_assume!(label(&id).is_none());
        let mut like = extra;
        like.push(family.to_string());
        let like_refs: Vec<&str> = like.iter().map(String::as_str).collect();
        let c = classify_of(Some(&id), &like_refs, version.as_deref());
        proptest::prop_assert!(
            matches!(c.support, FamilySupport::Refused(_)),
            "{id} {like:?}: {:?}", c.support
        );
    }

    /// Classification is a pure function of its inputs: the same host reads the
    /// same verdict every time (no hidden state, same live and offline).
    #[test]
    fn classification_is_deterministic(
        id in proptest::option::of("[a-z][a-z0-9_-]{0,12}"),
        like in proptest::collection::vec("[a-z]{1,8}", 0..4),
        version in proptest::option::of("[0-9][0-9.]{0,6}"),
    ) {
        let like_refs: Vec<&str> = like.iter().map(String::as_str).collect();
        let first = classify_of(id.as_deref(), &like_refs, version.as_deref());
        let again = classify_of(id.as_deref(), &like_refs, version.as_deref());
        proptest::prop_assert_eq!(first, again);
    }
}
