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
    assert_eq!(supported_platforms(), "Debian 13, Ubuntu 24.04 and 26.04");
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
fn ubuntu_2404_is_a_tested_release_that_runs_clean() {
    // 26.04 is tested too but carries a caveat, so it is checked on its own
    // below.
    let c = classify_of(Some("ubuntu"), &["debian"], Some("24.04"));
    assert_eq!(c.family, Some(Family::Debian));
    assert_eq!(c.support, FamilySupport::Supported);
}

#[test]
fn ubuntu_2604_is_tested_but_carries_a_caveat() {
    // 26.04 stays a tested release, but a known upstream issue affects it, so it
    // is admitted with a specific warning rather than a clean pass.
    let c = classify_of(Some("ubuntu"), &["debian"], Some("26.04"));
    assert_eq!(c.family, Some(Family::Debian));
    match c.support {
        FamilySupport::SupportedWithCaveat(warning) => {
            assert!(
                warning.starts_with("Ubuntu 26.04 is tested, but a known upstream issue"),
                "{warning}"
            );
            assert!(warning.contains("AppArmor blocks chrony"), "{warning}");
            assert!(warning.contains("reboot the decoy fully"), "{warning}");
            assert!(warning.contains("not in NAILS"), "{warning}");
        }
        other => panic!("expected a tested release with a caveat, got {other:?}"),
    }
    // It is still named in the generated tested-release sentence.
    assert!(
        supported_platforms().contains("26.04"),
        "{}",
        supported_platforms()
    );
}

#[test]
fn an_untested_ubuntu_release_is_admitted_with_a_warning() {
    // 26.10 among them: no run of NAILS on it has passed yet.
    for release in ["26.10", "28.04", "24.10", "25.04"] {
        match classify_of(Some("ubuntu"), &["debian"], Some(release)).support {
            FamilySupport::Untested(warning) => {
                assert!(
                    warning.starts_with(&format!(
                        "Ubuntu {release} is not a release NAILS has been tested on \
                         (tested: Ubuntu 24.04 and 26.04)."
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
fn an_unvalidated_family_anywhere_in_id_like_refuses_the_host() {
    // os-release lists ID_LIKE closest relative first. Arch named first is an
    // Arch derivative; Debian named first still declares kinship with Arch,
    // which NAILS has not validated. Both are refused rather than run as a
    // Debian derivative.
    for like in [["arch", "debian"], ["debian", "arch"], ["ubuntu", "arch"]] {
        let c = classify_of(Some("someos"), &like, Some("1"));
        assert_eq!(c.family, Some(Family::Arch), "{like:?}");
        let FamilySupport::Refused(reason) = &c.support else {
            panic!("{like:?}: expected a refusal, got {:?}", c.support);
        };
        assert!(reason.contains("part of the Arch family"), "{reason}");
    }
}

#[test]
fn the_refusal_names_the_closest_unvalidated_family() {
    let c = classify_of(Some("someos"), &["debian", "fedora", "arch"], None);
    assert_eq!(c.family, Some(Family::Fedora));
    let c = classify_of(Some("someos"), &["arch", "rhel"], None);
    assert_eq!(c.family, Some(Family::Arch));
}

#[test]
fn a_table_id_is_classified_by_its_row_whatever_id_like_says() {
    let c = classify_of(Some("ubuntu"), &["arch"], Some("24.04"));
    assert_eq!(c.family, Some(Family::Debian));
    assert_eq!(c.support, FamilySupport::Supported);
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
        let Gate::Versioned { min, validated, .. } = row.gate else {
            continue;
        };
        if !(row.kind == Kind::Base && row.admitted) {
            continue;
        }
        assert!(!validated.is_empty(), "{} lists no release", row.id);
        for version in validated {
            assert!(*version >= min, "{} {version}", row.id);
            // A tested release is never refused: it either runs clean or is
            // admitted with a documented caveat. Both keep it in the
            // tested-release sentence; a caveat only adds a warning.
            let support = classify_of(Some(row.id), &[], Some(&version.to_string())).support;
            assert!(
                matches!(
                    support,
                    FamilySupport::Supported | FamilySupport::SupportedWithCaveat(_)
                ),
                "{} {version}: {support:?}",
                row.id
            );
        }
    }
}

#[test]
fn base_admitted_reports_which_families_have_an_admitted_base_row() {
    // Debian is an admitted base family in the table, so its base is admitted:
    // a derivative of it would run (with a warning) rather than be refused.
    assert!(base_admitted(Family::Debian));
    // Arch and Fedora sit in the table but are not admitted, and neither has an
    // admitted base row, so their base is not admitted and their derivatives are
    // refused until the base is verified.
    assert!(!base_admitted(Family::Arch));
    assert!(!base_admitted(Family::Fedora));
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

/// An `ID_LIKE` token for a generated host: one the classifier recognises,
/// Debian-family and unvalidated alike, or a word it does not.
fn id_like_token() -> impl proptest::strategy::Strategy<Value = String> {
    use proptest::strategy::Strategy;
    proptest::prop_oneof![
        proptest::sample::select(vec!["debian", "ubuntu", "fedora", "rhel", "centos", "arch"])
            .prop_map(str::to_string),
        "[a-z]{1,8}",
    ]
}

/// The family an `ID_LIKE` token names when it is one NAILS has not validated.
fn unvalidated_family(token: &str) -> Option<Family> {
    match token {
        "fedora" | "rhel" | "centos" => Some(Family::Fedora),
        "arch" => Some(Family::Arch),
        _ => None,
    }
}

/// Every `ID` the table or the named refusals list.
fn listed_ids() -> Vec<&'static str> {
    TABLE
        .iter()
        .map(|row| row.id)
        .chain(NAMED_REFUSALS.iter().map(|row| row.id))
        .collect()
}

proptest::proptest! {
    /// An unknown `ID` whose `ID_LIKE` names an unvalidated family is always
    /// refused, naming the first such family in the list's closest-first
    /// order. That holds wherever the family stands in the list and whatever
    /// else it names, `debian` and `ubuntu` before or after it included, and
    /// whatever the version.
    #[test]
    fn an_unknown_id_like_an_unvalidated_family_is_always_refused(
        id in "[a-z][a-z0-9_-]{0,12}",
        before in proptest::collection::vec(id_like_token(), 0..3),
        family in proptest::sample::select(vec!["fedora", "rhel", "centos", "arch"]),
        after in proptest::collection::vec(id_like_token(), 0..3),
        version in proptest::option::of("[0-9][0-9.]{0,6}"),
    ) {
        // Skip ids the table or named-refusal lists claim directly.
        proptest::prop_assume!(label(&id).is_none());
        let like: Vec<String> = before
            .into_iter()
            .chain([family.to_string()])
            .chain(after)
            .collect();
        let closest = like
            .iter()
            .find_map(|token| unvalidated_family(token))
            .expect("the list names an unvalidated family");
        let like_refs: Vec<&str> = like.iter().map(String::as_str).collect();
        let c = classify_of(Some(&id), &like_refs, version.as_deref());
        proptest::prop_assert_eq!(c.family, Some(closest), "{} {:?}", id, like);
        let named = format!("part of the {} family", closest.label());
        proptest::prop_assert!(
            matches!(&c.support, FamilySupport::Refused(reason) if reason.contains(&named)),
            "{id} {like:?}: {:?}", c.support
        );
    }

    /// An `ID` outside the table runs only as an untested Debian derivative:
    /// it is admitted, with the derivative warning and never as a tested
    /// release, exactly when `ID_LIKE` names `debian` or `ubuntu` and no
    /// unvalidated family, whatever the version; every other such host is
    /// refused.
    #[test]
    fn an_unknown_id_runs_only_as_an_untested_debian_derivative(
        id in "[a-z][a-z0-9_-]{0,12}",
        like in proptest::collection::vec(id_like_token(), 0..5),
        version in proptest::option::of("[0-9][0-9.]{0,6}"),
    ) {
        proptest::prop_assume!(label(&id).is_none());
        let like_refs: Vec<&str> = like.iter().map(String::as_str).collect();
        let c = classify_of(Some(&id), &like_refs, version.as_deref());
        let debian_like = like.iter().any(|token| token == "debian" || token == "ubuntu");
        let unvalidated = like.iter().any(|token| unvalidated_family(token).is_some());
        if debian_like && !unvalidated {
            proptest::prop_assert_eq!(c.family, Some(Family::Debian));
            proptest::prop_assert_eq!(
                c.support,
                FamilySupport::Untested(derivative_warning(Family::Debian))
            );
        } else {
            proptest::prop_assert!(
                matches!(c.support, FamilySupport::Refused(_)),
                "{id} {like:?}: {:?}", c.support
            );
        }
    }

    /// An `ID` the table or the named refusals list is classified by its row
    /// alone: whatever `ID_LIKE` names, the verdict is the one the same `ID`
    /// and version get with no `ID_LIKE` at all.
    #[test]
    fn a_listed_id_is_classified_by_its_row_whatever_id_like_says(
        id in proptest::sample::select(listed_ids()),
        like in proptest::collection::vec(id_like_token(), 1..4),
        version in proptest::option::of("[0-9][0-9.]{0,6}"),
    ) {
        let like_refs: Vec<&str> = like.iter().map(String::as_str).collect();
        proptest::prop_assert_eq!(
            classify_of(Some(id), &like_refs, version.as_deref()),
            classify_of(Some(id), &[], version.as_deref()),
            "{} {:?}", id, like
        );
    }
}
