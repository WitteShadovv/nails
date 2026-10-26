// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the family table and its classification.

use super::*;

/// The verdict for a host with this `ID`, `ID_LIKE` and `VERSION_ID`, and no
/// `VARIANT_ID`.
fn classify_of(id: Option<&str>, id_like: &[&str], version_id: Option<&str>) -> Classification {
    classify_variant_of(id, id_like, version_id, None)
}

/// The verdict for a host with this `ID`, `ID_LIKE`, `VERSION_ID` and
/// `VARIANT_ID`.
fn classify_variant_of(
    id: Option<&str>,
    id_like: &[&str],
    version_id: Option<&str>,
    variant_id: Option<&str>,
) -> Classification {
    let like: Vec<String> = id_like.iter().map(|t| t.to_string()).collect();
    classify(id, &like, version_id, variant_id)
}

/// The table row for `id`.
fn row(id: &str) -> &'static FamilyRow {
    TABLE
        .iter()
        .find(|row| row.id == id)
        .unwrap_or_else(|| panic!("the table has no row '{id}'"))
}

/// The verdict on a host of the row for `id` once NAILS admits the row (for a
/// derivative, its base family): the gate the row is held to then.
fn once_admitted(id: &str, version_id: Option<&str>, variant_id: Option<&str>) -> FamilySupport {
    admitted_verdict(row(id), version_id, variant_id)
}

/// The warning in `support`, or a panic naming what it was instead.
fn warning_of(support: FamilySupport) -> String {
    match support {
        FamilySupport::Untested(warning) => warning,
        other => panic!("expected a warning, got {other:?}"),
    }
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

#[test]
fn alternatives_are_listed_as_in_a_sentence() {
    let v = DistroVersion::new;
    assert_eq!(either(&[]), "");
    assert_eq!(either(&[v(13, 0)]), "13");
    assert_eq!(either(&[v(24, 4), v(26, 4)]), "24.04 or 26.04");
    assert_eq!(
        either(&[v(22, 4), v(24, 4), v(26, 4)]),
        "22.04, 24.04 or 26.04"
    );
}

#[test]
fn editions_are_listed_as_in_a_sentence() {
    assert_eq!(joined(&["Cloud"], "and"), "Cloud");
    assert_eq!(
        joined(&["Cloud", "Server", "IoT"], "and"),
        "Cloud, Server and IoT"
    );
    assert_eq!(gate::tested_editions(row("fedora")), "Fedora Cloud");
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

#[test]
fn edition_label_names_an_edition_the_row_lists() {
    assert_eq!(edition_label("fedora", "cloud"), Some("Cloud"));
    assert_eq!(edition_label("fedora", "workstation"), Some("Workstation"));
    assert_eq!(edition_label("fedora", "kde"), Some("KDE Plasma Desktop"));
    // An edition the row does not list, a row with no editions, an ID the
    // table does not list.
    assert_eq!(edition_label("fedora", "server"), None);
    assert_eq!(edition_label("nobara", "kde"), None);
    assert_eq!(edition_label("ubuntu", "cloud"), None);
    assert_eq!(edition_label("linuxmint", "cloud"), None);
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
                assert!(warning.contains(&rehearse_line()), "{warning}");
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
fn fedora_is_refused_whatever_its_edition() {
    // The edition gate is the one Fedora will take once admitted; until then
    // every edition gets the same refusal.
    for variant in [Some("cloud"), Some("workstation"), Some("server"), None] {
        let c = classify_variant_of(Some("fedora"), &[], Some("44"), variant);
        assert_eq!(
            c,
            classify_of(Some("fedora"), &[], Some("44")),
            "{variant:?}"
        );
        assert!(
            matches!(&c.support, FamilySupport::Refused(reason)
                if reason.starts_with("Fedora is not yet a validated platform")),
            "{variant:?}: {:?}",
            c.support
        );
    }
}

// --- Fedora's gate once admitted: its release and its edition -------------

#[test]
fn fedora_cloud_on_a_tested_release_runs_clean_once_admitted() {
    assert_eq!(
        once_admitted("fedora", Some("44"), Some("cloud")),
        FamilySupport::Supported
    );
}

#[test]
fn fedora_workstation_and_kde_warn_as_untested_editions_once_admitted() {
    for (variant, label) in [
        ("workstation", "Workstation"),
        ("kde", "KDE Plasma Desktop"),
    ] {
        let warning = warning_of(once_admitted("fedora", Some("44"), Some(variant)));
        assert!(
            warning.starts_with(&format!(
                "Fedora 44 {label} is not an edition NAILS has been tested on \
                 (tested: Fedora Cloud). NAILS runs on it, but a change in this \
                 edition can break the session"
            )),
            "{warning}"
        );
        assert!(
            warning.contains("Use a tested edition, or run `"),
            "{warning}"
        );
        assert!(warning.contains(&rehearse_line()), "{warning}");
    }
}

#[test]
fn any_other_fedora_edition_warns_naming_its_variant_id_once_admitted() {
    for variant in ["server", "xfce", "kde-mobile", "cosmic"] {
        let warning = warning_of(once_admitted("fedora", Some("44"), Some(variant)));
        assert!(
            warning.starts_with(&format!(
                "Fedora 44 with VARIANT_ID '{variant}' is not an edition NAILS has been \
                 tested on (tested: Fedora Cloud)."
            )),
            "{warning}"
        );
    }
}

#[test]
fn a_fedora_host_that_names_no_edition_warns_once_admitted() {
    // Fedora's basic install sets no VARIANT_ID; an empty one names none either.
    for variant in [None, Some("")] {
        let warning = warning_of(once_admitted("fedora", Some("44"), variant));
        assert!(
            warning.starts_with(
                "Fedora 44 declares no edition (its os-release has no VARIANT_ID, or an \
                 empty one), so NAILS cannot tell whether it is a tested one (tested: Fedora \
                 Cloud)."
            ),
            "{variant:?}: {warning}"
        );
        assert!(warning.contains("Use a tested edition"), "{warning}");
    }
}

#[test]
fn an_untested_fedora_release_of_the_tested_edition_warns_about_the_release() {
    let warning = warning_of(once_admitted("fedora", Some("45"), Some("cloud")));
    assert!(
        warning.starts_with(
            "Fedora 45 is not a release NAILS has been tested on (tested: Fedora 44). NAILS \
             runs on it, but a change in this release can break the session"
        ),
        "{warning}"
    );
    assert!(
        warning.contains("Use a tested release, or run `"),
        "{warning}"
    );
    assert!(!warning.contains("is not an edition"), "{warning}");
}

#[test]
fn an_untested_release_and_edition_warn_once_naming_both() {
    let warning = warning_of(once_admitted("fedora", Some("45"), Some("workstation")));
    assert!(
        warning.starts_with(
            "Fedora 45 is not a release NAILS has been tested on (tested: Fedora 44). \
             Fedora 45 Workstation is not an edition NAILS has been tested on (tested: \
             Fedora Cloud). NAILS runs on it, but a change in this release or edition can \
             break the session"
        ),
        "{warning}"
    );
    assert!(
        warning.contains("Use a tested release and edition, or run `"),
        "{warning}"
    );
    // One warning, pointing at the rehearsal once.
    assert_eq!(warning.matches(&rehearse_line()).count(), 1, "{warning}");
}

#[test]
fn fedoras_release_gate_still_refuses_whatever_the_edition() {
    let FamilySupport::Refused(reason) = once_admitted("fedora", Some("43"), Some("cloud")) else {
        panic!("Fedora 43 is below the minimum");
    };
    assert!(reason.contains("(Fedora 44)"), "{reason}");
    assert!(reason.contains("minimum"), "{reason}");

    for version in [None, Some("rawhide")] {
        assert!(
            matches!(
                once_admitted("fedora", version, Some("cloud")),
                FamilySupport::Refused(reason) if reason.contains("VERSION_ID")
            ),
            "{version:?}"
        );
    }
}

#[test]
fn a_caveat_of_a_tested_release_holds_on_an_untested_edition() {
    // No row both lists editions and carries a caveat yet; this is the rule
    // for the first that does.
    let caveated = FamilyRow {
        gate: Gate::Versioned {
            min: FEDORA_MIN,
            validated: &[FEDORA_MIN],
            caveats: &[(FEDORA_MIN, "A known issue affects it.")],
        },
        ..*row("fedora")
    };
    assert_eq!(
        admitted_verdict(&caveated, Some("44"), Some("cloud")),
        FamilySupport::SupportedWithCaveat("A known issue affects it.".to_string())
    );
    let warning = warning_of(admitted_verdict(&caveated, Some("44"), Some("kde")));
    assert!(
        warning.starts_with("Fedora 44 KDE Plasma Desktop is not an edition"),
        "{warning}"
    );
    assert!(warning.ends_with(" A known issue affects it."), "{warning}");
}

#[test]
fn a_rolling_row_that_lists_editions_gates_the_edition_alone() {
    // No rolling row lists editions yet; this is the rule for the first that
    // does: no release to gate on or to name, only the edition.
    let rolling = FamilyRow {
        gate: Gate::Rolling,
        ..*row("fedora")
    };
    assert_eq!(
        admitted_verdict(&rolling, None, Some("cloud")),
        FamilySupport::Supported
    );
    let warning = warning_of(admitted_verdict(&rolling, None, Some("kde")));
    assert!(
        warning.starts_with(
            "Fedora KDE Plasma Desktop is not an edition NAILS has been tested on \
             (tested: Fedora Cloud)."
        ),
        "{warning}"
    );
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
    // Whatever its release: the base refusal comes before the release gate.
    for id in ["nobara", "ultramarine"] {
        for version in [Some("44"), Some("41"), None] {
            let c = classify_of(Some(id), &["fedora"], version);
            assert_eq!(c.family, Some(Family::Fedora), "{id}");
            assert!(
                matches!(&c.support, FamilySupport::Refused(reason) if reason.contains("based on Fedora")),
                "{id} {version:?}: {:?}",
                c.support
            );
        }
    }
}

#[test]
fn a_fedora_derivative_needs_release_44_once_fedora_is_admitted() {
    for (id, label) in [("nobara", "Nobara"), ("ultramarine", "Ultramarine")] {
        for version in ["43", "41"] {
            let FamilySupport::Refused(reason) = once_admitted(id, Some(version), Some("kde"))
            else {
                panic!("{id} {version} is below the minimum");
            };
            assert!(
                reason.starts_with(&format!(
                    "{label} {version} is older than the minimum supported release \
                     ({label} 44)."
                )),
                "{reason}"
            );
        }
        for version in [None, Some("rolling")] {
            assert!(
                matches!(
                    once_admitted(id, version, None),
                    FamilySupport::Refused(reason) if reason.contains("VERSION_ID")
                ),
                "{id} {version:?}"
            );
        }
    }
}

#[test]
fn a_fedora_derivative_from_release_44_warns_as_an_untested_derivative_once_admitted() {
    // A derivative's own editions are not gated: it warns as a derivative.
    for id in ["nobara", "ultramarine"] {
        for (version, variant) in [("44", Some("kde")), ("45", None), ("46", Some("plasma"))] {
            assert_eq!(
                once_admitted(id, Some(version), variant),
                FamilySupport::Untested(derivative_warning(Family::Fedora)),
                "{id} {version} {variant:?}"
            );
        }
    }
}

#[test]
fn a_derivative_row_is_held_to_its_gate_once_its_base_family_is_admitted() {
    // No derivative row has an admitted base yet. Placed in the Debian family,
    // which is admitted, Nobara's row shows the path it takes the day Fedora
    // is: refused below its minimum, an untested derivative from it.
    let derivative = FamilyRow {
        family: Family::Debian,
        ..*row("nobara")
    };
    assert_eq!(
        classify_row(&derivative, Some("44"), Some("kde")).support,
        FamilySupport::Untested(derivative_warning(Family::Debian))
    );
    assert!(matches!(
        classify_row(&derivative, Some("43"), Some("kde")).support,
        FamilySupport::Refused(reason) if reason.contains("minimum")
    ));
}

#[test]
fn an_arch_derivative_is_not_release_gated_once_admitted() {
    for id in ["endeavouros", "cachyos", "manjaro"] {
        assert_eq!(
            once_admitted(id, None, None),
            FamilySupport::Untested(derivative_warning(Family::Arch)),
            "{id}"
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
            assert!(warning.contains(&rehearse_line()), "{warning}");
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
fn every_tested_release_and_edition_runs_clean_once_its_row_is_admitted() {
    for row in TABLE.iter().filter(|row| row.kind == Kind::Base) {
        let Gate::Versioned { min, validated, .. } = row.gate else {
            continue;
        };
        assert!(!validated.is_empty(), "{} lists no release", row.id);
        // The tested editions, or the host that names none where the row
        // lists no editions.
        let editions: Vec<Option<&str>> = if row.editions.is_empty() {
            vec![None]
        } else {
            row.editions
                .iter()
                .filter(|edition| edition.validated)
                .map(|edition| Some(edition.id))
                .collect()
        };
        for version in validated {
            assert!(*version >= min, "{} {version}", row.id);
            let raw = version.to_string();
            for edition in &editions {
                // A tested release and edition are never refused: they either
                // run clean or are admitted with a documented caveat. Both
                // keep the release in the tested-release sentence; a caveat
                // only adds a warning.
                let support = admitted_verdict(row, Some(&raw), *edition);
                assert!(
                    matches!(
                        support,
                        FamilySupport::Supported | FamilySupport::SupportedWithCaveat(_)
                    ),
                    "{} {raw} {edition:?}: {support:?}",
                    row.id
                );
                // An admitted row is classified so today.
                if row.admitted {
                    assert_eq!(
                        classify_variant_of(Some(row.id), &[], Some(&raw), *edition).support,
                        support
                    );
                }
            }
        }
    }
}

#[test]
fn a_row_that_lists_editions_is_a_base_with_a_tested_edition() {
    for row in TABLE.iter().filter(|row| !row.editions.is_empty()) {
        // A derivative warns as a derivative, whatever its edition.
        assert_eq!(row.kind, Kind::Base, "{}", row.id);
        assert!(
            row.editions.iter().any(|edition| edition.validated),
            "{} lists no tested edition",
            row.id
        );
        for (i, edition) in row.editions.iter().enumerate() {
            // os-release writes a VARIANT_ID in lowercase, and detection
            // lowercases it, so an edition is listed the same way.
            assert!(
                !edition.id.is_empty() && edition.id == edition.id.to_ascii_lowercase(),
                "{} {}",
                row.id,
                edition.id
            );
            assert!(!edition.label.is_empty(), "{} {}", row.id, edition.id);
            assert!(
                row.editions[..i].iter().all(|other| other.id != edition.id),
                "{} lists {} twice",
                row.id,
                edition.id
            );
        }
    }
}

#[test]
fn a_derivative_lists_no_tested_release_and_a_caveat_names_a_tested_one() {
    for row in TABLE {
        let Gate::Versioned {
            validated, caveats, ..
        } = row.gate
        else {
            continue;
        };
        if row.kind == Kind::Derivative {
            // NAILS tests no release of a derivative: the gate holds only its
            // minimum.
            assert!(validated.is_empty() && caveats.is_empty(), "{}", row.id);
        }
        for (version, _) in caveats {
            assert!(validated.contains(version), "{} {version}", row.id);
        }
    }
}

#[test]
fn the_fedora_derivatives_start_at_fedoras_minimum() {
    // Nobara and Ultramarine number their releases after Fedora's.
    let Gate::Versioned { min: fedora, .. } = row("fedora").gate else {
        panic!("Fedora is versioned");
    };
    for id in ["nobara", "ultramarine"] {
        assert!(
            matches!(row(id).gate, Gate::Versioned { min, .. } if min == fedora),
            "{id}"
        );
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

/// A `VARIANT_ID` for a generated host, or none: an edition the table lists,
/// another Fedora edition, an empty value, or a word no row lists.
fn variant_id() -> impl proptest::strategy::Strategy<Value = Option<String>> {
    use proptest::strategy::Strategy;
    proptest::option::of(proptest::prop_oneof![
        proptest::sample::select(vec!["cloud", "workstation", "kde", "server", ""])
            .prop_map(str::to_string),
        "[a-z0-9._-]{1,12}",
    ])
}

/// The `ID` of every row that lists editions.
fn edition_row_ids() -> Vec<&'static str> {
    TABLE
        .iter()
        .filter(|row| !row.editions.is_empty())
        .map(|row| row.id)
        .collect()
}

/// An `ID` for a generated host: one the table or the named refusals list, or
/// a word they do not.
fn host_id() -> impl proptest::strategy::Strategy<Value = String> {
    use proptest::strategy::Strategy;
    proptest::prop_oneof![
        proptest::sample::select(listed_ids()).prop_map(str::to_string),
        "[a-z][a-z0-9_-]{0,12}",
    ]
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
    /// alone: whatever `ID_LIKE` names, the verdict is the one the same `ID`,
    /// version and edition get with no `ID_LIKE` at all.
    #[test]
    fn a_listed_id_is_classified_by_its_row_whatever_id_like_says(
        id in proptest::sample::select(listed_ids()),
        like in proptest::collection::vec(id_like_token(), 1..4),
        version in proptest::option::of("[0-9][0-9.]{0,6}"),
        variant in variant_id(),
    ) {
        let like_refs: Vec<&str> = like.iter().map(String::as_str).collect();
        proptest::prop_assert_eq!(
            classify_variant_of(Some(id), &like_refs, version.as_deref(), variant.as_deref()),
            classify_variant_of(Some(id), &[], version.as_deref(), variant.as_deref()),
            "{} {:?}", id, like
        );
    }

    /// `VARIANT_ID` decides a verdict only on an admitted row that lists
    /// editions. For any other host, listed or not, the verdict is the one it
    /// gets without a `VARIANT_ID`.
    #[test]
    fn variant_id_decides_nothing_outside_an_admitted_row_with_editions(
        id in host_id(),
        like in proptest::collection::vec(id_like_token(), 0..4),
        version in proptest::option::of("[0-9][0-9.]{0,6}"),
        variant in variant_id(),
    ) {
        let gated = TABLE
            .iter()
            .any(|row| row.id == id && row.admitted && !row.editions.is_empty());
        proptest::prop_assume!(!gated);
        let like_refs: Vec<&str> = like.iter().map(String::as_str).collect();
        proptest::prop_assert_eq!(
            classify_variant_of(Some(&id), &like_refs, version.as_deref(), variant.as_deref()),
            classify_of(Some(&id), &like_refs, version.as_deref()),
            "{} {:?} {:?}", id, like, variant
        );
    }

    /// The edition gate only warns: on a tested release of a row that lists
    /// editions, once NAILS admits the row, a host runs clean exactly when its
    /// `VARIANT_ID` names a tested edition, and runs with a warning otherwise.
    /// It is never refused.
    #[test]
    fn the_edition_gate_passes_a_tested_edition_and_warns_on_any_other(
        id in proptest::sample::select(edition_row_ids()),
        variant in variant_id(),
    ) {
        let row = row(id);
        // The row's tested releases, or no release for a rolling row.
        let releases: Vec<Option<String>> = match row.gate {
            Gate::Versioned { validated, .. } => {
                validated.iter().map(|version| Some(version.to_string())).collect()
            }
            Gate::Rolling => vec![None],
        };
        let tested = row
            .editions
            .iter()
            .any(|edition| edition.validated && Some(edition.id) == variant.as_deref());
        for release in releases {
            let support = admitted_verdict(row, release.as_deref(), variant.as_deref());
            if tested {
                proptest::prop_assert!(
                    matches!(support, FamilySupport::Supported | FamilySupport::SupportedWithCaveat(_)),
                    "{} {:?} {:?}: {:?}", id, release, variant, support
                );
            } else {
                proptest::prop_assert!(
                    matches!(&support, FamilySupport::Untested(warning)
                        if warning.contains("Use a tested edition, or run `")),
                    "{} {:?} {:?}: {:?}", id, release, variant, support
                );
            }
        }
    }

    /// Once Fedora is admitted, a Fedora derivative runs, as an untested
    /// derivative, exactly from Fedora's minimum release upward, whatever
    /// edition it names; below it, or without a release NAILS can read, it is
    /// refused.
    #[test]
    fn a_fedora_derivative_runs_from_fedoras_minimum_once_admitted(
        id in proptest::sample::select(vec!["nobara", "ultramarine"]),
        version in proptest::option::of("[0-9][0-9.]{0,6}"),
        variant in variant_id(),
    ) {
        let support = once_admitted(id, version.as_deref(), variant.as_deref());
        let from_minimum = version
            .as_deref()
            .and_then(DistroVersion::parse)
            .is_some_and(|release| release >= FEDORA_MIN);
        if from_minimum {
            proptest::prop_assert_eq!(
                support,
                FamilySupport::Untested(derivative_warning(Family::Fedora))
            );
        } else {
            proptest::prop_assert!(
                matches!(support, FamilySupport::Refused(_)),
                "{} {:?}: {:?}", id, version, support
            );
        }
    }
}
