// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The "Inherited decoy state" part of the `check` report.
//!
//! The JSON report lists every inherited entry with what becomes of it; the
//! human listing shows only the entries that need review or are masked, counts
//! the desktop's and distribution's own components, and says on a line of its
//! own when the hidden session starts in the decoy home (`shared-home`).

use nails_core::EntryStatus;
use nails_core::app::readiness::{InheritedEntry, InheritedSummary};
use nails_core::output::{Mark, Style};

use crate::cli::output::count_noun;

/// The lines of the human "Inherited decoy state" section, without its
/// heading. `persona_mode` is the configured mode's spelling.
pub fn inherited_lines(
    summary: &InheritedSummary,
    persona_mode: &str,
    style: Style,
) -> Vec<String> {
    let mut lines = Vec::new();
    if persona_mode == "shared-home" {
        lines.push(style.marked(
            Mark::Info,
            "shared-home: the hidden session starts in the decoy home, so the decoy's accounts, \
             keys, browser profiles and shell history are live in it (persona.mode = \
             \"fresh-home\" starts it in an empty home)",
        ));
    }
    if !summary.inspected {
        lines.push(style.marked(
            Mark::Info,
            "not inspected (could not resolve the target user)",
        ));
        return lines;
    }

    let listed: Vec<&InheritedEntry> = summary
        .entries
        .iter()
        .filter(|entry| entry.status != EntryStatus::Ignored.as_str())
        .collect();
    if listed.is_empty() {
        let none = if summary.entries.is_empty() {
            "none inherited"
        } else {
            "nothing to review"
        };
        lines.push(style.marked(Mark::Pass, none));
    }
    for entry in listed {
        let mut tags = Vec::new();
        if entry.remote_linked {
            tags.push("remote-linked");
        }
        if entry.status == EntryStatus::Masked.as_str() {
            tags.push("masked");
        } else if entry.maskable {
            tags.push("maskable");
        }
        let tags = if tags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", tags.join(", "))
        };
        lines.push(style.marked(
            Mark::Bullet,
            format!("{} ({}){tags}", entry.name, entry.source),
        ));
    }

    let ignored = summary.count(EntryStatus::Ignored);
    if ignored > 0 {
        lines.push(style.marked(
            Mark::Info,
            format!(
                "{} of the desktop or distribution not listed (--json lists every entry)",
                count_noun(ignored, "component", "components")
            ),
        ));
    }
    let remote = summary
        .entries
        .iter()
        .filter(|entry| entry.remote_linked && entry.status == EntryStatus::Review.as_str())
        .count();
    if remote > 0 {
        let looks = if remote == 1 {
            "1 entry looks like a remote-linked client".to_string()
        } else {
            format!("{remote} entries look like remote-linked clients")
        };
        lines.push(style.marked(
            Mark::Warn,
            format!("{looks}; mask with [persona] mask_inherited"),
        ));
    }
    if !summary.unmatched_masks.is_empty() {
        let (matches, them) = if summary.unmatched_masks.len() == 1 {
            ("matches", "it")
        } else {
            ("match", "them")
        };
        lines.push(style.marked(
            Mark::Info,
            format!(
                "mask_inherited names {}, which {matches} no inherited autostart entry or user \
                 unit; activation masks {them} anyway",
                summary.unmatched_masks.join(", ")
            ),
        ));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_core::config::{PersonaConfig, PersonaMode};
    use nails_core::{InheritedSource, PersonaEntry, PersonaInventory};

    const PLAIN: Style = Style {
        color: false,
        ascii: true,
    };

    fn inventory() -> PersonaInventory {
        PersonaInventory {
            entries: vec![
                PersonaEntry::new("dropbox", InheritedSource::UserAutostart),
                PersonaEntry::new("backup", InheritedSource::UserAutostart),
                PersonaEntry::new("xdg-user-dirs", InheritedSource::GlobalAutostart),
                PersonaEntry::new("pipewire.socket", InheritedSource::GlobalUnit),
                PersonaEntry::new("alice", InheritedSource::Linger),
            ],
        }
    }

    fn persona(masks: &[&str]) -> PersonaConfig {
        PersonaConfig {
            mode: PersonaMode::SharedHome,
            mask_inherited: masks.iter().map(|name| name.to_string()).collect(),
        }
    }

    #[test]
    fn entries_carry_origin_and_status() {
        let summary = InheritedSummary::from_inventory(&inventory(), &persona(&["backup"]));
        assert!(summary.inspected);
        let by_name = |name: &str| {
            summary
                .entries
                .iter()
                .find(|entry| entry.name == name)
                .unwrap()
        };
        assert_eq!(
            (by_name("dropbox").origin, by_name("dropbox").status),
            ("added", "review")
        );
        assert_eq!(by_name("backup").status, "masked");
        assert_eq!(
            (
                by_name("xdg-user-dirs").origin,
                by_name("xdg-user-dirs").status
            ),
            ("desktop", "ignored")
        );
        assert!(!by_name("alice").maskable);
        assert_eq!(summary.remote_linked, vec!["dropbox".to_string()]);
    }

    #[test]
    fn the_listing_shows_what_needs_review_and_counts_the_rest() {
        let summary = InheritedSummary::from_inventory(&inventory(), &persona(&["backup"]));
        let lines = inherited_lines(&summary, "fresh-home", PLAIN);
        assert_eq!(
            lines,
            vec![
                "- dropbox (user-autostart)  [remote-linked, maskable]",
                "- backup (user-autostart)  [masked]",
                "- alice (linger)",
                "[INFO] 2 components of the desktop or distribution not listed (--json lists \
                 every entry)",
                "[WARN] 1 entry looks like a remote-linked client; mask with [persona] \
                 mask_inherited",
            ]
        );
    }

    #[test]
    fn masks_that_match_nothing_are_named() {
        let summary = InheritedSummary::from_inventory(
            &inventory(),
            &persona(&["dropbox", "dropbx", "ghost.service", "*"]),
        );
        assert_eq!(summary.unmatched_masks, vec!["dropbx", "ghost.service"]);
        let lines = inherited_lines(&summary, "fresh-home", PLAIN);
        assert_eq!(
            lines.last().unwrap(),
            "[INFO] mask_inherited names dropbx, ghost.service, which match no inherited \
             autostart entry or user unit; activation masks them anyway"
        );
        let one = InheritedSummary::from_inventory(&inventory(), &persona(&["ghost.service"]));
        assert_eq!(
            inherited_lines(&one, "fresh-home", PLAIN).last().unwrap(),
            "[INFO] mask_inherited names ghost.service, which matches no inherited autostart \
             entry or user unit; activation masks it anyway"
        );
    }

    #[test]
    fn shared_home_gets_its_own_line() {
        let summary = InheritedSummary::not_inspected();
        let lines = inherited_lines(&summary, "shared-home", PLAIN);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines[0].starts_with("[INFO] shared-home: the hidden session starts in the decoy home")
        );
        assert!(lines[1].contains("not inspected"));
        assert!(
            inherited_lines(&summary, "fresh-home", PLAIN)
                .iter()
                .all(|line| !line.contains("shared-home"))
        );
    }

    #[test]
    fn a_decoy_with_only_desktop_components_has_nothing_to_review() {
        let inventory = PersonaInventory {
            entries: vec![PersonaEntry::new(
                "gnome-keyring-ssh",
                InheritedSource::GlobalAutostart,
            )],
        };
        let summary = InheritedSummary::from_inventory(&inventory, &persona(&[]));
        let lines = inherited_lines(&summary, "fresh-home", PLAIN);
        assert_eq!(lines[0], "[PASS] nothing to review");
        assert!(lines[1].starts_with("[INFO] 1 component of the desktop"));

        let empty = InheritedSummary::from_inventory(&PersonaInventory::default(), &persona(&[]));
        assert_eq!(
            inherited_lines(&empty, "fresh-home", PLAIN),
            vec!["[PASS] none inherited"]
        );
    }
}
