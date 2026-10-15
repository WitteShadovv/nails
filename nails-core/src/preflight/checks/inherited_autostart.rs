// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Inherited decoy persona state pre-flight check.
//!
//! Warns, never fails: it reports the decoy autostart entries, enabled user
//! services, lingering and autologin the hidden session would inherit that
//! need the operator's review. Components the installed desktop or
//! distribution ships are not reported unless their name is on the list of
//! known trace writers, and entries `[persona] mask_inherited` names count as
//! handled (see [`crate::persona::review`]). It runs in the shared registry, so
//! both `nails check` and the activation confirmation surface it; the full
//! entry-by-entry listing is shown separately by `nails check`.

use std::path::PathBuf;

use super::super::{CheckResult, PreFlightCheck};
use crate::config::{PersonaConfig, PersonaMode};
use crate::persona::{EntryStatus, InheritedSource, PersonaEntry, collect_inherited_persona};
use crate::{Filesystem, Result};

/// How many reviewed entries the message names before it counts the rest.
const NAMED_ENTRIES: usize = 6;

/// Reports the decoy persona state the hidden session would inherit.
#[derive(Debug, Clone, Default)]
pub struct InheritedAutostartCheck {
    /// The operator whose inherited state is inspected. `None` when the target
    /// user could not be resolved, in which case the check reports a Pass that
    /// says the inventory was skipped rather than erroring.
    operator: Option<Operator>,
}

/// The resolved operator context the inventory is collected for.
#[derive(Debug, Clone)]
struct Operator {
    home: PathBuf,
    user: String,
    persona: PersonaConfig,
}

impl InheritedAutostartCheck {
    /// Create a check for a resolved operator under the configured `[persona]`
    /// table: in fresh-home mode only system-level inherited state is reported,
    /// and the entries `mask_inherited` names count as handled.
    pub fn new(home: PathBuf, user: String, persona: PersonaConfig) -> Self {
        Self {
            operator: Some(Operator {
                home,
                user,
                persona,
            }),
        }
    }

    /// Create a check that reports Pass without inspecting anything, used when
    /// the target user could not be resolved.
    pub fn disabled() -> Self {
        Self { operator: None }
    }
}

/// `name (source[, remote-linked])`, as the message names an entry.
fn label(entry: &PersonaEntry) -> String {
    if entry.remote_linked {
        format!("{} ({}, remote-linked)", entry.name, entry.source.as_str())
    } else {
        format!("{} ({})", entry.name, entry.source.as_str())
    }
}

/// `count` with the noun in the number it needs: `1 item`, `3 items`.
fn count_noun(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("{count} {singular}")
    } else {
        format!("{count} {plural}")
    }
}

/// What the operator can do about the reviewed entries. Autologin is the
/// decoy's to keep: it is turned off for the hidden session only, as the
/// operator guide describes, and the inventory, which reads the decoy's
/// display-manager files, keeps listing it while the decoy has it.
fn remedies(review: &[&PersonaEntry]) -> String {
    let mut out = Vec::new();
    if review.iter().any(|entry| entry.source.is_maskable()) {
        out.push(
            "mask autostart entries and user units with [persona] mask_inherited in nails.toml"
                .to_string(),
        );
    }
    if review
        .iter()
        .any(|entry| entry.source == InheritedSource::Linger)
    {
        out.push("turn off lingering on the decoy".to_string());
    }
    if review
        .iter()
        .any(|entry| entry.source == InheritedSource::Autologin)
    {
        out.push(
            "turn autologin off for the hidden session only (operator guide: Inherited \
             autostart, services and autologin); autologin stays listed here while the decoy \
             keeps it"
                .to_string(),
        );
    }
    out.join("; ")
}

/// The entries that are not reported, as a clause, or empty when there are none.
fn not_counted(ignored: usize, masked: usize) -> String {
    let mut parts = Vec::new();
    if ignored > 0 {
        parts.push(format!(
            "{} not counted",
            count_noun(
                ignored,
                "desktop or distribution component",
                "desktop and distribution components"
            )
        ));
    }
    if masked > 0 {
        parts.push(format!("{masked} masked with [persona] mask_inherited"));
    }
    parts.join(", ")
}

impl<F: Filesystem> PreFlightCheck<F> for InheritedAutostartCheck {
    fn name(&self) -> &'static str {
        "inherited-autostart"
    }

    fn description(&self) -> &'static str {
        "Reports the decoy autostart, user services and autologin the hidden session would inherit"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let Some(operator) = self.operator.as_ref() else {
            return Ok(CheckResult::Pass(
                "Target user could not be resolved; inherited decoy state was not inspected".into(),
            ));
        };

        let persona = &operator.persona;
        let fresh_home = persona.mode == PersonaMode::FreshHome;
        let inventory = collect_inherited_persona(fs, &operator.home, &operator.user, fresh_home);

        if inventory.is_empty() {
            return Ok(CheckResult::Pass(
                "No decoy autostart entries, user services, lingering or autologin would be inherited".into(),
            ));
        }

        let review: Vec<&PersonaEntry> = inventory
            .with_status(persona, EntryStatus::Review)
            .collect();
        let others = not_counted(
            inventory.with_status(persona, EntryStatus::Ignored).count(),
            inventory.with_status(persona, EntryStatus::Masked).count(),
        );

        if review.is_empty() {
            return Ok(CheckResult::Pass(format!(
                "No inherited decoy item needs review ({others})"
            )));
        }

        let mut named: Vec<String> = review
            .iter()
            .copied()
            .take(NAMED_ENTRIES)
            .map(label)
            .collect();
        if review.len() > NAMED_ENTRIES {
            named.push(format!("and {} more", review.len() - NAMED_ENTRIES));
        }
        let mut message = format!(
            "Hidden session would inherit {} to review: {}. To keep {} out of the hidden \
             session, {}.",
            count_noun(review.len(), "decoy item", "decoy items"),
            named.join(", "),
            if review.len() == 1 { "it" } else { "them" },
            remedies(&review)
        );
        if !others.is_empty() {
            message.push_str(&format!(" ({others})"));
        }
        Ok(CheckResult::Warn(message))
    }
}

#[cfg(test)]
mod tests;
