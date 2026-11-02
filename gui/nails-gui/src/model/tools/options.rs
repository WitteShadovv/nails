// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Activation Options: how the checks and the activation the window runs
//! treat the hidden system, as the CLI's `check` and `activate` take it.
//!
//! **Use this computer's system** runs the decoy's own system in the hidden
//! session (`--overlay-only`); otherwise a **NixOS flake** can name the one
//! the hidden NixOS system is built from (`--nixos-flake`), instead of the
//! one the settings name. They hold for the window's checks and its
//! activation until it closes, and the session's page names them while they
//! are set. A flake reference the helper would refuse unread, which would end
//! the window's session, is never sent: the options keep it out until it
//! holds no control character.

use nails_api::protocol::{CheckArgs, Op, validate};

use super::{ToolKind, tool_page};
use crate::model::{Field, Page, Switch};
use crate::text;

/// The options the checks and the activation take.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// Run the decoy's own system (`--overlay-only`).
    pub overlay_only: bool,
    /// The flake, as typed (`--nixos-flake`); not with the decoy's own
    /// system.
    flake: String,
}

impl Options {
    /// The flake the options name: spaces around it dropped, none with the
    /// decoy's own system, and none the helper would refuse.
    #[must_use]
    pub fn flake(&self) -> Option<String> {
        let flake = self.flake.trim();
        if self.overlay_only || flake.is_empty() {
            return None;
        }
        let args = CheckArgs {
            nixos_flake: Some(flake.to_string()),
            ..CheckArgs::default()
        };
        validate(&Op::Check(args)).ok().map(|()| flake.to_string())
    }

    /// What the checks and the activation take from the options: this
    /// computer's system, and the flake.
    pub(crate) fn effective(&self) -> (bool, Option<String>) {
        (self.overlay_only, self.flake())
    }

    /// What the session's page says the options are, when any is set.
    #[must_use]
    pub fn summary(&self) -> Option<String> {
        if self.overlay_only {
            return Some(text::OPTION_OVERLAY_ONLY.to_string());
        }
        self.flake().map(|flake| text::option_flake(&flake))
    }

    /// The flake field changed to `typed`.
    pub(crate) fn edited(&mut self, typed: &str) {
        typed.clone_into(&mut self.flake);
    }

    /// The switch to this computer's system turned `on` or off.
    pub(crate) fn toggled(&mut self, on: bool) {
        self.overlay_only = on;
    }

    /// The page: the switch first, then the flake while it is off.
    pub(crate) fn page(&self) -> Page {
        let mut page = tool_page(ToolKind::Options, text::ACTIVATION_OPTIONS_WHAT);
        page.switch_first = true;
        page.switch = Some(Switch {
            title: text::SWITCH_OVERLAY_ONLY.to_string(),
            subtitle: text::OVERLAY_ONLY_WHAT.to_string(),
            on: self.overlay_only,
        });
        if !self.overlay_only {
            let typed = !self.flake.trim().is_empty();
            page.field = Some(Field {
                label: text::FIELD_FLAKE.to_string(),
                text: self.flake.clone(),
                hint: if typed && self.flake().is_none() {
                    text::FLAKE_NOT_A_REFERENCE
                } else {
                    text::FLAKE_HINT
                }
                .to_string(),
            });
        }
        page
    }
}
