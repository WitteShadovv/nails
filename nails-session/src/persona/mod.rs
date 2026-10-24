// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Persona inventory: the decoy state the hidden session inherits.
//!
//! This is the runtime collector that lists the decoy autostart entries, enabled
//! user units, lingering and display-manager autologin the hidden session would
//! inherit when it runs in the decoy home. It is distinct from the
//! [`config::persona`](crate::config::persona) table, which decides *how* the
//! hidden session relates to the decoy account; this module reports *what* that
//! choice would carry over, judges which of it needs the operator's review
//! ([`classify`], [`review`]), and provides the data the inherited-autostart
//! pre-flight check, `nails check` and the activation-time masking all consume.

mod autologin;
mod autostart;
pub mod classify;
pub mod inventory;
pub mod review;

pub use inventory::{
    InheritedSource, PersonaEntry, PersonaInventory, PersonaSource, collect_inherited_persona,
};
pub use review::{EntryStatus, MaskKind, MaskTarget};
