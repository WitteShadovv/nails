// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The pre-flight check that runs the residue catalog's probes. The registry
//! that holds it is assembled in `nails-core`; the framework is
//! `nails_base::preflight`.

pub mod residue_catalog;

pub use residue_catalog::ResidueCatalogCheck;
