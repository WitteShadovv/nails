// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Read-only forensic readers shared by `verify --examiner` and `rehearse`.
//!
//! Everything here reads the way an examiner would and never writes: raw
//! devices and images are opened `O_RDONLY | O_NOATIME` and read with bounded
//! positioned reads ([`raw`]), trees are walked with `O_NOATIME` listings and
//! `lstat` ([`tree`]). Nothing mounts anything.

pub mod entropy;
pub mod layout;
pub mod raw;
pub mod scan;
pub mod tree;

pub use raw::{RawSource, SourceKind};
pub use scan::{Encoding, Hit, ScanOutcome, TokenScan};
