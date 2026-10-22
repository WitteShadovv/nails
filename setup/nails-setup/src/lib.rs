// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `nails-setup` prepares the hidden storage a NAILS session uses, guiding the
//! operator from an empty disk to a working hidden volume without their having
//! to read the threat model first.
//!
//! The guided create flow is not implemented yet. This crate is the initial
//! scaffold: the shared building blocks the flow will use, starting with the
//! vendored word list the passphrase helper draws from.

pub mod wordlist;
