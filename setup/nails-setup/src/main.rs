// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `nails-setup` binary.
//!
//! A placeholder entry point while the guided create flow is built. It reports
//! the version and that the flow is not available yet, so the binary exists and
//! builds as part of the workspace.

fn main() {
    println!(
        "nails-setup {}: guided setup for a nails hidden volume.",
        env!("CARGO_PKG_VERSION")
    );
    println!("The guided create flow is not available in this build yet.");
}
