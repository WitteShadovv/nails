// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The `nails-gui` binary.
//!
//! A placeholder entry point while the graphical interface is built. It reports
//! the version and that the interface is not available yet, so the binary
//! exists and builds as part of the workspace. The toolkit it will use is not
//! chosen yet, so it draws no window and pulls in no toolkit.

fn main() {
    println!(
        "nails-gui {}: the graphical interface for running a nails session.",
        env!("CARGO_PKG_VERSION")
    );
    println!("The graphical interface is not built yet.");
}
