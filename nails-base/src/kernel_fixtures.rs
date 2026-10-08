// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The captured kernel and systemd output in `tests/fixtures/kernel/` (see the
//! README there), for parser tests that must see what the kernel and the tools
//! really print. Test-only; never in a shipped binary.
//!
//! The `userns/` capture is committed and always present. The `vm/` capture is
//! taken as root in a NixOS test VM; until a VM run has produced it, [`vm`]
//! returns `None` and says so on stderr, and the tests that need it return
//! early. `scripts/capture-kernel-fixtures.sh` writes both.

use std::path::{Path, PathBuf};

/// The fixture root, `nails-base/tests/fixtures/kernel`.
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kernel")
}

/// A file of the unprivileged capture.
///
/// # Panics
///
/// When the file is missing: the `userns/` capture is committed.
pub fn userns(name: &str) -> String {
    let path = root().join("userns").join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read the captured fixture {}: {e}", path.display()))
}

/// A path inside the VM capture, or `None` (with the reason on stderr) when
/// no VM run has produced it yet.
pub fn vm_path(name: &str) -> Option<PathBuf> {
    let path = root().join("vm").join(name);
    if path.exists() {
        Some(path)
    } else {
        eprintln!(
            "the VM fixture {name} is not captured yet; the decoy-journal-leak VM test \
             produces it (tests/fixtures/kernel/README.md)"
        );
        None
    }
}

/// A file of the VM capture, or `None` when it is not captured yet.
pub fn vm(name: &str) -> Option<String> {
    let path = vm_path(name)?;
    Some(
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read the captured fixture {}: {e}", path.display())),
    )
}
