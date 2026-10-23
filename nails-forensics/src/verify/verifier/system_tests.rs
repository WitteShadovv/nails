// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the guidance a system finding carries.

use super::*;

/// The `runtime-copy-dir` leftover is an interrupted activation's RAM copy,
/// so its guidance is distinct from the bare fallback: it names the cause and
/// offers `nails recover` on the decoy as the proper undo, not only a
/// power-off. Dropping the arm would fall through to the generic `_` text,
/// which says neither, so these assertions pin the per-id guidance contract.
#[test]
fn runtime_copy_dir_guidance_names_recover_and_the_interrupted_activation() {
    let path = Path::new("/run/overlay-runtime/copy");
    let guidance = runtime_fix_guidance("runtime-copy-dir", path);

    // The cause, which only this arm states.
    assert!(
        guidance.contains("Leftover of an interrupted activation"),
        "names the interrupted-activation cause: {guidance}"
    );
    // The `recover` remedy this arm offers (via the rendered sudo line),
    // which the generic fallback and the other arms do not mention.
    assert!(
        guidance.contains(" recover"),
        "offers the recover command: {guidance}"
    );
    // Still names the leftover path to confirm after a power-off.
    assert!(
        guidance.contains("/run/overlay-runtime/copy"),
        "names the leftover path: {guidance}"
    );
    // It must not collapse to the generic fallback wording.
    assert_ne!(
        guidance,
        format!(
            "In RAM; power off (then confirm {} is gone)",
            path.display()
        ),
        "runtime-copy-dir gets its own guidance, not the fallback"
    );
}
