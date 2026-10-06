// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The per-activation runtime scaffolding root.
//!
//! Every volatile scaffold an activation needs — pivot staging mount points, the
//! vfat snapshot tmpfs, and the read-only pre-overlay `/nix/store` bind the
//! command cache resolves against — lives under one tmpfs created per activation
//! at a **random, non-derivable** path directly under `/run`.
//!
//! The earlier design used two fixed names, `/run/nails` and `/run/nails-pivot`.
//! Both were recognizable: anyone who knew the tool knew exactly where to look
//! while a session ran, and state-independent teardown keyed on those literals.
//! A random child directory removes the recognizable name while keeping the two
//! properties that matter:
//!
//! - It sits on `/run`, a tmpfs that is always overlay-excluded and volatile, so
//!   the scaffolding never reaches the decoy disk and is gone on power-off.
//! - Its path is recorded in the state file and pushed onto the mount tracker,
//!   so a trusted teardown unmounts and removes exactly the tree it created, and
//!   a state-independent emergency teardown still finds it structurally (the
//!   overlays, binds and tmpfs it hosts all resolve back to it in the live mount
//!   table — see [`crate::filesystem::mountinfo`]).
//!
//! The tmpfs is mounted `mode=0700,nosuid,nodev`. The umbrella provides only the
//! volatile *mount points* for the overlays, binds and the sized snapshot tmpfs
//! stacked inside it; it holds no bulk data of its own, so its own cap is small.

use std::path::{Path, PathBuf};

/// Parent directory of the per-activation runtime root.
///
/// `/run` is a tmpfs on every systemd host and is unconditionally excluded from
/// overlays (see `config::dynamic`), so a directory created here is volatile and
/// never lands on the persistent decoy filesystem.
pub(crate) const RUNTIME_PARENT: &str = "/run";

/// Bytes of randomness in a runtime-root name. Hex-encoded, so the directory
/// name is twice this many characters. Eight bytes (64 bits) makes the name
/// impossible to guess or derive and collision-free in practice.
const RANDOM_NAME_BYTES: usize = 8;

/// Size cap for the umbrella tmpfs.
///
/// The umbrella only hosts mount points (overlay staging dirs, the store-bind
/// dir) and, as a stacked child mount, the separately-sized vfat snapshot tmpfs.
/// It stores no bulk data itself, so a small cap is ample while still bounding
/// any accidental write into a bare staging directory before its overlay lands.
pub(crate) const UMBRELLA_TMPFS_SIZE: &str = "16M";

/// Generate a fresh, non-derivable runtime-root path under `/run`.
///
/// The name is the lowercase hex encoding of [`RANDOM_NAME_BYTES`] bytes read
/// from the kernel CSPRNG (`/dev/urandom`). If that read fails for any reason,
/// it falls back to mixing the process id with the current time — far weaker,
/// but a last resort that still yields a usable, non-fixed path rather than
/// aborting activation. The returned path is only *computed* here; mounting the
/// tmpfs and recording the path are the caller's job.
pub(crate) fn random_runtime_root() -> PathBuf {
    Path::new(RUNTIME_PARENT).join(random_name())
}

/// The directory, inside `root`, that holds the read-only pre-overlay
/// `/nix/store` bind the command cache resolves systemctl/nix against.
pub(crate) fn store_bind_source(root: &Path) -> PathBuf {
    root.join("original-nix-store")
}

fn random_name() -> String {
    let mut bytes = [0u8; RANDOM_NAME_BYTES];
    if read_urandom(&mut bytes).is_ok() {
        return hex::encode(bytes);
    }

    // Fallback: no CSPRNG available. Mix the pid and the wall clock so the name
    // is still non-fixed per invocation. This is not cryptographically strong,
    // but a recognizable constant would be worse, and a failed activation worse
    // still.
    let pid = std::process::id() as u64;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    hex::encode((pid ^ nanos.rotate_left(17)).to_le_bytes())
}

fn read_urandom(buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_runtime_root_is_under_run() {
        let root = random_runtime_root();
        assert_eq!(root.parent(), Some(Path::new("/run")));
    }

    #[test]
    fn random_runtime_root_name_is_neutral_lowercase_hex() {
        let root = random_runtime_root();
        let name = root.file_name().unwrap().to_string_lossy();
        // A neutral name: only lowercase hex, never the tool's name or any other
        // recognizable token.
        assert!(
            name.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "name should be lowercase hex: {name}"
        );
        assert!(
            !name.contains("nails"),
            "the runtime root must not be recognizable by name: {name}"
        );
        assert_eq!(name.len(), RANDOM_NAME_BYTES * 2);
    }

    #[test]
    fn random_runtime_root_differs_between_activations() {
        // Two activations must not share a derivable path. With 64 bits of
        // entropy a collision is astronomically unlikely; this guards against a
        // constant having been reintroduced.
        let a = random_runtime_root();
        let b = random_runtime_root();
        assert_ne!(a, b, "each activation must get a fresh runtime root");
    }

    #[test]
    fn store_bind_source_is_inside_the_root() {
        let root = PathBuf::from("/run/deadbeefdeadbeef");
        let bind = store_bind_source(&root);
        assert!(bind.starts_with(&root));
        assert_eq!(
            bind,
            PathBuf::from("/run/deadbeefdeadbeef/original-nix-store")
        );
    }
}
