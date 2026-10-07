// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Mount-table checks: leftover overlays, a still-mounted hidden root, and writable decoy OS trees.

use super::*;

impl<F: Filesystem> Verifier<F> {
    /// Flag every overlay mount whose `upperdir` sits under the configured hidden
    /// volume root, at any mount point.
    ///
    /// Reads `/proc/self/mountinfo` rather than probing a fixed list of mount
    /// points, so a leftover overlay at `/var`, `/nix`, `/srv` or anywhere else
    /// is caught, not only `/home`, `/etc` and `/root`. Attribution is by the
    /// overlay's upper layer: an overlay whose writable layer lives on the hidden
    /// volume is unambiguously one NAILS mounted, regardless of the mount point's
    /// name. Without a configured hidden root there is nothing to attribute, so
    /// this reports nothing (the config-path check still covers configured
    /// targets).
    pub(super) fn check_overlay_upperdirs(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let Some(hidden_root) = self.hidden_root() else {
            return Ok(findings);
        };

        let Ok(mountinfo) = self.filesystem.read_file_content(Path::new(SELF_MOUNTINFO)) else {
            return Ok(findings);
        };

        // The shared parser decodes the kernel's octal escapes in the mount
        // point and in the overlay options, so a hidden root whose path holds a
        // space, a comma or a backslash still matches its overlays' upper dirs.
        for entry in crate::filesystem::parse_mountinfo(&mountinfo) {
            if entry.fstype != "overlay" {
                continue;
            }
            let Some(upperdir) = crate::filesystem::parse_overlay_opts(&entry.super_opts).upperdir
            else {
                continue;
            };
            if !upperdir.starts_with(hidden_root) {
                continue;
            }
            findings.push(
                Finding::new(
                    Severity::Critical,
                    "mount",
                    format!(
                        "Leftover overlay at {} (upper layer {} on the hidden volume)",
                        entry.mount_point.display(),
                        upperdir.display()
                    ),
                )
                .with_fix_guidance("Run 'nails deactivate' to unmount overlays"),
            );
        }

        Ok(findings)
    }

    /// Flag the hidden volume root still being a live mount point while no hidden
    /// session is active.
    ///
    /// A mounted hidden root is expected while active, so this fires only when the
    /// recorded state is Inactive (or absent): overlays torn down, state reset,
    /// yet the backend still mounted — the signature of an emergency teardown that
    /// did not close the backend, which leaves the hidden filesystem readable and
    /// the master key in RAM. Reported Critical with the manual close guidance.
    /// Needs a configured hidden root to have a path to check.
    pub(super) fn check_hidden_root_mounted(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // A decoy-scoped baseline runs while the hidden volume is deliberately
        // attached for the activation about to start, so its mount is expected,
        // not residue; reporting it would make every pre-activation baseline cry
        // "critical" about the tool's own hidden root.
        if self.scope_to_decoy {
            return Ok(findings);
        }

        let Some(hidden_root) = self.hidden_root() else {
            return Ok(findings);
        };

        // Expected while active; only a non-active state makes a mounted root a
        // problem. An absent state file is treated as non-active (nothing claims
        // an active session).
        let active = self
            .state
            .as_ref()
            .is_some_and(|state| matches!(state.state, crate::state::SystemState::Active { .. }));
        if active {
            return Ok(findings);
        }

        if self.filesystem.is_mounted(hidden_root).unwrap_or(false) {
            findings.push(
                Finding::new(
                    Severity::Critical,
                    "mount",
                    format!("hidden root still mounted at {}", hidden_root.display()),
                )
                .with_fix_guidance(
                    "The hidden filesystem is still readable and its key is in RAM; \
                     unmount it and close the encrypted backend, or reboot",
                ),
            );
        }

        Ok(findings)
    }

    /// While a hidden session is active, flag any base-OS tree on the decoy that
    /// is mounted writable and is not an overlay.
    ///
    /// The read-only invariant ([`crate::platform::ro_guard`]) says the decoy's
    /// base-OS trees are either overlaid or kept read-only for the session. A
    /// writable, non-overlay mount of `/` or `/usr` (and the other core binary
    /// roots) backed by a real block device means hidden-session writes are
    /// reaching the decoy disk — the exact leak the invariant exists to prevent —
    /// so it is reported Critical. The walk reads `/proc/self/mountinfo` directly
    /// rather than trusting recorded state; it runs only in the active state,
    /// since a writable decoy root is expected when nothing is hidden.
    pub(super) fn check_writable_decoy_mounts(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let active = self
            .state
            .as_ref()
            .is_some_and(|state| matches!(state.state, crate::state::SystemState::Active { .. }));
        if !active {
            return Ok(findings);
        }

        let Ok(mountinfo) = self.filesystem.read_file_content(Path::new(SELF_MOUNTINFO)) else {
            return Ok(findings);
        };

        let hidden_root = self.hidden_root();

        for line in mountinfo.lines() {
            let Some((pre, post)) = line.split_once(" - ") else {
                continue;
            };
            let pre_fields: Vec<&str> = pre.split(' ').collect();
            // mountinfo pre fields: id parent maj:min root mountpoint options ...
            let (Some(mount_point), Some(options)) = (pre_fields.get(4), pre_fields.get(5)) else {
                continue;
            };
            let post_fields: Vec<&str> = post.split(' ').collect();
            // mountinfo post fields: fstype source superopts.
            let (Some(fstype), Some(source)) = (post_fields.first(), post_fields.get(1)) else {
                continue;
            };

            let mount_point = Path::new(mount_point);
            let is_os_tree = mount_point == Path::new("/")
                || OS_TREE_MOUNTS
                    .iter()
                    .any(|tree| mount_point == Path::new(tree));
            if !is_os_tree {
                continue;
            }
            // A tree that lives under the hidden volume is supposed to be writable.
            if let Some(root) = hidden_root
                && mount_point.starts_with(root)
            {
                continue;
            }
            let writable = options.split(',').any(|opt| opt == "rw");
            let is_overlay = *fstype == "overlay";
            let block_backed = source.starts_with("/dev/");
            if writable && !is_overlay && block_backed {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "mount",
                        format!(
                            "Writable non-overlay decoy mount at {} ({fstype} on {source}); \
                             hidden-session writes are reaching the decoy disk",
                            mount_point.display()
                        ),
                    )
                    .with_fix_guidance(
                        "The decoy OS tree must be overlaid or kept read-only while hidden is \
                         active; run 'nails deactivate' and re-activate",
                    ),
                );
            }
        }

        Ok(findings)
    }

    /// Scan the live mount table for NAILS overlays and staging binds left at a
    /// non-standard target.
    ///
    /// [`check_overlay_mounts`](Self::check_overlay_mounts) covers the expected
    /// `/home`, `/etc` and `/root` overlays. This catches everything else an
    /// incomplete teardown can leave behind: an ephemeral `/var`, `/tmp`,
    /// `/srv`, `/opt` or `/nix` overlay whose upper or work dir resolves under
    /// the runtime directory, a pivot staging bind, or — when a config pins the
    /// hidden volume — an overlay whose upper or work dir resolves under the
    /// hidden root. Such a mount at an unexpected target means scaffolding is
    /// still mounted, so it is reported Critical.
    ///
    /// The table is parsed from `/proc/self/mountinfo` through the shared parser
    /// ([`parse_mountinfo`](crate::filesystem::parse_mountinfo)) and classified
    /// by [`NailsMounts`](crate::filesystem::NailsMounts), so a fake table can be
    /// injected in tests. Only mounts positively attributable to NAILS are
    /// flagged: staging binds and runtime-backed ephemeral overlays are always
    /// NAILS, while a generic overlay is attributed only when a configured
    /// hidden root places its upper or work dir inside the hidden volume. This
    /// keeps a foreign overlay (a container or build sandbox) from being
    /// mistaken for a leftover when verify runs without a config.
    pub(super) fn check_nails_owned_mounts(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let Ok(content) = self.filesystem.read_file_content(Path::new(SELF_MOUNTINFO)) else {
            return Ok(findings);
        };

        let hidden_root = self
            .config
            .as_ref()
            .map(|config| config.hidden_volume_root.clone())
            .filter(|root| !root.as_os_str().is_empty());

        let entries = crate::filesystem::parse_mountinfo(&content);
        let owned = crate::filesystem::NailsMounts::from_entries(&entries, hidden_root.as_deref());

        // Staging binds and runtime-backed ephemeral overlays are unambiguously
        // NAILS and are not reported anywhere else, so this scan owns them. A
        // persistent overlay (upper/work under the configured hidden root) is
        // already reported by `check_overlay_upperdirs`, which runs first and
        // catches it at every mount point, so it is intentionally not repeated
        // here to avoid double-reporting the same mount.
        let mut suspects: Vec<std::path::PathBuf> = Vec::new();
        suspects.extend(owned.pivot_binds.iter().cloned());
        suspects.extend(owned.ephemeral_overlays.iter().cloned());

        let is_standard = |p: &Path| STANDARD_OVERLAY_TARGETS.iter().any(|t| p == Path::new(t));

        let mut seen: Vec<std::path::PathBuf> = Vec::new();
        for target in suspects {
            if is_standard(&target) || seen.contains(&target) {
                continue;
            }
            seen.push(target.clone());
            findings.push(
                Finding::new(
                    Severity::Critical,
                    "mount",
                    format!(
                        "NAILS overlay or staging mount left at non-standard target {}; \
                         teardown did not remove all scaffolding",
                        target.display()
                    ),
                )
                .with_fix_guidance(
                    "Run 'nails deactivate' (or 'nails emergency') to tear down leftover \
                     overlays, staging binds and the runtime directory",
                ),
            );
        }

        Ok(findings)
    }
}
