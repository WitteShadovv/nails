//! Keeping host submounts visible under overlaid targets.
//!
//! When a parent target is overlaid, any filesystem the host had mounted beneath
//! it is hidden. [`classify_submounts`](crate::filesystem) already sorts those
//! submounts into plans; this module enacts the two that need mounts of their own.
//!
//! The order is what makes it correct. A submount must be captured *before* the
//! parent overlay hides it: [`stage_submounts`](NailsManager::stage_submounts)
//! recursively binds each one to a path under the hidden root while it is still
//! reachable. After the parent overlay is mounted,
//! [`reattach_staged_submounts`](NailsManager::reattach_staged_submounts) either
//! binds the capture back over the overlay (read-only for a squashfs or ESP) or
//! gives a writable, decoy-backed partition its own nested overlay with upper/work
//! under the hidden root, so its writes never reach the decoy disk.
//!
//! Every mount is pushed onto the [`MountTracker`] (so a mid-activation failure
//! rolls it back) and appended to the caller's [`SubmountAttachment`] list (so
//! deactivation undoes it, in reverse, before the parent overlays come down). The
//! staging bind is recorded before the re-attach/nest, so the reverse teardown
//! takes a nested overlay off before the staging bind backing its lower layer.

use super::{MountInfo, MountTracker};
use crate::filesystem::Submount;
use crate::state::SubmountAttachment;
use crate::{Filesystem, NailsManager, Result};
use std::path::{Path, PathBuf};

/// Directory under the hidden root holding submount staging binds and the
/// upper/work trees of nested overlays.
const SUBMOUNT_BASE: &str = ".nails-submounts";

/// A submount captured to staging, awaiting re-attach or nesting once its parent
/// overlay is in place.
pub(super) struct StagedSubmount {
    mount_point: PathBuf,
    staging: PathBuf,
    plan: StagedPlan,
}

enum StagedPlan {
    /// Re-attach the capture over the overlay, read-only when `true`.
    Reattach { read_only: bool },
    /// Give the submount its own nested overlay (writable decoy-backed partition).
    NestedOverlay,
}

/// Encode a mount point into a single, collision-free path component.
///
/// `/` and `%` are percent-escaped so distinct mount points never map to the same
/// staging directory (`/var/log` and a literal `/var%2Flog` stay distinct).
fn encode_component(mount_point: &Path) -> String {
    let raw = mount_point.to_string_lossy();
    let trimmed = raw.trim_start_matches('/');
    let mut out = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '/' => out.push_str("%2F"),
            other => out.push(other),
        }
    }
    if out.is_empty() {
        out.push_str("root");
    }
    out
}

impl<F: Filesystem> NailsManager<F> {
    /// The hidden-root-relative staging directory for a submount.
    fn submount_staging_rel(mount_point: &Path) -> PathBuf {
        Path::new(SUBMOUNT_BASE)
            .join("staging")
            .join(encode_component(mount_point))
    }

    /// The hidden-root-relative upper and work directories for a nested overlay.
    fn submount_overlay_rel(mount_point: &Path) -> (PathBuf, PathBuf) {
        let base = Path::new(SUBMOUNT_BASE).join(encode_component(mount_point));
        (base.join("upper"), base.join("work"))
    }

    /// Stage every hidden submount under `target` before the parent overlay hides
    /// it.
    ///
    /// Best-effort: a submount that cannot be enumerated or staged is logged and
    /// skipped rather than failing activation, because the parent overlay still
    /// protects the tree (an un-staged submount is shadowed, so writes to its path
    /// land in the parent overlay's hidden upper, never on the decoy submount).
    /// Extra-lower binds are handled by the lower-layer computation and skipped
    /// here.
    pub(super) fn stage_submounts(
        &self,
        target: &Path,
        tracker: &mut MountTracker<F>,
        attachments: &mut Vec<SubmountAttachment>,
    ) -> Vec<StagedSubmount> {
        let submounts = match self.filesystem.find_submounts(target) {
            Ok(submounts) => submounts,
            Err(error) => {
                tracing::warn!(
                    target = %target.display(),
                    error = %error,
                    "Failed to enumerate submounts; none will be re-attached under {}",
                    target.display()
                );
                return Vec::new();
            }
        };

        let hidden_root = self.config.hidden_volume_root.clone();
        let mut staged = Vec::new();

        for submount in submounts {
            let plan = match &submount {
                Submount::ExtraLower { .. } => continue,
                Submount::Reattach { read_only, .. } => StagedPlan::Reattach {
                    read_only: *read_only,
                },
                Submount::NestedOverlay { .. } => StagedPlan::NestedOverlay,
            };
            let mount_point = submount.mount_point().to_path_buf();

            let staging_rel = Self::submount_staging_rel(&mount_point);
            if let Err(error) = self
                .filesystem
                .create_hidden_dir_all(&hidden_root, &staging_rel)
            {
                tracing::warn!(
                    mount_point = %mount_point.display(),
                    error = %error,
                    "Failed to create submount staging dir; leaving {} shadowed by the overlay",
                    mount_point.display()
                );
                continue;
            }
            let staging = hidden_root.join(&staging_rel);

            // Recursive bind captures the live submount while it is still reachable
            // (before the parent overlay mounts over it).
            if let Err(error) = self.filesystem.bind_mount(&mount_point, &staging) {
                tracing::warn!(
                    mount_point = %mount_point.display(),
                    staging = %staging.display(),
                    error = %error,
                    "Failed to stage submount; leaving {} shadowed by the overlay",
                    mount_point.display()
                );
                continue;
            }
            tracker.push_mount(MountInfo::bind(staging.clone()));
            attachments.push(SubmountAttachment::Bind {
                path: staging.clone(),
            });

            staged.push(StagedSubmount {
                mount_point,
                staging,
                plan,
            });
        }

        staged
    }

    /// Re-attach or nest each staged submount now that the parent overlay is
    /// mounted.
    ///
    /// Best-effort for the same reason as [`stage_submounts`](Self::stage_submounts):
    /// a submount that cannot be re-attached becomes an empty directory in the
    /// merged view (a visibility regression, logged), but its path still resolves
    /// into the parent overlay's hidden upper, so the decoy disk is never written.
    pub(super) fn reattach_staged_submounts(
        &self,
        staged: &[StagedSubmount],
        tracker: &mut MountTracker<F>,
        attachments: &mut Vec<SubmountAttachment>,
    ) {
        let hidden_root = self.config.hidden_volume_root.clone();

        for item in staged {
            match &item.plan {
                StagedPlan::Reattach { read_only } => {
                    if let Err(error) = self.filesystem.reattach_submount(
                        &item.staging,
                        &item.mount_point,
                        *read_only,
                    ) {
                        tracing::warn!(
                            mount_point = %item.mount_point.display(),
                            error = %error,
                            read_only = *read_only,
                            "Failed to re-attach submount over the overlay"
                        );
                        continue;
                    }
                    tracing::info!(
                        mount_point = %item.mount_point.display(),
                        read_only = *read_only,
                        "Re-attached submount over the overlay"
                    );
                    tracker.push_mount(MountInfo::bind(item.mount_point.clone()));
                    attachments.push(SubmountAttachment::Bind {
                        path: item.mount_point.clone(),
                    });
                }
                StagedPlan::NestedOverlay => {
                    let (upper_rel, work_rel) = Self::submount_overlay_rel(&item.mount_point);
                    if let Err(error) = self
                        .filesystem
                        .create_hidden_dir_all(&hidden_root, &upper_rel)
                        .and_then(|()| {
                            self.filesystem
                                .create_hidden_dir_all(&hidden_root, &work_rel)
                        })
                    {
                        tracing::warn!(
                            mount_point = %item.mount_point.display(),
                            error = %error,
                            "Failed to create nested-overlay dirs; leaving {} shadowed",
                            item.mount_point.display()
                        );
                        continue;
                    }
                    let upper = hidden_root.join(&upper_rel);
                    let work = hidden_root.join(&work_rel);

                    if let Err(error) = self.filesystem.mount_overlay(
                        &[item.staging.as_path()],
                        &upper,
                        &work,
                        &item.mount_point,
                    ) {
                        tracing::warn!(
                            mount_point = %item.mount_point.display(),
                            error = %error,
                            "Failed to mount nested overlay for writable submount"
                        );
                        continue;
                    }
                    tracing::info!(
                        mount_point = %item.mount_point.display(),
                        "Mounted nested overlay for writable submount (writes land on the hidden volume)"
                    );
                    tracker.push_mount(MountInfo::nested_overlay(item.mount_point.clone()));
                    attachments.push(SubmountAttachment::Overlay {
                        path: item.mount_point.clone(),
                    });
                }
            }
        }
    }

    /// Persist the submount attachments activation created, so deactivation and
    /// emergency teardown undo exactly those mounts. Appends to any already
    /// recorded (each target's submounts are recorded as its overlay is mounted).
    pub(super) fn record_submount_attachments(
        &self,
        attachments: &[SubmountAttachment],
    ) -> Result<()> {
        if attachments.is_empty() {
            return Ok(());
        }
        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file
                .submount_attachments
                .extend_from_slice(attachments);
            drop(cached);
            self.save_cached_state()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockFilesystem;
    use crate::config::Config;
    use crate::manager::NailsManager;

    fn manager_with_hidden_root(
        hidden_root: &str,
    ) -> (MockFilesystem, NailsManager<MockFilesystem>) {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(hidden_root, true);
        fs.mock_set_writable(hidden_root, true);
        // The mock's create_directory only descends through directories it already
        // knows are writable, so pre-create the submount base the real filesystem's
        // openat2 resolver would make on its own.
        let base = format!("{hidden_root}/{SUBMOUNT_BASE}");
        fs.mock_set_path_exists(&base, true);
        fs.mock_set_writable(&base, true);
        let config = Config {
            hidden_volume_root: PathBuf::from(hidden_root),
            ..Config::test_default()
        };
        let state_path = PathBuf::from(hidden_root).join("state.json");
        let manager = NailsManager::new(fs.clone(), config, state_path);
        (fs, manager)
    }

    #[test]
    fn ro_submount_is_staged_reattached_read_only_and_torn_down() {
        let (fs, manager) = manager_with_hidden_root("/mnt/hidden");
        fs.mock_set_path_exists("/snap/firefox/1234", true);
        fs.mock_set_submounts(
            Path::new("/snap"),
            vec![Submount::Reattach {
                mount_point: PathBuf::from("/snap/firefox/1234"),
                fstype: "squashfs".to_string(),
                read_only: true,
            }],
        );

        let mut tracker = MountTracker::new(manager.filesystem());
        let mut attachments = Vec::new();
        let staged = manager.stage_submounts(Path::new("/snap"), &mut tracker, &mut attachments);
        manager.reattach_staged_submounts(&staged, &mut tracker, &mut attachments);
        tracker.commit();

        // A read-only bind now sits at the snap path over the overlay.
        assert!(fs.mock_is_read_only_guarded(Path::new("/snap/firefox/1234")));
        // Two attachments: the staging bind, then the read-only re-attach.
        assert_eq!(attachments.len(), 2);
        assert!(matches!(
            attachments.last().unwrap(),
            SubmountAttachment::Bind { path } if path == Path::new("/snap/firefox/1234")
        ));

        manager.teardown_submount_attachments(&attachments);
        assert!(!fs.mock_is_read_only_guarded(Path::new("/snap/firefox/1234")));
    }

    #[test]
    fn writable_submount_gets_a_nested_overlay_under_the_hidden_root() {
        let (fs, manager) = manager_with_hidden_root("/mnt/hidden");
        fs.mock_set_path_exists("/var/log", true);
        fs.mock_set_submounts(
            Path::new("/var"),
            vec![Submount::NestedOverlay {
                mount_point: PathBuf::from("/var/log"),
                fstype: "ext4".to_string(),
            }],
        );

        let mut tracker = MountTracker::new(manager.filesystem());
        let mut attachments = Vec::new();
        let staged = manager.stage_submounts(Path::new("/var"), &mut tracker, &mut attachments);
        manager.reattach_staged_submounts(&staged, &mut tracker, &mut attachments);
        tracker.commit();

        // The writable partition is covered by a nested overlay at its mount point.
        assert!(
            fs.is_overlay_mounted(Path::new("/var/log")).unwrap(),
            "writable submount must get a nested overlay"
        );
        // Last attachment is the nested overlay; its upper/work live under the
        // hidden root.
        assert!(matches!(
            attachments.last().unwrap(),
            SubmountAttachment::Overlay { path } if path == Path::new("/var/log")
        ));

        manager.teardown_submount_attachments(&attachments);
        assert!(!fs.is_overlay_mounted(Path::new("/var/log")).unwrap());
    }

    #[test]
    fn extra_lower_submounts_are_not_staged() {
        let (fs, manager) = manager_with_hidden_root("/mnt/hidden");
        fs.mock_set_submounts(
            Path::new("/etc"),
            vec![Submount::ExtraLower {
                mount_point: PathBuf::from("/etc/nixos"),
                source: PathBuf::from("/persist/etc/nixos"),
            }],
        );

        let mut tracker = MountTracker::new(manager.filesystem());
        let mut attachments = Vec::new();
        let staged = manager.stage_submounts(Path::new("/etc"), &mut tracker, &mut attachments);
        tracker.commit();

        assert!(staged.is_empty(), "extra-lower binds are not staged here");
        assert!(attachments.is_empty());
    }

    #[test]
    fn encode_component_is_collision_free() {
        assert_eq!(encode_component(Path::new("/var/log")), "var%2Flog");
        assert_ne!(
            encode_component(Path::new("/var/log")),
            encode_component(Path::new("/var%2Flog")),
        );
        assert_eq!(encode_component(Path::new("/")), "root");
    }
}
