// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Real overlay and teardown behaviour against the kernel.
//!
//! These tests drive the overlay, bind and tmpfs mounts the session builds
//! against a real overlayfs. All but one run in the normal test run, each as
//! root of its own unprivileged user + mount namespace (`rootless`, built on
//! `nails_core::test_support::Rerun`), so every mount is private to the child
//! and vanishes with it, even after a panic. Each test still builds its own
//! tmpfs-backed root and tears it down in reverse order, so the teardown path
//! itself is exercised and asserted. `just kernel-tests` turns a host without
//! user namespaces from a skip into a failure.
//!
//! The whiteout and opaque-directory test needs `trusted.*` xattrs, which a
//! user namespace cannot set, so it alone stays `#[ignore]`d and runs as real
//! root in the privileged-mounts CI job:
//!
//! ```sh
//! cargo test -p nails-core --test privileged_mounts --no-run
//! sudo unshare --mount --propagation private <test-bin> --ignored --test-threads=1
//! ```

use nails_core::filesystem::{escape_overlay_path, parse_overlay_opts, read_mountinfo};
use nails_core::test_path;
use nails_core::test_support::Rerun;
use nix::errno::Errno;
use nix::mount::{MntFlags, MsFlags};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Run `body` as root of a fresh user + mount namespace (see
/// `nails_core::test_support`): every mount dies with the child, and a host
/// without user namespaces skips unless `NAILS_REQUIRE_USERNS=1`.
fn rootless(test: &str, body: impl FnOnce()) {
    let _ = Rerun::new(test).in_user_mount_ns().run(body);
}

/// The mount operations the tests drive, straight on the kernel.
struct Mounts;

impl Mounts {
    fn mount_tmpfs(&self, target: &Path, size: &str) -> nix::Result<()> {
        std::fs::create_dir_all(target).expect("create tmpfs mount point");
        nix::mount::mount(
            Some("tmpfs"),
            target,
            Some("tmpfs"),
            MsFlags::empty(),
            Some(format!("size={size}").as_str()),
        )
    }

    fn mount_overlay(
        &self,
        lowers: &[&Path],
        upper: &Path,
        work: &Path,
        target: &Path,
    ) -> nix::Result<()> {
        let esc = |p: &Path| escape_overlay_path(p).expect("escapable path");
        let lowerdir: Vec<String> = lowers.iter().map(|l| esc(l)).collect();
        let options = format!(
            "lowerdir={},upperdir={},workdir={}",
            lowerdir.join(":"),
            esc(upper),
            esc(work)
        );
        nix::mount::mount(
            Some("overlay"),
            target,
            Some("overlay"),
            MsFlags::empty(),
            Some(options.as_str()),
        )
    }

    fn bind_mount(&self, source: &Path, target: &Path) -> nix::Result<()> {
        nix::mount::mount(
            Some(source),
            target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
    }

    /// A plain unmount, or with `detach` a lazy one (`MNT_DETACH`): the two
    /// kinds NAILS makes. Neither adds `MNT_FORCE`, which only calls a
    /// filesystem's `umount_begin` (overlayfs and tmpfs have none) and, before
    /// Linux 6.15, needs `CAP_SYS_ADMIN` in the initial user namespace, which
    /// the root of this test's namespace lacks.
    fn unmount(&self, target: &Path, detach: bool) -> nix::Result<()> {
        let flags = if detach {
            MntFlags::MNT_DETACH
        } else {
            MntFlags::empty()
        };
        nix::mount::umount2(target, flags)
    }

    fn mount_at(&self, target: &Path) -> Option<String> {
        let canonical = target.canonicalize().ok()?;
        read_mountinfo()
            .expect("read mountinfo")
            .into_iter()
            .rev()
            .find(|e| e.mount_point == canonical)
            .map(|e| e.fstype)
    }

    fn is_mounted(&self, target: &Path) -> bool {
        self.mount_at(target).is_some()
    }

    fn is_overlay_mounted(&self, target: &Path) -> bool {
        self.mount_at(target).as_deref() == Some("overlay")
    }
}

/// A tmpfs-backed root for one test.
///
/// overlayfs needs its upper and work layers on a filesystem it supports as an
/// upper; a fresh tmpfs guarantees that regardless of what backs the host's
/// `TempDir`, and keeps the test self-contained inside the private namespace.
struct TmpfsRoot {
    _temp: TempDir,
    root: PathBuf,
}

impl TmpfsRoot {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("create temp dir");
        let root = temp.path().join("root");
        Mounts
            .mount_tmpfs(&root, "256M")
            .expect("mount tmpfs root (needs CAP_SYS_ADMIN)");
        Self { _temp: temp, root }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    /// Unmount the backing tmpfs. Called once a test's submounts are gone.
    fn teardown(&self) {
        Mounts
            .unmount(&self.root, false)
            .expect("unmount tmpfs root");
    }
}

fn mkdir(path: &Path) {
    std::fs::create_dir_all(path).expect("create directory");
}

fn write(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write file");
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read file")
}

/// A content fingerprint of a directory tree: relative path, kind, and bytes of
/// every entry in sorted order. Any change to the tree changes the fingerprint,
/// which is what lets a test assert the lower layer stayed byte-identical.
fn fingerprint(root: &Path) -> u64 {
    let mut entries: Vec<PathBuf> = Vec::new();
    collect(root, &mut entries);
    entries.sort();

    let mut hasher = DefaultHasher::new();
    for path in &entries {
        let rel = path.strip_prefix(root).expect("entry under root");
        rel.to_string_lossy().hash(&mut hasher);
        let meta = std::fs::symlink_metadata(path).expect("stat entry");
        if meta.is_dir() {
            "dir".hash(&mut hasher);
        } else if meta.file_type().is_symlink() {
            "symlink".hash(&mut hasher);
            std::fs::read_link(path)
                .expect("read symlink")
                .to_string_lossy()
                .hash(&mut hasher);
        } else {
            "file".hash(&mut hasher);
            std::fs::read(path).expect("read entry").hash(&mut hasher);
        }
    }
    hasher.finish()
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path).expect("stat");
        out.push(path.clone());
        if meta.is_dir() {
            collect(&path, out);
        }
    }
}

// ===========================================================================
// Overlay stack: mount, submounts, and reverse-order teardown
// ===========================================================================

#[test]
fn overlay_stack_mounts_and_tears_down_in_reverse_order() {
    rootless(
        test_path!(overlay_stack_mounts_and_tears_down_in_reverse_order),
        || {
            let fs = Mounts;
            let root = TmpfsRoot::new();

            let lower1 = root.path("lower1");
            let lower2 = root.path("lower2");
            let lower3 = root.path("lower3");
            let upper = root.path("upper");
            let work = root.path("work");
            let target = root.path("target");
            for dir in [&lower1, &lower2, &lower3, &upper, &work, &target] {
                mkdir(dir);
            }

            // Leftmost lower has priority: a.txt in lower1 shadows a.txt in lower2.
            write(&lower1.join("a.txt"), "one");
            write(&lower2.join("a.txt"), "shadowed");
            write(&lower2.join("b.txt"), "two");
            write(&lower3.join("c.txt"), "three");

            fs.mount_overlay(
                &[lower1.as_path(), lower2.as_path(), lower3.as_path()],
                &upper,
                &work,
                &target,
            )
            .expect("mount overlay with three lowers");
            assert!(fs.is_overlay_mounted(&target));

            assert_eq!(read(&target.join("a.txt")), "one", "leftmost lower wins");
            assert_eq!(read(&target.join("b.txt")), "two");
            assert_eq!(read(&target.join("c.txt")), "three");

            // Bind a source directory to a path inside the overlay.
            let bind_src = root.path("bind-src");
            mkdir(&bind_src);
            write(&bind_src.join("bound.txt"), "bound content");
            let bind_target = target.join("mnt");
            mkdir(&bind_target);
            fs.bind_mount(&bind_src, &bind_target)
                .expect("bind mount into overlay");
            assert!(fs.is_mounted(&bind_target));
            assert_eq!(read(&bind_target.join("bound.txt")), "bound content");

            // Mount a tmpfs at another path inside the overlay.
            let tmpfs_target = target.join("scratch");
            fs.mount_tmpfs(&tmpfs_target, "16M")
                .expect("tmpfs submount into overlay");
            assert!(fs.is_mounted(&tmpfs_target));
            write(&tmpfs_target.join("ram.txt"), "ephemeral");
            assert_eq!(read(&tmpfs_target.join("ram.txt")), "ephemeral");

            // Tear down in reverse order and assert each layer is gone.
            fs.unmount(&tmpfs_target, false)
                .expect("unmount tmpfs submount");
            assert!(!fs.is_mounted(&tmpfs_target));

            fs.unmount(&bind_target, false)
                .expect("unmount bind submount");
            assert!(!fs.is_mounted(&bind_target));

            fs.unmount(&target, false).expect("unmount overlay");
            assert!(!fs.is_overlay_mounted(&target));
            assert!(!fs.is_mounted(&target));

            root.teardown();
        },
    );
}

// ===========================================================================
// The moved real-overlay merged-view test (was filesystem/real/tests.rs)
// ===========================================================================

#[test]
fn real_overlay_mount_creates_merged_view() {
    rootless(test_path!(real_overlay_mount_creates_merged_view), || {
        let fs = Mounts;
        let root = TmpfsRoot::new();

        let lower = root.path("lower");
        let upper = root.path("upper");
        let work = root.path("work");
        let target = root.path("target");
        for dir in [&lower, &upper, &work, &target] {
            mkdir(dir);
        }

        write(&lower.join("from_lower.txt"), "content from lower layer");
        write(&upper.join("from_upper.txt"), "content from upper layer");

        fs.mount_overlay(&[lower.as_path()], &upper, &work, &target)
            .expect("overlay mount");

        // Both layers are visible in the merged view with their original content.
        assert_eq!(
            read(&target.join("from_lower.txt")),
            "content from lower layer"
        );
        assert_eq!(
            read(&target.join("from_upper.txt")),
            "content from upper layer"
        );

        fs.unmount(&target, false).expect("unmount overlay");
        root.teardown();
    });
}

// ===========================================================================
// Lower-tree byte-identical invariant
// ===========================================================================

#[test]
fn hidden_session_writes_never_touch_the_lower_tree() {
    rootless(
        test_path!(hidden_session_writes_never_touch_the_lower_tree),
        || {
            let fs = Mounts;
            let root = TmpfsRoot::new();

            let lower = root.path("lower");
            let upper = root.path("upper");
            let work = root.path("work");
            let target = root.path("target");
            for dir in [&lower, &upper, &work, &target] {
                mkdir(dir);
            }

            mkdir(&lower.join("sub"));
            write(&lower.join("keep.txt"), "keep");
            write(&lower.join("mod.txt"), "original");
            write(&lower.join("del.txt"), "delete me");
            write(&lower.join("sub/nested.txt"), "nested");

            let before = fingerprint(&lower);

            fs.mount_overlay(&[lower.as_path()], &upper, &work, &target)
                .expect("overlay mount");

            // Create, modify, and delete through the overlay: everything lands in upper.
            write(&target.join("newfile.txt"), "created in session");
            write(&target.join("mod.txt"), "changed in session");
            std::fs::remove_file(target.join("del.txt")).expect("delete through overlay");

            assert_eq!(read(&target.join("mod.txt")), "changed in session");
            assert!(
                !target.join("del.txt").exists(),
                "delete hidden in merged view"
            );
            assert_eq!(read(&target.join("newfile.txt")), "created in session");

            fs.unmount(&target, false).expect("unmount overlay");

            let after = fingerprint(&lower);
            assert_eq!(
                before, after,
                "the lower tree must be byte-identical after a hidden session"
            );
            // Spot-check the raw lower files directly, not just the fingerprint.
            assert_eq!(read(&lower.join("mod.txt")), "original");
            assert_eq!(read(&lower.join("del.txt")), "delete me");
            assert!(!lower.join("newfile.txt").exists());

            root.teardown();
        },
    );
}

/// Negative control: the fingerprint must notice a write into the lower tree, so
/// the invariant test above cannot pass vacuously. This is the deliberate
/// mutation that proves the check has teeth.
#[test]
fn fingerprint_detects_a_write_redirected_into_the_lower_tree() {
    rootless(
        test_path!(fingerprint_detects_a_write_redirected_into_the_lower_tree),
        || {
            let root = TmpfsRoot::new();
            let lower = root.path("lower");
            mkdir(&lower);
            write(&lower.join("keep.txt"), "keep");

            let before = fingerprint(&lower);

            // Simulate the failure mode the invariant guards against: a write that
            // reaches the lower layer instead of the upper.
            write(
                &lower.join("leaked.txt"),
                "this must never reach the lower layer",
            );

            let after = fingerprint(&lower);
            assert_ne!(
                before, after,
                "a write into the lower tree must change its fingerprint"
            );

            root.teardown();
        },
    );
}

// ===========================================================================
// Mountinfo parsing of paths with spaces, tabs, and backslashes
// ===========================================================================

#[test]
fn mountinfo_decodes_overlay_target_with_space_tab_and_backslash() {
    rootless(
        test_path!(mountinfo_decodes_overlay_target_with_space_tab_and_backslash),
        || {
            let fs = Mounts;
            let root = TmpfsRoot::new();

            let lower = root.path("lower");
            let upper = root.path("upper");
            let work = root.path("work");
            // The mount point carries a space, a tab, and a backslash: exactly the bytes
            // the kernel octal-escapes in mountinfo and the parser must decode.
            let target = root.path("weird dir\twith\\chars");
            for dir in [&lower, &upper, &work, &target] {
                mkdir(dir);
            }
            write(&lower.join("probe.txt"), "probe");

            fs.mount_overlay(&[lower.as_path()], &upper, &work, &target)
                .expect("overlay mount at escaped path");

            let canonical = target.canonicalize().expect("canonicalize escaped target");
            let entries = read_mountinfo().expect("read mountinfo");
            let entry = entries
                .iter()
                .find(|e| e.fstype == "overlay" && e.mount_point == canonical)
                .expect("overlay entry found with decoded special-character mount point");

            // The parser round-trips the space, tab, and backslash back to the real path.
            assert_eq!(entry.mount_point, canonical);

            // The overlay option string decodes to the layers we asked for.
            let opts = parse_overlay_opts(&entry.super_opts);
            assert_eq!(opts.lowerdir, vec![lower.clone()]);
            assert_eq!(opts.upperdir.as_deref(), Some(upper.as_path()));
            assert_eq!(opts.workdir.as_deref(), Some(work.as_path()));

            fs.unmount(&target, false).expect("unmount overlay");
            root.teardown();
        },
    );
}

// ===========================================================================
// A busy overlay is detached lazily (MNT_DETACH)
// ===========================================================================

#[test]
fn lazy_unmount_detaches_overlay_with_an_open_fd() {
    rootless(
        test_path!(lazy_unmount_detaches_overlay_with_an_open_fd),
        || {
            let fs = Mounts;
            let root = TmpfsRoot::new();

            let lower = root.path("lower");
            let upper = root.path("upper");
            let work = root.path("work");
            let target = root.path("target");
            for dir in [&lower, &upper, &work, &target] {
                mkdir(dir);
            }
            write(&lower.join("seed.txt"), "seed");

            fs.mount_overlay(&[lower.as_path()], &upper, &work, &target)
                .expect("overlay mount");

            // Hold an open fd under the mount so a plain unmount is refused with EBUSY.
            let busy = target.join("busy.txt");
            write(&busy, "hold me");
            let mut held = std::fs::File::open(&busy).expect("open fd under mount");

            match fs.unmount(&target, false) {
                Err(Errno::EBUSY) => {}
                other => panic!("expected EBUSY with an open fd, got {other:?}"),
            }

            // A lazy unmount, the session's fallback for a busy mount, detaches
            // it despite the fd.
            fs.unmount(&target, true).expect("lazy unmount");
            assert!(
                !fs.is_overlay_mounted(&target),
                "overlay detached from the namespace after MNT_DETACH"
            );

            // The detached superblock stays alive for the open fd: it still reads.
            let mut contents = String::new();
            held.read_to_string(&mut contents).expect("read held fd");
            assert_eq!(contents, "hold me");
            drop(held);

            root.teardown();
        },
    );
}

// ===========================================================================
// Opaque directory and whiteout semantics
// ===========================================================================

#[test]
#[ignore = "root only: directory whiteouts need trusted.* xattrs"]
fn whiteout_and_opaque_hide_lower_entries_without_deleting_them() {
    let fs = Mounts;
    let root = TmpfsRoot::new();

    let lower = root.path("lower");
    let upper = root.path("upper");
    let work = root.path("work");
    let target = root.path("target");
    for dir in [&lower, &upper, &work, &target] {
        mkdir(dir);
    }

    write(&lower.join("visible.txt"), "from lower");
    mkdir(&lower.join("shadowed"));
    write(&lower.join("shadowed/inner.txt"), "lower inner");

    fs.mount_overlay(&[lower.as_path()], &upper, &work, &target)
        .expect("overlay mount");

    // Whiteout: deleting a lower-only file hides it in the merged view while the
    // real file survives on the lower layer.
    std::fs::remove_file(target.join("visible.txt")).expect("whiteout lower file");
    assert!(
        !target.join("visible.txt").exists(),
        "whiteout hides the file"
    );
    assert!(
        lower.join("visible.txt").exists(),
        "lower copy survives the whiteout"
    );

    // Opaque directory: removing and recreating a lower-backed directory makes it
    // opaque, so the lower directory's contents no longer show through.
    std::fs::remove_dir_all(target.join("shadowed")).expect("remove lower-backed dir");
    mkdir(&target.join("shadowed"));
    write(&target.join("shadowed/fresh.txt"), "fresh");
    assert!(
        !target.join("shadowed/inner.txt").exists(),
        "opaque dir hides lower contents"
    );
    assert_eq!(read(&target.join("shadowed/fresh.txt")), "fresh");
    assert!(
        lower.join("shadowed/inner.txt").exists(),
        "lower directory contents survive the opaque overlay"
    );

    fs.unmount(&target, false).expect("unmount overlay");

    // The whole lower tree is intact after the session.
    assert_eq!(read(&lower.join("visible.txt")), "from lower");
    assert_eq!(read(&lower.join("shadowed/inner.txt")), "lower inner");

    root.teardown();
}
