// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Real overlay and teardown behaviour against the kernel.
//!
//! These tests drive the overlay, bind and tmpfs mounts the session builds
//! against a real overlayfs. All but four run in the normal test run, each as
//! root of its own unprivileged user + mount namespace (`rootless`, built on
//! `nails_core::test_support::Rerun`), so every mount is private to the child
//! and vanishes with it, even after a panic. Each test still builds its own
//! tmpfs-backed root and tears it down in reverse order, so the teardown path
//! itself is exercised and asserted. `just kernel-tests` turns a host without
//! user namespaces from a skip into a failure.
//!
//! Three tests need `trusted.*` xattrs, which a user namespace cannot set,
//! and one binds a loop device, which only root of the initial namespace may,
//! so they alone stay `#[ignore]`d and run as real root in the
//! privileged-mounts CI job: the whiteout and opaque-directory test, the test
//! of the `kernel-modules` check against the kernel's own whiteouts and opaque
//! directories, the test of the whole upper-filesystem probe, and the test of
//! the loop driver's record of the file behind a loop device:
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
    /// filesystem's `umount_begin` (overlayfs and tmpfs have none) and, on a
    /// kernel without Linux 6.15's change to its permission check (older
    /// stable kernels may carry it), needs `CAP_SYS_ADMIN` in the initial user
    /// namespace, which the root of this test's namespace lacks.
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

/// What a kernel update in a hidden session leaves in the upper, made by the
/// kernel through the root overlay a real entry mounts, with the `trusted.*`
/// opaque markers only real root can write, read the way the `kernel-modules`
/// pre-flight check reads it: the release deleted, made again without its
/// index and with it, and the whole module directory made again without the
/// release. Without `CAP_SYS_ADMIN` the kernel reports every marker missing,
/// and the check says it cannot tell rather than passing.
#[test]
#[ignore = "root only: opaque directories need trusted.* xattrs"]
fn the_kernel_modules_check_reads_the_kernels_own_whiteouts_and_opaque_directories() {
    use nails_core::session::kernel_modules::{
        Doubt, Held, Hiding, KernelModulesCheck, Opacity, Step, TrustedXattrs, Verdict, judge,
        read_decoy, read_upper,
    };
    use rustix::thread::{CapabilitySet, capabilities, set_capabilities};
    use std::ffi::OsStr;

    let root = TmpfsRoot::new();
    let decoy = root.path("decoy");
    let upper = root.path("hidden/upper");
    let work = root.path("hidden/work");
    let next = root.path("next");
    for dir in [&upper, &work, &next] {
        mkdir(dir);
    }
    let release = OsStr::new("6.17.1-arch1-1");
    let tree = Path::new("usr/lib/modules").join(release);
    mkdir(&decoy.join(&tree).join("kernel/fs"));
    write(&decoy.join(&tree).join("kernel/fs/ext4.ko"), "module");
    write(
        &decoy.join(&tree).join("modules.dep"),
        "kernel/fs/ext4.ko:\n",
    );
    let before = fingerprint(&decoy);
    assert_eq!(TrustedXattrs::of_this_process(), TrustedXattrs::Visible);
    let verdict = || {
        judge(
            &read_decoy(&decoy, release),
            &read_upper(&upper, release, TrustedXattrs::Visible),
        )
    };
    let hidden = |at, how| Verdict::Hidden { at, how };

    nails_teardown::whole_root::nextroot::overlay_over(
        &decoy,
        &root.path("lower"),
        &upper,
        &work,
        &next,
    )
    .expect("the root overlay");
    assert_eq!(verdict(), Verdict::Intact);

    // A kernel update deletes the release's files, then its directory.
    std::fs::remove_dir_all(next.join(&tree)).expect("delete the release");
    assert_eq!(verdict(), hidden(Step::Release, Hiding::Deleted));

    // Installed again, the release directory is new and opaque.
    mkdir(&next.join(&tree).join("kernel"));
    assert_eq!(verdict(), hidden(Step::Release, Hiding::CopyWithoutIndex));
    write(
        &next.join(&tree).join("modules.dep"),
        "kernel/fs/ext4.ko:\n",
    );
    assert_eq!(verdict(), hidden(Step::Release, Hiding::OwnCopy));

    // The whole module directory deleted, then made again for another
    // kernel only.
    std::fs::remove_dir_all(next.join("usr/lib/modules")).expect("delete the modules");
    mkdir(&next.join("usr/lib/modules/6.18.0-arch1-1"));
    assert_eq!(verdict(), hidden(Step::ModuleDir, Hiding::Covered));

    Mounts
        .unmount(&next, false)
        .expect("unmount the root overlay");
    assert_eq!(fingerprint(&decoy), before, "the decoy changed");

    // Capabilities are per thread: drop CAP_SYS_ADMIN from this test's
    // thread alone, and take it back before the teardown needs it.
    let sets = capabilities(None).expect("read the capabilities");
    let mut without_admin = sets;
    without_admin.effective.remove(CapabilitySet::SYS_ADMIN);
    set_capabilities(None, without_admin).expect("drop CAP_SYS_ADMIN");
    let invisible = TrustedXattrs::of_this_process();
    let held = read_upper(&upper, release, TrustedXattrs::Invisible);
    let check = KernelModulesCheck::new(decoy.clone(), upper.clone(), release.to_os_string());
    let unprivileged = check.result(invisible);
    set_capabilities(None, sets).expect("take CAP_SYS_ADMIN back");

    assert_eq!(invisible, TrustedXattrs::Invisible);
    assert_eq!(
        held[2],
        Held::Dir(Opacity::Unknown(Doubt::NeedsRoot)),
        "the opaque module directory reads as a doubt: {held:?}"
    );
    assert!(unprivileged.is_warn(), "{unprivileged:?}");
    assert!(
        unprivileged.message().contains("only root can see"),
        "{unprivileged:?}"
    );
    let privileged = check.result(TrustedXattrs::of_this_process());
    assert!(
        privileged
            .message()
            .contains("with a new directory without /usr/lib/modules/6.17.1-arch1-1"),
        "{privileged:?}"
    );
    // The new module directory hides every kernel's tree, so the fix is its
    // discard alone, never a kernel update.
    assert!(
        privileged.message().ends_with(
            "A kernel update on the decoy would not bring its modules back, since the change \
             hides them for every kernel."
        ),
        "{privileged:?}"
    );

    root.teardown();
}

// ===========================================================================
// The upper-filesystem capability probe, whole, as `check` runs it
// ===========================================================================

/// The `upper-fs-capability` check against a real hidden root, as root: every
/// step of the probe runs (the `trusted.*` xattr included), it passes, and it
/// leaves nothing. Its trial overlay is mounted detached, so the mount table
/// neither lists it nor signals a change at any point, the event systemd
/// waits for (a `POLLPRI` on `/proc/self/mountinfo`) to record a mount unit.
#[test]
#[ignore = "root only: the probe sets a trusted.* xattr"]
fn the_upper_fs_probe_as_root_passes_and_leaves_nothing() {
    use nails_core::preflight::{PreFlightCheck, UpperFsCapabilityCheck};
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use std::os::fd::AsFd;

    let root = TmpfsRoot::new();
    let table = std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
    let watched = std::fs::File::open("/proc/self/mountinfo").expect("open mountinfo");

    let result = UpperFsCapabilityCheck::new(root.root.clone())
        .run(&nails_core::RealFilesystem)
        .expect("the check runs");
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        result.message(),
        format!(
            "Hidden root at {} can host an overlayfs upper layer",
            root.root.display()
        )
    );

    let mut fds = [PollFd::new(watched.as_fd(), PollFlags::POLLPRI)];
    poll(&mut fds, PollTimeout::ZERO).expect("poll mountinfo");
    let signalled = fds[0]
        .revents()
        .is_some_and(|r| r.intersects(PollFlags::POLLPRI | PollFlags::POLLERR));
    assert!(!signalled, "the probe changed the mount table");
    assert_eq!(
        std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo"),
        table
    );
    let left: Vec<_> = std::fs::read_dir(&root.root)
        .expect("read the hidden root")
        .collect();
    assert!(left.is_empty(), "the probe left {left:?}");

    root.teardown();
}

// ===========================================================================
// The loop driver's record of the file behind a loop device
// ===========================================================================

/// `LOOP_CTL_GET_FREE`, `LOOP_SET_FD` and `LOOP_CLR_FD` from `<linux/loop.h>`.
const LOOP_CTL_GET_FREE: u32 = 0x4C82;
const LOOP_SET_FD: u32 = 0x4C00;
const LOOP_CLR_FD: u32 = 0x4C01;

/// A loop device bound to a file, unbound again when dropped.
struct LoopDevice {
    /// Its node, `/dev/loop<N>`.
    node: PathBuf,
    /// Its device number, as the mount table writes it (`7:<minor>`).
    dev: String,
    device: Option<std::fs::File>,
}

impl LoopDevice {
    /// Bind a free loop device to `file`, read-write.
    #[allow(unsafe_code)]
    fn attach(file: &Path) -> Self {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let control = std::fs::File::open("/dev/loop-control").expect("open /dev/loop-control");
        let backing = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(file)
            .expect("open the image file");
        // Another program can take the free device between the two calls:
        // then ask for another.
        for _ in 0..10 {
            // SAFETY: LOOP_CTL_GET_FREE takes no argument and returns the
            // number of a free loop device, or -1.
            let number = unsafe { nix::libc::ioctl(control.as_raw_fd(), LOOP_CTL_GET_FREE as _) };
            assert!(
                number >= 0,
                "LOOP_CTL_GET_FREE: {}",
                std::io::Error::last_os_error()
            );
            let node = PathBuf::from(format!("/dev/loop{number}"));
            let device = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&node)
                .expect("open the loop device");
            // SAFETY: LOOP_SET_FD takes the descriptor of the backing file as
            // its argument, by value; `backing` keeps it open for the call.
            let bound = unsafe {
                nix::libc::ioctl(device.as_raw_fd(), LOOP_SET_FD as _, backing.as_raw_fd())
            };
            if bound == 0 {
                let rdev = device.metadata().expect("stat the loop device").rdev();
                let dev = format!("{}:{}", rustix::fs::major(rdev), rustix::fs::minor(rdev));
                return Self {
                    node,
                    dev,
                    device: Some(device),
                };
            }
            let error = std::io::Error::last_os_error();
            assert_eq!(
                error.raw_os_error(),
                Some(nix::libc::EBUSY),
                "LOOP_SET_FD: {error}"
            );
        }
        panic!("no free loop device");
    }
}

impl Drop for LoopDevice {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        if let Some(device) = self.device.take() {
            // SAFETY: LOOP_CLR_FD takes no argument.
            unsafe { nix::libc::ioctl(device.as_raw_fd(), LOOP_CLR_FD as _) };
        }
        // The driver lets go of the file at the device's last close, which
        // can be that of a probe udev runs on it: wait for that, so that the
        // file's filesystem unmounts.
        for _ in 0..300 {
            if nails_teardown::loop_device::record(&self.node).is_err() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

/// The loop driver's record, read through a real loop device: it names the
/// filesystem that holds the device's backing file by the number the mount
/// table shows for that filesystem. A filesystem on the loop device is told
/// by the device's own number, and one that shows an anonymous number, as
/// btrfs does, by its source, the device's node. So a session whose hidden
/// volume holds the file counts that filesystem, mounted below the hidden
/// root, as its own storage, and nothing else. The mount table lines are the
/// test's own, for the filesystems the device could hold: the driver's
/// record is what is read.
#[test]
#[ignore = "root only: binding a loop device needs CAP_SYS_ADMIN in the initial namespace"]
fn the_loop_driver_names_the_filesystem_that_holds_a_loop_device_s_file() {
    use nails_teardown::loop_device::backing_filesystem;
    use nails_teardown::mountinfo::{parse_mountinfo, read_mountinfo, top_mount_at};
    use nails_teardown::whole_root::plan::{PLAN_VERSION, Plan};

    // The tmpfs stands in for the hidden volume, with an image file on it.
    let root = TmpfsRoot::new();
    let at = root.root.canonicalize().expect("canonical tmpfs root");
    let table = read_mountinfo().expect("read mountinfo");
    let volume = top_mount_at(&table, &at).expect("the tmpfs").dev.clone();
    let image = root.path("disk.img");
    std::fs::File::create(&image)
        .and_then(|file| file.set_len(1 << 20))
        .expect("create the image file");
    let device = LoopDevice::attach(&image);

    let mounts = parse_mountinfo(&format!(
        "1 0 {dev} / {at}/vm rw - ext4 {node} rw\n\
         2 0 0:999 / {at}/pool rw - btrfs {node} rw\n\
         3 0 0:998 / {at}/ram rw - tmpfs tmpfs rw\n\
         4 0 {dev} / /media/vm rw - ext4 {node} rw\n",
        dev = device.dev,
        node = device.node.display(),
        at = at.display(),
    ));
    let holders: Vec<Option<String>> = mounts.iter().map(backing_filesystem).collect();
    let on_volume = Some(volume.clone());
    assert_eq!(
        holders,
        [on_volume.clone(), on_volume.clone(), None, on_volume],
        "{mounts:?}"
    );

    let plan = Plan::from_json(
        &serde_json::json!({
            "version": PLAN_VERSION,
            "hidden_root": at,
            "hidden_dev": volume,
            "upper": at.join("root/upper"),
            "work": at.join("root/work"),
            "decoy_root": {"source": "/dev/vda2", "fstype": "ext4"},
            "decoy": {"init": "/sbin/init"},
            "hidden": {"init": "/sbin/init"},
        })
        .to_string(),
    )
    .expect("a session plan");
    let own: Vec<bool> = mounts.iter().map(|m| plan.is_hidden_storage(m)).collect();
    assert_eq!(own, [true, true, false, false], "{mounts:?}");

    // Unbound, the device has no record left to read.
    let node = device.node.clone();
    drop(device);
    assert!(
        nails_teardown::loop_device::record(&node).is_err(),
        "{} is still bound",
        node.display()
    );
    root.teardown();
}
