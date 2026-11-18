// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Real overlay and teardown behaviour against the kernel.
//!
//! These tests drive the overlay, bind and tmpfs mounts the session builds
//! against a real overlayfs. All but seven run in the normal test run, each as
//! root of its own unprivileged user + mount namespace (`rootless`, built on
//! `nails_core::test_support::Rerun`), so every mount is private to the child
//! and vanishes with it, even after a panic. Each test still builds its own
//! tmpfs-backed root and tears it down in reverse order, so the teardown path
//! itself is exercised and asserted. `just kernel-tests` turns a host without
//! user namespaces from a skip into a failure.
//!
//! Four tests need `trusted.*` xattrs, which a user namespace cannot set, and
//! three bind loop devices, which only root of the initial namespace may, so
//! they alone stay `#[ignore]`d and run as real root in the privileged-mounts
//! CI job: the whiteout and opaque-directory test, the test of the
//! `kernel-modules` check against the kernel's own whiteouts and opaque
//! directories, the two tests of the whole upper-filesystem probe (with the
//! label copy the host asks for, and with the SELinux label required), the two
//! tests of the loop driver's record of the file behind a loop device, one on a
//! tmpfs and one on a btrfs filesystem it makes with `mkfs.btrfs`, which must
//! be on `PATH` (btrfs-progs), and the test of the reads that change no access
//! time, on such a btrfs filesystem too: a child's mount namespace, the quiet
//! mounts and the quiet copy of a tree change mounts as only root of the
//! initial namespace may. The two loop driver tests also mount a FUSE
//! filesystem through `/dev/fuse`, which no daemon serves, and the test of the
//! reads mounts such a one and one that a thread of the test serves:
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

    // The label copy this host asks for, as the registry gives it.
    let host = nails_core::platform::detect(&nails_core::RealFilesystem).ok();
    let result = UpperFsCapabilityCheck::new(root.root.clone())
        .labels(nails_core::session::labels::Labels::for_host(host.as_ref()))
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

/// The `upper-fs-capability` check against a real hidden root, as root, where
/// the host requires the SELinux labels: the probe gives its trial upper the
/// label of the decoy root and reads it back, and it fails, as the entry is
/// refused, where the decoy root has no label. Either way it leaves nothing
/// on the hidden root and the decoy root keeps its label. On a kernel that
/// labels every file itself (SELinux active) the decoy root has a label from
/// the start, so only the pass is checked there.
#[test]
#[ignore = "root only: the probe sets a trusted.* xattr"]
fn the_upper_fs_probe_as_root_copies_the_decoy_roots_label_where_one_is_required() {
    use nails_core::preflight::{PreFlightCheck, UpperFsCapabilityCheck};
    use nails_core::session::labels::{LABEL_XATTR, Labels, Reason};

    let label_of = |path: &Path| {
        let mut value = vec![0; 4096];
        rustix::fs::lgetxattr(path, LABEL_XATTR, &mut value[..]).map(|len| {
            value.truncate(len);
            value
        })
    };
    let hidden = TmpfsRoot::new();
    let decoy = TmpfsRoot::new();
    let check = || {
        UpperFsCapabilityCheck::new(hidden.root.clone())
            .labels(Labels::Required(Reason::SelinuxRunning))
            .labelled_like(decoy.root.clone())
            .run(&nails_core::RealFilesystem)
            .expect("the check runs")
    };
    let left = || -> Vec<_> {
        std::fs::read_dir(&hidden.root)
            .expect("read the hidden root")
            .collect()
    };

    if label_of(&decoy.root) == Err(rustix::io::Errno::NODATA) {
        // A decoy root without a label: the copy the entry would refuse.
        let refused = check();
        assert!(refused.is_fail(), "{refused:?}");
        assert!(
            refused.message().contains(&format!(
                "must carry the SELinux label of {0}, but {0} has no label",
                decoy.root.display()
            )),
            "{refused:?}"
        );
        // The hidden tmpfs stores labels: the failure does not blame it.
        assert!(
            !refused.message().contains("security.selinux attributes"),
            "{refused:?}"
        );
        assert!(left().is_empty(), "the probe left {:?}", left());
        rustix::fs::lsetxattr(
            &decoy.root,
            LABEL_XATTR,
            b"system_u:object_r:root_t:s0\0",
            rustix::fs::XattrFlags::empty(),
        )
        .expect("label the decoy root");
    }
    let label = label_of(&decoy.root).expect("the decoy root's label");

    let passed = check();
    assert!(passed.is_pass(), "{passed:?}");
    assert!(left().is_empty(), "the probe left {:?}", left());
    assert_eq!(label_of(&decoy.root).expect("read again"), label);

    hidden.teardown();
    decoy.teardown();
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

/// A FUSE filesystem that no daemon serves: mounted from a `/dev/fuse` the
/// test holds open and never reads, so the kernel's first request, and every
/// lookup through the mount after it, waits for an answer. Dropping it closes
/// the device, which ends the connection and every wait on it, and detaches
/// the mount.
struct SilentFuse {
    device: Option<std::fs::File>,
    at: PathBuf,
}

impl SilentFuse {
    fn mount(at: &Path) -> Self {
        Self::mount_as(at, "fuse", 0, MsFlags::empty())
    }

    /// One of type `fstype` that the account `owner` (its user and group)
    /// mounted without `allow_other`, as `fusermount3` mounts a user's.
    fn mount_as(at: &Path, fstype: &str, owner: u32, flags: MsFlags) -> Self {
        use std::os::fd::AsRawFd;
        let device = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/fuse")
            .expect("open /dev/fuse");
        let options = format!(
            "fd={},rootmode=40000,user_id={owner},group_id={owner}",
            device.as_raw_fd()
        );
        nix::mount::mount(
            Some("nails-test"),
            at,
            Some(fstype),
            flags,
            Some(options.as_str()),
        )
        .expect("mount a FUSE filesystem");
        Self {
            device: Some(device),
            at: at.to_path_buf(),
        }
    }
}

impl Drop for SilentFuse {
    fn drop(&mut self) {
        drop(self.device.take());
        let _ = Mounts.unmount(&self.at, true);
    }
}

/// What `backing_filesystem` names for `mount`, and whether `plan` counts it
/// as its own storage, asked on a thread of its own while `fuse` is mounted.
/// An answer that takes longer than ten seconds waits on the FUSE
/// filesystem, which never answers: the test then fails, once dropping
/// `fuse` has ended the wait.
fn asked_beside(
    fuse: SilentFuse,
    mount: &nails_teardown::mountinfo::MountEntry,
    plan: &nails_teardown::whole_root::plan::Plan,
) -> (Option<String>, bool) {
    let (sent, answer) = std::sync::mpsc::channel();
    let (mount, plan) = (mount.clone(), plan.clone());
    std::thread::spawn(move || {
        let held = nails_teardown::loop_device::backing_filesystem(&mount);
        let _ = sent.send((held, plan.is_hidden_storage(&mount)));
    });
    let answer = answer.recv_timeout(std::time::Duration::from_secs(10));
    drop(fuse);
    answer.expect("an answer that does not wait on the FUSE filesystem")
}

/// The loop driver's record, read through a real loop device: it names the
/// filesystem that holds the device's backing file by the number the mount
/// table shows for that filesystem. A filesystem on the loop device is told
/// by the device's own number, and one that shows an anonymous number, as
/// btrfs does, by its source, the device's node. So a session whose hidden
/// volume holds the file counts that filesystem, mounted below the hidden
/// root, as its own storage, and nothing else. The mount table lines are the
/// test's own, for the filesystems the device could hold: what is read is the
/// driver's record, and the real mount table, which shows the tmpfs that
/// holds the file. While a FUSE filesystem that no daemon serves is mounted
/// over the file's folder, nothing is asked of it, and the image counts as a
/// disk of its own.
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

    // The path the driver shows for the file runs through a FUSE filesystem
    // now. A file there would have its daemon answer for the driver's
    // record, and a lookup of the path asks the daemon in any case, so
    // neither is asked: the image counts as a disk of its own, though it
    // still lies on the tmpfs.
    let fuse = SilentFuse::mount(&at);
    assert_eq!(asked_beside(fuse, &mounts[0], &plan), (None, false));
    assert_eq!(backing_filesystem(&mounts[0]), Some(volume.clone()));

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

/// On btrfs a file shows its subvolume's own device number, which no mount
/// line shows: the mount table writes the filesystem's. The loop driver
/// records the file's number, so the filesystem that holds a loop device's
/// file is found through the path the driver shows for it: the mount that
/// path leads to, when it leads to the recorded file. A session whose hidden
/// volume is that btrfs counts an image on it, mounted below the hidden root
/// from its loop device, as its own storage, and not while a tmpfs mounted
/// over the image's folder holds what the path leads to. Nor while a FUSE
/// filesystem that no daemon serves is mounted there: the path is not looked
/// up through it, which would wait for good.
#[test]
#[ignore = "root only: binding a loop device needs CAP_SYS_ADMIN in the initial namespace, and mkfs.btrfs"]
fn a_loop_device_s_file_on_btrfs_is_found_by_the_path_the_driver_shows() {
    use nails_teardown::loop_device::{backing_filesystem, record};
    use nails_teardown::mountinfo::{parse_mountinfo, read_mountinfo, top_mount_at};
    use nails_teardown::whole_root::plan::{PLAN_VERSION, Plan};
    use std::os::unix::fs::MetadataExt;

    // The hidden volume: a btrfs filesystem in an image on the tmpfs, on a
    // loop device of its own.
    let root = TmpfsRoot::new();
    let at = root.root.canonicalize().expect("canonical tmpfs root");
    let volume_image = at.join("volume.img");
    std::fs::File::create(&volume_image)
        .and_then(|file| file.set_len(256 << 20))
        .expect("create the volume's image file");
    let made = std::process::Command::new("mkfs.btrfs")
        .arg("-q")
        .arg(&volume_image)
        .status()
        .expect("run mkfs.btrfs, from btrfs-progs");
    assert!(made.success(), "mkfs.btrfs: {made}");
    let volume_device = LoopDevice::attach(&volume_image);
    let volume = at.join("volume");
    mkdir(&volume);
    nix::mount::mount(
        Some(volume_device.node.as_path()),
        &volume,
        Some("btrfs"),
        MsFlags::empty(),
        None::<&str>,
    )
    .expect("mount the btrfs volume");
    let table = read_mountinfo().expect("read mountinfo");
    let volume_dev = top_mount_at(&table, &volume)
        .expect("the btrfs volume")
        .dev
        .clone();

    // An image on it, bound to a loop device: the file shows the
    // subvolume's own number, and the driver records that one.
    let folder = volume.join("images");
    mkdir(&folder);
    let image = folder.join("disk.img");
    std::fs::File::create(&image)
        .and_then(|file| file.set_len(1 << 20))
        .expect("create the image file");
    let file = std::fs::metadata(&image).expect("stat the image");
    assert_ne!(
        format!(
            "{}:{}",
            rustix::fs::major(file.dev()),
            rustix::fs::minor(file.dev())
        ),
        volume_dev,
        "a file on btrfs shows a number of its own"
    );
    let device = LoopDevice::attach(&image);
    let recorded = record(&device.node).expect("the loop driver's record");
    assert_eq!((recorded.device, recorded.inode), (file.dev(), file.ino()));

    let mounts = parse_mountinfo(&format!(
        "1 0 {dev} / {volume}/vm rw - ext4 {node} rw\n",
        dev = device.dev,
        node = device.node.display(),
        volume = volume.display(),
    ));
    let plan = Plan::from_json(
        &serde_json::json!({
            "version": PLAN_VERSION,
            "hidden_root": volume,
            "hidden_dev": volume_dev,
            "upper": volume.join("root/upper"),
            "work": volume.join("root/work"),
            "decoy_root": {"source": "/dev/vda2", "fstype": "ext4"},
            "decoy": {"init": "/sbin/init"},
            "hidden": {"init": "/sbin/init"},
        })
        .to_string(),
    )
    .expect("a session plan");
    assert_eq!(backing_filesystem(&mounts[0]), Some(volume_dev.clone()));
    assert!(plan.is_hidden_storage(&mounts[0]));

    // A tmpfs over the image's folder, with a file of its own where the
    // path the driver shows leads: that file is on another device.
    Mounts
        .mount_tmpfs(&folder, "1M")
        .expect("mount a tmpfs over the folder");
    write(&image, "");
    assert_eq!(backing_filesystem(&mounts[0]), None);
    assert!(!plan.is_hidden_storage(&mounts[0]));
    Mounts
        .unmount(&folder, false)
        .expect("unmount the tmpfs over the folder");
    assert_eq!(backing_filesystem(&mounts[0]), Some(volume_dev.clone()));

    // A FUSE filesystem over the folder that no daemon serves: a lookup of
    // the path through it would wait for good, so none is made.
    let fuse = SilentFuse::mount(&folder);
    assert_eq!(asked_beside(fuse, &mounts[0], &plan), (None, false));
    assert_eq!(backing_filesystem(&mounts[0]), Some(volume_dev));

    drop(device);
    Mounts
        .unmount(&volume, false)
        .expect("unmount the btrfs volume");
    drop(volume_device);
    root.teardown();
}

/// A process that dies with the mounts quiet (here: one that abandons its
/// value, closing its descriptors and giving no mode back, as a SIGKILL
/// would) leaves them `noatime`. The record it handed
/// over before the change gives them their own mode back. `disk` is a mount
/// that keeps access times `relatime`; `has` and `options` read its options.
fn a_record_gives_a_killed_window_s_modes_back(
    disk: &Path,
    has: &dyn Fn(&str) -> bool,
    options: &dyn Fn() -> String,
) {
    use nails_teardown::noatime::QuietMounts;
    let mut recorded = Vec::new();
    let quiet = QuietMounts::open_recorded(|records| {
        recorded = records.to_vec();
        Ok(())
    })
    .expect("quiet the mounts");
    assert!(
        recorded
            .iter()
            .any(|record| record.mount_point == disk && record.relatime),
        "the disk is in the record: {recorded:?}"
    );
    quiet.abandon();
    assert!(has("noatime"), "{}", options());
    assert_eq!(
        nails_teardown::noatime::restore(&recorded),
        Vec::<std::path::PathBuf>::new()
    );
    assert!(
        has("relatime"),
        "the record gave the disk its mode back: {}",
        options()
    );
    // A record whose change failed changes nothing.
    let refused = QuietMounts::open_recorded(|_| Err(std::io::Error::other("no plan")));
    assert!(refused.is_err());
    assert!(has("relatime"), "{}", options());
    // Closed, the mounts have their own mode back.
    QuietMounts::open()
        .expect("quiet the mounts")
        .close()
        .expect("give the modes back");
    assert!(has("relatime"), "{}", options());
}

/// What the daemon of an [`AnsweringFuse`] does with a request.
const LIVE: u8 = 0;
/// It reads each request, counts it and never answers it, as a hung daemon.
const HUNG: u8 = 1;
/// It closes the device, as a daemon that died: the kernel ends the
/// connection and fails every request with `ENOTCONN`.
const DEAD: u8 = 2;

/// A FUSE filesystem everyone may enter (`allow_other`, as `bindfs` or
/// `sshfs -o allow_other` mounts it), served by a thread of the test that
/// answers what a mount inside it needs: its root and one directory,
/// `inner`, whose lookup the kernel may keep for no time at all, so that
/// every later lookup of `inner` asks the daemon again. The daemon can then
/// hang ([`HUNG`]) or die ([`DEAD`]).
struct AnsweringFuse {
    state: std::sync::Arc<std::sync::atomic::AtomicU8>,
    /// The lookups of `inner` it answered.
    answered: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// The requests it read while hung.
    unanswered: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    daemon: Option<std::thread::JoinHandle<()>>,
    at: PathBuf,
}

impl AnsweringFuse {
    fn mount(at: &Path) -> Self {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        use std::sync::atomic::{AtomicU8, AtomicUsize};
        let device = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open("/dev/fuse")
            .expect("open /dev/fuse");
        let options = format!(
            "fd={},rootmode=40000,user_id=0,group_id=0,allow_other",
            device.as_raw_fd()
        );
        nix::mount::mount(
            Some("nails-test"),
            at,
            Some("fuse.nailstest"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some(options.as_str()),
        )
        .expect("mount a FUSE filesystem");
        let state = std::sync::Arc::new(AtomicU8::new(LIVE));
        let answered = std::sync::Arc::new(AtomicUsize::new(0));
        let unanswered = std::sync::Arc::new(AtomicUsize::new(0));
        let daemon = {
            let (state, answered, unanswered) =
                (state.clone(), answered.clone(), unanswered.clone());
            std::thread::spawn(move || serve(device, &state, &answered, &unanswered))
        };
        Self {
            state,
            answered,
            unanswered,
            daemon: Some(daemon),
            at: at.to_path_buf(),
        }
    }

    fn set(&self, state: u8) {
        self.state.store(state, std::sync::atomic::Ordering::SeqCst);
        if state == DEAD {
            // Wait for the device to close, so that the connection is over.
            while !self
                .daemon
                .as_ref()
                .is_none_or(|daemon| daemon.is_finished())
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }

    fn answered(&self) -> usize {
        self.answered.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn unanswered(&self) -> usize {
        self.unanswered.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for AnsweringFuse {
    fn drop(&mut self) {
        self.set(DEAD);
        let _ = Mounts.unmount(&self.at, true);
    }
}

/// The attributes of a directory, as FUSE's `struct fuse_attr` (88 bytes).
fn fuse_dir_attr(node: u64) -> Vec<u8> {
    let mut attr = Vec::with_capacity(88);
    attr.extend_from_slice(&node.to_ne_bytes()); // ino
    attr.extend_from_slice(&[0; 5 * 8 + 3 * 4]); // size, blocks, times
    attr.extend_from_slice(&0o040_755_u32.to_ne_bytes()); // mode
    attr.extend_from_slice(&2_u32.to_ne_bytes()); // nlink
    attr.extend_from_slice(&[0; 3 * 4]); // uid, gid, rdev
    attr.extend_from_slice(&4096_u32.to_ne_bytes()); // blksize
    attr.extend_from_slice(&0_u32.to_ne_bytes()); // flags
    attr
}

/// The daemon of an [`AnsweringFuse`]: it answers `FUSE_INIT`, a lookup of
/// `inner` in the root (node 2, valid for no time) and the attributes of
/// either, needs no answer for a `FORGET` or an `INTERRUPT`, and answers
/// anything else with `ENOSYS`, while `state` is [`LIVE`].
fn serve(
    mut device: std::fs::File,
    state: &std::sync::atomic::AtomicU8,
    answered: &std::sync::atomic::AtomicUsize,
    unanswered: &std::sync::atomic::AtomicUsize,
) {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::sync::atomic::Ordering::SeqCst;
    let mut buffer = vec![0_u8; 1 << 20];
    loop {
        if state.load(SeqCst) == DEAD {
            drop(device);
            return;
        }
        let mut fds = [PollFd::new(device.as_fd(), PollFlags::POLLIN)];
        if poll(&mut fds, PollTimeout::from(50_u16)).unwrap_or(0) == 0 {
            continue;
        }
        let length = match device.read(&mut buffer) {
            Ok(length) if length >= 40 => length,
            Ok(_) => continue,
            Err(error) if error.raw_os_error() == Some(nix::libc::ENODEV) => return,
            Err(_) => continue,
        };
        let word = |at: usize| u32::from_ne_bytes(buffer[at..at + 4].try_into().expect("4 bytes"));
        let long = |at: usize| u64::from_ne_bytes(buffer[at..at + 8].try_into().expect("8 bytes"));
        let (opcode, unique, node) = (word(4), long(8), long(16));
        if state.load(SeqCst) == HUNG {
            // A FORGET, a BATCH_FORGET or an INTERRUPT asks for no answer.
            if !matches!(opcode, 2 | 36 | 42) {
                unanswered.fetch_add(1, SeqCst);
            }
            continue;
        }
        let name = &buffer[40..length];
        let (error, body): (i32, Vec<u8>) = match opcode {
            // FUSE_INIT: protocol 7.31, writes of at most 4 KiB.
            26 => {
                let mut init = Vec::with_capacity(64);
                for value in [7_u32, 31, 0, 0] {
                    init.extend_from_slice(&value.to_ne_bytes());
                }
                init.extend_from_slice(&[0; 4]); // max_background, congestion
                init.extend_from_slice(&4096_u32.to_ne_bytes()); // max_write
                init.extend_from_slice(&1_u32.to_ne_bytes()); // time_gran
                init.resize(64, 0);
                (0, init)
            }
            // FUSE_LOOKUP of `inner` in the root.
            1 if node == 1 && name.starts_with(b"inner\0") => {
                answered.fetch_add(1, SeqCst);
                let mut entry = Vec::with_capacity(128);
                entry.extend_from_slice(&2_u64.to_ne_bytes()); // nodeid
                entry.extend_from_slice(&[0; 3 * 8 + 2 * 4]); // generation, validity
                entry.extend_from_slice(&fuse_dir_attr(2));
                (0, entry)
            }
            1 => (-nix::libc::ENOENT, Vec::new()),
            // FUSE_GETATTR.
            3 => {
                let mut out = vec![0_u8; 16]; // valid for no time
                out.extend_from_slice(&fuse_dir_attr(node));
                (0, out)
            }
            // FUSE_FORGET, FUSE_INTERRUPT, FUSE_BATCH_FORGET.
            2 | 36 | 42 => continue,
            _ => (-nix::libc::ENOSYS, Vec::new()),
        };
        let mut reply = Vec::with_capacity(16 + body.len());
        let total = u32::try_from(16 + body.len()).expect("a short reply");
        reply.extend_from_slice(&total.to_ne_bytes());
        reply.extend_from_slice(&error.to_ne_bytes());
        reply.extend_from_slice(&unique.to_ne_bytes());
        reply.extend_from_slice(&body);
        let _ = device.write_all(&reply);
    }
}

/// FUSE mounts, and the mounts inside them, stay out of the quiet mounts and
/// as they are, and the window asks their daemons nothing: it opens and
/// closes within ten seconds while `disk`, a btrfs mount that keeps access
/// times `relatime`, is `noatime` between. Below `disk` lie a user's FUSE
/// mount without `allow_other` that no daemon serves, with a disk mount it
/// covers at `user-fuse/inner`, and an [`AnsweringFuse`] everyone may enter,
/// with a disk mount inside it at `everyones/inner`, whose every lookup asks
/// its daemon: first one that never answers, then one that is gone.
fn fuse_mounts_and_what_is_inside_them_stay_out_of_the_window(disk: &Path) {
    use nails_teardown::mountinfo::read_mountinfo;
    use nails_teardown::noatime::QuietMounts;
    /// The options of each mount at `point`, the topmost last.
    fn modes(point: &Path) -> Vec<String> {
        read_mountinfo()
            .expect("read mountinfo")
            .iter()
            .filter(|mount| mount.mount_point == point)
            .map(|mount| mount.mount_opts.clone())
            .collect()
    }
    /// Whether the topmost mount at `point` has the option `word`.
    fn has(point: &Path, word: &str) -> bool {
        modes(point)
            .last()
            .is_some_and(|options| options.split(',').any(|option| option == word))
    }
    let bind = |source: &Path, target: &Path| {
        nix::mount::mount(
            Some(source),
            target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .expect("bind a directory of the disk");
    };
    let source = disk.join("source");
    let user = disk.join("user-fuse");
    let covered = user.join("inner");
    let everyones = disk.join("everyones");
    let inside = everyones.join("inner");
    mkdir(&source);
    mkdir(&covered);
    mkdir(&everyones);
    let fuse = AnsweringFuse::mount(&everyones);
    bind(&source, &inside);
    // The disk mount the user's FUSE mount covers, mounted before it.
    bind(&source, &covered);
    let user_fuse = SilentFuse::mount_as(
        &user,
        "fuse.nailstest",
        1000,
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
    );
    // Every lookup of the disk mount inside asks the daemon.
    let before = fuse.answered();
    assert!(std::fs::metadata(&inside).expect("look it up").is_dir());
    assert!(fuse.answered() > before, "a lookup of it asks the daemon");
    let out = [&user, &covered, &everyones, &inside];
    for point in out {
        assert!(
            has(point, "relatime"),
            "{}: {:?}",
            point.display(),
            modes(point)
        );
    }

    for (daemon, state) in [("one that never answers", HUNG), ("one that is gone", DEAD)] {
        fuse.set(state);
        let (sent, answer) = std::sync::mpsc::channel();
        let watched: Vec<PathBuf> = out.iter().map(|point| point.to_path_buf()).collect();
        let disk_point = disk.to_path_buf();
        std::thread::spawn(move || {
            let mut recorded = Vec::new();
            let opened = QuietMounts::open_recorded(|records| {
                recorded = records.to_vec();
                Ok(())
            });
            let outcome = opened.map(|quiet| {
                let during: Vec<bool> =
                    watched.iter().map(|point| has(point, "relatime")).collect();
                let disk_quiet = has(&disk_point, "noatime");
                (quiet.close(), during, disk_quiet)
            });
            let _ = sent.send((outcome, recorded));
        });
        let Ok((outcome, recorded)) = answer.recv_timeout(std::time::Duration::from_secs(10))
        else {
            drop(fuse);
            panic!("the window waits on a FUSE daemon: {daemon}");
        };
        let (closed, during, disk_quiet) =
            outcome.unwrap_or_else(|error| panic!("the window opens beside {daemon}: {error}"));
        closed.expect("give the modes back");
        if state == HUNG {
            assert_eq!(fuse.unanswered(), 0, "the window asked the hung daemon");
        }
        assert!(disk_quiet, "the disk is noatime in the window");
        assert!(
            recorded.iter().any(|record| record.mount_point == disk),
            "the disk is in the record: {recorded:?}"
        );
        for (point, kept) in out.iter().zip(during) {
            assert!(
                !recorded.iter().any(|record| record.mount_point == **point),
                "{} is not in the record: {recorded:?}",
                point.display()
            );
            assert!(kept, "{} stays relatime in the window", point.display());
            assert!(
                has(point, "relatime"),
                "{}: {:?}",
                point.display(),
                modes(point)
            );
        }
    }
    // Gone, the daemon fails a lookup of the mount inside.
    let gone = std::fs::metadata(&inside).expect_err("a lookup asks the daemon");
    assert_eq!(gone.raw_os_error(), Some(nix::libc::ENOTCONN), "{gone}");

    drop(fuse);
    drop(user_fuse);
    Mounts
        .unmount(&covered, true)
        .expect("unmount the covered disk mount");
    std::fs::remove_dir_all(&user).expect("remove the user's FUSE mount point");
    std::fs::remove_dir(&everyones).expect("remove the FUSE mount point");
    std::fs::remove_dir(&source).expect("remove the bound directory");
}

/// What NAILS reads on the decoy leaves its access times alone: a program it
/// starts runs with every mount of a namespace of its own `noatime`, and while
/// it asks PID 1 for something that makes PID 1 read the decoy, the mounts
/// that keep access times are `noatime` and get their own mode back after.
/// Both on a btrfs filesystem in an image on a loop device, mounted
/// `relatime`, with a file whose access time is set two days back before each
/// read, so that a read that counts updates it; a plain read is the control.
#[test]
#[ignore = "root only: a child's mount namespace and the quiet mounts need CAP_SYS_ADMIN in the initial namespace, and mkfs.btrfs"]
fn quiet_children_mounts_and_trees_change_no_access_time() {
    use nails_teardown::mountinfo::{read_mountinfo, top_mount_at};
    use nails_teardown::noatime::{
        QuietMounts, may_spawn_without_access_times, spawn_without_access_times,
    };
    use nails_teardown::whole_root::nextroot::QuietRoot;
    use std::os::unix::fs::MetadataExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, SystemTime};

    assert!(
        may_spawn_without_access_times(),
        "run as root of the initial user namespace"
    );
    let root = TmpfsRoot::new();
    let at = root.root.canonicalize().expect("canonical tmpfs root");
    let image = at.join("disk.img");
    std::fs::File::create(&image)
        .and_then(|file| file.set_len(256 << 20))
        .expect("create the image file");
    let made = Command::new("mkfs.btrfs")
        .arg("-q")
        .arg(&image)
        .status()
        .expect("run mkfs.btrfs, from btrfs-progs");
    assert!(made.success(), "mkfs.btrfs: {made}");
    let device = LoopDevice::attach(&image);
    let disk = at.join("disk");
    mkdir(&disk);
    nix::mount::mount(
        Some(device.node.as_path()),
        &disk,
        Some("btrfs"),
        MsFlags::MS_RELATIME,
        None::<&str>,
    )
    .expect("mount the btrfs disk");
    let file = disk.join("file");
    write(&file, "decoy");
    let age = || {
        let two_days_ago = SystemTime::now() - Duration::from_secs(2 * 86_400);
        std::fs::File::open(&file)
            .and_then(|handle| {
                handle.set_times(std::fs::FileTimes::new().set_accessed(two_days_ago))
            })
            .expect("set the access time back");
        let meta = std::fs::metadata(&file).expect("stat the file");
        (meta.atime(), meta.atime_nsec())
    };
    let atime = || {
        let meta = std::fs::metadata(&file).expect("stat the file");
        (meta.atime(), meta.atime_nsec())
    };
    let options = || {
        top_mount_at(&read_mountinfo().expect("read mountinfo"), &disk)
            .expect("the disk's mount")
            .mount_opts
            .clone()
    };
    let has = |word: &str| options().split(',').any(|option| option == word);
    let cat = |quiet: bool| {
        let mut command = Command::new("/bin/cat");
        command.arg(&file).stdout(Stdio::null());
        if quiet {
            spawn_without_access_times(&mut command);
        }
        assert!(command.status().expect("run cat").success());
    };

    let aged = age();
    cat(true);
    assert_eq!(atime(), aged, "a child without access times read the file");
    cat(false);
    assert_ne!(atime(), aged, "a plain child updates the access time");

    // Such a child can still mount a proc of its own in a user and PID
    // namespace of its own, as Nix's sandbox does: the kernel allows it only
    // where the proc the child sees has the access-time mode a new one gets.
    let mut command = Command::new("unshare");
    command
        .args(["--user", "--map-root-user", "--mount", "--pid", "--fork"])
        .args(["--mount-proc", "/bin/true"]);
    spawn_without_access_times(&mut command);
    let status = command.status().expect("run unshare, from util-linux");
    assert!(status.success(), "a proc of its own: {status}");

    let aged = age();
    assert!(has("relatime"), "{}", options());
    {
        let quiet = QuietMounts::open().expect("quiet the mounts");
        assert!(!quiet.is_empty());
        assert!(has("noatime"), "{}", options());
        read(&file);
        assert_eq!(atime(), aged, "a read under quiet mounts");
    }
    assert!(
        has("relatime"),
        "the mount has its own mode back: {}",
        options()
    );
    read(&file);
    assert_ne!(atime(), aged, "a read after the quiet mounts updates it");

    // A bind made while the mounts are quiet takes `noatime` from the mount
    // it copies, and gets that mount's own mode when they get theirs back.
    let bound = at.join("bound");
    mkdir(&bound);
    let bound_options = || {
        top_mount_at(&read_mountinfo().expect("read mountinfo"), &bound)
            .expect("the bind's mount")
            .mount_opts
            .clone()
    };
    let bound_has = |word: &str| bound_options().split(',').any(|option| option == word);
    {
        let _quiet = QuietMounts::open().expect("quiet the mounts");
        nix::mount::mount(
            Some(disk.as_path()),
            &bound,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .expect("bind the disk");
        assert!(bound_has("noatime"), "{}", bound_options());
    }
    assert!(
        bound_has("relatime"),
        "the bind has the disk's own mode: {}",
        bound_options()
    );
    nix::mount::umount(&bound).expect("unmount the bind");

    a_record_gives_a_killed_window_s_modes_back(&disk, &has, &options);
    fuse_mounts_and_what_is_inside_them_stay_out_of_the_window(&disk);

    // A lookup through a quiet copy of the tree follows a symlink without
    // updating the link's access time, where a plain lookup updates it.
    let link = disk.join("link");
    std::os::unix::fs::symlink("file", &link).expect("make the link");
    let link_atime = || {
        let meta = std::fs::symlink_metadata(&link).expect("look at the link");
        (meta.atime(), meta.atime_nsec())
    };
    let age_link = || {
        use rustix::fs::{AtFlags, CWD, Timespec, Timestamps, UTIME_OMIT, utimensat};
        let since = (SystemTime::now() - Duration::from_secs(2 * 86_400))
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("a time after the epoch");
        let times = Timestamps {
            last_access: Timespec {
                tv_sec: i64::try_from(since.as_secs()).expect("seconds"),
                tv_nsec: 0,
            },
            last_modification: Timespec {
                tv_sec: 0,
                tv_nsec: UTIME_OMIT,
            },
        };
        utimensat(CWD, &link, &times, AtFlags::SYMLINK_NOFOLLOW)
            .expect("set the link's access time back");
        link_atime()
    };
    let aged = age_link();
    let tree = QuietRoot::open(&disk).expect("open the tree");
    assert!(tree.is_file(Path::new("/link")));
    drop(tree);
    assert_eq!(link_atime(), aged, "a lookup through the quiet tree");
    assert!(link.is_file());
    assert_ne!(
        link_atime(),
        aged,
        "a plain lookup updates the link's access time"
    );

    Mounts
        .unmount(&disk, false)
        .expect("unmount the btrfs disk");
    drop(device);
    root.teardown();
}
