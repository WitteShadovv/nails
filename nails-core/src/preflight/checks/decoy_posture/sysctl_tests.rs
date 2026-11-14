// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::filesystem::MockFilesystem;
use std::cell::RefCell;
use std::path::Path;

/// An in-memory decoy whose directories list what is added below them.
struct Tree {
    fs: MockFilesystem,
    listings: RefCell<BTreeMap<PathBuf, Vec<PathBuf>>>,
}

impl Tree {
    fn new() -> Self {
        Self {
            fs: MockFilesystem::new(),
            listings: RefCell::new(BTreeMap::new()),
        }
    }

    fn list(&self, path: &Path) {
        let mut listings = self.listings.borrow_mut();
        let mut child = path.to_path_buf();
        while let Some(parent) = child.parent().map(Path::to_path_buf) {
            let entries = listings.entry(parent.clone()).or_default();
            if !entries.contains(&child) {
                entries.push(child.clone());
                self.fs
                    .mock_set_directory_contents(&parent, entries.clone());
            }
            child = parent;
        }
    }

    fn file(&self, path: &str, text: &str) -> &Self {
        self.fs.mock_add_file(path, text);
        self.list(Path::new(path));
        self
    }

    fn link(&self, path: &str, target: &str) -> &Self {
        self.fs
            .create_symlink(Path::new(target), Path::new(path))
            .unwrap();
        self.list(Path::new(path));
        self
    }

    fn pattern(&self) -> Result<Option<(String, String)>, String> {
        core_pattern(&DecoyFiles::new(&self.fs, Path::new("/"), &[]))
    }
}

fn set(pattern: &str, file: &str) -> Result<Option<(String, String)>, String> {
    Ok(Some((pattern.to_string(), file.to_string())))
}

#[test]
fn the_last_file_by_name_sets_the_pattern() {
    let tree = Tree::new();
    assert_eq!(tree.pattern(), Ok(None));
    // systemd's own file, as Fedora installs it.
    tree.file(
        "/usr/lib/sysctl.d/50-coredump.conf",
        "# comment\nkernel.core_pattern=|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h\n",
    );
    assert_eq!(
        tree.pattern(),
        set(
            "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h",
            "/usr/lib/sysctl.d/50-coredump.conf"
        )
    );
    // A later name wins, in any spelling of the key.
    tree.file(
        "/etc/sysctl.d/90-crash.conf",
        "; mine\n -kernel/core_pattern = /var/crash/core.%e.%p.%t \n",
    );
    assert_eq!(
        tree.pattern(),
        set("/var/crash/core.%e.%p.%t", "/etc/sysctl.d/90-crash.conf")
    );
    // The same name in /etc shadows the one in /usr/lib, and an empty file
    // or a link to /dev/null sets nothing.
    let tree = Tree::new();
    tree.file(
        "/usr/lib/sysctl.d/50-coredump.conf",
        "kernel.core_pattern=|/usr/lib/systemd/systemd-coredump %P\n",
    )
    .link("/etc/sysctl.d/50-coredump.conf", "/dev/null");
    assert_eq!(tree.pattern(), Ok(None));
    // A line without a value only keeps globs off the key.
    let tree = Tree::new();
    tree.file("/etc/sysctl.d/10-a.conf", "kernel.core_pattern = core\n")
        .file(
            "/etc/sysctl.d/20-b.conf",
            "-kernel.core_pattern\nkernel.* = x\n",
        );
    assert_eq!(tree.pattern(), Ok(None));
}

#[test]
fn a_glob_that_may_set_the_pattern_leaves_it_unknown() {
    let tree = Tree::new();
    tree.file(
        "/etc/sysctl.d/10-net.conf",
        "net.ipv4.conf.*.rp_filter = 2\nkernel/*/x = 1\n",
    );
    assert_eq!(tree.pattern(), Ok(None));
    tree.file(
        "/etc/sysctl.d/20-core.conf",
        "kernel.core_* = |/bin/handler\n",
    );
    assert_eq!(
        tree.pattern(),
        Err(
            "/etc/sysctl.d/20-core.conf sets keys by a glob that may match kernel.core_pattern"
                .to_string()
        )
    );
    // A key the files name outright wins over a glob.
    tree.file("/etc/sysctl.d/30-core.conf", "kernel.core_pattern = core\n");
    assert_eq!(tree.pattern(), set("core", "/etc/sysctl.d/30-core.conf"));
    for (pattern, matches) in [
        ("kernel/core_*", true),
        ("kernel/*", true),
        ("*/core_pattern", true),
        ("kernel/core_patter?", true),
        ("kernel/[c]ore_pattern", true),
        ("*", false),
        ("kernel/*/core_pattern", false),
        ("net/*", false),
        ("kernel/core_pid", false),
    ] {
        assert_eq!(
            may_match(pattern.as_bytes(), CORE_PATTERN_KEY.as_bytes()),
            matches,
            "{pattern}"
        );
    }
    for (key, normal) in [
        ("kernel.core_pattern", "kernel/core_pattern"),
        ("kernel/core_pattern", "kernel/core_pattern"),
        ("/kernel//core_pattern", "kernel/core_pattern"),
        (
            "net/ipv4/conf/enp3s0.200/forwarding",
            "net/ipv4/conf/enp3s0.200/forwarding",
        ),
        (
            "net.ipv4.conf.enp3s0/200.forwarding",
            "net/ipv4/conf/enp3s0.200/forwarding",
        ),
    ] {
        assert_eq!(normalized(key), normal, "{key}");
    }
}

#[test]
fn a_file_nails_cannot_read_leaves_the_pattern_unknown() {
    let tree = Tree::new();
    tree.file("/etc/sysctl.d/10-a.conf", "kernel.core_pattern = core\n");
    tree.fs.mock_set_unreadable_dir("/run/sysctl.d");
    tree.list(Path::new("/run/sysctl.d"));
    let found = tree.pattern();
    assert!(
        found
            .as_ref()
            .is_err_and(|why| why.starts_with("NAILS cannot list /run/sysctl.d")),
        "{found:?}"
    );
}
