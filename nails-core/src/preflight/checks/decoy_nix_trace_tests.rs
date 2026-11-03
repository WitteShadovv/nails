// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The check on decoy trees laid out in a temporary directory: a stock
//! Debian, the same with what Nix's multi-user installer writes, with what
//! an incomplete removal leaves, and with a distribution's Nix package.

use super::*;
use crate::RealFilesystem;
use crate::filesystem::{MockFilesystem, PathKind};
use std::os::unix::fs::PermissionsExt;

/// The hook the installer adds to each shell startup file
/// (`shell_source_lines` of install-multi-user.sh).
const HOOK: &str = "\n# Nix\nif [ -e '/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh' ]; then\n  \
                    . '/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh'\nfi\n# End Nix\n\n";

/// Where the installer's links into the default profile lead.
const PROFILE: &str = "/nix/var/nix/profiles/default";

/// A decoy tree in a temporary directory.
struct Decoy {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Decoy {
    /// What a stock Debian 13 holds of what the check reads: root and one
    /// user, a bash.bashrc without Nix, a unit enabled the usual way, and a
    /// merged `/usr`.
    fn stock() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let decoy = Self { _dir: dir, root };
        decoy.file(
            "etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
             alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
        );
        decoy.file("etc/group", "root:x:0:\nsudo:x:27:alice\nalice:x:1000:\n");
        decoy.file(
            "etc/bash.bashrc",
            "# System-wide .bashrc file for interactive bash(1) shells.\nPS1='\\u@\\h:\\w\\$ '\n",
        );
        decoy.dir("etc/profile.d");
        decoy.file("usr/lib/systemd/system/ssh.service", "[Service]\n");
        decoy.link(
            "etc/systemd/system/multi-user.target.wants/ssh.service",
            "/usr/lib/systemd/system/ssh.service",
        );
        decoy.link("lib", "usr/lib");
        decoy.dir("root");
        decoy.dir("home/alice");
        decoy
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn dir(&self, rel: &str) {
        std::fs::create_dir_all(self.path(rel)).unwrap();
    }

    fn file(&self, rel: &str, text: &str) {
        let path = self.path(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn append(&self, rel: &str, text: &str) {
        let old = std::fs::read_to_string(self.path(rel)).unwrap_or_default();
        self.file(rel, &format!("{old}{text}"));
    }

    fn link(&self, rel: &str, target: &str) {
        let path = self.path(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, path).unwrap();
    }

    fn remove(&self, rel: &str) {
        let path = self.path(rel);
        if path.is_dir() && !path.is_symlink() {
            std::fs::remove_dir_all(path).unwrap();
        } else {
            std::fs::remove_file(path).unwrap();
        }
    }

    fn set_mode(&self, rel: &str, mode: u32) {
        std::fs::set_permissions(self.path(rel), std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// What Nix's multi-user installer writes on a systemd host, run as
    /// root with `--daemon --no-channel-add`: the store, its settings, the
    /// build group and 32 build users, the daemon linked from the default
    /// profile and its socket enabled, the tmpfiles rule, the hook in each
    /// shell startup file whose directory exists (with a backup of each one
    /// that existed before), and root's profile links.
    fn install_nix(&self) {
        self.dir("nix/store");
        self.dir("nix/var/nix/profiles/per-user");
        self.link("nix/var/nix/profiles/default", "default-1-link");
        self.file("etc/nix/nix.conf", "\nbuild-users-group = nixbld\n");
        let members: Vec<String> = (1..=32).map(|n| format!("nixbld{n}")).collect();
        self.append(
            "etc/group",
            &format!("nixbld:x:30000:{}\n", members.join(",")),
        );
        for n in 1..=32 {
            self.append(
                "etc/passwd",
                &format!(
                    "nixbld{n}:x:{}:30000:Nix build user {n}:/var/empty:/sbin/nologin\n",
                    30000 + n
                ),
            );
        }
        for unit in ["nix-daemon.service", "nix-daemon.socket"] {
            self.link(
                &format!("etc/systemd/system/{unit}"),
                &format!("{PROFILE}/lib/systemd/system/{unit}"),
            );
        }
        self.link(
            "etc/systemd/system/sockets.target.wants/nix-daemon.socket",
            &format!("{PROFILE}/lib/systemd/system/nix-daemon.socket"),
        );
        self.link(
            "etc/tmpfiles.d/nix-daemon.conf",
            &format!("{PROFILE}/lib/tmpfiles.d/nix-daemon.conf"),
        );
        let bashrc = std::fs::read_to_string(self.path("etc/bash.bashrc")).unwrap();
        self.file("etc/bash.bashrc.backup-before-nix", &bashrc);
        self.file("etc/bash.bashrc", &format!("{HOOK}{bashrc}"));
        for stub in ["etc/bashrc", "etc/zshrc", "etc/profile.d/nix.sh"] {
            self.file(stub, HOOK);
        }
        self.link("root/.nix-profile", PROFILE);
        self.link(
            "root/.nix-defexpr/channels",
            "/nix/var/nix/profiles/per-user/root/channels",
        );
    }

    fn check(&self, is_nixos: bool) -> CheckResult {
        DecoyNixTraceCheck::new(self.path("mnt/data"), is_nixos)
            .with_root(&self.root)
            .run(&RealFilesystem)
            .unwrap()
    }

    /// The warning's first line, the traces it names.
    fn warning(&self) -> String {
        let result = self.check(false);
        assert!(result.is_warn(), "{result:?}");
        result.message().lines().next().unwrap().to_string()
    }
}

/// Whether NAILS runs with the privileges that read past a mode of 000, as
/// root does, so a test of an unreadable file has nothing to show.
fn privileged() -> bool {
    let probe = tempfile::NamedTempFile::new().unwrap();
    std::fs::set_permissions(probe.path(), std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::read(probe.path()).is_ok()
}

#[test]
fn a_decoy_without_nix_passes() {
    let result = Decoy::stock().check(false);
    assert_eq!(
        result,
        CheckResult::Pass("no trace of a Nix install on the decoy".to_string())
    );
}

#[test]
fn what_the_installer_writes_is_named_in_its_order() {
    let decoy = Decoy::stock();
    decoy.install_nix();
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    let (message, fix) = result.message().split_once('\n').unwrap();
    assert_eq!(
        message,
        "Nix is installed on the decoy, or was: it holds /nix, \
         /etc/systemd/system/nix-daemon.service, /etc/systemd/system/nix-daemon.socket, \
         /etc/systemd/system/sockets.target.wants/nix-daemon.socket, \
         /etc/tmpfiles.d/nix-daemon.conf, /etc/nix, the nixbld group in /etc/group, 32 Nix \
         build users in /etc/passwd (nixbld1, nixbld2 and 30 more), /etc/profile.d/nix.sh, \
         the Nix lines in /etc/bashrc, the Nix lines in /etc/bash.bashrc, the Nix lines in \
         /etc/zshrc, /etc/bash.bashrc.backup-before-nix, /root/.nix-profile and \
         /root/.nix-defexpr."
    );
    assert_eq!(
        fix,
        "What Nix installs or builds on the decoy is written to its disk under the name of \
         each package. Install the hidden session's software inside a hidden session, where \
         everything Nix writes lands on the hidden volume, and if the decoy does not need Nix, \
         remove it and these traces long before the next session. See \
         docs/decoy-requirements.md#nix-on-the-decoy."
    );
}

/// What a removal of /nix and /etc/nix alone leaves is still named: the
/// links to nothing, the accounts, the hooks and the backup.
#[test]
fn what_a_partial_removal_leaves_is_named() {
    let decoy = Decoy::stock();
    decoy.install_nix();
    decoy.remove("nix");
    decoy.remove("etc/nix");
    let warning = decoy.warning();
    assert!(!warning.contains("/nix,"), "{warning}");
    assert!(!warning.contains("/etc/nix,"), "{warning}");
    for left in [
        "/etc/systemd/system/nix-daemon.socket",
        "/etc/systemd/system/sockets.target.wants/nix-daemon.socket",
        "/etc/tmpfiles.d/nix-daemon.conf",
        "the nixbld group in /etc/group",
        "/etc/bash.bashrc.backup-before-nix",
        "/root/.nix-profile",
    ] {
        assert!(warning.contains(left), "{left} missing: {warning}");
    }

    // An empty /nix left behind is a trace of its own.
    decoy.dir("nix");
    assert!(
        decoy
            .warning()
            .starts_with("Nix is installed on the decoy, or was: it holds /nix, "),
        "{}",
        decoy.warning()
    );
}

/// A distribution's package puts the daemon's units in /usr/lib, which a
/// merged /usr also shows as /lib: each is named once, as /usr/lib holds
/// it. The command in /usr/bin, a profile script and a drop-in directory are
/// named too.
#[test]
fn a_packaged_nix_is_named_once_through_a_merged_usr() {
    let decoy = Decoy::stock();
    decoy.file("usr/lib/systemd/system/nix-daemon.service", "[Service]\n");
    decoy.file("usr/lib/systemd/system/nix-daemon.socket", "[Socket]\n");
    decoy.file("usr/bin/nix", "\x7fELF");
    decoy.file("etc/profile.d/nix-daemon.sh", "# Nix\n");
    decoy.dir("etc/systemd/system/nix-daemon.service.d");
    assert_eq!(
        decoy.warning(),
        "Nix is installed on the decoy, or was: it holds \
         /usr/lib/systemd/system/nix-daemon.service, /usr/lib/systemd/system/nix-daemon.socket, \
         /etc/systemd/system/nix-daemon.service.d, /usr/bin/nix and /etc/profile.d/nix-daemon.sh."
    );

    // Without the merge, /lib is a unit directory of its own.
    decoy.remove("lib");
    decoy.file("lib/systemd/system/nix-daemon.socket", "[Socket]\n");
    assert!(
        decoy.warning().contains(
            "/usr/lib/systemd/system/nix-daemon.socket, /lib/systemd/system/nix-daemon.socket,"
        ),
        "{}",
        decoy.warning()
    );
}

/// The links that enable a unit are looked for in every dependency
/// directory of /etc/systemd/system, and in no other directory there.
#[test]
fn an_enabling_link_is_named_in_each_dependency_directory() {
    let decoy = Decoy::stock();
    for dir in [
        "multi-user.target.wants",
        "a.target.requires",
        "b.target.upholds",
    ] {
        decoy.link(
            &format!("etc/systemd/system/{dir}/nix-daemon.service"),
            "/nowhere",
        );
    }
    decoy.link("etc/systemd/system/other.d/nix-daemon.service", "/nowhere");
    assert_eq!(
        decoy.warning(),
        "Nix is installed on the decoy, or was: it holds \
         /etc/systemd/system/a.target.requires/nix-daemon.service, \
         /etc/systemd/system/b.target.upholds/nix-daemon.service and \
         /etc/systemd/system/multi-user.target.wants/nix-daemon.service."
    );
}

#[test]
fn build_users_are_named_by_their_name_or_their_group() {
    assert!(is_build_user("nixbld1"));
    assert!(is_build_user("nixbld32"));
    assert!(is_build_user("_nixbld7"));
    for name in [
        "nixbld",
        "nixbldx",
        "nixbld1x",
        "__nixbld1",
        "xnixbld1",
        "",
        "nix",
    ] {
        assert!(!is_build_user(name), "{name}");
    }

    let decoy = Decoy::stock();
    decoy.append("etc/group", "nixbld:x:30000:\n");
    decoy.append(
        "etc/passwd",
        "_nixbld1:x:301:30000:Nix build user 1:/var/empty:/usr/bin/false\n\
         builder:x:30002:30000::/var/empty:/sbin/nologin\n\
         nixbldx:x:30003:1000::/home/nixbldx:/bin/sh\n",
    );
    assert_eq!(
        decoy.warning(),
        "Nix is installed on the decoy, or was: it holds the nixbld group in /etc/group and 2 \
         Nix build users in /etc/passwd (_nixbld1 and builder)."
    );
}

/// A group line without an id makes no user without a group its member.
#[test]
fn a_group_without_an_id_has_no_members_by_group() {
    let decoy = Decoy::stock();
    decoy.append("etc/group", "nixbld:x::\n");
    decoy.append("etc/passwd", "odd:x:5000::/var/empty:/usr/bin/false\n");
    assert_eq!(
        decoy.warning(),
        "Nix is installed on the decoy, or was: it holds the nixbld group in /etc/group."
    );
}

#[test]
fn build_users_are_counted_past_three() {
    let names =
        |count: usize| -> Vec<String> { (1..=count).map(|n| format!("nixbld{n}")).collect() };
    assert_eq!(build_users(&[]), "");
    assert_eq!(
        build_users(&names(1)),
        "the Nix build user nixbld1 in /etc/passwd"
    );
    assert_eq!(
        build_users(&names(2)),
        "2 Nix build users in /etc/passwd (nixbld1 and nixbld2)"
    );
    assert_eq!(
        build_users(&names(3)),
        "3 Nix build users in /etc/passwd (nixbld1, nixbld2 and nixbld3)"
    );
    assert_eq!(
        build_users(&names(4)),
        "4 Nix build users in /etc/passwd (nixbld1, nixbld2 and 2 more)"
    );
}

/// A shell startup file counts only where it names a script of the default
/// profile, as the installer's hook does; other mentions of Nix do not.
#[test]
fn a_startup_file_counts_only_with_the_profile_hook() {
    let decoy = Decoy::stock();
    decoy.file("etc/zsh/zshrc", "alias nb='nix build'\n# nix is fun\n");
    decoy.append(
        "etc/bash.bashrc",
        "[ -e /nix/var/nix/profiles/default/etc/profile.d/nix.sh ] && . /nix/var/nix/profiles/default/etc/profile.d/nix.sh\n",
    );
    assert_eq!(
        decoy.warning(),
        "Nix is installed on the decoy, or was: it holds the Nix lines in /etc/bash.bashrc."
    );
}

/// Each backup the installer keeps is named, whatever the file it copies
/// holds now.
#[test]
fn each_backup_the_installer_keeps_is_named() {
    let decoy = Decoy::stock();
    for file in [
        "etc/bashrc",
        "etc/profile.d/nix.sh",
        "etc/zshrc",
        "etc/bash.bashrc",
        "etc/zsh/zshrc",
    ] {
        decoy.file(&format!("{file}{BACKUP_SUFFIX}"), "");
    }
    assert_eq!(
        decoy.warning(),
        "Nix is installed on the decoy, or was: it holds /etc/bashrc.backup-before-nix, \
         /etc/profile.d/nix.sh.backup-before-nix, /etc/zshrc.backup-before-nix, \
         /etc/bash.bashrc.backup-before-nix and /etc/zsh/zshrc.backup-before-nix."
    );
}

/// What Nix keeps in a home is named for root and for every home
/// /etc/passwd names, each home once; `/` is no home, and a home on the
/// hidden volume is not looked into.
#[test]
fn what_nix_keeps_in_a_home_is_named_for_each_home() {
    let decoy = Decoy::stock();
    decoy.append(
        "etc/passwd",
        "bob:x:1001:1001::/home/bob:/bin/bash\n\
         carol:x:1002:1002::/home/bob:/bin/bash\n\
         nobody:x:65534:65534::/:/usr/sbin/nologin\n",
    );
    decoy.dir("root/.config/nix");
    decoy.dir("home/alice/.cache/nix");
    decoy.dir("home/alice/.local/state/nix");
    decoy.file("home/bob/.nix-channels", "");
    decoy.dir(".nix-profile");
    // The hidden volume's own files are not the decoy's.
    decoy.append("etc/passwd", "dave:x:1003:1003::/mnt/data/dave:/bin/bash\n");
    decoy.dir("mnt/data/dave/.nix-profile");
    let result = DecoyNixTraceCheck::new(decoy.path("mnt/data"), false)
        .with_root(&decoy.root)
        .run(&RealFilesystem)
        .unwrap();
    assert!(result.is_warn(), "{result:?}");
    let warning = result.message().lines().next().unwrap().to_string();
    assert_eq!(
        warning,
        "Nix is installed on the decoy, or was: it holds /root/.config/nix, \
         /home/alice/.local/state/nix, /home/alice/.cache/nix and /home/bob/.nix-channels."
    );
}

#[test]
fn a_nixos_decoy_passes_whatever_it_holds() {
    let decoy = Decoy::stock();
    decoy.install_nix();
    assert_eq!(
        decoy.check(true),
        CheckResult::Pass("the decoy is NixOS, whose own package manager Nix is".to_string())
    );
}

/// What NAILS cannot look up or read is named, so a decoy it could not see
/// never passes; inside a home it cannot look into, the first lookup is
/// named and the rest of that home is left.
#[test]
fn what_cannot_be_read_warns_and_never_passes() {
    if privileged() {
        return;
    }
    let decoy = Decoy::stock();
    decoy.set_mode("home/alice", 0o000);
    decoy.set_mode("etc/group", 0o000);
    let result = decoy.check(false);
    decoy.set_mode("home/alice", 0o755);
    decoy.set_mode("etc/group", 0o644);
    assert!(result.is_warn(), "{result:?}");
    assert_eq!(
        result.message(),
        format!(
            "NAILS cannot tell whether a Nix install left traces on the decoy: NAILS cannot \
             read {}; run the command again with sudo; NAILS cannot look up \
             /home/alice/.nix-profile; run the command again with sudo.\nSee \
             docs/decoy-requirements.md#nix-on-the-decoy.",
            decoy.path("etc/group").display()
        )
    );

    // Beside a trace, it says what it could not tell about.
    decoy.dir("nix");
    decoy.set_mode("etc/systemd/system", 0o000);
    let result = decoy.check(false);
    decoy.set_mode("etc/systemd/system", 0o755);
    assert!(
        result.message().starts_with(&format!(
            "Nix is installed on the decoy, or was: it holds /nix. NAILS cannot tell about the \
             rest: NAILS cannot look up /etc/systemd/system/nix-daemon.service; run the command \
             again with sudo; NAILS cannot look up /etc/systemd/system/nix-daemon.socket; run \
             the command again with sudo; NAILS cannot look up \
             /etc/systemd/system/nix-daemon.service.d; run the command again with sudo; NAILS \
             cannot look up /etc/systemd/system/nix-daemon.socket.d; run the command again with \
             sudo; NAILS cannot list {}; run the command again with sudo.\n",
            decoy.path("etc/systemd/system").display()
        )),
        "{result:?}"
    );
}

/// A lookup that fails for a reason other than a missing or a refused path
/// is named with its error, and the rest of that home is left.
#[test]
fn a_lookup_that_fails_otherwise_is_named_with_its_error() {
    let decoy = Decoy::stock();
    decoy.append("etc/passwd", "eve:x:1004:1004::/home/eve:/bin/bash\n");
    // A link to itself: every lookup through it loops.
    decoy.link("home/eve", "eve");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    let message = result.message();
    assert!(
        message.starts_with(
            "NAILS cannot tell whether a Nix install left traces on the decoy: NAILS cannot \
             look up /home/eve/.nix-profile ("
        ),
        "{result:?}"
    );
    assert!(!message.contains(".nix-defexpr"), "{result:?}");
}

/// A file whose link leads onto the hidden volume is not read, and says so.
#[test]
fn a_link_onto_the_hidden_volume_is_not_read() {
    let decoy = Decoy::stock();
    decoy.file("mnt/data/zshrc", HOOK);
    decoy.link("etc/zshrc", "../mnt/data/zshrc");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result.message().starts_with(&format!(
            "NAILS cannot tell whether a Nix install left traces on the decoy: {} leads onto \
             the hidden volume.",
            decoy.path("etc/zshrc").display()
        )),
        "{result:?}"
    );
}

/// Inside a hidden session `/` is its overlay, whose own Nix is no trace of
/// the decoy: the check is skipped there, and runs where the root overlay
/// is anyone else's.
#[test]
fn inside_a_hidden_session_the_check_is_skipped() {
    let check = DecoyNixTraceCheck::new(PathBuf::from("/mnt/data"), false);
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/nix", PathKind::Dir);
    fs.mock_set_mount_table(
        "22 1 0:40 / / rw - overlay overlay rw,lowerdir=/run/lower,upperdir=/mnt/data/root/upper,\
         workdir=/mnt/data/root/work\n\
         40 22 7:0 / /mnt/data rw - ext4 /dev/loop0 rw\n",
    );
    let result = check.run(&fs).unwrap();
    assert_eq!(
        result,
        CheckResult::skipped(
            "a hidden session is running, and `/` shows its files over the decoy's: run the \
             check on the decoy"
        )
    );

    let other = MockFilesystem::new();
    other.mock_set_path_type("/nix", PathKind::Dir);
    other.mock_set_mount_table(
        "22 1 0:40 / / rw - overlay overlay rw,lowerdir=/a,upperdir=/srv/upper,workdir=/srv/work\n",
    );
    let result = check.run(&other).unwrap();
    assert!(result.is_warn(), "{result:?}");
    assert!(result.message().contains("it holds /nix."), "{result:?}");

    // A mount table NAILS cannot read leaves the decoy to be read.
    other.mock_set_mount_table_error("no mountinfo");
    assert!(check.run(&other).unwrap().is_warn());
}

/// The check writes nothing, whatever it finds.
#[test]
fn the_check_writes_nothing() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/nix", PathKind::Dir);
    fs.mock_add_file(
        "/etc/passwd",
        "nixbld1:x:30001:30000::/var/empty:/sbin/nologin\n",
    );
    fs.mock_add_file("/etc/bash.bashrc", HOOK);
    fs.mock_set_directory_contents(
        Path::new("/etc/systemd/system"),
        vec![PathBuf::from("/etc/systemd/system/sockets.target.wants")],
    );
    let before = fs.mock_ops().len();
    let result = DecoyNixTraceCheck::new(PathBuf::from("/mnt/data"), false)
        .run(&fs)
        .unwrap();
    assert!(result.is_warn(), "{result:?}");
    assert_eq!(fs.mock_ops().len(), before, "the check wrote");
    assert!(fs.mock_written_paths().is_empty());
}

#[test]
fn a_listing_reads_as_a_sentence() {
    let items = |items: &[&str]| -> Vec<String> { items.iter().map(ToString::to_string).collect() };
    assert_eq!(listing(&[]), "");
    assert_eq!(listing(&items(&["a"])), "a");
    assert_eq!(listing(&items(&["a", "b"])), "a and b");
    assert_eq!(listing(&items(&["a", "b", "c"])), "a, b and c");
}

#[test]
fn the_check_metadata_is_stable() {
    let check = DecoyNixTraceCheck::new(PathBuf::from("/mnt/data"), false);
    assert_eq!(
        <DecoyNixTraceCheck as PreFlightCheck<MockFilesystem>>::name(&check),
        "decoy-nix-trace"
    );
    assert_eq!(
        <DecoyNixTraceCheck as PreFlightCheck<MockFilesystem>>::description(&check),
        "Warns when a decoy that is not NixOS holds what a Nix install leaves behind"
    );
    assert!(
        !<DecoyNixTraceCheck as PreFlightCheck<MockFilesystem>>::requires_hidden_volume(&check)
    );
}
