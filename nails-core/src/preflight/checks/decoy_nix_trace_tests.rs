// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The check on decoy trees laid out in a temporary directory: a stock
//! Debian, the same with what Nix's multi-user or single-user installer
//! writes, with what an incomplete removal or Nix's own uninstall steps
//! leave, and with a distribution's Nix package.

use super::*;
use crate::RealFilesystem;
use crate::filesystem::{MockFilesystem, PathKind};
use std::os::unix::fs::PermissionsExt;

/// The hook the installer adds to each shell startup file
/// (`shell_source_lines` of install-multi-user.sh).
const HOOK: &str = "\n# Nix\nif [ -e '/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh' ]; then\n  \
                    . '/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh'\nfi\n# End Nix\n\n";

/// The default profile, relative to the root: the installer's links lead
/// into it.
const PROFILE: &str = "nix/var/nix/profiles/default";

/// The hook the single-user installer adds to a home's shell startup files
/// (install-nix-from-tarball.sh), for the home `/home/alice`.
const USER_HOOK: &str = "\nif [ -e /home/alice/.nix-profile/etc/profile.d/nix.sh ]; then . \
                         /home/alice/.nix-profile/etc/profile.d/nix.sh; fi # added by Nix installer\n";

/// The stock accounts: root and one user.
const STOCK_PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
                            daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
                            alice:x:1000:1000:Alice:/home/alice:/bin/bash\n";
const STOCK_SHADOW: &str = "root:*:20000:0:99999:7:::\ndaemon:*:20000:0:99999:7:::\n\
                            alice:$y$j9T$salt$hash:20000:0:99999:7:::\n";
const STOCK_GROUP: &str = "root:x:0:\nsudo:x:27:alice\nalice:x:1000:\n";
const STOCK_GSHADOW: &str = "root:*::\nsudo:*::alice\nalice:!::\n";

/// A decoy tree in a temporary directory.
struct Decoy {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Decoy {
    /// What a stock Debian 13 holds of what the check reads: root and one
    /// user, with the account files, their shadow files and the copies
    /// shadow-utils keeps of them, a bash.bashrc and /etc/profile without Nix,
    /// the shell startup files of each home, a unit enabled the usual way,
    /// and a merged `/usr`.
    fn stock() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let decoy = Self { _dir: dir, root };
        for (file, text) in [
            ("etc/passwd", STOCK_PASSWD),
            ("etc/shadow", STOCK_SHADOW),
            ("etc/group", STOCK_GROUP),
            ("etc/gshadow", STOCK_GSHADOW),
        ] {
            decoy.file(file, text);
            decoy.file(&format!("{file}-"), text);
        }
        decoy.file(
            "etc/bash.bashrc",
            "# System-wide .bashrc file for interactive bash(1) shells.\nPS1='\\u@\\h:\\w\\$ '\n",
        );
        decoy.file(
            "etc/profile",
            "PATH=\"/usr/local/bin:/usr/bin:/bin\"\nfor i in /etc/profile.d/*.sh; do . \"$i\"; done\n",
        );
        decoy.dir("etc/profile.d");
        decoy.file("usr/lib/systemd/system/ssh.service", "[Service]\n");
        decoy.link(
            "etc/systemd/system/multi-user.target.wants/ssh.service",
            "/usr/lib/systemd/system/ssh.service",
        );
        decoy.link("lib", "usr/lib");
        for home in ["root", "home/alice"] {
            decoy.file(
                &format!("{home}/.profile"),
                "[ -f ~/.bashrc ] && . ~/.bashrc\n",
            );
            decoy.file(&format!("{home}/.bashrc"), "HISTCONTROL=ignoreboth\n");
        }
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

    /// A link at `rel` to `target`, both relative to the root: the link
    /// names the target's path under the root, as the decoy's own absolute
    /// link names it below `/`, so that it leads to nothing once the target
    /// is gone, on every host.
    fn link_in_root(&self, rel: &str, target: &str) {
        self.link(rel, &self.path(target).display().to_string());
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

    /// The account files as `groupadd` and then a `useradd` per build user
    /// leave them, the users `nixbld1` to `nixbld<last>`: each user is a
    /// member of the group, and the copy of each file is what it held before
    /// the last `useradd`.
    fn build_accounts(&self, last: u32) {
        let users = |count: u32, line: &dyn Fn(u32) -> String| -> String {
            (1..=count).map(line).collect()
        };
        let passwd = |n: u32| {
            format!(
                "nixbld{n}:x:{}:30000:Nix build user {n}:/var/empty:/sbin/nologin\n",
                30000 + n
            )
        };
        let shadow = |n: u32| format!("nixbld{n}:!:20000::::::\n");
        let members = |count: u32| -> String {
            (1..=count)
                .map(|n| format!("nixbld{n}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        for (copy, count) in [("", last), ("-", last - 1)] {
            self.file(
                &format!("etc/passwd{copy}"),
                &format!("{STOCK_PASSWD}{}", users(count, &passwd)),
            );
            self.file(
                &format!("etc/shadow{copy}"),
                &format!("{STOCK_SHADOW}{}", users(count, &shadow)),
            );
            self.file(
                &format!("etc/group{copy}"),
                &format!("{STOCK_GROUP}nixbld:x:30000:{}\n", members(count)),
            );
            self.file(
                &format!("etc/gshadow{copy}"),
                &format!("{STOCK_GSHADOW}nixbld:!::{}\n", members(count)),
            );
        }
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
        self.build_accounts(32);
        for unit in ["nix-daemon.service", "nix-daemon.socket"] {
            self.link_in_root(
                &format!("etc/systemd/system/{unit}"),
                &format!("{PROFILE}/lib/systemd/system/{unit}"),
            );
        }
        self.link_in_root(
            "etc/systemd/system/sockets.target.wants/nix-daemon.socket",
            &format!("{PROFILE}/lib/systemd/system/nix-daemon.socket"),
        );
        self.link_in_root(
            "etc/tmpfiles.d/nix-daemon.conf",
            &format!("{PROFILE}/lib/tmpfiles.d/nix-daemon.conf"),
        );
        let bashrc = std::fs::read_to_string(self.path("etc/bash.bashrc")).unwrap();
        self.file("etc/bash.bashrc.backup-before-nix", &bashrc);
        self.file("etc/bash.bashrc", &format!("{HOOK}{bashrc}"));
        for stub in ["etc/bashrc", "etc/zshrc", "etc/profile.d/nix.sh"] {
            self.file(stub, HOOK);
        }
        self.link_in_root("root/.nix-profile", PROFILE);
        self.link_in_root(
            "root/.nix-defexpr/channels",
            "nix/var/nix/profiles/per-user/root/channels",
        );
    }

    /// Nix's uninstall steps for a multi-user install on Linux with systemd:
    /// the units disabled, the files removed, `userdel` for each build user
    /// and then `groupdel`, and the references to Nix taken out of the shell
    /// startup files, `/etc/bash.bashrc` by moving its backup back and the
    /// stubs the installer made by removing them. Each `userdel` changes all
    /// four account files, so their copies keep the last build user, and the
    /// `groupdel` the group and its shadow file, whose copies keep the group.
    fn uninstall_nix(&self) {
        for unit in [
            "etc/systemd/system/nix-daemon.service",
            "etc/systemd/system/nix-daemon.socket",
            "etc/systemd/system/sockets.target.wants/nix-daemon.socket",
        ] {
            self.remove(unit);
        }
        for path in [
            "etc/nix",
            "etc/profile.d/nix.sh",
            "etc/tmpfiles.d/nix-daemon.conf",
            "nix",
            "root/.nix-defexpr",
            "root/.nix-profile",
        ] {
            self.remove(path);
        }
        let last = "nixbld32:x:30032:30000:Nix build user 32:/var/empty:/sbin/nologin\n";
        self.file("etc/passwd", STOCK_PASSWD);
        self.file("etc/passwd-", &format!("{STOCK_PASSWD}{last}"));
        self.file("etc/shadow", STOCK_SHADOW);
        self.file(
            "etc/shadow-",
            &format!("{STOCK_SHADOW}nixbld32:!:20000::::::\n"),
        );
        self.file("etc/group", STOCK_GROUP);
        self.file("etc/group-", &format!("{STOCK_GROUP}nixbld:x:30000:\n"));
        self.file("etc/gshadow", STOCK_GSHADOW);
        self.file("etc/gshadow-", &format!("{STOCK_GSHADOW}nixbld:!::\n"));
        std::fs::rename(
            self.path("etc/bash.bashrc.backup-before-nix"),
            self.path("etc/bash.bashrc"),
        )
        .unwrap();
        for stub in ["etc/bashrc", "etc/zshrc"] {
            self.remove(stub);
        }
    }

    /// What Nix's single-user installer writes for alice, run as her with
    /// `--no-daemon`: the store, owned by her, her profile and channel links,
    /// the hook in the first of `.bash_profile`, `.bash_login` and `.profile`
    /// and in the first of `.zshenv` and `.zshrc` that she can write, and the
    /// Fish hook, as her `~/.config/fish` exists.
    fn install_nix_for_alice(&self) {
        self.dir("nix/store");
        self.dir("nix/var/nix/profiles/per-user/alice");
        self.link_in_root(
            "home/alice/.nix-profile",
            "nix/var/nix/profiles/per-user/alice/profile",
        );
        self.dir("home/alice/.nix-defexpr");
        self.file(
            "home/alice/.nix-channels",
            "https://nixos.org/channels/nixpkgs-unstable nixpkgs\n",
        );
        self.append("home/alice/.profile", USER_HOOK);
        self.file("home/alice/.zshrc", USER_HOOK);
        self.file(
            "home/alice/.config/fish/conf.d/nix.fish",
            "\nif test -e /home/alice/.nix-profile/etc/profile.d/nix.fish; . \
             /home/alice/.nix-profile/etc/profile.d/nix.fish; end # added by Nix installer\n",
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
         /etc/tmpfiles.d/nix-daemon.conf, /etc/nix, the nixbld group (in /etc/group, \
         /etc/gshadow, /etc/group- and /etc/gshadow-), 32 Nix build users (nixbld1, nixbld2 \
         and 30 more, in /etc/passwd, /etc/shadow, /etc/passwd- and /etc/shadow-), \
         /etc/profile.d/nix.sh, the Nix lines in /etc/bashrc, the Nix lines in \
         /etc/bash.bashrc, the Nix lines in /etc/zshrc, /etc/bash.bashrc.backup-before-nix, \
         /root/.nix-profile and /root/.nix-defexpr."
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
    // Every link the installer made leads to nothing now.
    for link in [
        "etc/systemd/system/nix-daemon.socket",
        "etc/systemd/system/sockets.target.wants/nix-daemon.socket",
        "etc/tmpfiles.d/nix-daemon.conf",
        "root/.nix-profile",
    ] {
        assert!(decoy.path(link).is_symlink(), "{link}");
        assert!(!decoy.path(link).exists(), "{link} leads somewhere");
    }
    let warning = decoy.warning();
    assert!(!warning.contains("/nix,"), "{warning}");
    assert!(!warning.contains("/etc/nix,"), "{warning}");
    for left in [
        "/etc/systemd/system/nix-daemon.socket",
        "/etc/systemd/system/sockets.target.wants/nix-daemon.socket",
        "/etc/tmpfiles.d/nix-daemon.conf",
        "the nixbld group (in /etc/group,",
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

/// A Nix built from source and installed below /usr/local is named: its
/// command, its units in the administrator's unit directory below
/// /usr/local, and its Fish hook below the Fish prefix there.
#[test]
fn a_nix_installed_below_usr_local_is_named() {
    let decoy = Decoy::stock();
    decoy.file("usr/local/bin/nix", "\x7fELF");
    decoy.file(
        "usr/local/lib/systemd/system/nix-daemon.service",
        "[Service]\n",
    );
    decoy.file(
        "usr/local/lib/systemd/system/nix-daemon.socket",
        "[Socket]\n",
    );
    decoy.file("usr/local/etc/fish/conf.d/nix.fish", "# Nix\n");
    assert_eq!(
        decoy.warning(),
        "Nix is installed on the decoy, or was: it holds \
         /usr/local/lib/systemd/system/nix-daemon.service, \
         /usr/local/lib/systemd/system/nix-daemon.socket, /usr/local/bin/nix and \
         /usr/local/etc/fish/conf.d/nix.fish."
    );
}

/// The multi-user installer's Fish hook is named below each Fish prefix it
/// writes to.
#[test]
fn the_fish_hook_is_named_below_each_prefix() {
    let decoy = Decoy::stock();
    for prefix in [
        "etc/fish",
        "usr/local/etc/fish",
        "opt/homebrew/etc/fish",
        "opt/local/etc/fish",
    ] {
        decoy.file(&format!("{prefix}/conf.d/nix.fish"), "# Nix\n");
    }
    assert_eq!(
        decoy.warning(),
        "Nix is installed on the decoy, or was: it holds /etc/fish/conf.d/nix.fish, \
         /usr/local/etc/fish/conf.d/nix.fish, /opt/homebrew/etc/fish/conf.d/nix.fish and \
         /opt/local/etc/fish/conf.d/nix.fish."
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
        "Nix is installed on the decoy, or was: it holds the nixbld group (in /etc/group) and 2 \
         Nix build users (_nixbld1 and builder, in /etc/passwd)."
    );

    // A shadow file names no group, so its users count by name alone; the
    // copy of /etc/passwd counts by group as /etc/passwd does.
    decoy.append(
        "etc/shadow",
        "builder:!:20000::::::\nnixbld9:!:20000::::::\n",
    );
    decoy.append(
        "etc/passwd-",
        "builder2:x:30004:30000::/var/empty:/sbin/nologin\n",
    );
    assert_eq!(
        decoy.warning(),
        "Nix is installed on the decoy, or was: it holds the nixbld group (in /etc/group) and 4 \
         Nix build users (_nixbld1, builder and 2 more, in /etc/passwd, /etc/shadow and \
         /etc/passwd-)."
    );
}

/// Nix's own uninstall steps delete the build users and the group with
/// `userdel` and `groupdel`, and the copies shadow-utils keeps of the account
/// files still name the group and the last user deleted: so the check names
/// them after the uninstall, and passes once the copies are clean.
#[test]
fn what_the_documented_uninstall_leaves_is_named() {
    let decoy = Decoy::stock();
    decoy.install_nix();
    decoy.uninstall_nix();
    assert_eq!(
        decoy.warning(),
        "Nix is installed on the decoy, or was: it holds the nixbld group (in /etc/group- and \
         /etc/gshadow-) and the Nix build user nixbld32 (in /etc/passwd- and /etc/shadow-)."
    );

    for file in ["passwd", "shadow", "group", "gshadow"] {
        let text = std::fs::read_to_string(decoy.path(&format!("etc/{file}"))).unwrap();
        decoy.file(&format!("etc/{file}-"), &text);
    }
    assert_eq!(
        decoy.check(false),
        CheckResult::Pass("no trace of a Nix install on the decoy".to_string())
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
        "Nix is installed on the decoy, or was: it holds the nixbld group (in /etc/group)."
    );
}

#[test]
fn build_users_are_counted_past_three() {
    let names =
        |count: usize| -> Vec<String> { (1..=count).map(|n| format!("nixbld{n}")).collect() };
    let passwd = ["/etc/passwd".to_string()];
    assert_eq!(build_users(&[], &passwd), "");
    assert_eq!(
        build_users(&names(1), &passwd),
        "the Nix build user nixbld1 (in /etc/passwd)"
    );
    assert_eq!(
        build_users(&names(2), &passwd),
        "2 Nix build users (nixbld1 and nixbld2, in /etc/passwd)"
    );
    assert_eq!(
        build_users(&names(3), &passwd),
        "3 Nix build users (nixbld1, nixbld2 and nixbld3, in /etc/passwd)"
    );
    assert_eq!(
        build_users(
            &names(4),
            &["/etc/passwd".to_string(), "/etc/shadow".to_string()]
        ),
        "4 Nix build users (nixbld1, nixbld2 and 2 more, in /etc/passwd and /etc/shadow)"
    );
}

/// A shell startup file counts only where it names a script of a Nix
/// profile, the default one as the multi-user installer's hook does or a
/// user's own as the single-user installer's does; other mentions of Nix do
/// not.
#[test]
fn a_startup_file_counts_only_with_the_profile_hook() {
    let decoy = Decoy::stock();
    decoy.file("etc/zsh/zshrc", "alias nb='nix build'\n# nix is fun\n");
    decoy.append("home/alice/.bashrc", "alias ns='nix-shell'\n");
    decoy.append(
        "etc/bash.bashrc",
        "[ -e /nix/var/nix/profiles/default/etc/profile.d/nix.sh ] && . /nix/var/nix/profiles/default/etc/profile.d/nix.sh\n",
    );
    assert_eq!(
        decoy.warning(),
        "Nix is installed on the decoy, or was: it holds the Nix lines in /etc/bash.bashrc."
    );

    // Each system startup file is read, /etc/profile among them, and either
    // hook counts in it.
    decoy.append("etc/zsh/zshrc", HOOK);
    decoy.append(
        "etc/profile",
        ". \"$HOME/.nix-profile/etc/profile.d/nix.sh\"\n",
    );
    assert_eq!(
        decoy.warning(),
        "Nix is installed on the decoy, or was: it holds the Nix lines in /etc/bash.bashrc, the \
         Nix lines in /etc/profile and the Nix lines in /etc/zsh/zshrc."
    );
}

/// What the single-user installer writes in a home is named, and what a
/// removal of the store and the profile links leaves there: the hooks in the
/// shell startup files and the Fish hook.
#[test]
fn what_the_single_user_installer_writes_in_a_home_is_named() {
    let decoy = Decoy::stock();
    decoy.install_nix_for_alice();
    assert_eq!(
        decoy.warning(),
        "Nix is installed on the decoy, or was: it holds /nix, /home/alice/.nix-profile, \
         /home/alice/.nix-defexpr, /home/alice/.nix-channels, \
         /home/alice/.config/fish/conf.d/nix.fish, the Nix lines in /home/alice/.profile and \
         the Nix lines in /home/alice/.zshrc."
    );

    for path in [
        "nix",
        "home/alice/.nix-profile",
        "home/alice/.nix-defexpr",
        "home/alice/.nix-channels",
    ] {
        decoy.remove(path);
    }
    assert_eq!(
        decoy.warning(),
        "Nix is installed on the decoy, or was: it holds \
         /home/alice/.config/fish/conf.d/nix.fish, the Nix lines in /home/alice/.profile and \
         the Nix lines in /home/alice/.zshrc."
    );

    // Each startup file of a home is read, and a hook in it counts.
    decoy.remove("home/alice/.config");
    decoy.remove("home/alice/.zshrc");
    decoy.file("home/alice/.profile", "");
    for file in [".bash_profile", ".bash_login", ".bashrc", ".zshenv"] {
        decoy.file(&format!("home/alice/{file}"), USER_HOOK);
    }
    assert_eq!(
        decoy.warning(),
        "Nix is installed on the decoy, or was: it holds the Nix lines in \
         /home/alice/.bash_profile, the Nix lines in /home/alice/.bash_login, the Nix lines in \
         /home/alice/.bashrc and the Nix lines in /home/alice/.zshenv."
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
    decoy.file("root/.local/share/nix/trusted-settings.json", "{}\n");
    decoy.dir("home/alice/.cache/nix");
    decoy.dir("home/alice/.local/state/nix");
    decoy.file("home/alice/.local/share/nix/repl-history", "1 + 1\n");
    decoy.file("home/bob/.nix-channels", "");
    decoy.dir(".nix-profile");
    // The hidden volume's own files are not the decoy's, whether the home
    // lies there as named or a link leads there.
    decoy.append(
        "etc/passwd",
        "dave:x:1003:1003::/mnt/data/dave:/bin/bash\neve:x:1004:1004::/home/eve:/bin/bash\n",
    );
    decoy.dir("mnt/data/dave/.nix-profile");
    decoy.dir("mnt/data/eve/.nix-profile");
    decoy.file("mnt/data/eve/.profile", USER_HOOK);
    decoy.link("home/eve", "../mnt/data/eve");
    let result = DecoyNixTraceCheck::new(decoy.path("mnt/data"), false)
        .with_root(&decoy.root)
        .run(&RealFilesystem)
        .unwrap();
    assert!(result.is_warn(), "{result:?}");
    let warning = result.message().lines().next().unwrap().to_string();
    assert_eq!(
        warning,
        "Nix is installed on the decoy, or was: it holds /root/.local/share/nix, \
         /root/.config/nix, /home/alice/.local/state/nix, /home/alice/.local/share/nix, \
         /home/alice/.cache/nix and /home/bob/.nix-channels."
    );
}

/// A home that is a file holds nothing of Nix and is no reason to doubt.
#[test]
fn a_home_that_is_a_file_holds_nothing() {
    let decoy = Decoy::stock();
    decoy.file("var/odd", "");
    decoy.append(
        "etc/passwd",
        "odd:x:1005:1005::/var/odd:/usr/sbin/nologin\n",
    );
    assert_eq!(
        decoy.check(false),
        CheckResult::Pass("no trace of a Nix install on the decoy".to_string())
    );
}

/// The decoy's root filesystem, as the mount table lists it.
const ROOT_MOUNT: &str = "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n";

/// The directory of an indirect map at `/net`, as the automounter mounts it:
/// a lookup of a name in it mounts that name, while the directory itself is
/// no automount point.
const NET_MAP: &str = "40 1 0:60 / /net rw,relatime - autofs /etc/auto.net \
                       rw,fd=7,pgrp=900,timeout=300,minproto=5,maxproto=5,indirect,pipe_ino=200\n";

/// What the automounter mounts for the name `srv` of that map.
const NET_SRV: &str = "41 40 0:61 / /net/srv rw,relatime - nfs4 srv:/export rw,vers=4.2\n";

/// The accounts of root and of bob, whose home leads onto the share.
const BOB_PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
                          bob:x:1001:1001:Bob:/home/bob:/bin/bash\n";

/// The account of root alone.
const ROOT_PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n";

/// The first line of what the check says on `fs`.
fn first_line(fs: &MockFilesystem) -> String {
    let result = DecoyNixTraceCheck::new(PathBuf::from("/mnt/data"), false)
        .run(fs)
        .unwrap();
    assert!(result.is_warn() || result.is_pass(), "{result:?}");
    result.message().lines().next().unwrap().to_string()
}

/// Why the check does not look up each of `paths`, behind the automount
/// point `point`, as the warning says it.
fn behind(point: &str, paths: &[&str]) -> String {
    let reasons: Vec<String> = paths
        .iter()
        .map(|path| {
            format!(
                "NAILS does not look up {path}, since the lookup would mount the automount \
                 point {point}"
            )
        })
        .collect();
    format!(
        "NAILS cannot tell whether a Nix install left traces on the decoy: {}.",
        reasons.join("; ")
    )
}

/// A home behind an automount point that nothing is mounted on yet is not
/// looked into, since the lookup would mount it, and the warning names it;
/// once the automount is mounted, the home is looked into. An automount
/// point whose type the table does not give counts as one itself.
#[test]
fn a_home_behind_an_automount_point_is_named_and_not_looked_into() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/passwd", STOCK_PASSWD);
    fs.mock_set_path_type("/home/alice/.nix-profile", PathKind::Symlink);
    fs.mock_set_mount_table(&format!(
        "{ROOT_MOUNT}30 1 0:50 / /home rw,relatime - autofs systemd-1 rw,fd=50\n"
    ));
    let check = DecoyNixTraceCheck::new(PathBuf::from("/mnt/data"), false);
    let result = check.run(&fs).unwrap();
    assert!(result.is_warn(), "{result:?}");
    assert_eq!(
        result.message().lines().next().unwrap(),
        "NAILS cannot tell whether a Nix install left traces on the decoy: NAILS does not look \
         into /home/alice, since the lookup would mount the automount point /home."
    );

    fs.mock_set_mount_table(&format!(
        "{ROOT_MOUNT}30 1 0:50 / /home rw,relatime - autofs systemd-1 rw,fd=50\n\
         31 30 8:2 / /home rw,relatime - ext4 /dev/sda2 rw\n"
    ));
    let result = check.run(&fs).unwrap();
    assert_eq!(
        result.message().lines().next().unwrap(),
        "Nix is installed on the decoy, or was: it holds /home/alice/.nix-profile."
    );
}

/// A home whose link leads behind an automount point that nothing is
/// mounted on yet, a name of an indirect map here, is not looked into
/// either, and the warning names it. The directory of the map mounts
/// nothing itself: once the name is mounted, the lookup passes it and the
/// home is looked into.
#[test]
fn a_home_whose_link_leads_behind_an_automount_point_is_named_and_not_looked_into() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/passwd", BOB_PASSWD);
    fs.create_symlink(Path::new("/net/srv/bob"), Path::new("/home/bob"))
        .unwrap();
    // The mock reads each path as it is named, so what Nix keeps in the home
    // is set where the check names it.
    fs.mock_set_path_type("/home/bob/.nix-profile", PathKind::Symlink);
    fs.mock_set_mount_table(&format!("{ROOT_MOUNT}{NET_MAP}"));
    assert_eq!(
        first_line(&fs),
        "NAILS cannot tell whether a Nix install left traces on the decoy: NAILS does not look \
         into /home/bob, since the lookup would mount the automount point /net/srv."
    );

    fs.mock_set_mount_table(&format!("{ROOT_MOUNT}{NET_MAP}{NET_SRV}"));
    assert_eq!(
        first_line(&fs),
        "Nix is installed on the decoy, or was: it holds /home/bob/.nix-profile."
    );
}

/// A path below a direct automount point, as systemd makes one for
/// `x-systemd.automount`, is not looked up while nothing is mounted there,
/// and the warning names each; once it is mounted, they are looked up.
#[test]
fn a_path_behind_an_automount_point_is_named_and_not_looked_up() {
    let automount = "30 1 0:50 / /usr/local rw,relatime - autofs systemd-1 \
                     rw,fd=50,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=100\n";
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/passwd", ROOT_PASSWD);
    fs.mock_set_path_type("/usr/local/bin/nix", PathKind::Symlink);
    fs.mock_set_mount_table(&format!("{ROOT_MOUNT}{automount}"));
    assert_eq!(
        first_line(&fs),
        behind(
            "/usr/local",
            &[
                "/usr/local/lib/systemd/system/nix-daemon.service",
                "/usr/local/lib/systemd/system/nix-daemon.socket",
                "/usr/local/bin/nix",
                "/usr/local/etc/fish/conf.d/nix.fish",
            ]
        )
    );

    fs.mock_set_mount_table(&format!(
        "{ROOT_MOUNT}{automount}31 30 8:3 / /usr/local rw,relatime - ext4 /dev/sda3 rw\n"
    ));
    assert_eq!(
        first_line(&fs),
        "Nix is installed on the decoy, or was: it holds /usr/local/bin/nix."
    );
}

/// A link on the way to a path is read and followed to where it leads, a
/// relative one with `..` too, before the lookup: one that leads behind an
/// automount point keeps each path below it from being looked up.
#[test]
fn a_link_on_the_way_is_followed_where_it_leads_before_the_lookup() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/passwd", ROOT_PASSWD);
    fs.create_symlink(Path::new("../net/srv/local"), Path::new("/usr/local"))
        .unwrap();
    fs.mock_set_path_type("/usr/local/bin/nix", PathKind::Symlink);
    fs.mock_set_mount_table(&format!("{ROOT_MOUNT}{NET_MAP}"));
    assert_eq!(
        first_line(&fs),
        behind(
            "/net/srv",
            &[
                "/usr/local/lib/systemd/system/nix-daemon.service",
                "/usr/local/lib/systemd/system/nix-daemon.socket",
                "/usr/local/bin/nix",
                "/usr/local/etc/fish/conf.d/nix.fish",
            ]
        )
    );

    fs.mock_set_mount_table(&format!("{ROOT_MOUNT}{NET_MAP}{NET_SRV}"));
    assert_eq!(
        first_line(&fs),
        "Nix is installed on the decoy, or was: it holds /usr/local/bin/nix."
    );
}

/// A link a lookup ends in is not followed, as `/nix` is looked up: the link
/// is the trace, wherever it leads.
#[test]
fn a_link_at_the_end_of_a_lookup_is_named_and_not_followed() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/passwd", ROOT_PASSWD);
    fs.create_symlink(Path::new("/net/srv/nix"), Path::new("/nix"))
        .unwrap();
    fs.mock_set_mount_table(&format!("{ROOT_MOUNT}{NET_MAP}"));
    assert_eq!(
        first_line(&fs),
        "Nix is installed on the decoy, or was: it holds /nix."
    );
}

/// A file the check reads, a startup file of a home here, whose link leads
/// behind an automount point is not read, and the warning names it.
#[test]
fn a_file_whose_link_leads_behind_an_automount_point_is_not_read() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/passwd", STOCK_PASSWD);
    fs.mock_set_path_type("/home/alice", PathKind::Dir);
    fs.create_symlink(
        Path::new("/net/srv/dotfiles/bashrc"),
        Path::new("/home/alice/.bashrc"),
    )
    .unwrap();
    fs.mock_set_mount_table(&format!("{ROOT_MOUNT}{NET_MAP}"));
    assert_eq!(
        first_line(&fs),
        behind("/net/srv", &["/home/alice/.bashrc"])
    );
}

/// A unit directory whose link leads behind an automount point is neither
/// resolved nor listed, and nothing in it is looked up.
#[test]
fn a_unit_directory_behind_an_automount_point_is_not_listed() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/passwd", ROOT_PASSWD);
    fs.create_symlink(
        Path::new("/net/srv/units"),
        Path::new("/etc/systemd/system"),
    )
    .unwrap();
    fs.mock_set_mount_table(&format!("{ROOT_MOUNT}{NET_MAP}"));
    assert_eq!(
        first_line(&fs),
        behind(
            "/net/srv",
            &[
                "/etc/systemd/system/nix-daemon.service",
                "/etc/systemd/system/nix-daemon.socket",
                "/etc/systemd/system/nix-daemon.service.d",
                "/etc/systemd/system/nix-daemon.socket.d",
                "/etc/systemd/system",
            ]
        )
    );
}

/// A lookup follows as many links as the kernel follows in one, 40, and
/// stops at a loop.
#[test]
fn a_lookup_follows_as_many_links_as_the_kernel_and_ends_at_a_loop() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/passwd", BOB_PASSWD);
    // /home/bob, /l1, ..., /l39: 40 links, the last onto the share.
    fs.create_symlink(Path::new("/l1"), Path::new("/home/bob"))
        .unwrap();
    for n in 1..39 {
        fs.create_symlink(
            Path::new(&format!("/l{}", n + 1)),
            Path::new(&format!("/l{n}")),
        )
        .unwrap();
    }
    fs.create_symlink(Path::new("/net/srv/bob"), Path::new("/l39"))
        .unwrap();
    fs.mock_set_mount_table(&format!("{ROOT_MOUNT}{NET_MAP}"));
    assert_eq!(
        first_line(&fs),
        "NAILS cannot tell whether a Nix install left traces on the decoy: NAILS does not look \
         into /home/bob, since the lookup would mount the automount point /net/srv."
    );

    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/passwd", BOB_PASSWD);
    fs.create_symlink(Path::new("/home/bob"), Path::new("/home/bob"))
        .unwrap();
    fs.mock_set_mount_table(&format!("{ROOT_MOUNT}{NET_MAP}"));
    assert_eq!(
        first_line(&fs),
        "NAILS cannot tell whether a Nix install left traces on the decoy: NAILS cannot look \
         into /home/bob (/home/bob: Too many levels of symbolic links (os error 40))."
    );
}

/// The direct automount point at `/usr/local`, as systemd makes one for
/// `x-systemd.automount`, that nothing is mounted on yet.
const USR_LOCAL: &str = "30 1 0:50 / /usr/local rw,relatime - autofs systemd-1 \
                         rw,fd=50,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=100\n";

/// The check's result on `fs`, read as the running system.
fn run_on(fs: &MockFilesystem) -> CheckResult {
    DecoyNixTraceCheck::new(PathBuf::from("/mnt/data"), false)
        .run(fs)
        .unwrap()
}

/// Whether `fs` looked up `point` or a path below it, its links on the way
/// followed.
fn reached(fs: &MockFilesystem, point: &str) -> bool {
    fs.mock_reached(Path::new(point))
}

/// Each automount point the check did not look behind is named, and the
/// warning ends with one fix that mounts them all and runs the check
/// again; nothing at or below a point is looked up, the guard's own
/// reading of the way included.
#[test]
fn the_warning_says_once_to_mount_each_point_and_nothing_behind_one_is_looked_up() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/passwd", BOB_PASSWD);
    fs.create_symlink(Path::new("/net/srv/bob"), Path::new("/home/bob"))
        .unwrap();
    fs.mock_set_mount_table(&format!("{ROOT_MOUNT}{USR_LOCAL}{NET_MAP}"));
    let result = run_on(&fs);
    assert!(result.is_warn(), "{result:?}");
    let message = result.message();
    assert!(
        message.contains(
            "NAILS does not look up /usr/local/bin/nix, since the lookup would mount the \
             automount point /usr/local"
        ),
        "{message}"
    );
    assert!(
        message.contains(
            "NAILS does not look into /home/bob, since the lookup would mount the automount \
             point /net/srv"
        ),
        "{message}"
    );
    let lines: Vec<&str> = message.lines().collect();
    assert_eq!(
        lines[1..],
        [
            "See docs/decoy-requirements.md#nix-on-the-decoy.".to_string(),
            crate::filesystem::automount::mount_fix(&[
                Path::new("/usr/local"),
                Path::new("/net/srv")
            ])
        ]
    );
    assert!(!reached(&fs, "/usr/local"), "{:?}", fs.mock_lookups());
    assert!(!reached(&fs, "/net/srv"), "{:?}", fs.mock_lookups());
}

/// A trace is whatever is at its path: a link counts as there without its
/// target being looked up, also where that target cannot be.
#[test]
fn a_link_counts_as_a_trace_whatever_it_leads_to() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/passwd", ROOT_PASSWD);
    fs.mock_set_lookup_error("/srv/locked", std::io::ErrorKind::PermissionDenied);
    fs.create_symlink(Path::new("/srv/locked/nix"), Path::new("/nix"))
        .unwrap();
    fs.mock_set_mount_table(ROOT_MOUNT);
    assert_eq!(
        first_line(&fs),
        "Nix is installed on the decoy, or was: it holds /nix."
    );
}

/// A path that cannot be looked up is named by why: one NAILS may not look
/// up asks for sudo, any other names its error, and neither is taken for a
/// path that is not there.
#[test]
fn a_path_that_cannot_be_looked_up_is_named_by_why() {
    for (kind, reason) in [
        (
            std::io::ErrorKind::PermissionDenied,
            "NAILS cannot look up /etc/nix; run the command again with sudo",
        ),
        (
            std::io::ErrorKind::Other,
            "NAILS cannot look up /etc/nix (/etc/nix: Mock: the lookup fails here)",
        ),
    ] {
        let fs = MockFilesystem::new();
        fs.mock_add_file("/etc/passwd", ROOT_PASSWD);
        fs.mock_set_lookup_error("/etc/nix", kind);
        fs.mock_set_mount_table(ROOT_MOUNT);
        assert_eq!(
            first_line(&fs),
            format!("NAILS cannot tell whether a Nix install left traces on the decoy: {reason}."),
            "{kind:?}"
        );
    }
}

/// A home that cannot be looked into is named once, by why, and nothing in
/// it is looked up.
#[test]
fn a_home_that_cannot_be_looked_into_is_named_once() {
    for (kind, reason) in [
        (
            std::io::ErrorKind::PermissionDenied,
            "NAILS cannot look into /home/alice; run the command again with sudo",
        ),
        (
            std::io::ErrorKind::Other,
            "NAILS cannot look into /home/alice (/home/alice: Mock: the lookup fails here)",
        ),
    ] {
        let fs = MockFilesystem::new();
        fs.mock_add_file("/etc/passwd", STOCK_PASSWD);
        fs.mock_set_lookup_error("/home/alice", kind);
        fs.mock_set_mount_table(ROOT_MOUNT);
        assert_eq!(
            first_line(&fs),
            format!("NAILS cannot tell whether a Nix install left traces on the decoy: {reason}."),
            "{kind:?}"
        );
        let home = Path::new("/home/alice");
        assert!(
            !fs.mock_lookups()
                .iter()
                .any(|path| path.starts_with(home) && path != home),
            "{:?}",
            fs.mock_lookups()
        );
    }
}

/// A link on the way that cannot be read, or a directory on the way that
/// cannot be looked up, is the lookup's error: it is named, never taken for
/// a way that passes no automount point, and the lookup is not made.
#[test]
fn a_way_that_cannot_be_read_is_named_with_its_error() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/passwd", ROOT_PASSWD);
    // A link the guard cannot read: the mock has no target for it.
    fs.mock_set_path_type("/usr/local", PathKind::Symlink);
    fs.mock_set_mount_table(ROOT_MOUNT);
    let result = run_on(&fs);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .contains("NAILS cannot look up /usr/local/bin/nix (/usr/local/bin/nix: invalid input"),
        "{result:?}"
    );
    assert!(
        !fs.mock_lookups()
            .contains(&PathBuf::from("/usr/local/bin/nix"))
    );

    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/passwd", ROOT_PASSWD);
    fs.mock_set_lookup_error("/usr/local", std::io::ErrorKind::PermissionDenied);
    fs.mock_set_mount_table(ROOT_MOUNT);
    let result = run_on(&fs);
    assert!(
        result
            .message()
            .contains("NAILS cannot look up /usr/local/bin/nix; run the command again with sudo"),
        "{result:?}"
    );
    assert!(
        !fs.mock_lookups()
            .contains(&PathBuf::from("/usr/local/bin/nix"))
    );
}

/// Without the running system's mount table NAILS cannot tell where a
/// lookup would mount an automount point, so it looks up nothing, and the
/// warning says why.
#[test]
fn without_the_mount_table_nothing_is_looked_up() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/nix", PathKind::Dir);
    fs.mock_set_mount_table_error("no mountinfo");
    let line = first_line(&fs);
    assert!(
        line.starts_with(
            "NAILS cannot tell whether a Nix install left traces on the decoy: NAILS cannot read \
             the mount table ("
        ),
        "{line}"
    );
    assert!(line.contains("no mountinfo"), "{line}");
    assert!(
        line.ends_with(
            "), which shows whether a hidden session is running and where a lookup would mount \
             an automount point, so it looks up nothing."
        ),
        "{line}"
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

/// A home that cannot be looked into for a reason other than a missing or a
/// refused path is named once with its error, and the rest of it is left.
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
             look into /home/eve ("
        ),
        "{result:?}"
    );
    assert!(
        message.contains("Too many levels of symbolic links"),
        "{result:?}"
    );
    assert!(!message.contains(".nix-profile"), "{result:?}");
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
