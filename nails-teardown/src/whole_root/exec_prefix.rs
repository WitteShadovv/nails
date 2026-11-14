// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The program PID 1 starts the binary copy through, where the session plan
//! records one ([`Plan::exec_prefix`]).
//!
//! Under SELinux a program PID 1 starts runs in the domain the policy gives
//! the type of the program's file, and in PID 1's own domain where it gives
//! that type none. The binary copy in `/run` carries the type of the files
//! there, so a step PID 1 starts from the copy itself runs in PID 1's domain,
//! which a targeted policy confines. A system program such as [`TRAMPOLINE`]
//! carries the type of the system's programs, which a targeted policy starts
//! in a service domain of its own, and `env` then runs the copy in its own
//! place: the step runs in that domain instead. So on a host that may run
//! SELinux the entry records [`TRAMPOLINE`] in the plan, and every unit and
//! drop-in by which PID 1 starts the copy starts it through the plan's prefix
//! ([`command`]):
//!
//! - the transition step's drop-in
//!   ([`crate::whole_root::transition::dropin_text`]), written once at entry
//!   and run in both directions;
//! - the hidden session's own units, the watcher and the sleep guard, whose
//!   text the entry writes into the plan
//!   ([`Plan::session_units`]);
//! - the pieces the way back leaves for the decoy's first start, the reconcile
//!   one-shot ([`crate::whole_root::boot_records`]) and the wtmpdb writer's
//!   drop-in ([`crate::whole_root::boot_writer`]).
//!
//! The udev rule that keeps unused disks read-only
//! ([`crate::whole_root::disk_guard`]) runs the copy directly: udev starts
//! it, not PID 1. Where the plan records no prefix, every one of them starts
//! the copy as before, word for word. Nothing is installed into the decoy's
//! policy.
//!
//! A step that does not start at all is worse than one that runs confined:
//! the drop-in's `-` ignores a start command that fails, and the switch goes
//! on without its step. So [`check`] tells whether a root holds the prefix as
//! PID 1 will start it there, and each root is checked before PID 1 starts
//! anything through it: the entry checks the decoy root, where the step of
//! the entry starts, and the next root, where the hidden session's units and
//! the step of the way back start; the way back checks the hidden root again
//! before it prepares anything, and the decoy root it mounts, where its pieces
//! for the decoy's first start run ([`crate::whole_root::ret`]).
//!
//! [`Plan::exec_prefix`]: crate::whole_root::plan::Plan::exec_prefix
//! [`Plan::session_units`]: crate::whole_root::plan::Plan::session_units

use crate::whole_root::nextroot;
use std::path::Path;

/// The program PID 1 starts the binary copy through on a host that may run
/// SELinux: given a program and its arguments, `env` runs that program in its
/// own place, and it takes no word after the program for an option of its
/// own.
pub const TRAMPOLINE: &str = "/usr/bin/env";

/// What PID 1 runs to start the binary copy at `binary`: `binary` alone, or
/// `prefix binary` where the plan records a `prefix`. The caller appends the
/// copy's arguments. `binary` is an absolute path, so `env` never reads it as
/// an option, and none of the copies' paths holds a `=`, which `env` would
/// read as a variable to set.
pub fn command(prefix: Option<&Path>, binary: &Path) -> String {
    match prefix {
        Some(prefix) => format!("{} {}", prefix.display(), binary.display()),
        None => binary.display().to_string(),
    }
}

/// Why a root cannot start the binary copy through a prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unusable {
    /// The prefix is not an absolute path of plain names ([`is_plain`]).
    NotPlain,
    /// Nothing is there, or a link on the way leads nowhere.
    Absent,
    /// The lookup failed otherwise, at a loop of links or a directory it may
    /// not search, say: its error.
    Unreachable(String),
    /// It resolves to something other than an executable regular file.
    NotExecutable,
}

/// What the prefix is or does in the root, to follow its path in a sentence:
/// "/usr/bin/env does not exist".
impl std::fmt::Display for Unusable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unusable::NotPlain => write!(f, "is not an absolute path of plain names"),
            Unusable::Absent => write!(f, "does not exist"),
            Unusable::Unreachable(why) => write!(f, "cannot be looked up: {why}"),
            Unusable::NotExecutable => write!(f, "is not an executable file"),
        }
    }
}

/// Whether `prefix` is an absolute path of plain names, written as such: a
/// `/` before each name, none after the last, each name made of ASCII letters,
/// digits, `.`, `_`, `+` and `-` and none of them `.` or `..`. systemd reads
/// such a path from a unit file's start command word for word, with no
/// specifier, quote, escape or variable in it to expand, so the command starts
/// the program the plan names.
pub fn is_plain(prefix: &Path) -> bool {
    let Some(names) = prefix.to_str().and_then(|text| text.strip_prefix('/')) else {
        return false;
    };
    names.split('/').all(|name| {
        !matches!(name, "" | "." | "..")
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    })
}

/// Check that `prefix` starts in `root` as PID 1 starts it once `root` is its
/// root: a plain absolute path ([`is_plain`]) that resolves inside `root`, its
/// links followed there as PID 1's start of it follows them, to an executable
/// regular file ([`nextroot::executable_in_root`]). The lookup reads no file,
/// so the program's access time stays as it is; a link on the way gets one,
/// as when PID 1 starts the program.
pub fn check(root: &Path, prefix: &Path) -> Result<(), Unusable> {
    if !is_plain(prefix) {
        return Err(Unusable::NotPlain);
    }
    match nextroot::executable_in_root(root, prefix) {
        Ok(true) => Ok(()),
        Ok(false) => Err(Unusable::NotExecutable),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Unusable::Absent),
        Err(e) => Err(Unusable::Unreachable(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::write_executable;
    use crate::whole_root::boot_records::{FIXUP_BINARY, FIXUP_DIR_PATH};
    use crate::whole_root::plan::{BINARY_NAME, RUNTIME_DIR};
    use std::os::unix::fs::symlink;

    #[test]
    fn without_a_prefix_the_copy_starts_as_before_and_with_one_through_it() {
        let binary = Path::new("/run/overlay-runtime/control");
        assert_eq!(command(None, binary), "/run/overlay-runtime/control");
        assert_eq!(
            command(Some(Path::new(TRAMPOLINE)), binary),
            "/usr/bin/env /run/overlay-runtime/control"
        );
    }

    /// Every copy PID 1 starts lies at a path that `env` takes for the program
    /// to run, never for an option or a variable to set, and that a unit file
    /// line holds word for word.
    #[test]
    fn the_trampoline_and_every_copy_are_plain_paths() {
        assert!(is_plain(Path::new(TRAMPOLINE)));
        for copy in [
            Path::new(RUNTIME_DIR).join(BINARY_NAME),
            Path::new(FIXUP_DIR_PATH).join(FIXUP_BINARY),
        ] {
            assert!(is_plain(&copy), "{}", copy.display());
        }
    }

    #[test]
    fn only_an_absolute_path_of_plain_names_is_plain() {
        for plain in ["/usr/bin/env", "/bin/x86_64-env+1.2", "/.env"] {
            assert!(is_plain(Path::new(plain)), "{plain}");
        }
        for odd in [
            "",
            "/",
            "usr/bin/env",
            "./env",
            "/usr//bin/env",
            "/usr/bin/env/",
            "/usr/./bin/env",
            "/usr/../bin/env",
            "/usr/bin/my env",
            "/usr/bin/%n",
            "/usr/bin/$ENV",
            "/usr/bin/a\\x20b",
            "/usr/bin/\"env\"",
            "/usr/bin/a;b",
            "/usr/bin/a=b",
            "/usr/bin/\u{e9}nv",
            "/usr/bin/env\n",
        ] {
            assert!(!is_plain(Path::new(odd)), "{odd:?}");
        }
    }

    #[test]
    fn a_root_holds_the_prefix_only_as_an_executable_file() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let env = Path::new(TRAMPOLINE);
        assert_eq!(check(root, env), Err(Unusable::Absent));

        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::create_dir(root.join("usr/bin/env")).unwrap();
        assert_eq!(check(root, env), Err(Unusable::NotExecutable), "a folder");
        std::fs::remove_dir(root.join("usr/bin/env")).unwrap();

        write_executable(&root.join("usr/bin/env"), "#!/bin/sh\n", 0o644);
        assert_eq!(check(root, env), Err(Unusable::NotExecutable), "no x bit");

        write_executable(&root.join("usr/bin/env"), "#!/bin/sh\n", 0o755);
        assert_eq!(check(root, env), Ok(()));

        assert_eq!(
            check(root, Path::new("/usr/bin/../bin/env")),
            Err(Unusable::NotPlain)
        );
    }

    /// A multi-call build of the tools installs `env` as a link to one
    /// program: it starts as that program does, and the link is followed
    /// inside the root, as PID 1 follows it once the root is its own.
    #[test]
    fn a_link_is_followed_inside_the_root() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let env = Path::new(TRAMPOLINE);
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        symlink("coreutils", root.join("usr/bin/env")).unwrap();
        assert_eq!(check(root, env), Err(Unusable::Absent), "a link to nothing");
        write_executable(&root.join("usr/bin/coreutils"), "", 0o755);
        assert_eq!(check(root, env), Ok(()));

        // An absolute link resolves in the root, never on the running system,
        // where /usr/bin/env exists.
        std::fs::remove_file(root.join("usr/bin/env")).unwrap();
        symlink("/usr/bin/missing", root.join("usr/bin/env")).unwrap();
        assert_eq!(check(root, env), Err(Unusable::Absent));
        symlink("/usr/bin/coreutils", root.join("usr/bin/missing")).unwrap();
        assert_eq!(check(root, env), Ok(()));

        // A loop of links is no program either.
        std::fs::remove_file(root.join("usr/bin/missing")).unwrap();
        symlink("/usr/bin/env", root.join("usr/bin/missing")).unwrap();
        assert!(
            matches!(check(root, env), Err(Unusable::Unreachable(_))),
            "{:?}",
            check(root, env)
        );
    }

    #[test]
    fn the_reasons_read_after_the_path_in_a_sentence() {
        assert_eq!(Unusable::Absent.to_string(), "does not exist");
        assert_eq!(
            Unusable::Unreachable("Too many levels of symbolic links (os error 40)".into())
                .to_string(),
            "cannot be looked up: Too many levels of symbolic links (os error 40)"
        );
        assert_eq!(
            Unusable::NotExecutable.to_string(),
            "is not an executable file"
        );
        assert_eq!(
            Unusable::NotPlain.to_string(),
            "is not an absolute path of plain names"
        );
    }
}
