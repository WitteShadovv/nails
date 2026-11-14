// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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
        Unusable::Unreachable("Too many levels of symbolic links (os error 40)".into()).to_string(),
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
