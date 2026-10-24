// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Test support shared by the crates of the workspace: writing a program that
//! a test, or the code it tests, then runs.
//!
//! It lives in this crate, below every other crate that has such tests, so
//! that this crate's own tests can use it too; the base crate's `test_support`
//! module re-exports it for the crates above. Test-only; never in a shipped
//! binary.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// Write `contents` to `path` and give it `mode`: a stub tool, a script or a
/// copied program that the test, or the code under test, runs next.
///
/// A child process writes the file, so this process never holds a write
/// descriptor for it. A process that another test thread forks gets a copy of
/// every descriptor open at that moment, close-on-exec ones included, and keeps
/// it until it calls `exec`; running the file in that window fails with
/// `ETXTBSY` ("Text file busy"), and the code under test sees a tool that did
/// not start. Writing to a temporary name and renaming it does not help: the
/// copied descriptor still refers to the file.
///
/// # Panics
///
/// When the file cannot be written or its mode cannot be set.
pub fn write_executable(path: &Path, contents: impl AsRef<[u8]>, mode: u32) {
    let mut writer = Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\"", "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("start the writer of {}: {e}", path.display()));
    // The pipe closes at the end of this statement, so the writer sees its end.
    let written = writer
        .stdin
        .take()
        .expect("the writer's stdin is a pipe")
        .write_all(contents.as_ref());
    let status = writer.wait().expect("wait for the writer");
    assert!(status.success(), "writing {}: {status}", path.display());
    written.unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("setting the mode of {}: {e}", path.display()));
}

#[cfg(test)]
mod tests {
    use super::write_executable;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_program_runs_with_the_contents_and_the_mode_it_was_given() {
        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("a tool");
        write_executable(&tool, "#!/bin/sh\necho \"ran $1\"\n", 0o750);

        let mode = std::fs::metadata(&tool).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o750);
        let output = std::process::Command::new(&tool)
            .arg("once")
            .output()
            .unwrap();
        assert_eq!(output.stdout, b"ran once\n");

        // Bytes are written as given, and a second write replaces the first.
        let bytes: Vec<u8> = (0..=255).cycle().take(300_000).collect();
        write_executable(&tool, &bytes, 0o644);
        assert_eq!(std::fs::read(&tool).unwrap(), bytes);
        let mode = std::fs::metadata(&tool).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o644);
    }

    #[test]
    #[should_panic(expected = "writing")]
    fn a_file_that_cannot_be_created_fails_the_test() {
        let dir = tempfile::tempdir().unwrap();
        write_executable(&dir.path().join("missing/tool"), "#!/bin/sh\n", 0o755);
    }
}
