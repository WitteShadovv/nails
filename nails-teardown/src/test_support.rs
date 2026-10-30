// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Test support shared by the crates of the workspace: writing or copying a
//! program that a test, or the code it tests, then runs, and the procfs files
//! the way back writes.
//!
//! It lives in this crate, below every other crate that has such tests, so
//! that this crate's own tests can use it too; the base crate's `test_support`
//! module re-exports it for the crates above. Test-only; never in a shipped
//! binary.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// Write `contents` to `path` and give it `mode`: a stub tool or a script that
/// the test, or the code under test, runs next.
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
/// When the file cannot be written or its mode cannot be set. The message
/// carries what the writer said.
pub fn write_executable(path: &Path, contents: impl AsRef<[u8]>, mode: u32) {
    let mut writer = shell("cat > \"$1\"", &[path])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("start the writer of {}: {e}", path.display()));
    // The pipe closes at the end of this statement, so the writer sees its end.
    let written = writer
        .stdin
        .take()
        .expect("the writer's stdin is a pipe")
        .write_all(contents.as_ref());
    // A writer that failed stopped reading: what it said tells more than the
    // broken pipe.
    assert_written(path, writer.wait_with_output());
    written.unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
    set_mode(path, mode);
}

/// Copy the program at `source` to `path` and give it `mode`, as
/// [`write_executable`] writes one: a child process makes the copy, so this
/// process never holds `path` open for writing, and a large binary does not
/// pass through it.
///
/// # Panics
///
/// When the file cannot be copied or its mode cannot be set. The message
/// carries what the copier said.
pub fn copy_executable(source: &Path, path: &Path, mode: u32) {
    let copier = shell("cat < \"$1\" > \"$2\"", &[source, path]).output();
    assert_written(path, copier);
    set_mode(path, mode);
}

/// `/bin/sh` running `script` with `args` as `$1`, `$2` and so on. Its stderr
/// is kept for the panic message rather than mixed into the test's output.
fn shell(script: &str, args: &[&Path]) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", script, "sh"])
        .args(args)
        .stderr(Stdio::piped());
    command
}

/// Panic unless the child that wrote `path` finished well, with what it said
/// on a line of its own.
fn assert_written(path: &Path, output: std::io::Result<Output>) {
    let output = output.unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
    assert!(
        output.status.success(),
        "writing {}: {}\n{}",
        path.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim_end()
    );
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("setting the mode of {}: {e}", path.display()));
}

/// Stage a process-number counter below `root` that the way back can lower,
/// as [`crate::whole_root::fresh_pids::Places::under`] finds it: the counter
/// at 1625, and this process in PID 1's PID namespace. Staging it again
/// sets the counter back to 1625.
///
/// # Panics
///
/// When a file cannot be written.
pub fn stage_pid_counter(root: &Path) {
    let proc = root.join("proc");
    for dir in ["sys/kernel", "1/ns", "self/ns"] {
        std::fs::create_dir_all(proc.join(dir)).expect("create the procfs stand-in");
    }
    std::fs::write(proc.join("sys/kernel/ns_last_pid"), "1625\n").expect("write the counter");
    std::fs::write(proc.join("1/ns/pid"), "").expect("write the namespace");
    let link = proc.join("self/ns/pid");
    if std::fs::symlink_metadata(&link).is_err() {
        std::os::unix::fs::symlink("../../1/ns/pid", link).expect("link the namespace");
    }
}

/// Stage below `root` what the way back reads to set the process-number
/// counter by a measure, and return the record of an entry it measures by:
/// the counter of [`stage_pid_counter`], and a procfs in which PID 1 runs in
/// `root` and the hidden start ran a getty on tty1 numbered 9150. The record
/// has the decoy's getty at 600 and the switch at 9031, so
/// [`crate::whole_root::fresh_pids::counter`] measures 481.
///
/// # Panics
///
/// When a file cannot be written.
pub fn stage_pid_measure(root: &Path) -> crate::whole_root::fresh_pids::Record {
    use crate::whole_root::fresh_pids::{Anchor, Record};
    stage_pid_counter(root);
    let proc = root.join("proc");
    let getty = proc.join("9150");
    std::fs::create_dir_all(&getty).expect("create the procfs stand-in");
    std::fs::write(
        getty.join("stat"),
        "9150 (agetty) S 1 9150 9150 1025 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n",
    )
    .expect("write the getty's stat");
    std::fs::write(getty.join("comm"), "agetty\n").expect("write the getty's comm");
    for link in [proc.join("1/root"), getty.join("root")] {
        if std::fs::symlink_metadata(&link).is_err() {
            std::os::unix::fs::symlink(root, link).expect("link the root");
        }
    }
    Record {
        floor: Some(388),
        anchors: vec![Anchor {
            comm: "agetty".to_string(),
            tty: 0x0401,
            pid: 600,
        }],
        at_switch: Some(9031),
        counter: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{copy_executable, write_executable};
    use std::io::{ErrorKind, Read as _};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::Path;
    use std::time::{Duration, Instant};

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn the_program_runs_with_the_contents_and_the_mode_it_was_given() {
        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("a tool");
        write_executable(&tool, "#!/bin/sh\necho \"ran $1\"\n", 0o750);

        assert_eq!(mode(&tool), 0o750);
        let output = std::process::Command::new(&tool)
            .arg("once")
            .output()
            .unwrap();
        assert_eq!(output.stdout, b"ran once\n");

        // Bytes are written as given, and a second write replaces the first.
        let bytes: Vec<u8> = (0..=255).cycle().take(300_000).collect();
        write_executable(&tool, &bytes, 0o644);
        assert_eq!(std::fs::read(&tool).unwrap(), bytes);
        assert_eq!(mode(&tool), 0o644);
    }

    #[test]
    fn a_copied_program_runs_with_the_mode_it_was_given() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source tool");
        write_executable(&source, "#!/bin/sh\necho copied\n", 0o644);
        let copy = dir.path().join("copied tool");

        copy_executable(&source, &copy, 0o700);

        assert_eq!(mode(&copy), 0o700);
        let output = std::process::Command::new(&copy).output().unwrap();
        assert_eq!(output.stdout, b"copied\n");
        assert_eq!(mode(&source), 0o644, "the source is left as it was");
    }

    /// The message of the panic that `write` ends in.
    fn panic_message(write: impl FnOnce() + std::panic::UnwindSafe) -> String {
        let panic = std::panic::catch_unwind(write).expect_err("the write fails");
        panic
            .downcast_ref::<String>()
            .expect("a formatted message")
            .clone()
    }

    #[test]
    fn a_file_that_cannot_be_written_fails_the_test_with_what_the_writer_said() {
        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("missing/tool");
        for message in [
            panic_message(|| write_executable(&tool, "#!/bin/sh\n", 0o755)),
            panic_message(|| copy_executable(Path::new("/bin/sh"), &tool, 0o755)),
        ] {
            let (ours, said) = message.split_once('\n').expect("two parts");
            assert!(ours.starts_with("writing "), "{message}");
            // The shell's complaint names the file, whichever shell /bin/sh is.
            assert!(said.contains(&*tool.to_string_lossy()), "{message}");
        }
    }

    #[test]
    fn the_file_is_written_without_this_process_holding_it_open() {
        // A FIFO stands in for the file. The write stops once the pipe is full
        // and goes on as the test reads, so the test looks at its own
        // descriptors in the middle of it: one this process held for writing
        // then is the one a process forked by another test thread would copy.
        // The reader opens first and without blocking, so a writer that never
        // opens the path (one that renames a file over it) fails at the
        // deadline instead of hanging the test.
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("tool");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .unwrap();
        let fifo_meta = std::fs::metadata(&fifo).unwrap();
        let id = (fifo_meta.dev(), fifo_meta.ino());
        let mut reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap();
        // Far more than a pipe holds: the writer is still at it when the first
        // bytes arrive.
        let contents = vec![b'#'; 4 << 20];
        let writer = std::thread::spawn({
            let (fifo, contents) = (fifo.clone(), contents.clone());
            move || write_executable(&fifo, contents, 0o755)
        });
        let held_here = || {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|fd| std::fs::metadata(fd.ok()?.path()).ok())
                .filter(|m| (m.dev(), m.ino()) == id)
                .count()
        };

        let mut read = Vec::new();
        let mut chunk = vec![0; 64 << 10];
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match reader.read(&mut chunk) {
                // The writer closed its end.
                Ok(0) if !read.is_empty() => break,
                Ok(n) if n > 0 => {
                    if read.is_empty() {
                        assert_eq!(held_here(), 1, "this process holds it only to read it");
                    }
                    read.extend_from_slice(&chunk[..n]);
                    continue;
                }
                // No writer yet, or nothing new from it.
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => panic!("reading {}: {e}", fifo.display()),
            }
            assert!(
                Instant::now() < deadline,
                "{} of {} bytes came through {}",
                read.len(),
                contents.len(),
                fifo.display()
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        writer.join().unwrap();
        assert!(read == contents, "the contents came through whole");
    }
}
