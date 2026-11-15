// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Test support shared by the crates of the workspace: writing or copying a
//! program that a test, or the code it tests, then runs, the procfs files
//! the way back writes, and a stand-in for the running kernel's SELinux.
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

/// A stand-in for the running kernel's SELinux
/// ([`crate::whole_root::selinux::Selinux`]), which records every label it is
/// given and every question it is asked. [`FakeSelinux::targeted`] answers as
/// a loaded targeted policy does: PID 1 runs in `init_t` and starts a program
/// labelled [`PROGRAM_LABEL`](crate::whole_root::program_label::PROGRAM_LABEL)
/// in `unconfined_service_t`, allowed every permission asked, with the
/// capability `nnp_nosuid_transition` on, and the process asking runs in
/// `unconfined_service_t` too. systemd-udevd runs in `udev_t` and starts such
/// a program in its own domain, `/run` is labelled `var_run_t` and `/run/udev`
/// `udev_var_run_t`, and a new file or directory takes the label of the
/// directory it is made in. A test changes its fields for another answer.
#[derive(Debug, Default)]
pub struct FakeSelinux {
    /// PID 1's context; `None` is a kernel with no policy loaded.
    pub pid1: Option<String>,
    /// That PID 1's context cannot be read: its error.
    pub pid1_error: Option<i32>,
    /// The context of the process asking.
    pub current: String,
    /// That the context of the process asking cannot be read: its error.
    pub current_error: Option<i32>,
    /// The context of the running systemd-udevd; `None` is a host where none
    /// runs.
    pub udevd: Option<String>,
    /// That udevd's context cannot be read: its error.
    pub udevd_error: Option<i32>,
    /// The context every start enters, where [`FakeSelinux::entered_from`]
    /// names no other.
    pub entered: String,
    /// The context a start from a process of this type enters, as (the
    /// process's type, context), before [`FakeSelinux::entered`].
    pub entered_from: Vec<(&'static str, String)>,
    /// The label of a new file or directory a process of this type makes, as
    /// (the process's type, label), where not that of its directory.
    pub created_by: Vec<(&'static str, String)>,
    /// The labels of files by their path; any other path is not there.
    pub path_labels: Vec<(std::path::PathBuf, String)>,
    /// The permissions the policy denies, as (class, permission), whatever
    /// the contexts.
    pub denied: Vec<(&'static str, &'static str)>,
    /// The permissions the policy denies on a label of this type only, as
    /// (type, class, permission).
    pub denied_on: Vec<(&'static str, &'static str, &'static str)>,
    /// That the policy cannot be asked: the error of every question.
    pub policy_error: Option<i32>,
    /// Whether the policy turns `nnp_nosuid_transition` on.
    pub capability: bool,
    /// The error every label written fails with, or with
    /// [`FakeSelinux::write_error_from`] every one from that one on.
    pub write_error: Option<i32>,
    /// The number of labels written before [`FakeSelinux::write_error`]
    /// fails the rest, where not every one.
    pub write_error_from: Option<usize>,
    /// What a label reads back as, where not the last one written.
    pub read_back: Option<Vec<u8>>,
    /// Every label written, in order.
    pub written: std::sync::Mutex<Vec<Vec<u8>>>,
    /// Every question asked of the policy, in order: `pid1`, `current`,
    /// `udevd`, `create <source> <file>`,
    /// `new <source> <parent> <class> <name, or ->`, `label <path>`,
    /// `access <source> <target> <class>`, `capability <name>`.
    pub asked: std::sync::Mutex<Vec<String>>,
}

/// systemd-udevd's context under a targeted policy, as Fedora runs it.
pub const UDEVD_CONTEXT: &str = "system_u:system_r:udev_t:s0-s0:c0.c1023";

impl FakeSelinux {
    /// A loaded targeted policy, as [`FakeSelinux`] says.
    pub fn targeted() -> Self {
        Self {
            pid1: Some("system_u:system_r:init_t:s0".to_string()),
            current: "system_u:system_r:unconfined_service_t:s0".to_string(),
            udevd: Some(UDEVD_CONTEXT.to_string()),
            entered: "system_u:system_r:unconfined_service_t:s0".to_string(),
            entered_from: vec![("udev_t", UDEVD_CONTEXT.to_string())],
            path_labels: vec![
                (
                    std::path::PathBuf::from("/run"),
                    "system_u:object_r:var_run_t:s0".to_string(),
                ),
                (
                    std::path::PathBuf::from("/run/udev"),
                    "system_u:object_r:udev_var_run_t:s0".to_string(),
                ),
            ],
            capability: true,
            ..Self::default()
        }
    }

    /// A kernel that runs no SELinux, or runs it with no policy loaded.
    pub fn without_policy() -> Self {
        Self::default()
    }

    /// This stand-in for as long as the test process runs, for the hosts
    /// that hold a `&'static dyn Selinux`.
    pub fn leak(self) -> &'static Self {
        Box::leak(Box::new(self))
    }

    /// The labels written so far.
    pub fn labels_written(&self) -> Vec<Vec<u8>> {
        self.written.lock().expect("the labels written").clone()
    }

    /// The questions asked so far.
    pub fn questions(&self) -> Vec<String> {
        self.asked.lock().expect("the questions asked").clone()
    }

    fn ask(&self, question: String) -> std::io::Result<()> {
        self.asked
            .lock()
            .expect("the questions asked")
            .push(question);
        match self.policy_error {
            Some(errno) => Err(std::io::Error::from_raw_os_error(errno)),
            None => Ok(()),
        }
    }
}

impl crate::whole_root::selinux::Selinux for FakeSelinux {
    fn pid1(&self) -> std::io::Result<Option<String>> {
        self.asked
            .lock()
            .expect("the questions asked")
            .push("pid1".to_string());
        match self.pid1_error {
            Some(errno) => Err(std::io::Error::from_raw_os_error(errno)),
            None => Ok(self.pid1.clone()),
        }
    }

    fn current(&self) -> std::io::Result<String> {
        self.asked
            .lock()
            .expect("the questions asked")
            .push("current".to_string());
        match self.current_error {
            Some(errno) => Err(std::io::Error::from_raw_os_error(errno)),
            None => Ok(self.current.clone()),
        }
    }

    fn udevd(&self) -> std::io::Result<Option<String>> {
        self.asked
            .lock()
            .expect("the questions asked")
            .push("udevd".to_string());
        match self.udevd_error {
            Some(errno) => Err(std::io::Error::from_raw_os_error(errno)),
            None => Ok(self.udevd.clone()),
        }
    }

    fn exec_context(&self, source: &str, file: &str) -> std::io::Result<String> {
        self.ask(format!("create {source} {file}"))?;
        let kind = crate::whole_root::selinux::type_of(source);
        Ok(self
            .entered_from
            .iter()
            .find(|(from, _)| Some(*from) == kind)
            .map_or_else(|| self.entered.clone(), |(_, entered)| entered.clone()))
    }

    fn new_label(
        &self,
        source: &str,
        parent: &str,
        class: &str,
        name: Option<&str>,
    ) -> std::io::Result<String> {
        self.ask(format!(
            "new {source} {parent} {class} {}",
            name.unwrap_or("-")
        ))?;
        let kind = crate::whole_root::selinux::type_of(source);
        Ok(self
            .created_by
            .iter()
            .find(|(by, _)| Some(*by) == kind)
            .map_or_else(|| parent.to_string(), |(_, label)| label.clone()))
    }

    fn denied(
        &self,
        source: &str,
        target: &str,
        class: &str,
        perms: &[&'static str],
    ) -> std::io::Result<Vec<&'static str>> {
        self.ask(format!("access {source} {target} {class}"))?;
        let kind = crate::whole_root::selinux::type_of(target).unwrap_or_default();
        Ok(perms
            .iter()
            .copied()
            .filter(|perm| {
                self.denied.contains(&(class, perm))
                    || self
                        .denied_on
                        .iter()
                        .any(|&(on, of, denied)| on == kind && of == class && denied == *perm)
            })
            .collect())
    }

    fn capability(&self, name: &str) -> std::io::Result<bool> {
        self.ask(format!("capability {name}"))?;
        Ok(self.capability)
    }

    fn set_label(&self, _file: rustix::fd::BorrowedFd<'_>, value: &[u8]) -> std::io::Result<()> {
        let mut written = self.written.lock().expect("the labels written");
        if let Some(errno) = self.write_error
            && self
                .write_error_from
                .is_none_or(|from| written.len() >= from)
        {
            return Err(std::io::Error::from_raw_os_error(errno));
        }
        written.push(value.to_vec());
        Ok(())
    }

    fn label(&self, _file: rustix::fd::BorrowedFd<'_>) -> std::io::Result<Vec<u8>> {
        if let Some(value) = &self.read_back {
            return Ok(value.clone());
        }
        self.written
            .lock()
            .expect("the labels written")
            .last()
            .cloned()
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENODATA))
    }

    fn path_label(&self, path: &std::path::Path) -> std::io::Result<String> {
        self.asked
            .lock()
            .expect("the questions asked")
            .push(format!("label {}", path.display()));
        self.path_labels
            .iter()
            .find(|(at, _)| at == path)
            .map(|(_, label)| label.clone())
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))
    }
}

/// A kernel whose network state lives in a test's fake trees: the rules and
/// tables in memory, the links in a fake `/sys/class/net`, which the record
/// and the way back read and change as they would the kernel's. It logs every
/// change asked of it, in order. A list that is `None` stands for a kernel
/// that cannot list it.
#[derive(Debug, Default)]
pub struct FakeNetKernel {
    /// The fake `/sys/class/net` the link changes act on, `None` for none.
    pub sys_class_net: Option<std::path::PathBuf>,
    /// The state and the knobs.
    pub state: std::sync::Mutex<FakeNet>,
}

/// The state of a [`FakeNetKernel`], and how it behaves.
#[derive(Debug, Default, Clone)]
pub struct FakeNet {
    /// The IPv4 and the IPv6 rules.
    pub rules: [Option<Vec<crate::whole_root::net_kernel::Rule>>; 2],
    /// The nftables tables.
    pub tables: Option<Vec<crate::whole_root::net_kernel::Table>>,
    /// Rules the kernel refuses to delete.
    pub kept_rules: Vec<crate::whole_root::net_kernel::Rule>,
    /// Names of tables the kernel refuses to delete.
    pub kept_tables: Vec<String>,
    /// After this many lists of rules or tables, every list fails.
    pub lists_left: Option<usize>,
    /// Links whose driver refuses an address change while they are up.
    pub busy_while_up: Vec<String>,
    /// Links whose driver refuses every address change.
    pub refusing: Vec<String>,
    /// The changes asked for: `delete rule IPv4 32765`, `delete table inet
    /// x`, `delete link wg0`, `set eth0 address <mac>`, `set eth0 down`, `set
    /// eth0 up`, `delete wireless mon0`.
    pub calls: Vec<String>,
}

impl FakeNetKernel {
    /// A kernel that lists nothing and changes nothing: entry records the
    /// rules and tables as unknown, and the way back leaves them.
    pub fn offline() -> Self {
        Self::default()
    }

    /// A kernel with `state` whose links are in the fake tree `sys_class_net`.
    pub fn new(sys_class_net: Option<&Path>, state: FakeNet) -> Self {
        FakeNetKernel {
            sys_class_net: sys_class_net.map(Path::to_path_buf),
            state: std::sync::Mutex::new(state),
        }
    }

    /// The changes asked for so far.
    pub fn calls(&self) -> Vec<String> {
        self.state.lock().unwrap().calls.clone()
    }

    /// The fake link with interface index `index`: its directory and name.
    fn link(&self, index: u32) -> Option<(std::path::PathBuf, String)> {
        let sys = self.sys_class_net.as_ref()?;
        std::fs::read_dir(sys).ok()?.flatten().find_map(|entry| {
            let dir = entry.path();
            let found: u32 = std::fs::read_to_string(dir.join("ifindex"))
                .ok()?
                .trim()
                .parse()
                .ok()?;
            (found == index).then(|| (dir, entry.file_name().to_string_lossy().into_owned()))
        })
    }

    /// Whether a list may answer now.
    fn may_list(state: &mut FakeNet) -> bool {
        match &mut state.lists_left {
            Some(0) => false,
            Some(left) => {
                *left -= 1;
                true
            }
            None => true,
        }
    }
}

impl crate::whole_root::net_kernel::NetKernel for FakeNetKernel {
    fn rules(
        &self,
        family: crate::whole_root::net_kernel::Family,
    ) -> Option<Vec<crate::whole_root::net_kernel::Rule>> {
        let mut state = self.state.lock().unwrap();
        if !Self::may_list(&mut state) {
            return None;
        }
        let at = usize::from(family == crate::whole_root::net_kernel::Family::V6);
        state.rules[at].clone()
    }

    fn delete_rule(&self, rule: &crate::whole_root::net_kernel::Rule) {
        let mut state = self.state.lock().unwrap();
        let family = if rule.family() == crate::netlink::route::AF_INET6 {
            "IPv6"
        } else {
            "IPv4"
        };
        state
            .calls
            .push(format!("delete rule {family} {}", rule.priority()));
        if state.kept_rules.contains(rule) {
            return;
        }
        for list in state.rules.iter_mut().flatten() {
            if let Some(at) = list.iter().position(|listed| listed == rule) {
                list.remove(at);
                return;
            }
        }
    }

    fn tables(&self) -> Option<Vec<crate::whole_root::net_kernel::Table>> {
        let mut state = self.state.lock().unwrap();
        if !Self::may_list(&mut state) {
            return None;
        }
        state.tables.clone()
    }

    fn delete_table(&self, table: &crate::whole_root::net_kernel::Table) {
        let mut state = self.state.lock().unwrap();
        state
            .calls
            .push(format!("delete table {} {}", table.family, table.name));
        if state.kept_tables.contains(&table.name) {
            return;
        }
        if let Some(list) = state.tables.as_mut() {
            list.retain(|listed| listed != table);
        }
    }

    fn delete_link(&self, index: u32) {
        let link = self.link(index);
        let mut state = self.state.lock().unwrap();
        let Some((dir, name)) = link else {
            state.calls.push(format!("delete link {index}"));
            return;
        };
        state.calls.push(format!("delete link {name}"));
        let _ = std::fs::remove_dir_all(dir);
    }

    fn set_address(&self, index: u32, mac: &[u8]) {
        let link = self.link(index);
        let mut state = self.state.lock().unwrap();
        let text: Vec<String> = mac.iter().map(|b| format!("{b:02x}")).collect();
        let text = text.join(":");
        let Some((dir, name)) = link else {
            state.calls.push(format!("set {index} address {text}"));
            return;
        };
        state.calls.push(format!("set {name} address {text}"));
        let up = std::fs::read_to_string(dir.join("flags"))
            .unwrap_or_default()
            .trim()
            == "0x1003";
        if state.refusing.contains(&name) || (up && state.busy_while_up.contains(&name)) {
            return;
        }
        let _ = std::fs::write(dir.join("address"), format!("{text}\n"));
    }

    fn set_up(&self, index: u32, up: bool) {
        let link = self.link(index);
        let mut state = self.state.lock().unwrap();
        let word = if up { "up" } else { "down" };
        let Some((dir, name)) = link else {
            state.calls.push(format!("set {index} {word}"));
            return;
        };
        state.calls.push(format!("set {name} {word}"));
        let flags = if up { "0x1003\n" } else { "0x1002\n" };
        let _ = std::fs::write(dir.join("flags"), flags);
    }

    fn delete_wireless(&self, index: u32) {
        let link = self.link(index);
        let mut state = self.state.lock().unwrap();
        let Some((dir, name)) = link else {
            state.calls.push(format!("delete wireless {index}"));
            return;
        };
        state.calls.push(format!("delete wireless {name}"));
        let _ = std::fs::remove_dir_all(dir);
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
