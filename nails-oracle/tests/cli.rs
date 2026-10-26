// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `nails-oracle` binary end to end, over outputs trees written here: the
//! exit status and the verdict it prints. `ci/oracle/run-scan.sh` passes a
//! scan only when the binary exits 0 and its verdict says clean, so the binary
//! must exit 0 on a clean verdict alone, 1 on a failing one and 2 when it
//! cannot read what it was given.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A self-cleaning unique temporary directory, built with the standard
/// library only (nails-oracle carries no `tempfile` dev-dependency).
struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("nails-oracle-cli-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Write `contents` at `path`, creating its directory.
fn write(path: &Path, contents: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().expect("parent")).expect("create dir");
    fs::write(path, contents).expect("write");
}

/// Write the outputs tree of one scan in which every channel reports on every
/// image: a restored `/etc/hostname`, the canary carved from each image and
/// the planted control carved from `after`, and plaso's stat of the hostname.
/// `after_files` are files only the restored `after` tree holds. Returns the
/// arguments that render the scan's verdict.
fn scan(dir: &Path, after_files: &[&str]) -> Vec<String> {
    let outputs = dir.join("outputs");
    for label in ["before", "control", "after"] {
        let mut files = vec!["etc/hostname"];
        let mut emails = String::from("4096\tcanary@oracle.example\tctx\n");
        if label == "after" {
            files.extend(after_files);
            emails.push_str("8192\tplanted@oracle.example\tctx\n");
        }
        let mut manifest = String::new();
        for file in files {
            write(&outputs.join("restore").join(label).join(file), "");
            manifest.push_str(&format!("{}  ./{file}\0", "0".repeat(64)));
        }
        write(
            &outputs.join("restore").join(format!("{label}.sha256")),
            manifest,
        );
        write(
            &outputs.join("bulk_extractor").join(label).join("email.txt"),
            emails,
        );
        write(
            &outputs.join("plaso").join(format!("{label}.jsonl")),
            "{\"path\":\"/etc/hostname\",\"data_type\":\"fs:stat\"}\n",
        );
    }
    let allowlist = dir.join("allowlist.json");
    write(&allowlist, r#"{"entries":[]}"#);
    let controls = dir.join("controls.json");
    write(
        &controls,
        r#"{
          "positive_controls": [{"name": "planted", "tool": "bulk_extractor",
                                 "path": "email", "field": "planted@oracle.example"}],
          "canary": {"tool": "bulk_extractor", "path": "email",
                     "field": "canary@oracle.example"}
        }"#,
    );
    vec![
        outputs.display().to_string(),
        "--allowlist".into(),
        allowlist.display().to_string(),
        "--controls".into(),
        controls.display().to_string(),
    ]
}

/// Run the binary with `args`.
fn oracle(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nails-oracle"))
        .args(args)
        .output()
        .expect("the binary runs")
}

/// The verdict the binary printed on stdout.
fn verdict(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).expect("a JSON verdict on stdout")
}

#[test]
fn a_clean_scan_exits_zero_and_says_clean() {
    let dir = TmpDir::new();
    let out = oracle(&scan(&dir.0, &[]));
    let summary = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{summary}");
    assert_eq!(verdict(&out)["status"], "clean");
    assert!(summary.starts_with("CLEAN: "), "{summary}");
    assert!(summary.contains("; not seen: timestamps"), "{summary}");
}

#[test]
fn a_scan_with_residue_exits_one_and_says_fail() {
    // A file only after holds is a leak: the binary must not exit 0 on it,
    // whatever its verdict prints.
    let dir = TmpDir::new();
    let out = oracle(&scan(&dir.0, &["etc/leak"]));
    let summary = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{summary}");
    let verdict = verdict(&out);
    assert_eq!(verdict["status"], "fail");
    assert_eq!(verdict["failures"][0]["kind"], "unexplained_residue");
    assert_eq!(verdict["failures"][0]["path"], "/etc/leak");
    assert!(summary.starts_with("FAIL: "), "{summary}");
}

#[test]
fn an_outputs_tree_it_cannot_read_exits_two() {
    let dir = TmpDir::new();
    let mut args = scan(&dir.0, &[]);
    fs::remove_file(dir.0.join("outputs").join("restore").join("after.sha256"))
        .expect("remove the after manifest");
    let out = oracle(&args);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "no verdict without the whole tree");

    args[0] = dir.0.join("missing").display().to_string();
    assert_eq!(oracle(&args).status.code(), Some(2));
}
