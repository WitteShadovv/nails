// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `nails rehearse` through the real binary: the guided status, and an offline
//! scan of image files with a planted and a clean image. The token must never
//! appear in the output, only its fingerprint.

use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const TOKEN: &str = "5a17c0ffee5a17c0ffee5a17c0ffee00";

struct Harness {
    dir: tempfile::TempDir,
    config: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let hidden = dir.path().join("hidden");
        std::fs::create_dir_all(&hidden).unwrap();
        let config = dir.path().join("nails.toml");
        std::fs::write(
            &config,
            format!(
                "hidden_volume_root = {root:?}\nstate_file_path = {state:?}\n\
                 show_opsec_reminders = false\n",
                root = hidden.display().to_string(),
                state = hidden.join("state.json").display().to_string(),
            ),
        )
        .unwrap();
        Self { dir, config }
    }

    fn image(&self, name: &str, token_at: Option<u64>) -> PathBuf {
        let path = self.dir.path().join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.set_len(32 << 20).unwrap();
        if let Some(offset) = token_at {
            file.seek(SeekFrom::Start(offset)).unwrap();
            file.write_all(TOKEN.as_bytes()).unwrap();
        }
        file.sync_all().unwrap();
        path
    }

    fn token_file(&self) -> PathBuf {
        let path = self.dir.path().join("token");
        std::fs::write(&path, format!("{TOKEN}\n")).unwrap();
        path
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(assert_cmd::cargo::cargo_bin!("nails"))
            .env_remove("NO_COLOR")
            .arg("--no-log-file")
            .arg("--config")
            .arg(&self.config)
            .args(args)
            .output()
            .expect("run nails")
    }
}

fn json(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim().lines().next_back().unwrap_or(""))
        .unwrap_or_else(|e| panic!("not one JSON document ({e}): {stdout}"))
}

fn assert_no_token(output: &Output) {
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !all.contains(TOKEN),
        "the token leaked into the output: {all}"
    );
}

fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn status_without_a_rehearsal_names_the_first_step() {
    let harness = Harness::new();
    let output = harness.run(&["--json", "rehearse"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let value = json(&output);
    assert_eq!(value["data"]["phase"], "none");
    assert!(
        value["data"]["next_step"]
            .as_str()
            .unwrap()
            .starts_with("Step 1 of 3"),
        "{value:#}"
    );
}

#[test]
fn an_offline_scan_finds_a_planted_token_by_offset_and_never_prints_it() {
    let harness = Harness::new();
    let leaky = harness.image("leaky.img", Some(3 << 20));
    let token = harness.token_file();

    let output = harness.run(&[
        "--json",
        "rehearse",
        "scan",
        "--offline",
        "--image",
        path(&leaky),
        "--token-file",
        path(&token),
    ]);

    assert_eq!(output.status.code(), Some(11), "{output:?}");
    assert_no_token(&output);
    let value = json(&output);
    let devices = value["data"]["scan"]["devices"].as_array().unwrap();
    assert_eq!(devices[0]["hits"][0]["offset"], 3 << 20);
    assert_eq!(devices[0]["hits"][0]["encoding"], "ascii");
    assert!(
        value["data"]["scan"]["not_visible"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| line.as_str().unwrap().contains("SSD")),
        "{value:#}"
    );
}

#[test]
fn an_offline_scan_of_a_clean_image_exits_zero() {
    let harness = Harness::new();
    let clean = harness.image("clean.img", None);
    let token = harness.token_file();

    let output = harness.run(&[
        "rehearse",
        "scan",
        "--offline",
        "--image",
        path(&clean),
        "--token-file",
        path(&token),
    ]);

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_no_token(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("not found on the scanned devices"),
        "{stdout}"
    );
    assert!(stdout.contains("Not visible to this scan:"), "{stdout}");
}

#[test]
fn an_unreadable_image_is_reported_as_incomplete() {
    let harness = Harness::new();
    let token = harness.token_file();
    let missing = harness.dir.path().join("missing.img");

    let output = harness.run(&[
        "rehearse",
        "scan",
        "--offline",
        "--image",
        path(&missing),
        "--token-file",
        path(&token),
    ]);

    assert_eq!(output.status.code(), Some(9), "{output:?}");
}

#[test]
fn a_scan_without_a_token_source_is_refused() {
    let harness = Harness::new();
    let clean = harness.image("clean.img", None);
    let output = harness.run(&["rehearse", "scan", "--offline", "--image", path(&clean)]);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no rehearsal state"), "{stderr}");
}

#[test]
fn plant_outside_an_active_session_is_refused() {
    let harness = Harness::new();
    let output = harness.run(&["rehearse", "plant"]);
    // The tempdir hidden root is not a mounted volume, or no session is active;
    // either way nothing is planted.
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    assert!(!harness.dir.path().join("hidden/rehearse").exists());
}
