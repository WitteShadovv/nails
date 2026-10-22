// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `nails rehearse` through the real binary: the guided status, and an offline
//! scan of image files with a planted and a clean image. The token must never
//! appear in the output, only its fingerprint.

use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use nails_core::rehearse::{self, ChannelKind, ChannelRecord, Phase, RehearsalState, ScanSummary};
use nails_core::test_support::ScratchTmpfs;

const TOKEN: &str = "5a17c0ffee5a17c0ffee5a17c0ffee00";

struct Harness {
    // Declared first so a tmpfs hidden root is detached before the directories go.
    _volume: Option<ScratchTmpfs>,
    dir: tempfile::TempDir,
    config: PathBuf,
    hidden: PathBuf,
}

impl Harness {
    /// A hidden root that is a plain directory: the attach gate refuses it.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let hidden = dir.path().join("hidden");
        std::fs::create_dir_all(&hidden).unwrap();
        Self::with_root(dir, hidden, None)
    }

    /// A hidden root that is a tmpfs of its own, which the attach gate accepts.
    /// Build it only inside a [`Rerun::in_user_mount_ns`] body.
    fn on_a_volume() -> Self {
        let volume = ScratchTmpfs::new("");
        let hidden = volume.path().to_path_buf();
        Self::with_root(tempfile::tempdir().unwrap(), hidden, Some(volume))
    }

    fn with_root(dir: tempfile::TempDir, hidden: PathBuf, volume: Option<ScratchTmpfs>) -> Self {
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
        Self {
            _volume: volume,
            dir,
            config,
            hidden,
        }
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

    /// The hidden root, resolved the way the binary resolves it.
    fn hidden(&self) -> PathBuf {
        self.hidden.canonicalize().unwrap()
    }

    fn state_path(&self) -> PathBuf {
        self.hidden().join(rehearse::state_relative_path())
    }

    /// Write `state` as the hidden volume's rehearsal state.
    fn write_state(&self, state: &RehearsalState) {
        let path = self.state_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(state).unwrap()).unwrap();
    }

    /// Mark the hidden root as a NAILS volume, so the attach check accepts it
    /// once it is a volume of its own.
    fn write_marker(&self) {
        std::fs::write(self.hidden().join("state.json"), "{}").unwrap();
    }
}

/// A boot ID that is never the running one.
const OTHER_BOOT: &str = "00000000-0000-0000-0000-000000000000";

/// A planted rehearsal: one overlay file whose upper copy carries the token in
/// its name, and one skipped channel.
fn planted(
    harness: &Harness,
    boot_id: Option<String>,
    soft_reboots: Option<u64>,
) -> RehearsalState {
    let upper = harness.hidden().join(format!(
        "root/upper/home/op/{}{TOKEN}",
        rehearse::FILE_PREFIX
    ));
    RehearsalState {
        schema_version: rehearse::STATE_SCHEMA_VERSION,
        token: TOKEN.to_string(),
        phase: Phase::Planted,
        planted_at: "2026-01-01T10:00:00Z".to_string(),
        planted_boot_id: boot_id,
        planted_entered_at: Some(1_700_000_000),
        planted_soft_reboots: soft_reboots,
        channels: vec![
            ChannelRecord {
                kind: ChannelKind::OverlayFile,
                location: format!("/home/op/{}{TOKEN}", rehearse::FILE_PREFIX),
                upper_copy: Some(upper),
                skipped: None,
            },
            ChannelRecord {
                kind: ChannelKind::Notification,
                location: "desktop notification".to_string(),
                upper_copy: None,
                skipped: Some("no session bus".to_string()),
            },
        ],
        scans: Vec::new(),
    }
}

/// The running boot as the binary sees it: its boot ID and systemd's
/// soft-reboot count (`None` where the service manager does not report one).
fn this_boot() -> (String, Option<u64>) {
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap()
        .trim()
        .to_string();
    let soft_reboots = Command::new("systemctl")
        .args(["show", "-p", "SoftRebootsCount", "--value"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8_lossy(&out.stdout).trim().parse().ok());
    (boot_id, soft_reboots)
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
    // The compression/copy-on-write caveat is serialized too, so a clean offline
    // scan of a captured image is never read as conclusive.
    assert!(
        value["data"]["scan"]["not_visible"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| line
                .as_str()
                .unwrap()
                .contains("stored compressed or copy-on-write")),
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
    // The compression/copy-on-write caveat prints with every result, so a clean
    // scan over such storage is never read as conclusive.
    assert!(
        stdout.contains("stored compressed or copy-on-write"),
        "{stdout}"
    );
    // A token file names no channels: nothing to list as untested.
    assert!(!stdout.contains("Not tested"), "{stdout}");
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
fn plant_on_a_folder_is_refused_by_the_attach_gate() {
    let harness = Harness::new();
    let output = harness.run(&["--json", "rehearse", "plant"]);
    // The tempdir hidden root is a folder, not a volume of its own: the gate
    // refuses it before anything is planted.
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    assert_eq!(json(&output)["error"]["code"], "not_separate_volume");
    assert!(!harness.dir.path().join("hidden/rehearse").exists());
}

#[test]
fn status_of_a_planted_rehearsal_shows_its_fingerprint_channels_and_the_scan_step() {
    let harness = Harness::new();
    harness.write_state(&planted(&harness, Some(OTHER_BOOT.to_string()), Some(0)));

    let output = harness.run(&["--ascii", "rehearse", "status"]);

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_no_token(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[INFO] Rehearsal 5a17c0"), "{stdout}");
    assert!(
        stdout.contains(" planted at 2026-01-01T10:00:00Z (planted)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("OverlayFile: /home/op/rehearse-<canary>"),
        "{stdout}"
    );
    assert!(
        stdout.contains("Notification: not planted (no session bus)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("-> Step 3 of 3: run `sudo ") && stdout.contains("rehearse scan`."),
        "{stdout}"
    );
}

#[test]
fn status_outside_a_hidden_session_names_the_scan_step_in_the_planting_boot() {
    // Planted in this boot, and the soft-reboots of a plain deactivation keep
    // the boot ID (with no count on systemd 255): with no hidden session live,
    // the planting session has ended all the same.
    let harness = Harness::new();
    let (boot_id, soft_reboots) = this_boot();
    harness.write_state(&planted(&harness, Some(boot_id), soft_reboots));

    let output = harness.run(&["--json", "rehearse"]);

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let value = json(&output);
    assert_eq!(value["data"]["phase"], "planted");
    let next_step = value["data"]["next_step"].as_str().unwrap();
    assert!(
        next_step.starts_with("Step 3 of 3: run `sudo ") && next_step.ends_with("rehearse scan`."),
        "{value:#}"
    );
}

#[test]
fn status_of_a_scanned_rehearsal_lists_each_scan_and_is_done() {
    let harness = Harness::new();
    let mut state = planted(&harness, Some(OTHER_BOOT.to_string()), Some(0));
    state.phase = Phase::Scanned;
    state.scans.push(ScanSummary {
        at: "2026-01-02T08:00:00Z".to_string(),
        boot_id: None,
        devices: vec!["/dev/vda".to_string(), "/dev/vdb".to_string()],
        hits: 0,
    });
    harness.write_state(&state);

    let human = harness.run(&["--ascii", "rehearse", "status"]);
    let stdout = String::from_utf8_lossy(&human.stdout);
    assert!(
        stdout.contains("- scan at 2026-01-02T08:00:00Z: 0 hits on /dev/vda, /dev/vdb"),
        "{stdout}"
    );
    assert!(stdout.contains("-> Done. Scan again any time"), "{stdout}");

    let output = harness.run(&["--json", "rehearse", "status"]);
    assert_no_token(&output);
    let value = json(&output);
    assert_eq!(value["data"]["phase"], "scanned");
    assert_eq!(value["data"]["fingerprint"], "5a17c0\u{2026}");
    assert_eq!(value["data"]["planted_at"], "2026-01-01T10:00:00Z");
    assert_eq!(
        value["data"]["channels"][0]["location"],
        "/home/op/rehearse-<canary>"
    );
}

#[test]
fn an_unreadable_rehearsal_state_is_an_invalid_state() {
    let harness = Harness::new();
    let path = harness.state_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "not json").unwrap();

    let output = harness.run(&["--json", "rehearse"]);

    assert_eq!(output.status.code(), Some(6), "{output:?}");
    let value = json(&output);
    assert_eq!(value["error"]["code"], "rehearse_state");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("is unreadable"),
        "{value:#}"
    );
}

#[test]
fn an_offline_scan_with_the_state_token_records_the_scan_phase() {
    let harness = Harness::new();
    // Planted in this very session: an offline scan of an image is still fine.
    let (boot_id, soft_reboots) = this_boot();
    harness.write_state(&planted(&harness, Some(boot_id), soft_reboots));
    let leaky = harness.image("leaky.img", Some(1 << 20));

    let output = harness.run(&[
        "--json",
        "rehearse",
        "scan",
        "--offline",
        "--image",
        path(&leaky),
    ]);

    assert_eq!(output.status.code(), Some(11), "{output:?}");
    assert_no_token(&output);
    let value = json(&output);
    assert_eq!(value["data"]["phase"], "scanned");
    assert_eq!(value["data"]["planted_at"], "2026-01-01T10:00:00Z");
    assert_eq!(
        value["data"]["scan"]["devices"][0]["hits"][0]["offset"],
        1 << 20
    );
    assert!(
        value["data"]["next_step"]
            .as_str()
            .unwrap()
            .starts_with("Done."),
        "{value:#}"
    );
}

#[test]
fn a_scan_outside_a_hidden_session_runs_in_the_planting_boot() {
    // The boot ID and soft-reboot count of this very boot, as a deactivation
    // back to the decoy leaves them: only a live hidden session can be the
    // planting session, so the scan runs without --allow-same-boot. The
    // refusal inside that session is the NixOS VM test's and the distribution
    // smoke test's to show; the decision itself has unit tests.
    let harness = Harness::new();
    let (boot_id, soft_reboots) = this_boot();
    harness.write_state(&planted(&harness, Some(boot_id), soft_reboots));
    let clean = harness.image("clean.img", None);

    let output = harness.run(&["--json", "rehearse", "scan", "--device", path(&clean)]);

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        json(&output)["data"]["scan"]["devices"][0]["hits"],
        serde_json::json!([])
    );
}

#[test]
fn a_clean_scan_names_the_channels_the_canary_never_went_into() {
    let harness = Harness::new();
    harness.write_state(&planted(&harness, Some(OTHER_BOOT.to_string()), Some(0)));
    let clean = harness.image("clean.img", None);

    let output = harness.run(&["--ascii", "rehearse", "scan", "--device", path(&clean)]);

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_no_token(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("not found on the scanned devices"),
        "{stdout}"
    );
    let untested = stdout
        .find("Not tested, because the canary was never planted there:")
        .unwrap_or_else(|| panic!("no untested channels listed: {stdout}"));
    let not_visible = stdout.find("Not visible to this scan:").unwrap();
    assert!(untested < not_visible, "{stdout}");
    assert!(
        stdout.contains("  [-] Notification: no session bus"),
        "{stdout}"
    );
    assert!(!stdout.contains("OverlayFile: "), "{stdout}");
}

#[test]
fn a_token_file_without_a_valid_token_is_refused() {
    let harness = Harness::new();
    let clean = harness.image("clean.img", None);
    let bad = harness.dir.path().join("bad-token");
    std::fs::write(&bad, "not-hex\n").unwrap();
    let missing = harness.dir.path().join("no-such-token");

    let invalid = harness.run(&[
        "--json",
        "rehearse",
        "scan",
        "--offline",
        "--image",
        path(&clean),
        "--token-file",
        path(&bad),
    ]);
    assert_eq!(invalid.status.code(), Some(6), "{invalid:?}");
    let value = json(&invalid);
    assert_eq!(value["error"]["code"], "no_token");
    assert_eq!(
        value["error"]["message"],
        format!("{} holds no valid token", bad.display())
    );

    let unreadable = harness.run(&[
        "--json",
        "rehearse",
        "scan",
        "--offline",
        "--image",
        path(&clean),
        "--token-file",
        path(&missing),
    ]);
    assert_eq!(unreadable.status.code(), Some(6), "{unreadable:?}");
    assert!(
        json(&unreadable)["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with(&format!("cannot read {}", missing.display())),
        "{unreadable:?}"
    );
}

#[test]
fn reset_on_a_folder_is_refused_and_removes_nothing() {
    let harness = Harness::new();
    let state = planted(&harness, Some(OTHER_BOOT.to_string()), Some(0));
    let upper = state.channels[0].upper_copy.clone().unwrap();
    std::fs::create_dir_all(upper.parent().unwrap()).unwrap();
    std::fs::write(&upper, TOKEN).unwrap();
    harness.write_state(&state);

    let output = harness.run(&["--json", "rehearse", "reset"]);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_no_token(&output);
    assert_eq!(json(&output)["error"]["code"], "reset");
    assert!(upper.exists());
    assert!(harness.state_path().exists());
}

#[test]
fn reset_without_a_rehearsal_is_refused() {
    let harness = Harness::new();
    let output = harness.run(&["--json", "rehearse", "reset"]);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    let value = json(&output);
    assert_eq!(value["error"]["code"], "no_rehearsal");
    assert_eq!(value["error"]["message"], "no rehearsal to reset");
}

/// The tests that need the attach gate to accept the hidden root: each runs in
/// an unprivileged user + mount namespace with a tmpfs as the hidden root, and
/// the binary it spawns inherits that namespace.
mod kernel_tests {
    use super::*;
    use nails_core::test_path;
    use nails_core::test_support::Rerun;

    #[test]
    fn reset_removes_the_planted_copy_and_the_state_with_the_token_redacted() {
        let _ = Rerun::new(test_path!(
            reset_removes_the_planted_copy_and_the_state_with_the_token_redacted
        ))
        .in_user_mount_ns()
        .run(|| {
            let harness = Harness::on_a_volume();
            harness.write_marker();
            let state = planted(&harness, Some(OTHER_BOOT.to_string()), Some(0));
            let upper = state.channels[0].upper_copy.clone().unwrap();
            std::fs::create_dir_all(upper.parent().unwrap()).unwrap();
            std::fs::write(&upper, TOKEN).unwrap();
            harness.write_state(&state);

            let output = harness.run(&["--json", "rehearse", "reset"]);

            assert_eq!(output.status.code(), Some(0), "{output:?}");
            assert_no_token(&output);
            let value = json(&output);
            assert_eq!(value["data"]["phase"], "none");
            let hidden = harness.hidden().display().to_string();
            assert_eq!(
                value["data"]["removed"],
                serde_json::json!([
                    format!("{hidden}/root/upper/home/op/rehearse-<canary>"),
                    format!("{hidden}/rehearse/state.json"),
                ])
            );
            assert!(!upper.exists());
            assert!(!harness.state_path().exists());
        });
    }

    #[test]
    fn reset_in_human_form_lists_what_it_removed() {
        let _ = Rerun::new(test_path!(reset_in_human_form_lists_what_it_removed))
            .in_user_mount_ns()
            .run(|| {
                let harness = Harness::on_a_volume();
                harness.write_marker();
                harness.write_state(&planted(&harness, Some(OTHER_BOOT.to_string()), Some(0)));

                let output = harness.run(&["--ascii", "rehearse", "reset"]);

                assert_eq!(output.status.code(), Some(0), "{output:?}");
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(
                    stdout.contains("[PASS] Removed rehearsal 5a17c0"),
                    "{stdout}"
                );
                assert!(
                    stdout.contains(&format!("  removed {}", harness.state_path().display())),
                    "{stdout}"
                );
                assert!(
                    stdout.contains("-> Step 1 of 3: activate a hidden session"),
                    "{stdout}"
                );
            });
    }

    #[test]
    fn a_device_scan_records_the_scan_in_the_state_on_an_attached_volume() {
        let _ = Rerun::new(test_path!(
            a_device_scan_records_the_scan_in_the_state_on_an_attached_volume
        ))
        .in_user_mount_ns()
        .run(|| {
            let harness = Harness::on_a_volume();
            harness.write_marker();
            harness.write_state(&planted(&harness, Some(OTHER_BOOT.to_string()), Some(0)));
            let clean = harness.image("clean.img", None);

            let output = harness.run(&["--json", "rehearse", "scan", "--device", path(&clean)]);

            assert_eq!(output.status.code(), Some(0), "{output:?}");
            assert_eq!(json(&output)["data"]["phase"], "scanned");
            let saved: RehearsalState =
                serde_json::from_str(&std::fs::read_to_string(harness.state_path()).unwrap())
                    .unwrap();
            assert_eq!(saved.phase, Phase::Scanned);
            assert_eq!(saved.scans.len(), 1);
            assert_eq!(saved.scans[0].devices, vec![clean.display().to_string()]);
            assert_eq!(saved.scans[0].hits, 0);
        });
    }

    #[test]
    fn plant_on_an_attached_volume_without_a_session_names_the_missing_session() {
        let _ = Rerun::new(test_path!(
            plant_on_an_attached_volume_without_a_session_names_the_missing_session
        ))
        .in_user_mount_ns()
        .run(|| {
            let harness = Harness::on_a_volume();
            harness.write_marker();
            let output = harness.run(&["--json", "rehearse", "plant"]);
            assert_eq!(output.status.code(), Some(6), "{output:?}");
            assert_eq!(json(&output)["error"]["code"], "not_active");
            assert!(!harness.state_path().exists());
        });
    }

    #[test]
    fn plant_on_an_unattached_volume_names_the_attach_problem() {
        let _ = Rerun::new(test_path!(
            plant_on_an_unattached_volume_names_the_attach_problem
        ))
        .in_user_mount_ns()
        .run(|| {
            let harness = Harness::on_a_volume();
            // No marker: the root is a volume of its own, but no NAILS volume.
            let output = harness.run(&["--json", "rehearse", "plant"]);
            assert_eq!(output.status.code(), Some(6), "{output:?}");
            let value = json(&output);
            assert_eq!(value["error"]["code"], "not_attached");
            assert!(
                value["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("holds no NAILS marker"),
                "{value:#}"
            );
        });
    }
}
