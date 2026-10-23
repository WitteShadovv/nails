// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The scan parsers' unit tests: the pure per-format helpers, and the
//! filesystem-facing scanners over real temporary trees (no root needed).

use super::*;
use std::path::PathBuf;

#[test]
fn bulk_extractor_skips_comments_and_keeps_the_feature_column() {
    let contents = "# banner\n4096\ta@b.example\tctx\n8192\tc@d.example\tmore\n\n";
    let findings = bulk_extractor_findings("email", contents);
    assert_eq!(findings.len(), 2);
    assert_eq!(
        findings[0],
        Finding::new(Tool::BulkExtractor, "email", "a@b.example")
    );
    assert_eq!(findings[1].field, "c@d.example");
}

#[test]
fn carved_object_recorders_are_skipped_but_value_recorders_kept() {
    // The `*_carved` recorders are offset-keyed binary carvings, redundant
    // with the restore and value channels; the value recorders are kept.
    for carved in [
        "utmp_carved",
        "sqlite_carved",
        "ntfsmft_carved",
        "winpe_carved",
    ] {
        assert!(
            is_carved_object_recorder(carved),
            "{carved} must be skipped"
        );
    }
    for value in ["email", "domain", "url", "json", "ip"] {
        assert!(
            !is_carved_object_recorder(value),
            "{value} is a value recorder and must be kept"
        );
    }
}

#[test]
fn bulk_extractor_tolerates_a_single_column_line() {
    let findings = bulk_extractor_findings("note", "lonevalue\n");
    assert_eq!(
        findings,
        [Finding::new(Tool::BulkExtractor, "note", "lonevalue")]
    );
}

#[test]
fn plaso_pulls_the_source_path_and_descriptor() {
    let line = r#"{"path":"/var/log/wtmp.db","data_type":"linux:wtmp:event","message":"boot"}"#;
    let finding = plaso_finding(line).expect("a path is present");
    assert_eq!(
        finding,
        Finding::new(Tool::Plaso, "/var/log/wtmp.db", "linux:wtmp:event")
    );
}

#[test]
fn plaso_without_a_path_is_skipped_and_bad_json_too() {
    assert!(plaso_finding(r#"{"message":"no path here"}"#).is_none());
    assert!(plaso_finding("not json at all").is_none());
}

#[test]
fn journal_events_key_on_content_not_the_rotating_file() {
    // Two different journal files (rotation) carrying the same line collapse
    // to one content-keyed finding, so a benign line subtracts across images
    // instead of resurfacing under every new per-boot filename.
    let a = r#"{"data_type":"systemd:journal","display_name":"EXT:/var/log/journal/m/system@aaaa-0001-1111.journal","reporter":"systemd","message_body":"Stopped target System Shutdown."}"#;
    let b = r#"{"data_type":"systemd:journal","display_name":"EXT:/var/log/journal/m/system@bbbb-0002-2222.journal","reporter":"systemd","message_body":"Stopped target System Shutdown."}"#;
    let fa = plaso_finding(a).expect("a journal finding");
    let fb = plaso_finding(b).expect("a journal finding");
    assert_eq!(fa, fb, "same content must give the same finding");
    assert_eq!(
        fa,
        Finding::new(
            Tool::Plaso,
            "journal",
            "systemd: Stopped target System Shutdown."
        )
    );
}

#[test]
fn journal_file_stat_events_are_dropped() {
    // plaso's fs:stat for the rotating journal file itself is volatile by
    // path and is dropped; the journal's content is compared separately.
    let line = r#"{"data_type":"fs:stat","display_name":"/var/log/journal/m/system@cccc-0003-3333.journal"}"#;
    assert!(plaso_finding(line).is_none());
    // A non-journal file's stat is still a finding.
    let other = r#"{"data_type":"fs:stat","display_name":"/home/user/secret.txt"}"#;
    assert_eq!(
        plaso_finding(other),
        Some(Finding::new(
            Tool::Plaso,
            "/home/user/secret.txt",
            "fs:stat"
        ))
    );
}

#[test]
fn normalize_journal_body_masks_volatile_tokens_but_keeps_identifiers() {
    // Decimal runs -> N, long hex ids -> X; a leaked username/path survives.
    assert_eq!(
        normalize_journal_body("Sending SIGKILL to PID 1234"),
        "Sending SIGKILL to PID N"
    );
    // A 32-char boot/machine id (digits + hex letters, >= 8) is masked.
    assert_eq!(
        normalize_journal_body("boot 3333f264b48240fc8d4c8635a75023a5 done"),
        "boot X done"
    );
    // A hex-ish word (only letters) is kept, and so is a real identifier.
    assert_eq!(
        normalize_journal_body("session opened for user testuser"),
        "session opened for user testuser"
    );
    assert_eq!(normalize_journal_body("cafe deed"), "cafe deed");
}

#[test]
fn is_journal_file_matches_only_journal_files() {
    assert!(is_journal_file("/var/log/journal/m/system@x-1-2.journal"));
    assert!(is_journal_file(
        "EXT:/var/log/journal/m/user-1000@x.journal"
    ));
    assert!(!is_journal_file("/var/log/journal/m/secret.txt"));
    assert!(!is_journal_file("/var/log/wtmp.db"));
}

#[test]
fn restore_paths_become_absolute_on_image_paths() {
    let root = PathBuf::from("/tmp/outputs/restore/after");
    let file = root.join("var/log/wtmp.db");
    assert_eq!(
        restore_abs_path(&root, &file).as_deref(),
        Some("/var/log/wtmp.db")
    );
    // The root itself maps to nothing.
    assert_eq!(restore_abs_path(&root, &root), None);
}

// --- normalization boundaries (pure, no filesystem) ---------------------

#[test]
fn normalize_masks_a_pure_decimal_run_to_n() {
    // Exercises the `run_len == 0` discriminator (scan.rs:251) with an
    // all-hex input so the masker terminates: a pure decimal run is a
    // volatile token and must collapse to `N`. If the `== 0` test were
    // flipped to `!= 0`, each hex char would be copied verbatim and "1234"
    // would survive as "1234" instead of masking to "N".
    assert_eq!(normalize_journal_body("1234"), "N");
}

#[test]
fn normalize_keeps_a_long_all_letter_hex_word() {
    // The hex-id rule is `run_len >= 8 && has_digit && has_hex_letter`
    // (scan.rs:261). A run of eight hex *letters* with no digit is a
    // hex-ish word, not an identifier, so it is kept verbatim. If the first
    // `&&` were an `||`, the >= 8 length alone would mask it to "X".
    assert_eq!(normalize_journal_body("deadbeef"), "deadbeef");
}

#[test]
fn normalize_keeps_a_short_mixed_hex_run() {
    // The decimal rule is `has_digit && !has_hex_letter` (scan.rs:263). A
    // short run that has both a digit and a hex letter ("a1") is neither a
    // long hex id nor a pure decimal, so it is kept verbatim. If that `&&`
    // were an `||`, the digit alone would mask it to "N".
    assert_eq!(normalize_journal_body("a1"), "a1");
}

// --- filesystem-facing scanners (real tmp tree, no root needed) ---------

/// A self-cleaning unique temp directory built with the standard library
/// only (nails-oracle carries no `tempfile` dev-dependency).
struct TmpDir {
    path: PathBuf,
}

impl TmpDir {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "nails-oracle-scan-{}-{}-{}",
            std::process::id(),
            nanos,
            n
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Write a populated `outputs/` tree for the `before` image: one restored
/// file, one bulk_extractor feature file, one plaso event line.
fn build_before_outputs(outputs: &Path) {
    let restore = outputs.join("restore").join("before").join("etc");
    fs::create_dir_all(&restore).expect("restore dir");
    fs::write(restore.join("hostname"), b"host").expect("restore file");

    let be = outputs.join("bulk_extractor").join("before");
    fs::create_dir_all(&be).expect("bulk_extractor dir");
    fs::write(be.join("email.txt"), "4096\ta@b.example\tctx\n").expect("feature file");

    let plaso = outputs.join("plaso");
    fs::create_dir_all(&plaso).expect("plaso dir");
    fs::write(
        plaso.join("before.jsonl"),
        "{\"path\":\"/var/log/wtmp.db\",\"data_type\":\"linux:wtmp:event\"}\n",
    )
    .expect("plaso file");
}

#[test]
fn scan_all_errors_when_the_outputs_directory_is_missing() {
    // scan_all must surface a NotFound error when `outputs` is absent (the
    // `!outputs.is_dir()` guard, scan.rs:31). Dropping the `!`, or stubbing
    // the body to `Ok(Default::default())`, would return an empty success
    // instead of the error.
    let dir = TmpDir::new();
    let missing = dir.path().join("does-not-exist");
    let err = scan_all(&missing).expect_err("a missing outputs dir is an error");
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn scan_all_reads_findings_from_every_tool_subtree() {
    // A populated tree yields the restore, bulk_extractor and plaso findings
    // for the scanned image. A stubbed scan_all (`Ok(Default::default())`),
    // a stubbed scan_image (`BTreeSet::new()`), or the `is_dir` guard
    // flipped (which would error on this valid directory) all lose these.
    let dir = TmpDir::new();
    let outputs = dir.path().join("outputs");
    build_before_outputs(&outputs);

    let scans = scan_all(&outputs).expect("a populated outputs dir scans cleanly");
    assert!(
        scans
            .before
            .contains(&Finding::new(Tool::BtrfsRestore, "/etc/hostname", "")),
        "restore finding missing: {:?}",
        scans.before
    );
    assert!(
        scans
            .before
            .contains(&Finding::new(Tool::BulkExtractor, "email", "a@b.example")),
        "bulk_extractor finding missing: {:?}",
        scans.before
    );
    assert!(
        scans.before.contains(&Finding::new(
            Tool::Plaso,
            "/var/log/wtmp.db",
            "linux:wtmp:event"
        )),
        "plaso finding missing: {:?}",
        scans.before
    );
}

#[test]
fn scan_image_collects_the_restore_findings() {
    // scan_image returns the per-image findings; a stub returning an empty
    // set would drop them.
    let dir = TmpDir::new();
    let outputs = dir.path().join("outputs");
    build_before_outputs(&outputs);

    let out = scan_image(&outputs, ImageLabel::Before);
    assert!(
        out.contains(&Finding::new(Tool::BtrfsRestore, "/etc/hostname", "")),
        "{out:?}"
    );
    assert!(
        out.contains(&Finding::new(Tool::BulkExtractor, "email", "a@b.example")),
        "{out:?}"
    );
}

#[test]
fn scan_restore_reports_every_entry_by_its_kind_but_not_journals() {
    // A restore tree with a nested file, a top-level file, an empty
    // directory, a journal file and (on unix) a symlink to a directory. The
    // walk must report every entry by its kind -- a file with an empty
    // field, a directory as `dir`, a symlink as `symlink` -- except the
    // rotating journal file, which plaso compares by content, and it must
    // not walk through the symlink. The exact set pins the recursion, each
    // kind, the journal exclusion and the no-follow rule at once: a stubbed
    // walk, a dropped kind, a kept journal file or a followed link (which
    // would add /link/hostname) all change it.
    let dir = TmpDir::new();
    let root = dir.path().join("restore_root");
    let nested = root.join("etc");
    fs::create_dir_all(&nested).expect("nested dir");
    fs::write(nested.join("hostname"), b"host").expect("nested file");
    fs::write(root.join("topfile.txt"), b"top").expect("top file");
    fs::create_dir_all(root.join("var").join("lib").join("staging")).expect("empty dir");

    let journal = root.join("var").join("log").join("journal").join("m");
    fs::create_dir_all(&journal).expect("journal dir");
    fs::write(journal.join("system@x-1-2.journal"), b"j").expect("journal file");

    #[cfg(unix)]
    std::os::unix::fs::symlink("etc", root.join("link")).expect("symlink");

    let mut out = BTreeSet::new();
    scan_restore(&root, &mut out);

    let mut want: BTreeSet<Finding> = [
        ("/etc", "dir"),
        ("/etc/hostname", ""),
        ("/topfile.txt", ""),
        ("/var", "dir"),
        ("/var/lib", "dir"),
        ("/var/lib/staging", "dir"),
        ("/var/log", "dir"),
        ("/var/log/journal", "dir"),
        ("/var/log/journal/m", "dir"),
    ]
    .into_iter()
    .map(|(path, kind)| Finding::new(Tool::BtrfsRestore, path, kind))
    .collect();
    #[cfg(unix)]
    want.insert(Finding::new(Tool::BtrfsRestore, "/link", "symlink"));
    assert_eq!(out, want);
}

/// The restore findings `after - before - control` over three restored
/// trees: the difference the verdict weighs.
fn restore_residue(before: &Path, control: &Path, after: &Path) -> BTreeSet<Finding> {
    let walk = |root: &Path| {
        let mut out = BTreeSet::new();
        scan_restore(root, &mut out);
        out
    };
    let (before, control) = (walk(before), walk(control));
    walk(after)
        .into_iter()
        .filter(|f| !before.contains(f) && !control.contains(f))
        .collect()
}

/// Three restored trees, `before`, `control` and `after`, sharing one
/// baseline: a file and the directories every boot keeps.
fn three_trees(dir: &Path) -> [PathBuf; 3] {
    ["before", "control", "after"].map(|label| {
        let root = dir.join(label);
        let wants = root.join("etc/systemd/system/multi-user.target.wants");
        fs::create_dir_all(&wants).expect("wants dir");
        fs::create_dir_all(root.join("var/lib")).expect("var/lib dir");
        fs::write(root.join("etc/hostname"), b"").expect("hostname");
        root
    })
}

#[test]
fn an_empty_directory_new_in_after_alone_is_restore_residue() {
    // A teardown that leaves an empty staging directory on the decoy root
    // leaves a trace with no file in it, so the difference must name the
    // directory. A directory the clean control cycle creates too is boot
    // noise and subtracts, as does every directory all three images share.
    let dir = TmpDir::new();
    let [before, control, after] = three_trees(dir.path());
    for root in [&control, &after] {
        fs::create_dir_all(root.join("var/tmp/cycle")).expect("cycle dir");
    }
    fs::create_dir_all(after.join("var/lib/staging")).expect("staging dir");

    assert_eq!(
        restore_residue(&before, &control, &after),
        BTreeSet::from([Finding::new(Tool::BtrfsRestore, "/var/lib/staging", "dir")])
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_new_in_after_alone_is_restore_residue() {
    // A teardown that leaves a unit enabled on the decoy leaves only a
    // symlink, in a directory every image has, so the difference must name
    // the link. Its target need not exist in the restored tree.
    let dir = TmpDir::new();
    let [before, control, after] = three_trees(dir.path());
    let link = "etc/systemd/system/multi-user.target.wants/hidden.service";
    std::os::unix::fs::symlink("/etc/systemd/system/hidden.service", after.join(link))
        .expect("symlink");

    assert_eq!(
        restore_residue(&before, &control, &after),
        BTreeSet::from([Finding::new(
            Tool::BtrfsRestore,
            format!("/{link}"),
            "symlink"
        )])
    );
}

#[test]
fn scan_bulk_extractor_reads_features_and_skips_histograms() {
    // A `*.txt` feature file yields findings; a `*_histogram.txt` file is
    // skipped. This pins the directory read (a stub does nothing), the
    // `.txt` suffix test (dropping its `!` would skip the feature file), and
    // the histogram exclusion (turning its `||` into `&&` would process the
    // histogram).
    let dir = TmpDir::new();
    fs::write(dir.path().join("email.txt"), "4096\ta@b.example\tctx\n").expect("feature file");
    fs::write(
        dir.path().join("foo_histogram.txt"),
        "4096\tHIST_VALUE\tctx\n",
    )
    .expect("histogram file");

    let mut out = BTreeSet::new();
    scan_bulk_extractor(dir.path(), &mut out);

    assert!(
        out.contains(&Finding::new(Tool::BulkExtractor, "email", "a@b.example")),
        "feature file must be read: {out:?}"
    );
    assert!(
        !out.iter().any(|f| f.field == "HIST_VALUE"),
        "a histogram file must be skipped: {out:?}"
    );
}

#[test]
fn scan_plaso_reads_event_lines_from_the_timeline_file() {
    // scan_plaso parses each JSON line into a finding; a stub does nothing.
    let dir = TmpDir::new();
    let file = dir.path().join("after.jsonl");
    fs::write(
        &file,
        "{\"path\":\"/var/log/wtmp.db\",\"data_type\":\"linux:wtmp:event\"}\n",
    )
    .expect("plaso file");

    let mut out = BTreeSet::new();
    scan_plaso(&file, &mut out);
    assert!(
        out.contains(&Finding::new(
            Tool::Plaso,
            "/var/log/wtmp.db",
            "linux:wtmp:event"
        )),
        "{out:?}"
    );
}

#[test]
fn the_cli_fails_a_scan_whose_plaso_channel_was_dropped() {
    // run-scan.sh drops the plaso channel whole when docker is absent, the
    // pinned image cannot be pulled or an image's timeline fails, and the
    // restore channel leaves the rotating journal files to plaso. A run
    // that is otherwise clean must then fail rather than read clean, so the
    // CLI must decide with scan_verdict. With a timeline for every image the
    // same run is clean.
    let dir = TmpDir::new();
    let outputs = dir.path().join("outputs");
    for label in ImageLabel::ALL {
        let name = label.dir_name();
        let etc = outputs.join("restore").join(name).join("etc");
        fs::create_dir_all(&etc).expect("restore dir");
        fs::write(etc.join("hostname"), b"").expect("restore file");
        let be = outputs.join("bulk_extractor").join(name);
        fs::create_dir_all(&be).expect("bulk_extractor dir");
        let mut emails = String::from("4096\tcanary@oracle.example\tctx\n");
        if label == ImageLabel::After {
            emails.push_str("8192\tplanted@oracle.example\tctx\n");
        }
        fs::write(be.join("email.txt"), emails).expect("feature file");
    }
    let allowlist = dir.path().join("allowlist.json");
    fs::write(&allowlist, r#"{"entries":[]}"#).expect("allowlist file");
    let controls = dir.path().join("controls.json");
    fs::write(
        &controls,
        r#"{
          "positive_controls": [{"name": "planted", "tool": "bulk_extractor",
                                 "path": "email", "field": "planted@oracle.example"}],
          "canary": {"tool": "bulk_extractor", "path": "email",
                     "field": "canary@oracle.example"}
        }"#,
    )
    .expect("controls file");
    let args = vec![
        outputs.display().to_string(),
        "--allowlist".to_string(),
        allowlist.display().to_string(),
        "--controls".to_string(),
        controls.display().to_string(),
    ];

    assert_eq!(
        crate::run_inner(&args),
        Ok(1),
        "no plaso timeline: the run fails"
    );

    let plaso = outputs.join("plaso");
    fs::create_dir_all(&plaso).expect("plaso dir");
    for label in ImageLabel::ALL {
        fs::write(
            plaso.join(format!("{}.jsonl", label.dir_name())),
            "{\"path\":\"/etc/hostname\",\"data_type\":\"fs:stat\"}\n",
        )
        .expect("plaso file");
    }
    assert_eq!(
        crate::run_inner(&args),
        Ok(0),
        "every channel reported: clean"
    );
}

#[test]
fn load_allowlist_parses_a_file_and_errors_on_a_missing_one() {
    // load_allowlist must actually read and deserialize the file, and must
    // surface a read error for a missing path. A stub returning
    // `Ok(Default::default())` would yield an empty allowlist and never
    // error.
    let dir = TmpDir::new();
    let file = dir.path().join("allow.json");
    fs::write(
        &file,
        r#"{"entries":[{"path":"/var/lib/nixos","cite":"var-lib-nixos"}]}"#,
    )
    .expect("allowlist file");

    let allowlist = load_allowlist(&file).expect("a valid allowlist parses");
    assert_eq!(allowlist.entries.len(), 1);
    assert_eq!(allowlist.entries[0].path, "/var/lib/nixos");
    assert_eq!(allowlist.entries[0].cite, "var-lib-nixos");

    let missing = dir.path().join("nope.json");
    assert!(
        load_allowlist(&missing).is_err(),
        "a missing allowlist file is an error"
    );
}
