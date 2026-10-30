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
fn bulk_extractor_tolerates_a_single_column_line() {
    let findings = bulk_extractor_findings("note", "lonevalue\n");
    assert_eq!(
        findings,
        [Finding::new(Tool::BulkExtractor, "note", "lonevalue")]
    );
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

// --- the digest manifest (pure) ----------------------------------------------

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

#[test]
fn a_manifest_maps_each_file_to_its_digest() {
    // sha256sum --zero: text and binary mode, a name with a newline and a
    // backslash unescaped, NUL-terminated records.
    let manifest = format!("{DIGEST_A}  ./etc/hostname\0{DIGEST_B} *./var/log/odd\nname\\x\0");
    let digests = parse_digest_manifest(manifest.as_bytes()).expect("a valid manifest");
    assert_eq!(
        digests,
        BTreeMap::from([
            ("/etc/hostname".to_string(), DIGEST_A.to_string()),
            (
                "/var/log/odd\nname\\x".to_string(),
                DIGEST_B.to_ascii_lowercase()
            ),
        ])
    );
    assert_eq!(parse_digest_manifest(b""), Ok(BTreeMap::new()));
}

#[test]
fn a_manifest_that_is_not_one_is_rejected() {
    for broken in [
        "short  ./x".to_string(),
        format!("{}  ./x", "g".repeat(64)),
        format!("{DIGEST_A}  /etc/hostname"),
        format!("{DIGEST_A}  ./"),
        format!("{DIGEST_A} ./x"),
        format!("{DIGEST_A}  ./x\0{DIGEST_B}  ./x"),
    ] {
        assert!(
            parse_digest_manifest(broken.as_bytes()).is_err(),
            "{broken:?}"
        );
    }
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

/// A stand-in for a file's SHA-256 in a test manifest: the scan never hashes
/// anything itself, it only carries the digest `run-scan.sh` recorded, so any
/// 64 hex digits that differ with the content do.
fn digest_of(content: &[u8]) -> String {
    let mut hex: String = content.iter().map(|b| format!("{b:02x}")).collect();
    hex.truncate(64);
    format!("{hex:0>64}")
}

/// Write the digest manifest of the restored tree at `root` next to it, as
/// `run-scan.sh` does, and return its path.
fn write_manifest(root: &Path) -> PathBuf {
    let mut records = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read dir") {
            let path = entry.expect("entry").path();
            let kind = fs::symlink_metadata(&path).expect("metadata").file_type();
            if kind.is_dir() {
                stack.push(path);
            } else if kind.is_file() {
                let rel = path.strip_prefix(root).expect("under root");
                let digest = digest_of(&fs::read(&path).expect("read file"));
                records.extend(format!("{digest}  ./{}\0", rel.display()).into_bytes());
            }
        }
    }
    let manifest = root.with_extension("sha256");
    fs::write(&manifest, records).expect("write manifest");
    manifest
}

/// Write a populated `outputs/` tree for the `before` image: one restored
/// file and its manifest, one bulk_extractor feature file, one plaso event
/// line.
fn build_before_outputs(outputs: &Path) {
    let root = outputs.join("restore").join("before");
    fs::create_dir_all(root.join("etc")).expect("restore dir");
    fs::write(root.join("etc").join("hostname"), b"host").expect("restore file");
    write_manifest(&root);

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

/// The restore finding for a file holding `content`.
fn restored_file(path: &str, content: &[u8]) -> Finding {
    Finding::new(
        Tool::BtrfsRestore,
        path,
        format!("sha256:{}", digest_of(content)),
    )
}

#[test]
fn scan_all_errors_when_the_outputs_directory_is_missing() {
    // scan_all must surface a NotFound error when `outputs` is absent (the
    // `!outputs.is_dir()` guard). Dropping the `!`, or stubbing the body to
    // `Ok(Default::default())`, would return an empty success instead of the
    // error.
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
    for want in [
        restored_file("/etc/hostname", b"host"),
        Finding::new(Tool::BulkExtractor, "email", "a@b.example"),
        Finding::new(Tool::Plaso, "/var/log/wtmp.db", "linux:wtmp:event"),
    ] {
        assert!(scans.before.contains(&want), "{want:?}: {:?}", scans.before);
    }
}

#[test]
fn scan_image_collects_the_restore_findings() {
    // scan_image returns the per-image findings; a stub returning an empty
    // set would drop them.
    let dir = TmpDir::new();
    let outputs = dir.path().join("outputs");
    build_before_outputs(&outputs);

    let out = scan_image(&outputs, ImageLabel::Before).expect("scans");
    assert!(
        out.contains(&restored_file("/etc/hostname", b"host")),
        "{out:?}"
    );
    assert!(
        out.contains(&Finding::new(Tool::BulkExtractor, "email", "a@b.example")),
        "{out:?}"
    );
}

/// Scan the restored tree at `root` against its manifest.
fn restore_findings(root: &Path) -> io::Result<BTreeSet<Finding>> {
    let mut out = BTreeSet::new();
    scan_restore(root, &root.with_extension("sha256"), &mut out)?;
    Ok(out)
}

#[test]
fn scan_restore_reports_every_entry_by_its_kind_and_content_but_not_journals() {
    // A restore tree with a nested file, a top-level file, an empty
    // directory, a journal file and (on unix) a symlink to a directory. The
    // walk must report every entry by its kind and content -- a file by its
    // digest, a directory as `dir`, a symlink with its target -- except the
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
    write_manifest(&root);

    let mut want: BTreeSet<Finding> = [
        ("/etc", "dir"),
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
    want.insert(restored_file("/etc/hostname", b"host"));
    want.insert(restored_file("/topfile.txt", b"top"));
    #[cfg(unix)]
    want.insert(Finding::new(Tool::BtrfsRestore, "/link", "symlink:etc"));
    assert_eq!(restore_findings(&root).expect("scans"), want);
}

#[test]
fn a_missing_restore_tree_yields_nothing_and_its_manifest_is_not_needed() {
    // A carve that did not run is a silent channel, which the verdict fails;
    // it is not an I/O error.
    let dir = TmpDir::new();
    let root = dir.path().join("never-carved");
    assert_eq!(restore_findings(&root).expect("scans"), BTreeSet::new());
}

#[test]
fn a_restore_tree_without_its_manifest_stops_the_scan() {
    let dir = TmpDir::new();
    let root = dir.path().join("restore_root");
    fs::create_dir_all(root.join("etc")).expect("dir");
    fs::write(root.join("etc").join("shadow"), b"x").expect("file");
    let err = restore_findings(&root).expect_err("no manifest");
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn a_file_and_its_digest_must_match_one_for_one() {
    // A file the manifest has no digest for, and a digest for a file the tree
    // lacks, each mean the tree is not the one that was hashed: never a
    // finding without content, never a silently dropped one.
    let dir = TmpDir::new();
    let root = dir.path().join("restore_root");
    fs::create_dir_all(&root).expect("dir");
    fs::write(root.join("kept"), b"x").expect("file");
    let manifest = write_manifest(&root);

    fs::write(root.join("unhashed"), b"y").expect("file");
    let err = restore_findings(&root).expect_err("a file without a digest");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("/unhashed"), "{err}");

    fs::remove_file(root.join("unhashed")).expect("remove");
    fs::remove_file(root.join("kept")).expect("remove");
    let err = restore_findings(&root).expect_err("a digest without a file");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("/kept"), "{err}");
    assert!(manifest.exists());
}

/// Make `path` unreadable and say whether that denies this process: as root,
/// nothing is denied and a test of the denial has nothing to check.
#[cfg(unix)]
fn deny(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o000)).expect("chmod");
    let denied = if path.is_dir() {
        fs::read_dir(path).is_err()
    } else {
        fs::read(path).is_err()
    };
    if !denied {
        allow(path);
    }
    denied
}

/// Undo [`deny`], so the temp directory can be removed.
#[cfg(unix)]
fn allow(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("chmod");
}

#[cfg(unix)]
#[test]
fn an_unreadable_directory_in_the_restore_tree_stops_the_scan() {
    // Re-rendering a verdict as a normal user over a tree carved as root
    // meets the decoy's root-only directories. Skipping one would drop a
    // leaked /root/.bash_history from every image alike and read clean.
    let dir = TmpDir::new();
    let root = dir.path().join("restore_root");
    let private = root.join("root");
    fs::create_dir_all(&private).expect("dir");
    fs::write(private.join(".bash_history"), b"leak").expect("file");
    write_manifest(&root);
    if !deny(&private) {
        return;
    }
    let result = restore_findings(&root);
    allow(&private);
    let err = result.expect_err("an unreadable directory is an error");
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
}

/// The restore findings `after - before - control` over three restored
/// trees: the additions the verdict weighs.
fn restore_residue(before: &Path, control: &Path, after: &Path) -> BTreeSet<Finding> {
    let walk = |root: &Path| {
        write_manifest(root);
        restore_findings(root).expect("scans")
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
            "symlink:/etc/systemd/system/hidden.service"
        )])
    );
}

#[test]
fn a_file_rewritten_in_place_reads_differently_in_after() {
    // The same path with other content is another finding: what the verdict
    // weighs as a change of that entry.
    let dir = TmpDir::new();
    let [before, control, after] = three_trees(dir.path());
    fs::write(after.join("etc/hostname"), b"hidden-host").expect("rewrite");
    assert_eq!(
        restore_residue(&before, &control, &after),
        BTreeSet::from([restored_file("/etc/hostname", b"hidden-host")])
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
    scan_bulk_extractor(dir.path(), &mut out).expect("scans");

    assert!(
        out.contains(&Finding::new(Tool::BulkExtractor, "email", "a@b.example")),
        "feature file must be read: {out:?}"
    );
    assert!(
        !out.iter().any(|f| f.field == "HIST_VALUE"),
        "a histogram file must be skipped: {out:?}"
    );
}

/// A 384-byte login record of `kind` for process `pid` on tty1.
fn login_record(kind: i16, pid: i32) -> Vec<u8> {
    let mut record = vec![0_u8; crate::carved::UTMP_RECORD_SIZE];
    record[0..2].copy_from_slice(&kind.to_le_bytes());
    record[4..8].copy_from_slice(&pid.to_le_bytes());
    record[8..12].copy_from_slice(b"tty1");
    record
}

/// A carved-object line of bulk_extractor: offset, saved file, context.
fn carved_line(offset: u64, file: &str, sha1: &str) -> String {
    format!(
        "{offset}\t{file}\t<fileobject><filename>{file}</filename>\
         <hashdigest type='sha1'>{sha1}</hashdigest></fileobject>\n"
    )
}

#[test]
fn carved_login_records_are_read_and_keyed_by_content() {
    // The utmp carver names each record by its offset; the scan reads the
    // saved record and keys it by what it records, so the same getty record at
    // two offsets is one finding. Other carvers are keyed by content hash,
    // and the sqlite carver and the duplicate-block list are left out.
    let dir = TmpDir::new();
    let be = dir.path();
    let saved = be.join("utmp_carved").join("000");
    fs::create_dir_all(&saved).expect("carved dir");
    fs::write(saved.join("100utmp"), login_record(6, 618)).expect("record");
    fs::write(saved.join("900utmp"), login_record(6, 627)).expect("record");
    fs::write(saved.join("500utmp"), login_record(6, 1625)).expect("record");
    let lines: String = [100, 900, 500]
        .map(|offset| carved_line(offset, &format!("utmp_carved/000/{offset}utmp"), "aa"))
        .concat();
    fs::write(be.join("utmp_carved.txt"), format!("# banner\n{lines}")).expect("feature file");
    fs::write(
        be.join("zip_carved.txt"),
        carved_line(7, "zip_carved/000/7.zip", "AB12"),
    )
    .expect("feature file");
    fs::write(
        be.join("sqlite_carved.txt"),
        carved_line(8, "sqlite_carved/000/8.sqlite3", "cd"),
    )
    .expect("feature file");
    fs::write(be.join("duplicates.txt"), "16777216\t50331648\tabcd\n").expect("feature file");

    let mut out = BTreeSet::new();
    scan_bulk_extractor(be, &mut out).expect("scans");
    let getty = |range: &str| {
        Finding::new(
            Tool::BulkExtractor,
            "utmp_carved",
            format!(
                "type=LOGIN_PROCESS pid={range} line=tty1 id= user= host= exit=0/0 addr=0.0.0.0"
            ),
        )
    };
    assert_eq!(
        out,
        BTreeSet::from([
            getty("512-1023"),
            getty("1024-2047"),
            Finding::new(Tool::BulkExtractor, "zip_carved", "sha1:ab12"),
        ])
    );
}

#[test]
fn a_carved_record_that_cannot_be_read_as_one_stops_the_scan() {
    // A record outside the output directory, a missing record file, a file
    // of the wrong size and a carved line with no hash are each output the
    // scan did not get from the carver: never skipped.
    let dir = TmpDir::new();
    let be = dir.path();
    fs::create_dir_all(be.join("utmp_carved")).expect("dir");
    fs::write(be.join("utmp_carved").join("short"), [0_u8; 10]).expect("file");
    for (file, line) in [
        ("utmp_carved.txt", carved_line(1, "../escape", "aa")),
        (
            "utmp_carved.txt",
            carved_line(1, "utmp_carved/missing", "aa"),
        ),
        ("utmp_carved.txt", carved_line(1, "utmp_carved/short", "aa")),
        (
            "zip_carved.txt",
            "7\tzip_carved/000/7.zip\t<fileobject/>\n".to_string(),
        ),
    ] {
        fs::write(be.join(file), line).expect("feature file");
        let mut out = BTreeSet::new();
        assert!(scan_bulk_extractor(be, &mut out).is_err(), "{file}");
        fs::remove_file(be.join(file)).expect("remove");
    }
}

#[cfg(unix)]
#[test]
fn an_unreadable_feature_file_stops_the_scan() {
    let dir = TmpDir::new();
    let feature = dir.path().join("email.txt");
    fs::write(&feature, "4096\tleak@hidden.example\tctx\n").expect("feature file");
    if !deny(&feature) {
        return;
    }
    let mut out = BTreeSet::new();
    let result = scan_bulk_extractor(dir.path(), &mut out);
    allow(&feature);
    let err = result.expect_err("an unreadable feature file is an error");
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn a_missing_bulk_extractor_dir_or_timeline_yields_nothing() {
    let dir = TmpDir::new();
    let mut out = BTreeSet::new();
    scan_bulk_extractor(&dir.path().join("none"), &mut out).expect("scans");
    scan_plaso(&dir.path().join("none.jsonl"), &mut out).expect("scans");
    assert!(out.is_empty());
}

#[test]
fn scan_plaso_reads_event_lines_from_the_timeline_file() {
    // scan_plaso parses each JSON line into a finding; a stub does nothing. A
    // byte that is not UTF-8 costs its own line, never the timeline.
    let dir = TmpDir::new();
    let file = dir.path().join("after.jsonl");
    let mut timeline =
        b"{\"path\":\"/var/log/wtmp.db\",\"data_type\":\"linux:wtmp:event\"}\n".to_vec();
    timeline.extend(b"{\"path\":\"/x\",\"data_type\":\"t\",\"v\":\"\xff\"}\n");
    fs::write(&file, timeline).expect("plaso file");

    let mut out = BTreeSet::new();
    scan_plaso(&file, &mut out).expect("scans");
    assert!(
        out.contains(&Finding::new(
            Tool::Plaso,
            "/var/log/wtmp.db",
            "linux:wtmp:event"
        )),
        "{out:?}"
    );
    assert!(
        out.contains(&Finding::new(Tool::Plaso, "/x", "t v=\u{fffd}")),
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
        let root = outputs.join("restore").join(name);
        fs::create_dir_all(root.join("etc")).expect("restore dir");
        fs::write(root.join("etc").join("hostname"), b"").expect("restore file");
        write_manifest(&root);
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

    // An outputs tree the scan cannot read in full is an I/O error (exit 2),
    // never a verdict.
    fs::remove_file(outputs.join("restore").join("after.sha256")).expect("remove");
    let err = crate::run_inner(&args).expect_err("an unreadable outputs tree");
    assert!(err.contains("after.sha256"), "{err}");
}

// --- the Nix store database's rows -------------------------------------------

/// The dump `run-scan.sh` writes of a store database that registers
/// `store_paths` and whose `ValidPaths` ids have reached `sequence`, one row a
/// line: a schema entry, then for each path its row and a reference to itself,
/// then the sequence.
fn store_dump(store_paths: &[&str], sequence: usize) -> String {
    let mut lines = vec![
        r#"{"table":"sqlite_master","row":{"type":"table","name":"ValidPaths","tbl_name":"ValidPaths","rootpage":2,"sql":"CREATE TABLE ValidPaths (id integer primary key, path text)"}}"#
            .to_string(),
    ];
    for (id, path) in (1..).zip(store_paths) {
        lines.push(format!(
            r#"{{"table":"ValidPaths","row":{{"id":{id},"path":"{path}","hash":"sha256:00","registrationTime":{id},"deriver":null,"narSize":1,"ultimate":null,"sigs":null,"ca":null}}}}"#
        ));
        lines.push(format!(
            r#"{{"table":"Refs","row":{{"referrer":{id},"reference":{id}}}}}"#
        ));
    }
    lines.push(format!(
        r#"{{"table":"sqlite_sequence","row":{{"name":"ValidPaths","seq":{sequence}}}}}"#
    ));
    lines.join("\n") + "\n"
}

/// Restore `db_bytes` as the Nix store database of the tree at `root`, and
/// write `dumped` as its dump at `dump` unless it is `None`.
fn restore_store_database(root: &Path, db_bytes: &[u8], dump: &Path, dumped: Option<&str>) {
    let db = root.join(NIX_DB_PATH.trim_start_matches('/'));
    fs::create_dir_all(db.parent().expect("parent")).expect("db dir");
    fs::write(&db, db_bytes).expect("db file");
    if let Some(dumped) = dumped {
        fs::create_dir_all(dump.parent().expect("parent")).expect("dump dir");
        fs::write(dump, dumped).expect("dump");
    }
}

/// The finding of the row that registers `store_path`.
fn store_row(store_path: &str) -> Finding {
    Finding::new(
        Tool::NixDb,
        NIX_DB_PATH,
        format!(r#"ValidPaths hash="sha256:00" narSize=1 path="{store_path}""#),
    )
}

#[test]
fn the_rows_of_a_restored_nix_store_database_are_read() {
    // Every row `run-scan.sh` dumped, of each table and of the schema, is a
    // finding of its own channel, next to the database file's restore entry.
    let dir = TmpDir::new();
    let outputs = dir.path().join("outputs");
    build_before_outputs(&outputs);
    let root = outputs.join("restore").join("before");
    let dump = outputs.join("nix_db").join("before.jsonl");
    let dumped = store_dump(&["/nix/store/a-decoy", "/nix/store/b-decoy"], 2);
    restore_store_database(&root, b"SQLite format 3", &dump, Some(&dumped));
    write_manifest(&root);

    let found = scan_image(&outputs, ImageLabel::Before).expect("scans");
    let row = |field: &str| Finding::new(Tool::NixDb, NIX_DB_PATH, field);
    for expected in [
        store_row("/nix/store/a-decoy"),
        store_row("/nix/store/b-decoy"),
        row("Refs reference=2 referrer=2"),
        row(r#"sqlite_sequence name="ValidPaths" seq=2"#),
        row(concat!(
            r#"sqlite_master name="ValidPaths" sql="CREATE TABLE ValidPaths (id integer primary "#,
            r#"key, path text)" tbl_name="ValidPaths" type="table""#,
        )),
        restored_file(NIX_DB_PATH, b"SQLite format 3"),
    ] {
        assert!(found.contains(&expected), "{expected:?} in {found:?}");
    }
}

#[test]
fn a_restored_nix_store_database_and_its_rows_go_together() {
    // A database without its rows would leave the file unread, its digest
    // being noise on the oracle's decoys; rows without the database are not
    // this carve's; rows that are not the dump's are not read. Each stops the
    // scan.
    let dir = TmpDir::new();
    let root = dir.path().join("restore").join("after");
    let dump = dir.path().join("nix_db").join("after.jsonl");
    fs::create_dir_all(&root).expect("restore dir");
    let mut out = BTreeSet::new();
    scan_nix_db(&root, &dump, &mut out).expect("no database, no rows: nothing to read");
    assert!(out.is_empty());

    restore_store_database(&root, b"db", &dump, None);
    let err = scan_nix_db(&root, &dump, &mut out).expect_err("a database without its rows");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("after.jsonl"), "{err}");

    fs::create_dir_all(dump.parent().expect("parent")).expect("dump dir");
    fs::write(&dump, "not the rows").expect("dump");
    let err = scan_nix_db(&root, &dump, &mut out).expect_err("rows that are not the dump's");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    fs::remove_file(root.join(NIX_DB_PATH.trim_start_matches('/'))).expect("remove");
    fs::write(&dump, "").expect("dump");
    let err = scan_nix_db(&root, &dump, &mut out).expect_err("rows without a database");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(out.is_empty());
}

/// Write a complete outputs tree for the three images, every channel
/// reporting, with the Nix store database restored on each: its file holds
/// another digest on every image, as each start of the oracle's decoy VMs
/// rewrites it, and `dumped` is its dump on `before` and the control cycle,
/// `after_dumped` on `after`. Returns the CLI arguments that render its
/// verdict.
fn store_database_world(dir: &Path, dumped: &str, after_dumped: &str) -> Vec<String> {
    let outputs = dir.join("outputs");
    for label in ImageLabel::ALL {
        let name = label.dir_name();
        let root = outputs.join("restore").join(name);
        fs::create_dir_all(root.join("etc")).expect("restore dir");
        fs::write(root.join("etc").join("hostname"), b"").expect("restore file");
        let image_dumped = if label == ImageLabel::After {
            after_dumped
        } else {
            dumped
        };
        restore_store_database(
            &root,
            name.as_bytes(),
            &outputs.join("nix_db").join(format!("{name}.jsonl")),
            Some(image_dumped),
        );
        write_manifest(&root);
        let be = outputs.join("bulk_extractor").join(name);
        fs::create_dir_all(&be).expect("bulk_extractor dir");
        let mut emails = String::from("4096\tcanary@oracle.example\tctx\n");
        if label == ImageLabel::After {
            emails.push_str("8192\tplanted@oracle.example\tctx\n");
        }
        fs::write(be.join("email.txt"), emails).expect("feature file");
        let plaso = outputs.join("plaso");
        fs::create_dir_all(&plaso).expect("plaso dir");
        fs::write(
            plaso.join(format!("{name}.jsonl")),
            "{\"path\":\"/etc/hostname\",\"data_type\":\"fs:stat\"}\n",
        )
        .expect("plaso file");
    }
    let allowlist = dir.join("allowlist.json");
    fs::write(&allowlist, r#"{"entries":[]}"#).expect("allowlist file");
    let controls = dir.join("controls.json");
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
    vec![
        outputs.display().to_string(),
        "--allowlist".to_string(),
        allowlist.display().to_string(),
        "--controls".to_string(),
        controls.display().to_string(),
    ]
}

#[test]
fn the_cli_fails_a_store_path_registered_in_the_database_a_reboot_rewrites() {
    // The database file differs on every image, so its restore entry is
    // noise whatever after holds; a store path the session registered is a
    // row only after has, and fails the run.
    let decoy = store_dump(&["/nix/store/a-decoy-system"], 1);
    let dir = TmpDir::new();
    let args = store_database_world(dir.path(), &decoy, &decoy);
    assert_eq!(
        crate::run_inner(&args),
        Ok(0),
        "the decoy's own rows: clean"
    );

    let dir = TmpDir::new();
    let hidden = store_dump(
        &["/nix/store/a-decoy-system", "/nix/store/b-hidden-package"],
        2,
    );
    let args = store_database_world(dir.path(), &decoy, &hidden);
    assert_eq!(
        crate::run_inner(&args),
        Ok(1),
        "a row new in after: residue"
    );
}

#[test]
fn the_cli_fails_a_store_path_registered_and_collected_again() {
    // The session registered a store path and collected it again: the database
    // registers the decoy's own paths once more, but the sequence of their ids
    // stays raised, a row only after has.
    let decoy = ["/nix/store/a-decoy-system"];
    let dir = TmpDir::new();
    let args = store_database_world(dir.path(), &store_dump(&decoy, 1), &store_dump(&decoy, 2));
    assert_eq!(crate::run_inner(&args), Ok(1));
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
        r#"{"entries":[{"path":"/var/lib/systemd/timesync/clock","cite":"timesync-clock"},
                       {"path":"/var/lib/old","cite":"timesync-clock","removed":true}]}"#,
    )
    .expect("allowlist file");

    let allowlist = load_allowlist(&file).expect("a valid allowlist parses");
    assert_eq!(allowlist.entries.len(), 2);
    assert_eq!(allowlist.entries[0].path, "/var/lib/systemd/timesync/clock");
    assert_eq!(allowlist.entries[0].cite, "timesync-clock");
    assert!(
        !allowlist.entries[0].removed,
        "an entry covers arrivals by default"
    );
    assert!(allowlist.entries[1].removed);

    let missing = dir.path().join("nope.json");
    assert!(
        load_allowlist(&missing).is_err(),
        "a missing allowlist file is an error"
    );
}

/// `present` tells a missing path, a tool that did not run, from one that
/// cannot be looked up: a path below a regular file is an error, never
/// absent, so a scan never reads such a tool's output as missing.
#[test]
fn present_tells_a_missing_path_from_one_that_cannot_be_looked_up() {
    let dir = TmpDir::new();
    let file = dir.path().join("file");
    std::fs::write(&file, "").unwrap();
    std::os::unix::fs::symlink(dir.path().join("gone"), dir.path().join("dangling")).unwrap();

    assert!(present(&file).unwrap());
    assert!(present(&dir.path().join("dangling")).unwrap());
    assert!(!present(&dir.path().join("missing")).unwrap());
    let err = present(&file.join("below")).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotADirectory, "{err}");
}
