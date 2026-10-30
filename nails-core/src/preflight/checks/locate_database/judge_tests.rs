// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

fn list(values: &[&str], origin: &str) -> List {
    List::complete(
        values
            .iter()
            .map(|value| Entry {
                value: value.as_bytes().to_vec(),
                origin: origin.to_string(),
            })
            .collect(),
    )
}

fn lists(paths: &[&str], names: &[&str], fs: &[&str]) -> Lists {
    Lists {
        paths: list(paths, "PRUNEPATHS in /etc/updatedb.conf"),
        names: list(names, "PRUNENAMES in /etc/updatedb.conf"),
        fs: list(fs, "PRUNEFS in /etc/updatedb.conf"),
        ..Lists::default()
    }
}

/// The volume at `/mnt/data`, mounted on a root of its own device.
fn volume() -> Location {
    Location {
        path: PathBuf::from("/mnt/data"),
        crossings: vec![(PathBuf::from("/mnt/data"), "ext4".to_string())],
    }
}

fn covered(cover: &Cover) -> &str {
    match cover {
        Cover::Covered(rule) => rule,
        other => panic!("not covered: {other:?}"),
    }
}

#[test]
fn a_path_entry_covers_the_volume_and_every_directory_below_it() {
    for entry in ["/mnt/data", "/mnt", "/"] {
        let cover = cover(&lists(&[entry], &[], &[]), &volume());
        assert_eq!(
            covered(&cover),
            format!("PRUNEPATHS in /etc/updatedb.conf lists {entry}")
        );
    }
}

#[test]
fn a_path_entry_must_name_a_directory_on_the_way_exactly() {
    for entry in [
        "/mnt/",
        "/mn",
        "/mnt/data/",
        "//mnt",
        "/mnt/data/x",
        "mnt",
        "",
    ] {
        assert_eq!(
            cover(&lists(&[entry], &[], &[]), &volume()),
            Cover::Not(PathBuf::from("/mnt/data")),
            "{entry:?}"
        );
    }
}

#[test]
fn a_name_entry_covers_a_directory_below_the_scan_root() {
    for name in ["mnt", "data"] {
        let cover = cover(&lists(&[], &[name], &[]), &volume());
        assert!(
            covered(&cover).starts_with(&format!("PRUNENAMES in /etc/updatedb.conf lists {name}")),
            "{cover:?}"
        );
    }
    assert!(matches!(
        cover(&lists(&[], &["Data", "mnt/data", "/"], &[]), &volume()),
        Cover::Not(_)
    ));
}

#[test]
fn a_filesystem_entry_covers_where_the_device_changes() {
    let cover = cover(&lists(&[], &[], &["EXT4"]), &volume());
    assert_eq!(
        covered(&cover),
        "PRUNEFS in /etc/updatedb.conf lists EXT4, the type of the filesystem mounted at /mnt/data"
    );
    // An ancestor's crossing covers the volume below it too.
    let below_tmpfs = Location {
        path: PathBuf::from("/run/media/data"),
        crossings: vec![
            (PathBuf::from("/run"), "tmpfs".to_string()),
            (PathBuf::from("/run/media/data"), "ext4".to_string()),
        ],
    };
    assert!(covered(&cover_of(&["tmpfs"], &below_tmpfs)).contains("mounted at /run"));
    // No crossing at the volume, no cover by its type.
    let folder = Location {
        path: PathBuf::from("/mnt/data"),
        crossings: Vec::new(),
    };
    assert!(matches!(cover_of(&["ext4"], &folder), Cover::Not(_)));
}

fn cover_of(fs: &[&str], location: &Location) -> Cover {
    cover(&lists(&[], &[], fs), location)
}

#[test]
fn the_scan_roots_own_filesystem_and_name_are_never_compared() {
    let mut scanned = lists(&[], &["data"], &["ext4"]);
    scanned.scan_root = Some((
        PathBuf::from("/mnt/data"),
        "--database-root in X".to_string(),
    ));
    assert_eq!(
        cover(&scanned, &volume()),
        Cover::Not(PathBuf::from("/mnt/data"))
    );
    // Its path is.
    scanned.paths = list(&["/mnt/data"], "--prunepaths in X");
    assert_eq!(
        covered(&cover(&scanned, &volume())),
        "--prunepaths in X lists /mnt/data"
    );
}

#[test]
fn a_scan_root_elsewhere_covers_and_one_inside_the_volume_does_not() {
    let mut elsewhere = lists(&[], &[], &[]);
    elsewhere.scan_root = Some((PathBuf::from("/home"), "--database-root in X".to_string()));
    assert_eq!(
        covered(&cover(&elsewhere, &volume())),
        "--database-root in X starts the scan at /home, which does not hold /mnt/data"
    );

    let mut inside = lists(&[], &[], &[]);
    inside.scan_root = Some((
        PathBuf::from("/mnt/data/root"),
        "--database-root in X".to_string(),
    ));
    assert_eq!(
        cover(&inside, &volume()),
        Cover::Not(PathBuf::from("/mnt/data"))
    );
    inside.paths = list(&["/mnt/data/root"], "--add-prunepaths in X");
    assert!(covered(&cover(&inside, &volume())).ends_with("where the scan starts"));
    inside.paths = List::default();
    inside.incomplete = Some("the file cannot be read".to_string());
    assert_eq!(
        cover(&inside, &volume()),
        Cover::Unknown("the file cannot be read".to_string())
    );
}

#[test]
fn an_incomplete_list_that_does_not_cover_cannot_tell() {
    let mut partial = lists(&["/tmp"], &[], &[]);
    partial.paths.complete = false;
    partial.incomplete = Some("NAILS cannot read /etc/updatedb.conf".to_string());
    assert_eq!(
        cover(&partial, &volume()),
        Cover::Unknown("NAILS cannot read /etc/updatedb.conf".to_string())
    );
    // What the options add covers whatever the file holds.
    partial.paths.entries.push(Entry {
        value: b"/mnt".to_vec(),
        origin: "--add-prunepaths in X".to_string(),
    });
    assert!(matches!(cover(&partial, &volume()), Cover::Covered(_)));
    // Without a reason the judge still cannot tell.
    let mut silent = lists(&[], &[], &[]);
    silent.fs.complete = false;
    assert!(matches!(cover(&silent, &volume()), Cover::Unknown(_)));
}

fn run(start: Start, lists: Result<Lists, String>) -> Run {
    Run {
        start,
        lists,
        database: Some("/var/lib/plocate/plocate.db".to_string()),
    }
}

#[test]
fn every_location_must_be_covered() {
    let second = Location {
        path: PathBuf::from("/srv/copy"),
        crossings: vec![(PathBuf::from("/srv/copy"), "ext4".to_string())],
    };
    let mnt = run(Start::Timer("t".into()), Ok(lists(&["/mnt"], &[], &[])));
    assert_eq!(
        run_cover(&mnt, &[volume(), second.clone()]),
        Cover::Not(PathBuf::from("/srv/copy"))
    );
    let both = run(
        Start::Timer("t".into()),
        Ok(lists(&["/mnt", "/srv"], &[], &[])),
    );
    assert_eq!(
        covered(&run_cover(&both, &[volume(), second])),
        "PRUNEPATHS in /etc/updatedb.conf lists /mnt, and PRUNEPATHS in /etc/updatedb.conf \
         lists /srv"
    );
    let unknown = run(Start::Timer("t".into()), Err("why".to_string()));
    assert_eq!(
        run_cover(&unknown, &[volume()]),
        Cover::Unknown("why".to_string())
    );
}

#[test]
fn the_verdict_fails_only_on_a_run_that_runs_now_or_is_scheduled() {
    let bare = || Ok(lists(&[], &[], &[]));
    assert_eq!(verdict(false, &[], &[volume()]), Verdict::NotInstalled);
    assert_eq!(verdict(true, &[], &[volume()]), Verdict::Pass(Vec::new()));

    let by_hand = run(Start::ByHand("/usr/bin/updatedb".into()), bare());
    let Verdict::Warn(warned) = verdict(true, std::slice::from_ref(&by_hand), &[volume()]) else {
        panic!("a run by hand warns");
    };
    assert_eq!(warned[0].run, by_hand);

    let timer = run(Start::Timer("plocate-updatedb.timer".into()), bare());
    let now = run(Start::Now("process 9".into()), bare());
    let cron = run(Start::Cron("/etc/cron.daily/mlocate".into()), bare());
    let Verdict::Fail(failed) = verdict(
        true,
        &[by_hand.clone(), timer.clone(), cron.clone(), now.clone()],
        &[volume()],
    ) else {
        panic!("a scheduled run that indexes the volume fails");
    };
    // Running now first, then the scheduled ones; a run by hand is left out.
    assert_eq!(
        failed.iter().map(|judged| &judged.run).collect::<Vec<_>>(),
        [&now, &timer, &cron]
    );
}

#[test]
fn a_run_that_cannot_be_told_warns_and_covered_runs_pass_with_their_rules() {
    let unknown = run(Start::Timer("t".into()), Err("updatedb stops".to_string()));
    let covered_run = run(Start::Now("n".into()), Ok(lists(&["/mnt"], &[], &[])));
    let Verdict::Warn(warned) = verdict(true, &[covered_run.clone(), unknown.clone()], &[volume()])
    else {
        panic!("a run NAILS cannot tell about warns");
    };
    assert_eq!(warned.len(), 1);
    assert_eq!(warned[0].run, unknown);

    let by_hand = run(Start::ByHand("p".into()), Ok(lists(&["/mnt"], &[], &[])));
    let by_name = run(Start::Timer("t".into()), Ok(lists(&[], &["data"], &[])));
    assert_eq!(
        verdict(true, &[covered_run, by_hand, by_name], &[volume()]),
        Verdict::Pass(vec![
            "PRUNEPATHS in /etc/updatedb.conf lists /mnt".to_string(),
            "PRUNENAMES in /etc/updatedb.conf lists data, a directory on the way to /mnt/data"
                .to_string(),
        ])
    );
}

#[test]
fn only_a_run_by_hand_is_not_scheduled() {
    assert!(Start::Now(String::new()).is_scheduled_or_running());
    assert!(Start::Timer(String::new()).is_scheduled_or_running());
    assert!(Start::Cron(String::new()).is_scheduled_or_running());
    assert!(!Start::ByHand(String::new()).is_scheduled_or_running());
}
