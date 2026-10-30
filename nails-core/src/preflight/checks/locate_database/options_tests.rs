// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

fn args(words: &[&str]) -> Vec<Vec<u8>> {
    words.iter().map(|word| word.as_bytes().to_vec()).collect()
}

fn scan(words: &[&str]) -> Scan {
    match invocation(&args(words)) {
        Invocation::Scans(scan) => scan,
        Invocation::Stops(why) => panic!("{words:?} stops: {why}"),
    }
}

fn stops(words: &[&str]) -> String {
    match invocation(&args(words)) {
        Invocation::Stops(why) => why,
        Invocation::Scans(scan) => panic!("{words:?} scans: {scan:?}"),
    }
}

fn values(change: &ListChange) -> Vec<(&str, &str)> {
    change
        .entries
        .iter()
        .map(|(value, option)| (std::str::from_utf8(value).unwrap(), *option))
        .collect()
}

#[test]
fn no_option_changes_nothing() {
    assert_eq!(scan(&[]), Scan::default());
}

#[test]
fn prunepaths_replaces_and_the_add_options_add() {
    let replaced = scan(&["--prunepaths", "/tmp /mnt"]);
    assert!(replaced.paths.replaced);
    assert_eq!(
        values(&replaced.paths),
        [("/tmp", "--prunepaths"), ("/mnt", "--prunepaths")]
    );

    let added = scan(&["-e", "/mnt /srv", "--add-single-prunepath", "/a b"]);
    assert!(!added.paths.replaced);
    assert_eq!(
        values(&added.paths),
        [
            ("/mnt", "--add-prunepaths"),
            ("/srv", "--add-prunepaths"),
            ("/a b", "--add-single-prunepath")
        ]
    );

    // An addition after the replacement extends it.
    let both = scan(&["--prunepaths=/tmp", "--add-prunepaths=/mnt"]);
    assert!(both.paths.replaced);
    assert_eq!(
        values(&both.paths),
        [("/tmp", "--prunepaths"), ("/mnt", "--add-prunepaths")]
    );
}

#[test]
fn the_other_lists_follow_the_same_rules() {
    let changed = scan(&["--prunefs", "EXT4", "-f", "btrfs"]);
    assert!(changed.fs.replaced);
    assert_eq!(
        values(&changed.fs),
        [("EXT4", "--prunefs"), ("btrfs", "--add-prunefs")]
    );
    // --prunenames after -n stops (below); here -n comes first.
    assert!(stops(&["-n", ".git", "--prunenames=x"]).contains("--prunenames"));
    let names = scan(&["--prunenames=x", "--add-prunenames", "y"]);
    assert!(names.names.replaced);
    assert_eq!(
        values(&names.names),
        [("x", "--prunenames"), ("y", "--add-prunenames")]
    );
}

#[test]
fn a_replacing_option_after_another_of_its_list_stops() {
    for words in [
        &["-e", "/a", "--prunepaths", "/b"][..],
        &["--add-single-prunepath", "/a", "--prunepaths", "/b"],
        &["--prunepaths", "/a", "--prunepaths", "/b"],
        &["-f", "x", "--prunefs", "y"],
        &["--prunefs", "x", "--prunefs", "y"],
    ] {
        assert!(stops(words).contains("follows another option"), "{words:?}");
    }
}

#[test]
fn a_long_option_may_be_cut_to_a_prefix_only_it_has() {
    assert!(scan(&["--prunep", "/mnt"]).paths.replaced);
    assert!(!scan(&["--add-prunep", "/mnt"]).paths.replaced);
    assert_eq!(
        scan(&["--add-s=/mnt"]).paths.entries,
        [(b"/mnt".to_vec(), "--add-single-prunepath")]
    );
    // `--prune` fits four options, `--add-prune` three.
    assert!(stops(&["--prune", "/mnt"]).contains("--prune"));
    assert!(stops(&["--add-prune", "/mnt"]).contains("--add-prune"));
    // An exact name wins over the longer option it starts.
    assert_eq!(scan(&["--debug"]), Scan::default());
    assert!(stops(&["--=x"]).contains("knows no option"));
}

#[test]
fn an_argument_comes_after_an_equals_sign_or_as_the_next_word() {
    assert_eq!(
        scan(&["--database-root", "/home"]).database_root,
        Some(b"/home".to_vec())
    );
    assert_eq!(
        scan(&["--database-root=/home"]).database_root,
        Some(b"/home".to_vec())
    );
    assert_eq!(scan(&["--database-root="]).database_root, Some(Vec::new()));
    // The next word is taken whatever it looks like.
    assert_eq!(
        values(&scan(&["--add-prunepaths", "--prunepaths"]).paths),
        [("--prunepaths", "--add-prunepaths")]
    );
    assert_eq!(
        scan(&["-o", "/var/cache/locatedb"]).output,
        Some(b"/var/cache/locatedb".to_vec())
    );
}

#[test]
fn short_options_share_a_word_and_take_its_rest() {
    let attached = scan(&["-ve/mnt"]);
    assert_eq!(values(&attached.paths), [("/mnt", "--add-prunepaths")]);
    let next = scan(&["-vDe", "/mnt"]);
    assert_eq!(values(&next.paths), [("/mnt", "--add-prunepaths")]);
    assert_eq!(scan(&["-U/srv"]).database_root, Some(b"/srv".to_vec()));
    assert_eq!(scan(&["-b", "64", "-l", "no"]), Scan::default());
}

#[test]
fn what_makes_updatedb_stop_before_it_scans() {
    for (words, why) in [
        (&["-x"][..], "knows no option -x"),
        (&["-B", "yes"], "knows no option -B"),
        (&["--nope"], "knows no option --nope"),
        (&["-e"], "-e has no argument"),
        (&["--prunepaths"], "--prunepaths has no argument"),
        (&["--verbose=1"], "--verbose takes no argument"),
        (&["/mnt"], "takes no operand"),
        (&["-"], "takes no operand"),
        (&["--", "/mnt"], "takes no operand"),
        (&["-h"], "prints its help"),
        (&["--version"], "prints its help or version"),
        (&["-U", "/a", "-U", "/b"], "--database-root is given twice"),
        (&["-o", "/a", "--output", "/b"], "--output is given twice"),
        (&["--prune-bind-mounts", "maybe"], "takes 0, no, 1 or yes"),
        (
            &["--prune-bind-mounts", "no", "--prune-bind-mounts=yes"],
            "--prune-bind-mounts is given twice",
        ),
        (&["-l", "2"], "takes 0, no, 1 or yes"),
        (&["-l", "1", "--require-visibility", "0"], "given twice"),
    ] {
        let message = stops(words);
        assert!(message.contains(why), "{words:?}: {message}");
    }
    // `--` alone ends the options and leaves no operand.
    assert_eq!(scan(&["--"]), Scan::default());
    // An operand stops it wherever it stands.
    assert!(stops(&["/mnt", "-e", "/srv"]).contains("operand"));
}

#[test]
fn prune_bind_mounts_and_the_other_options_change_no_list() {
    let scanned = scan(&[
        "--prune-bind-mounts",
        "yes",
        "--require-visibility=yes",
        "--debug-pruning",
        "-v",
        "--block-size",
        "32",
    ]);
    assert_eq!(scanned, Scan::default());
}
