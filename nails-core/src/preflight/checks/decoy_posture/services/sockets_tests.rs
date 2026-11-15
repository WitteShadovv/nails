// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::filesystem::MockFilesystem;

/// A socket table with the header the kernel prints and `lines`.
fn table(lines: &[&str]) -> String {
    let mut text = String::from_utf8(SOCKET_TABLE_HEADER.to_vec()).unwrap();
    for line in lines {
        text.push('\n');
        text.push_str(line);
    }
    text.push('\n');
    text
}

/// A connected stream socket bound to no path, as the service manager's
/// socket to the journal is.
const CLIENT: &str = "0000000000000000: 00000003 00000000 00000000 0001 03 24680";

/// journald's listening stream socket and the end of one stream it accepted,
/// which the table shows at the listener's path.
const MAIN_JOURNAL: &[&str] = &[
    "0000000000000000: 00000002 00000000 00010000 0001 01 20001 /run/systemd/journal/stdout",
    "0000000000000000: 00000003 00000000 00000000 0001 03 20002 /run/systemd/journal/stdout",
];

/// The sockets of the journal namespace `tn`'s journald.
const TN_JOURNAL: &[&str] = &[
    "0000000000000000: 00000002 00000000 00010000 0001 01 30001 /run/systemd/journal.tn/stdout",
    "0000000000000000: 00000002 00000000 00000000 0002 01 30002 /run/systemd/journal.tn/socket",
];

fn with_table(lines: &[&str]) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/proc/1/net/unix", &table(lines));
    fs
}

fn unknown(log: Log) -> String {
    match log {
        Log::Unknown(why) => why,
        other => panic!("not unknown: {other:?}"),
    }
}

#[test]
fn one_read_lists_the_connected_stream_sockets_with_no_path_and_the_namespaces() {
    let fs = with_table(&[
        CLIENT,
        // A small inode, which the kernel pads with spaces.
        "0000000000000000: 00000003 00000000 00000000 0001 03   812",
        MAIN_JOURNAL[0],
        MAIN_JOURNAL[1],
        TN_JOURNAL[0],
        TN_JOURNAL[1],
        "0000000000000000: 00000002 00000000 00000000 0002 01 30003 /run/systemd/journal.fw/dev-log",
        // A datagram socket, one that is not connected, and a name systemd
        // takes for no namespace count for nothing.
        "0000000000000000: 00000002 00000000 00000000 0002 03 40001",
        "0000000000000000: 00000002 00000000 00000000 0001 01 40002",
        "0000000000000000: 00000002 00000000 00010000 0001 01 40003 /run/systemd/journal../stdout",
        "0000000000000000: 00000002 00000000 00010000 0001 01 40004 /run/systemd/journal.x",
        // A name with a space gives the line more fields.
        "0000000000000000: 00000002 00000000 00010000 0001 01 40005 /run/a b",
    ]);
    let listed = read_once(&fs, Path::new("/")).unwrap();
    assert_eq!(listed.streams, BTreeSet::from([812, 24680]));
    assert_eq!(
        listed.namespaces,
        BTreeSet::from(["fw".to_string(), "tn".to_string()])
    );
}

#[test]
fn a_table_nails_cannot_read_is_untold() {
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error("/proc/1/net/unix", std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        read_once(&fs, Path::new("/")),
        Err(
            "NAILS cannot read PID 1's socket table, /proc/1/net/unix, which shows where it \
             leads; run the command again with sudo"
                .to_string()
        )
    );
    let fs = MockFilesystem::new();
    fs.mock_add_file("/proc/1/net/unix", "Num RefCount\n");
    assert_eq!(
        read_once(&fs, Path::new("/")),
        Err(
            "PID 1's socket table, /proc/1/net/unix, does not begin with the header the kernel \
             prints"
                .to_string()
        )
    );
    let fs = MockFilesystem::new();
    assert!(read_once(&fs, Path::new("/")).unwrap_err().starts_with(
        "NAILS cannot read PID 1's socket table, /proc/1/net/unix, which shows where it leads ("
    ));
}

#[test]
fn two_reads_list_what_either_lists() {
    let first = Listed {
        streams: BTreeSet::from([1]),
        namespaces: BTreeSet::from(["a".to_string()]),
    };
    let second = Listed {
        streams: BTreeSet::from([2]),
        namespaces: BTreeSet::from(["b".to_string()]),
    };
    assert_eq!(
        first.with(second),
        Listed {
            streams: BTreeSet::from([1, 2]),
            namespaces: BTreeSet::from(["a".to_string(), "b".to_string()]),
        }
    );
}

#[test]
fn a_socket_to_the_decoy_s_journal_alone_is_no_file() {
    let fs = with_table(&[CLIENT, MAIN_JOURNAL[0], MAIN_JOURNAL[1]]);
    let sockets = read(&fs, Path::new("/"));
    assert_eq!(judge(&sockets, Stream::Error, 24680), Log::NoFile);
    // A namespace whose journal stays in RAM keeps nothing either.
    let fs = with_table(&[CLIENT, TN_JOURNAL[0]]);
    fs.mock_add_file(
        "/etc/systemd/journald@tn.conf",
        "[Journal]\nStorage=volatile\n",
    );
    let sockets = read(&fs, Path::new("/"));
    assert_eq!(judge(&sockets, Stream::Error, 24680), Log::NoFile);
}

#[test]
fn a_socket_while_a_namespace_that_persists_listens_is_untold() {
    // systemd-cat --namespace=tn connects a command's streams to tn's socket
    // with no mount NAILS could read the namespace from.
    let fs = with_table(&[CLIENT, MAIN_JOURNAL[0], TN_JOURNAL[0], TN_JOURNAL[1]]);
    let sockets = read(&fs, Path::new("/"));
    assert_eq!(
        judge(&sockets, Stream::Error, 24680),
        Log::UntoldJournal {
            why: "it logs to its standard error, a socket, which NAILS does not follow to the \
                  journal at its other end, while PID 1's socket table lists a socket of the \
                  journal namespace tn, which journald keeps on the decoy disk unless \
                  journald@tn.conf sets Storage=volatile"
                .to_string(),
            fix: JournalFix::Namespaces(vec!["tn".to_string()]),
        }
    );
    // One whose storage NAILS cannot tell counts too, with why.
    let fs = with_table(&[CLIENT, TN_JOURNAL[0]]);
    fs.mock_set_lookup_error(
        "/etc/systemd/journald@tn.conf.d",
        std::io::ErrorKind::PermissionDenied,
    );
    let sockets = read(&fs, Path::new("/"));
    match judge(&sockets, Stream::Output, 24680) {
        Log::UntoldJournal { why, fix } => {
            assert!(
                why.ends_with(
                    "a socket of the journal namespace tn, of which NAILS cannot tell where \
                     journald keeps it: NAILS cannot read /etc/systemd/journald@tn.conf.d; run \
                     the command again with sudo"
                ),
                "{why}"
            );
            assert!(
                why.starts_with("it logs to its standard output, a socket"),
                "{why}"
            );
            assert_eq!(fix, JournalFix::Namespaces(vec!["tn".to_string()]));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_socket_the_table_does_not_list_as_one_to_a_journal_is_unknown() {
    let not_listed = "it logs to its standard error, a socket that PID 1's socket table does not \
                      list as a connected local stream socket bound to no path, as one the \
                      service manager connects to the journal is, so NAILS cannot tell where it \
                      leads";
    // Not listed at all, as a network socket or one of another network
    // namespace is not; the end a listening program accepted, which shows
    // the listener's path; a datagram socket.
    for (lines, inode) in [
        (&[MAIN_JOURNAL[0]][..], 24680),
        (
            &["0000000000000000: 00000003 00000000 00000000 0001 03 24680 /run/logger.sock"][..],
            24680,
        ),
        (
            &["0000000000000000: 00000002 00000000 00000000 0002 03 24680"][..],
            24680,
        ),
    ] {
        let sockets = read(&with_table(lines), Path::new("/"));
        assert_eq!(
            unknown(judge(&sockets, Stream::Error, inode)),
            not_listed,
            "{lines:?}"
        );
    }
    // A table NAILS cannot read leaves it unknown.
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error("/proc/1/net/unix", std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        unknown(judge(&read(&fs, Path::new("/")), Stream::Error, 24680)),
        "it logs to its standard error, a socket, and NAILS cannot read PID 1's socket table, \
         /proc/1/net/unix, which shows where it leads; run the command again with sudo"
    );
}
