// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The carved-object keys' unit tests: pure, over hand-built records and the
//! context column bulk_extractor writes.

use super::*;

/// A glibc x86_64 `struct utmp` record with the given fields; `when` and
/// `session` are the fields the key leaves out.
fn utmp(kind: i16, pid: i32, line: &str, user: &str, when: i32, session: i32) -> Vec<u8> {
    let mut record = vec![0_u8; UTMP_RECORD_SIZE];
    record[0..2].copy_from_slice(&kind.to_le_bytes());
    record[4..8].copy_from_slice(&pid.to_le_bytes());
    record[8..8 + line.len()].copy_from_slice(line.as_bytes());
    record[40..44].copy_from_slice(b"tty1");
    record[44..44 + user.len()].copy_from_slice(user.as_bytes());
    record[76..85].copy_from_slice(b"localhost");
    record[332..334].copy_from_slice(&2_i16.to_le_bytes());
    record[334..336].copy_from_slice(&15_i16.to_le_bytes());
    record[336..340].copy_from_slice(&session.to_le_bytes());
    record[340..344].copy_from_slice(&when.to_le_bytes());
    record
}

#[test]
fn a_login_record_is_keyed_by_what_it_records() {
    assert_eq!(
        utmp_record_key(&utmp(6, 1625, "tty1", "LOGIN", 1_792_747_139, 0)).as_deref(),
        Some(
            "type=LOGIN_PROCESS pid=1024-2047 line=tty1 id=tty1 user=LOGIN host=localhost \
             exit=2/15 addr=0.0.0.0"
        )
    );
}

#[test]
fn the_same_record_of_another_boot_is_one_key() {
    // A boot writes the same getty record with a new time, session and a
    // process number a few off: it subtracts against the control cycle's.
    assert_eq!(
        utmp_record_key(&utmp(5, 618, "tty1", "", 100, 1)),
        utmp_record_key(&utmp(5, 627, "tty1", "", 900, 2))
    );
}

#[test]
fn a_record_that_differs_in_what_it_records_is_a_new_key() {
    let base = utmp_record_key(&utmp(7, 618, "pts/0", "user", 100, 1));
    for other in [
        utmp(7, 1625, "pts/0", "user", 100, 1),
        utmp(7, 618, "pts/1", "user", 100, 1),
        utmp(7, 618, "pts/0", "hidden", 100, 1),
        utmp(8, 618, "pts/0", "user", 100, 1),
    ] {
        assert_ne!(base, utmp_record_key(&other));
    }
}

#[test]
fn a_record_carries_its_address_and_an_unknown_type_by_number() {
    let mut v4 = utmp(7, 618, "pts/0", "root", 1, 1);
    v4[348..352].copy_from_slice(&[203, 0, 113, 7]);
    assert!(utmp_record_key(&v4).unwrap().ends_with("addr=203.0.113.7"));
    let mut v6 = utmp(7, 618, "pts/0", "root", 1, 1);
    v6[348..350].copy_from_slice(&[0x20, 0x01]);
    v6[363] = 1;
    assert!(utmp_record_key(&v6).unwrap().ends_with("addr=2001::1"));
    let unknown = utmp(42, 618, "pts/0", "root", 1, 1);
    assert!(utmp_record_key(&unknown).unwrap().starts_with("type=42 "));
    let negative = utmp(-1, 618, "pts/0", "root", 1, 1);
    assert!(utmp_record_key(&negative).unwrap().starts_with("type=-1 "));
}

#[test]
fn a_buffer_that_is_not_one_record_has_no_key() {
    assert_eq!(utmp_record_key(&[0_u8; UTMP_RECORD_SIZE - 1]), None);
    assert_eq!(utmp_record_key(&[0_u8; UTMP_RECORD_SIZE + 1]), None);
    assert_eq!(utmp_record_key(&[]), None);
}

#[test]
fn every_recorder_is_read_the_way_its_output_allows() {
    assert_eq!(recorder("utmp_carved"), Recorder::LoginRecords);
    for skipped in ["sqlite_carved", "duplicates"] {
        assert_eq!(recorder(skipped), Recorder::Skipped, "{skipped}");
    }
    for hashed in [
        "zip_carved",
        "winpe_carved",
        "evtx_carved",
        "ntfsmft_carved",
    ] {
        assert_eq!(recorder(hashed), Recorder::CarvedObjects, "{hashed}");
    }
    for value in ["email", "domain", "url", "json", "ip", "carved"] {
        assert_eq!(recorder(value), Recorder::Values, "{value}");
    }
}

/// A carved object's SHA-1 as bulk_extractor records it, case and all.
const SHA1: &str = "C6E11131b33e1061df5540acb2fdc227dded7325"; // pragma: allowlist secret

#[test]
fn a_carved_object_is_keyed_by_the_hash_in_its_context() {
    let context = format!(
        "<fileobject><filename>zip_carved/000/1.zip</filename><filesize>384</filesize>\
         <hashdigest type='sha1'>{SHA1}</hashdigest></fileobject>"
    );
    assert_eq!(
        carved_hash(&context),
        Some(format!("sha1:{}", SHA1.to_ascii_lowercase()))
    );
    for broken in [
        "",
        "<fileobject></fileobject>",
        "<hashdigest type='sha1'></hashdigest>",
        "<hashdigest type=''>ab</hashdigest>",
        "<hashdigest type='sha1'>zz</hashdigest>",
        "<hashdigest type='sha 1'>ab</hashdigest>",
        "<hashdigest type='sha1'>ab",
    ] {
        assert_eq!(carved_hash(broken), None, "{broken}");
    }
}

#[test]
fn a_carved_object_path_stays_inside_the_recorder_directory() {
    let dir = Path::new("/out/after");
    assert_eq!(
        carved_object_path(dir, "utmp_carved/000/19461652480utmp"),
        Some(PathBuf::from("/out/after/utmp_carved/000/19461652480utmp"))
    );
    for outside in [
        "",
        "/etc/shadow",
        "../../etc/shadow",
        "utmp_carved/../x",
        "./x",
    ] {
        assert_eq!(carved_object_path(dir, outside), None, "{outside}");
    }
}

#[test]
fn a_saved_zip_member_names_the_offset_of_its_description() {
    assert_eq!(zip_member_offset("1304739840-ZIP-0"), Some("1304739840"));
    assert_eq!(zip_member_offset("7-ZIP-12"), Some("7"));
    // A member found in decompressed data, a zip in a zip included.
    assert_eq!(zip_member_offset("512-GZIP-80-ZIP-0"), Some("512-GZIP-80"));
    assert_eq!(zip_member_offset("7-ZIP-500-ZIP-0"), Some("7-ZIP-500"));
    for other in [
        "",
        "7",
        "7-ZIP-",
        "-ZIP-0",
        "7-ZIP-x",
        "x-ZIP-0",
        "7-zip-0",
        "7/../8-ZIP-0",
    ] {
        assert_eq!(zip_member_offset(other), None, "{other}");
    }
    assert!(is_zip_member_info("<zipinfo><name>a</name></zipinfo>"));
    assert!(!is_zip_member_info("<fileobject></fileobject>"));
}

#[test]
fn login_record_files_are_wtmp_btmp_and_their_rotations() {
    for file in [
        "/var/log/wtmp",
        "/var/log/btmp",
        "/var/log/wtmp.1",
        "/var/log/btmp.12",
        "/var/log/wtmp-20261029",
        "/root/var/log/wtmp",
        "wtmp",
    ] {
        assert!(is_login_record_file(file), "{file}");
    }
    for other in [
        "/var/log/wtmp.db",
        "/var/lib/wtmpdb/wtmp.db",
        "/var/log/wtmp.1.gz",
        "/var/log/wtmp.",
        "/var/log/wtmp-",
        "/var/log/wtmpx",
        "/var/log/xwtmp",
        "/var/log/lastlog",
        "/var/log/wtmp/old",
    ] {
        assert!(!is_login_record_file(other), "{other}");
    }
}

#[test]
fn a_login_record_file_is_read_as_its_whole_records() {
    // Each whole record gives its key, records with the same key give one,
    // and a torn record at the end gives none.
    let boot = utmp(2, 0, "~", "reboot", 100, 0);
    let getty = utmp(6, 700, "tty1", "LOGIN", 101, 0);
    let again = utmp(6, 800, "tty1", "LOGIN", 202, 0);
    let mut data = [boot.clone(), getty.clone(), again].concat();
    data.extend_from_slice(&getty[..100]);
    let key = |record: &[u8]| utmp_record_key(record).expect("a record");
    assert_eq!(
        login_record_keys(&data),
        BTreeSet::from([key(&boot), key(&getty)])
    );
    assert!(login_record_keys(&[]).is_empty());
    assert!(login_record_keys(&getty[..383]).is_empty());
}
