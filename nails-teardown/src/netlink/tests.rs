// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::filter::{self, Presence};
use super::route::{self, AF_INET, AF_INET6};
use super::*;

/// A message the kernel could send: its header and `body`.
fn raw(kind: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let len = u32::try_from(HEADER_LEN + body.len()).unwrap();
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&7u32.to_ne_bytes());
    out.extend_from_slice(body);
    out.resize(align(out.len()), 0);
    out
}

#[test]
fn a_message_carries_its_header_and_attributes_aligned() {
    let message = Message::new(34, F_REQUEST | F_DUMP, &[2, 0, 0, 0, 0, 0])
        .attr_str(3, "wg0")
        .attr_u32(6, 32765);
    let bytes = message.encode(9);
    assert_eq!(bytes.len() % 4, 0);
    assert_eq!(
        u32::from_ne_bytes(bytes[0..4].try_into().unwrap()) as usize,
        bytes.len()
    );
    assert_eq!(u16::from_ne_bytes([bytes[4], bytes[5]]), 34);
    assert_eq!(u16::from_ne_bytes([bytes[6], bytes[7]]), F_REQUEST | F_DUMP);
    assert_eq!(u32::from_ne_bytes(bytes[8..12].try_into().unwrap()), 9);
    let body = &bytes[HEADER_LEN..];
    // The six header bytes are padded to eight before the first attribute.
    assert_eq!(&body[..8], &[2, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        attributes(body, 6),
        vec![(3, &b"wg0\0"[..]), (6, &32765u32.to_ne_bytes()[..])]
    );
}

#[test]
fn the_messages_of_a_buffer_are_read_in_order_and_a_cut_one_ends_them() {
    let mut buf = raw(16, F_MULTI, 4, &[1, 2, 3]);
    buf.extend(raw(MSG_DONE, F_MULTI, 4, &0i32.to_ne_bytes()));
    let mut cut = raw(16, 0, 4, &[9; 8]);
    cut.truncate(cut.len() - 2);
    buf.extend(cut);
    let read = messages(&buf);
    assert_eq!(read.len(), 2);
    assert_eq!((read[0].kind, read[0].flags, read[0].seq), (16, F_MULTI, 4));
    assert_eq!(read[0].body, &[1, 2, 3]);
    assert_eq!(read[1].kind, MSG_DONE);
}

/// The list `buf` makes, read as [`Socket::dump`] reads it: `Ok(None)` when
/// the kernel marked it as changed while it was sent.
fn list_of(buf: &[u8]) -> io::Result<Option<Vec<Reply>>> {
    let mut list = List::default();
    for message in messages(buf) {
        if list.take(&message)? {
            return Ok(list.whole());
        }
    }
    panic!("the list did not end");
}

#[test]
fn a_list_ends_at_its_done_and_keeps_its_parts() {
    let mut buf = raw(16, F_MULTI, 4, &[1, 2, 3, 4]);
    buf.extend(raw(16, F_MULTI, 4, &[5, 6, 7, 8]));
    buf.extend(raw(MSG_DONE, F_MULTI, 4, &0i32.to_ne_bytes()));
    let replies = list_of(&buf).unwrap().unwrap();
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[1].body, vec![5, 6, 7, 8]);
}

#[test]
fn a_list_the_kernel_marks_as_changed_is_never_taken_as_whole() {
    // A marked part in the middle.
    let mut buf = raw(16, F_MULTI, 4, &[1, 2, 3, 4]);
    buf.extend(raw(16, F_MULTI | F_DUMP_INTR, 4, &[5, 6, 7, 8]));
    buf.extend(raw(MSG_DONE, F_MULTI, 4, &0i32.to_ne_bytes()));
    assert!(list_of(&buf).unwrap().is_none());
    // A marked end.
    let mut buf = raw(16, F_MULTI, 4, &[1, 2, 3, 4]);
    buf.extend(raw(MSG_DONE, F_MULTI | F_DUMP_INTR, 4, &0i32.to_ne_bytes()));
    assert!(list_of(&buf).unwrap().is_none());
    // A list of one part that is marked.
    let buf = raw(16, F_DUMP_INTR, 4, &[1, 2, 3, 4]);
    assert!(list_of(&buf).unwrap().is_none());
}

#[test]
fn a_list_that_ends_in_an_error_is_an_error() {
    let mut buf = raw(16, F_MULTI, 4, &[1, 2, 3, 4]);
    buf.extend(raw(MSG_DONE, F_MULTI, 4, &(-libc::EBUSY).to_ne_bytes()));
    assert_eq!(list_of(&buf).unwrap_err().raw_os_error(), Some(libc::EBUSY));
}

#[test]
fn an_attribute_s_flag_bits_are_not_its_type_and_a_cut_one_ends_the_list() {
    let mut body = vec![0u8; 4];
    body.extend_from_slice(&8u16.to_ne_bytes());
    body.extend_from_slice(&(0x8000u16 | 2).to_ne_bytes());
    body.extend_from_slice(&[1, 2, 3, 4]);
    body.extend_from_slice(&40u16.to_ne_bytes());
    body.extend_from_slice(&1u16.to_ne_bytes());
    assert_eq!(attributes(&body, 4), vec![(2, &[1, 2, 3, 4][..])]);
    assert_eq!(find(&attributes(&body, 4), 2), Some(&[1, 2, 3, 4][..]));
    assert_eq!(find(&attributes(&body, 4), 1), None);
}

#[test]
fn an_acknowledgement_is_ok_and_an_error_carries_the_kernel_s_number() {
    assert!(status(&0i32.to_ne_bytes()).is_ok());
    assert!(status(&[]).is_ok());
    let error = status(&(-libc::ENOENT).to_ne_bytes()).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
}

#[test]
fn the_values_of_attributes_read_back() {
    assert_eq!(u32_of(&51820u32.to_ne_bytes()), Some(51820));
    assert_eq!(u32_of(&[1, 2]), None);
    assert_eq!(str_of(b"inet\0junk"), Some("inet"));
    assert_eq!(str_of(b"keep"), Some("keep"));
}

#[test]
fn a_rule_is_the_same_whatever_the_kernel_flags_of_a_detached_interface() {
    let attached = route::rule_for_tests(AF_INET, 32765, 51820, 0x2);
    let detached = route::rule_for_tests(AF_INET, 32765, 51820, 0x2 | 0x8 | 0x10 | 0x4);
    assert_eq!(attached, detached);
    assert_ne!(attached, route::rule_for_tests(AF_INET, 32765, 51820, 0));
    assert_ne!(attached, route::rule_for_tests(AF_INET, 32764, 51820, 0x2));
    assert_ne!(attached, route::rule_for_tests(AF_INET6, 32765, 51820, 0x2));
    assert_eq!(
        (attached.family(), attached.priority(), attached.table()),
        (AF_INET, 32765, 51820)
    );
    assert!(attached.is_valid());
}

#[test]
fn a_rule_must_fill_its_body() {
    assert!(route::Rule::from_body(vec![2; 11]).is_none());
    let mut body = vec![0u8; 12];
    body[0] = AF_INET;
    assert!(route::Rule::from_body(body.clone()).is_some());
    body.extend_from_slice(&[8, 0, 6, 0, 1]);
    assert!(route::Rule::from_body(body).is_none());
}

#[test]
fn a_hardware_address_reads_as_its_bytes() {
    assert_eq!(
        route::parse_mac("02:00:0a:FF:00:01"),
        Some(vec![2, 0, 10, 255, 0, 1])
    );
    for wrong in [
        "",
        "2:00:00:00:00:01",
        "zz:00",
        "02-00-00-00-00-01",
        "02::01",
    ] {
        assert_eq!(route::parse_mac(wrong), None, "{wrong}");
    }
    // A link of another kind has an address of another length.
    assert_eq!(route::parse_mac("02:00"), Some(vec![2, 0]));
}

#[test]
fn the_table_families_go_both_ways() {
    for (name, number) in filter::FAMILIES {
        assert_eq!(filter::family_name(number), Some(name));
        assert_eq!(filter::family_number(name), Some(number));
    }
    assert_eq!(filter::family_name(0), None);
    assert_eq!(filter::family_number("ipx"), None);
}

#[test]
fn nf_tables_is_present_when_loaded_or_built_in_and_unknown_when_neither_reads() {
    let dir = tempfile::tempdir().unwrap();
    let sys_module = dir.path().join("module");
    std::fs::create_dir_all(&sys_module).unwrap();
    let kallsyms = dir.path().join("kallsyms");
    assert_eq!(filter::presence(&sys_module, &kallsyms), Presence::Unknown);

    std::fs::write(
        &kallsyms,
        "0000000000000000 T start_kernel\n0000000000000000 t nft_register_obj\n",
    )
    .unwrap();
    assert_eq!(filter::presence(&sys_module, &kallsyms), Presence::Absent);

    std::fs::write(
        &kallsyms,
        "0000000000000000 T start_kernel\n0000000000000000 T nft_register_expr\n",
    )
    .unwrap();
    assert_eq!(filter::presence(&sys_module, &kallsyms), Presence::Present);

    std::fs::write(&kallsyms, "").unwrap();
    std::fs::create_dir(sys_module.join("nf_tables")).unwrap();
    assert_eq!(filter::presence(&sys_module, &kallsyms), Presence::Present);
    assert!(module_present(&sys_module, "nf_tables"));
    std::fs::write(sys_module.join("cfg80211"), "").unwrap();
    assert!(
        !module_present(&sys_module, "cfg80211"),
        "a file is no module"
    );
}

#[test]
fn without_cfg80211_no_wi_fi_interface_is_asked_for() {
    let dir = tempfile::tempdir().unwrap();
    let error = super::wireless::delete_interface(dir.path(), 3).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
}
