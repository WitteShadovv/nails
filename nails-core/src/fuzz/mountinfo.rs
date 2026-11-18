// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The mountinfo parsers: [`parse_mountinfo`] and the mount-namespace check's
//! own tokenizer. A path the kernel prints may hold any byte but the
//! newline, valid UTF-8 or not, and so may an option.

use super::abs_path;
use crate::filesystem::mountinfo::{escaped_text, parse_mountinfo, path_from_bytes};
use crate::preflight::checks::mount_namespace::root_has_shared_propagation;
use proptest::prelude::*;
use std::path::Path;

/// What the kernel's `show_mountinfo` escapes in path fields.
const MANGLE: &[u8] = b" \t\n\\";

/// The kernel's `mangle`: every byte of `set` becomes `\ooo`, every other
/// byte stays as it is.
fn mangle(bytes: &[u8], set: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in bytes {
        if set.contains(&b) {
            out.extend(format!("\\{b:03o}").into_bytes());
        } else {
            out.push(b);
        }
    }
    out
}

/// An absolute path of one to four non-empty components, of any byte but
/// `/` and NUL, often one that is not valid UTF-8.
fn byte_path() -> impl Strategy<Value = Vec<u8>> {
    let byte = prop_oneof![
        3 => abs_path().prop_map(String::into_bytes),
        1 => prop::collection::vec(
            prop::collection::vec(
                prop_oneof![3 => b'a'..=b'z', 2 => 0x80u8..=0xff, 1 => 1u8..=0x7f]
                    .prop_filter("no slash", |b| *b != b'/'),
                1..8
            ),
            1..4
        )
        .prop_map(|parts| parts.into_iter().flat_map(|p| {
            let mut part = vec![b'/'];
            part.extend(p);
            part
        }).collect()),
    ];
    byte
}

/// Option text the kernel prints raw: ASCII option words and values, and
/// bytes that are not valid UTF-8.
fn option_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        prop_oneof![6 => prop::sample::select(b"abcdefxyz=,0123_".to_vec()), 1 => 0x80u8..=0xff],
        1..24,
    )
}

/// One mount as the kernel knows it, before rendering.
#[derive(Debug, Clone)]
struct Mount {
    id: i32,
    parent: i32,
    dev: String,
    root: Vec<u8>,
    mount_point: Vec<u8>,
    opts: String,
    optional: Vec<String>,
    fstype: String,
    source: Vec<u8>,
    super_opts: Vec<u8>,
}

impl Mount {
    /// Render the mountinfo line exactly as `show_mountinfo` does: single
    /// spaces, path fields mangled, an empty source printed as nothing.
    fn render(&self) -> Vec<u8> {
        let mut fields: Vec<Vec<u8>> = vec![
            self.id.to_string().into_bytes(),
            self.parent.to_string().into_bytes(),
            self.dev.clone().into_bytes(),
            mangle(&self.root, MANGLE),
            mangle(&self.mount_point, MANGLE),
            self.opts.clone().into_bytes(),
        ];
        fields.extend(self.optional.iter().map(|o| o.clone().into_bytes()));
        fields.push(b"-".to_vec());
        fields.push(self.fstype.clone().into_bytes());
        fields.push(mangle(&self.source, MANGLE));
        fields.push(self.super_opts.clone());
        fields.join(&b' ')
    }
}

fn optional_field() -> impl Strategy<Value = String> {
    prop_oneof![
        (1u32..500).prop_map(|n| format!("shared:{n}")),
        (1u32..500).prop_map(|n| format!("master:{n}")),
        (1u32..500).prop_map(|n| format!("propagate_from:{n}")),
        Just("unbindable".to_string()),
    ]
}

fn mount(mount_point: BoxedStrategy<Vec<u8>>) -> impl Strategy<Value = Mount> {
    (
        (1i32..10_000, 0i32..10_000),
        (0u32..300, 0u32..300).prop_map(|(a, b)| format!("{a}:{b}")),
        prop_oneof![Just(b"/".to_vec()), byte_path()],
        mount_point,
        prop_oneof![
            Just("rw,relatime"),
            Just("ro,nosuid,nodev"),
            Just("rw,noatime")
        ],
        prop::collection::vec(optional_field(), 0..3),
        "[a-z][a-z0-9._]{0,8}",
        prop_oneof![
            Just(Vec::new()),
            Just(b"none".to_vec()),
            byte_path(),
            "[a-z]{1,6}".prop_map(String::into_bytes)
        ],
        option_bytes(),
    )
        .prop_map(
            |((id, parent), dev, root, mount_point, opts, optional, fstype, source, super_opts)| {
                Mount {
                    id,
                    parent,
                    dev,
                    root,
                    mount_point,
                    opts: opts.to_string(),
                    optional,
                    fstype,
                    source,
                    super_opts,
                }
            },
        )
}

fn table() -> impl Strategy<Value = Vec<Mount>> {
    let point = prop_oneof![1 => Just(b"/".to_vec()), 4 => byte_path()].boxed();
    prop::collection::vec(mount(point), 0..8)
}

proptest! {
    /// Every rendered line parses back to the mount it came from: each path
    /// byte for byte, the option text with a byte that is not valid UTF-8 as
    /// an octal escape.
    #[test]
    fn fuzz_mountinfo_round_trips(mounts in table()) {
        let text: Vec<u8> = mounts.iter().flat_map(|m| {
            let mut line = m.render();
            line.push(b'\n');
            line
        }).collect();
        let parsed = parse_mountinfo(&text);
        prop_assert_eq!(parsed.len(), mounts.len(), "text: {:?}", text);
        for (entry, model) in parsed.iter().zip(&mounts) {
            prop_assert_eq!(entry.mount_id, model.id);
            prop_assert_eq!(entry.parent_id, model.parent);
            prop_assert_eq!(&entry.dev, &model.dev);
            prop_assert_eq!(&entry.root, &path_from_bytes(model.root.clone()));
            prop_assert_eq!(&entry.mount_point, &path_from_bytes(model.mount_point.clone()));
            prop_assert_eq!(&entry.mount_opts, &model.opts);
            prop_assert_eq!(&entry.fstype, &model.fstype);
            prop_assert_eq!(&entry.source, &path_from_bytes(model.source.clone()));
            prop_assert_eq!(&entry.super_opts, &escaped_text(&model.super_opts));
            prop_assert_eq!(
                crate::filesystem::mountinfo::unescape_octal_bytes(&entry.super_opts),
                crate::filesystem::mountinfo::unescape_octal_bytes(&model.super_opts)
            );
        }
    }

    /// The mount-namespace tokenizer and the shared parser agree on the root
    /// mount and its propagation, judged against the model.
    #[test]
    fn fuzz_mount_namespace_agrees_with_the_parser(mounts in table()) {
        let text: Vec<u8> = mounts.iter().flat_map(|m| {
            let mut line = m.render();
            line.push(b'\n');
            line
        }).collect();
        let expected = mounts
            .iter()
            .any(|m| m.mount_point == b"/" && m.optional.iter().any(|o| o.starts_with("shared:")));
        prop_assert_eq!(root_has_shared_propagation(&text), expected);
        let parsed_has_root = parse_mountinfo(&text)
            .iter()
            .any(|e| e.mount_point == Path::new("/"));
        prop_assert!(!expected || parsed_has_root);
    }

    /// Arbitrary bytes never panic either parser.
    #[test]
    fn fuzz_mountinfo_parsers_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        let _ = parse_mountinfo(&bytes);
        let _ = root_has_shared_propagation(&bytes);
    }
}
