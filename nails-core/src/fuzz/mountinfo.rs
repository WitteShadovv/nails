// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The mountinfo parsers: [`parse_mountinfo`], the submount classifier built on
//! it, and the mount-namespace check's own tokenizer.

use super::{abs_path, octal_escape};
use crate::filesystem::mountinfo::parse_mountinfo;
use crate::filesystem::real::classify_submounts;
use crate::preflight::checks::mount_namespace::root_has_shared_propagation;
use proptest::prelude::*;
use std::path::{Path, PathBuf};

/// What the kernel's `show_mountinfo` escapes in path fields.
const MANGLE: &str = " \t\n\\";

/// One mount as the kernel knows it, before rendering.
#[derive(Debug, Clone)]
struct Mount {
    id: i32,
    parent: i32,
    dev: String,
    root: String,
    mount_point: String,
    opts: String,
    optional: Vec<String>,
    fstype: String,
    source: String,
    super_opts: String,
}

impl Mount {
    /// Render the mountinfo line exactly as `show_mountinfo` does: single
    /// spaces, path fields mangled, an empty source printed as nothing.
    fn render(&self) -> String {
        let mut fields = vec![
            self.id.to_string(),
            self.parent.to_string(),
            self.dev.clone(),
            octal_escape(&self.root, MANGLE),
            octal_escape(&self.mount_point, MANGLE),
            self.opts.clone(),
        ];
        fields.extend(self.optional.iter().cloned());
        fields.push("-".into());
        fields.push(self.fstype.clone());
        fields.push(octal_escape(&self.source, MANGLE));
        fields.push(self.super_opts.clone());
        fields.join(" ")
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

fn mount(mount_point: BoxedStrategy<String>) -> impl Strategy<Value = Mount> {
    (
        (1i32..10_000, 0i32..10_000),
        (0u32..300, 0u32..300).prop_map(|(a, b)| format!("{a}:{b}")),
        prop_oneof![Just("/".to_string()), abs_path()],
        mount_point,
        prop_oneof![
            Just("rw,relatime"),
            Just("ro,nosuid,nodev"),
            Just("rw,noatime")
        ],
        prop::collection::vec(optional_field(), 0..3),
        "[a-z][a-z0-9._]{0,8}",
        prop_oneof![
            Just(String::new()),
            Just("none".to_string()),
            abs_path(),
            "[a-z]{1,6}"
        ],
        "[a-z=,0-9_]{1,24}",
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
    let point = prop_oneof![1 => Just("/".to_string()), 4 => abs_path()].boxed();
    prop::collection::vec(mount(point), 0..8)
}

proptest! {
    /// Every rendered line parses back to the mount it came from.
    #[test]
    fn fuzz_mountinfo_round_trips(mounts in table()) {
        let text: String = mounts.iter().map(|m| m.render() + "\n").collect();
        let parsed = parse_mountinfo(&text);
        prop_assert_eq!(parsed.len(), mounts.len(), "text: {:?}", text);
        for (entry, model) in parsed.iter().zip(&mounts) {
            prop_assert_eq!(entry.mount_id, model.id);
            prop_assert_eq!(entry.parent_id, model.parent);
            prop_assert_eq!(&entry.dev, &model.dev);
            prop_assert_eq!(&entry.root, &PathBuf::from(&model.root));
            prop_assert_eq!(&entry.mount_point, &PathBuf::from(&model.mount_point));
            prop_assert_eq!(&entry.mount_opts, &model.opts);
            prop_assert_eq!(&entry.fstype, &model.fstype);
            prop_assert_eq!(&entry.source, &PathBuf::from(&model.source));
            prop_assert_eq!(&entry.super_opts, &model.super_opts);
        }
    }

    /// The mount-namespace tokenizer and the shared parser agree on the root
    /// mount and its propagation, judged against the model.
    #[test]
    fn fuzz_mount_namespace_agrees_with_the_parser(mounts in table()) {
        let text: String = mounts.iter().map(|m| m.render() + "\n").collect();
        let expected = mounts
            .iter()
            .any(|m| m.mount_point == "/" && m.optional.iter().any(|o| o.starts_with("shared:")));
        prop_assert_eq!(root_has_shared_propagation(&text), expected);
        let parsed_has_root = parse_mountinfo(&text)
            .iter()
            .any(|e| e.mount_point == Path::new("/"));
        prop_assert!(!expected || parsed_has_root);
    }

    /// The submount classifier only ever plans mounts strictly below the target
    /// that the shared parser also reports, each mount point once.
    #[test]
    fn fuzz_submounts_agree_with_the_parser(mounts in table(), target in abs_path()) {
        let text: String = mounts.iter().map(|m| m.render() + "\n").collect();
        let target = PathBuf::from(target);
        let entries = parse_mountinfo(&text);
        let plans = classify_submounts(&text, &target);
        let mut seen = std::collections::HashSet::new();
        for plan in &plans {
            let point = plan.mount_point();
            prop_assert!(point.starts_with(&target) && point != target.as_path());
            prop_assert!(entries.iter().any(|e| e.mount_point == point));
            prop_assert!(seen.insert(point.to_path_buf()), "duplicate plan for {:?}", point);
        }
    }

    /// Arbitrary text never panics any of the three parsers.
    #[test]
    fn fuzz_mountinfo_parsers_never_panic(text in "\\PC{0,400}") {
        let _ = parse_mountinfo(&text);
        let _ = root_has_shared_propagation(&text);
        let _ = classify_submounts(&text, Path::new("/home"));
    }
}
