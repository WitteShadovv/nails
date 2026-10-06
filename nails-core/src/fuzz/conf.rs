// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The systemd `journald.conf` and `logind.conf` parsers: the last valid
//! assignment wins, comments and other keys are ignored.

use crate::preflight::checks::sleep_policy::{LogindSleepSettings, parse_logind_sleep};
use crate::preflight::checks::{JournaldStorage, parse_journald_storage};
use proptest::prelude::*;

/// One line of a generated configuration file.
#[derive(Debug, Clone)]
enum Line {
    Section(&'static str),
    Comment(String),
    Blank,
    Assign {
        key: &'static str,
        value: &'static str,
        pad: bool,
    },
}

impl Line {
    fn render(&self) -> String {
        match self {
            Line::Section(name) => format!("[{name}]"),
            Line::Comment(text) => text.clone(),
            Line::Blank => String::new(),
            Line::Assign { key, value, pad } if *pad => format!("  {key} = {value}  "),
            Line::Assign { key, value, .. } => format!("{key}={value}"),
        }
    }
}

const STORAGE_VALUES: &[&str] = &[
    "persistent",
    "volatile",
    "none",
    "auto",
    "Volatile",
    "bogus",
];
const ACTIONS: &[&str] = &["suspend", "ignore", "lock", "poweroff", "hibernate", "junk"];

fn line(
    keys: &'static [&'static str],
    values: &'static [&'static str],
) -> impl Strategy<Value = Line> {
    prop_oneof![
        Just(Line::Section("Journal")),
        Just(Line::Section("Login")),
        "[#;][ a-zA-Z=]{0,20}".prop_map(Line::Comment),
        Just(Line::Blank),
        (
            prop::sample::select(keys),
            prop::sample::select(values),
            any::<bool>()
        )
            .prop_map(|(key, value, pad)| Line::Assign { key, value, pad }),
    ]
}

fn storage(value: &str) -> Option<JournaldStorage> {
    match value.to_ascii_lowercase().as_str() {
        "persistent" => Some(JournaldStorage::Persistent),
        "volatile" => Some(JournaldStorage::Volatile),
        "none" => Some(JournaldStorage::None),
        "auto" => Some(JournaldStorage::Auto),
        _ => None,
    }
}

proptest! {
    /// The effective Storage= is the last recognised assignment.
    #[test]
    fn fuzz_journald_storage_last_valid_wins(
        lines in prop::collection::vec(line(&["Storage", "Compress", "SystemMaxUse"], STORAGE_VALUES), 0..12)
    ) {
        let text = lines.iter().map(Line::render).collect::<Vec<_>>().join("\n");
        let expected = lines.iter().rev().find_map(|l| match l {
            Line::Assign { key: "Storage", value, .. } => storage(value),
            _ => None,
        });
        prop_assert_eq!(parse_journald_storage(&text), expected);
    }

    /// Each logind key takes its last assignment; drop-ins applied in order
    /// behave like one concatenated file.
    #[test]
    fn fuzz_logind_last_assignment_wins(
        main in prop::collection::vec(line(&["HandleLidSwitch", "IdleAction", "KillUserProcesses"], ACTIONS), 0..8),
        drop_in in prop::collection::vec(line(&["HandleLidSwitch", "IdleAction"], ACTIONS), 0..8),
    ) {
        let render = |lines: &[Line]| lines.iter().map(Line::render).collect::<Vec<_>>().join("\n");
        let mut split = LogindSleepSettings::default();
        parse_logind_sleep(&render(&main), &mut split);
        parse_logind_sleep(&render(&drop_in), &mut split);
        let mut joined = LogindSleepSettings::default();
        parse_logind_sleep(&format!("{}\n{}", render(&main), render(&drop_in)), &mut joined);
        prop_assert_eq!(&split, &joined);

        let last = |key: &str| main.iter().chain(&drop_in).rev().find_map(|l| match l {
            Line::Assign { key: k, value, .. } if *k == key => Some(value.to_string()),
            _ => None,
        });
        prop_assert_eq!(split.handle_lid_switch.clone(), last("HandleLidSwitch"));
        prop_assert_eq!(split.idle_action.clone(), last("IdleAction"));
    }

    #[test]
    fn fuzz_conf_parsers_never_panic(text in "\\PC{0,300}") {
        let _ = parse_journald_storage(&text);
        parse_logind_sleep(&text, &mut LogindSleepSettings::default());
    }
}
