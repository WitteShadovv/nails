// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The display-manager configuration NAILS reads to list the autologin a
//! decoy carries into the hidden session: GDM's and LightDM's GLib key files,
//! SDDM's configuration and Plasma Login Manager's, which it parsed as SDDM
//! does up to 6.6 and reads through KConfig since. NAILS has to read these
//! files as the display managers do: a difference leaves out an account the
//! decoy logs in on its own.
//!
//! The input is up to three files, separated by NULs. For SDDM, Plasma Login
//! Manager and LightDM they are the main file, a drop-in in `/etc` and a
//! vendor drop-in, beside fixed files: a vendor drop-in that sorts first and
//! names an account, which the input can override, and one the display
//! manager does not read (a hidden one, or one that does not end in
//! `.conf`), which names another. Beside the drop-in in `/etc`, SDDM and
//! Plasma Login Manager find a second one, under a name that collations sort
//! before it or after it: a copy of the vendor drop-in, or one that turns
//! autologin off when there is none. Every directory lists its files in
//! reverse order. For GDM they are the three files a GDM build may read.
//!
//! The target checks that the accounts NAILS lists for each display manager
//! are the ones its model (`nails_fuzz::display_managers`,
//! `nails_fuzz::kconfig`) logs in, in any order the display manager may read
//! the files in, on Qt 5 and Qt 6, in any language, with KConfig before KDE
//! Frameworks 6.29 and since, however GLib's Unicode tables judge a key:
//! exactly, or, where a translated KConfig `User` leaves the account to more
//! than the files tell, at least every one.

#![no_main]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use libfuzzer_sys::fuzz_target;
use nails_base::MockFilesystem;
use nails_fuzz::display_managers::{self, Qt};
use nails_fuzz::kconfig::{self, Frameworks};
use nails_session::persona::{InheritedSource, collect_inherited_persona};

/// The operator NAILS lists for a GDM turned on without naming an account.
const OPERATOR: &str = "operator";

/// Languages the KConfig model is run in, beside those the files name.
const LOCALES: [&str; 4] = ["", "C", "en_US", "de_DE"];

/// The name of the drop-in beside the input's one in `/etc`: ICU sorts `_`
/// before `-`, the C locale after.
const SIBLING: &str = "50_local.conf";

/// What that drop-in holds without a vendor drop-in to copy.
const SIBLING_OFF: &str = "[Autologin]\nUser=\n";

fuzz_target!(|data: &[u8]| {
    let parts = nails_fuzz::parts(data, 3);
    let main = parts[0].as_str();
    let local = parts.get(1).map(String::as_str);
    let vendor = parts.get(2).map(String::as_str);
    gdm([Some(main), local, vendor]);
    sddm(main, local, vendor);
    plasma_login(main, local, vendor);
    lightdm(main, local, vendor);
});

/// A system holding `files`, each directory listing its files in reverse
/// order of their names.
fn stage(files: &[(&str, &str)]) -> MockFilesystem {
    let fs = MockFilesystem::new();
    let mut dirs: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    for (path, text) in files {
        fs.mock_set_file_content(path, text);
        let path = PathBuf::from(path);
        let dir = path.parent().expect("an absolute path").to_path_buf();
        dirs.entry(dir).or_default().push(path);
    }
    for (dir, mut entries) in dirs {
        entries.sort();
        entries.reverse();
        fs.mock_set_directory_contents(&dir, entries);
    }
    fs
}

/// The accounts NAILS lists as autologin on `fs`.
fn listed(fs: &MockFilesystem) -> Vec<String> {
    collect_inherited_persona(fs, Path::new("/home/operator"), OPERATOR, false)
        .entries
        .into_iter()
        .filter(|entry| entry.source == InheritedSource::Autologin)
        .map(|entry| entry.name)
        .collect()
}

/// `accounts` as NAILS lists them: trimmed, none empty, sorted, each once.
fn normalized(accounts: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut accounts: Vec<String> = accounts
        .into_iter()
        .map(|account| account.trim().to_string())
        .filter(|account| !account.is_empty())
        .collect();
    accounts.sort();
    accounts.dedup();
    accounts
}

fn gdm(texts: [Option<&str>; 3]) {
    let paths = [
        "/etc/gdm/custom.conf",
        "/etc/gdm3/custom.conf",
        "/etc/gdm3/daemon.conf",
    ];
    let files: Vec<(&str, &str)> = paths
        .into_iter()
        .zip(texts)
        .filter_map(|(path, text)| text.map(|text| (path, text)))
        .collect();
    let listed = listed(&stage(&files));
    let mut expected = Vec::new();
    for (_, text) in &files {
        for (enabled, account) in display_managers::gdm(text) {
            if enabled {
                // NAILS lists the operator for a GDM turned on for nobody.
                if account.trim().is_empty() {
                    expected.push(OPERATOR.to_string());
                } else {
                    expected.push(account);
                }
            }
        }
    }
    assert_eq!(listed, normalized(expected), "GDM");
}

/// The files staged for a Qt display manager, beside the fixed ones, and
/// each order it may read them in: the texts, each with whether it is the
/// main file.
fn qt_files<'a>(
    vendor_dir: &str,
    local_dir: &str,
    main_path: &str,
    fixed: &'a str,
    texts: (&'a str, Option<&'a str>, Option<&'a str>),
) -> (Vec<(String, &'a str)>, Vec<Vec<(&'a str, bool)>>) {
    let (main, local, vendor) = texts;
    let mut staged = vec![(format!("{vendor_dir}/05-fixed.conf"), fixed)];
    staged.extend(vendor.map(|text| (format!("{vendor_dir}/10-vendor.conf"), text)));
    // QDir lists no hidden file.
    staged.push((
        format!("{local_dir}/.unread.conf"),
        "[Autologin]\nUser=unread\n",
    ));
    let mut before: Vec<&str> = vec![fixed];
    before.extend(vendor);
    let mut orders: Vec<Vec<&str>> = Vec::new();
    match local {
        None => orders.push(before),
        Some(local) => {
            let sibling = vendor.unwrap_or(SIBLING_OFF);
            staged.push((format!("{local_dir}/50-local.conf"), local));
            staged.push((format!("{local_dir}/{SIBLING}"), sibling));
            for pair in [[local, sibling], [sibling, local]] {
                orders.push(before.iter().copied().chain(pair).collect());
            }
        }
    }
    staged.push((main_path.to_string(), main));
    let orders = orders
        .into_iter()
        .map(|order| {
            order
                .into_iter()
                .map(|text| (text, false))
                .chain(std::iter::once((main, true)))
                .collect()
        })
        .collect();
    (staged, orders)
}

fn staged(files: &[(String, &str)]) -> MockFilesystem {
    let files: Vec<(&str, &str)> = files
        .iter()
        .map(|(path, text)| (path.as_str(), *text))
        .collect();
    stage(&files)
}

fn sddm(main: &str, local: Option<&str>, vendor: Option<&str>) {
    let (files, orders) = qt_files(
        "/usr/lib/sddm/sddm.conf.d",
        "/etc/sddm.conf.d",
        "/etc/sddm.conf",
        "[Autologin]\nUser=vendor\n",
        (main, local, vendor),
    );
    let listed = listed(&staged(&files));
    let mut expected = Vec::new();
    for order in &orders {
        let texts: Vec<&str> = order.iter().map(|(text, _)| *text).collect();
        for qt in [Qt::Five, Qt::Six] {
            expected.push(display_managers::sddm_user(&texts, qt));
        }
    }
    assert_eq!(listed, normalized(expected), "SDDM");
}

/// ASCII whitespace off both ends, as `QByteArrayView::trimmed()`.
fn trimmed(s: &[u8]) -> &[u8] {
    let space = |c: &u8| *c == b' ' || (b'\t'..=b'\r').contains(c);
    let start = s.iter().position(|c| !space(c)).unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|c| !space(c))
        .map_or(start, |end| end + 1);
    &s[start..end]
}

/// The language tags translated keys in `texts` name: the brackets without
/// a `$` at the end of a key.
fn locale_tags(texts: &[&str]) -> BTreeSet<String> {
    let mut tags = BTreeSet::new();
    for text in texts {
        for line in text.as_bytes().split(|&c| c == b'\n') {
            let line = trimmed(line);
            let Some(eq) = line.iter().position(|&c| c == b'=') else {
                continue;
            };
            if line[0] == b'#' || line[0] == b'[' {
                continue;
            }
            let mut key = trimmed(&line[..eq]);
            while let Some(start) = key.iter().rposition(|&c| c == b'[') {
                let Some(end) = key[start..].iter().position(|&c| c == b']') else {
                    break;
                };
                if !(end > 1 && key[start + 1] == b'$') {
                    tags.insert(String::from_utf8_lossy(&key[start + 1..start + end]).into_owned());
                }
                key = &key[..start];
            }
        }
    }
    tags
}

fn plasma_login(main: &str, local: Option<&str>, vendor: Option<&str>) {
    let (files, orders) = qt_files(
        "/usr/lib/plasmalogin/plasmalogin.conf.d",
        "/etc/plasmalogin.conf.d",
        "/etc/plasmalogin.conf",
        "[Autologin]\nUser=vendor\n",
        (main, local, vendor),
    );
    let listed = listed(&staged(&files));
    let texts: Vec<&str> = files.iter().map(|(_, text)| *text).collect();
    let mut locales: BTreeSet<String> = LOCALES.iter().map(ToString::to_string).collect();
    locales.extend(locale_tags(&texts));
    let groups = ["Autologin", "Autologin\u{1d}seat0"];
    let mut expected = Vec::new();
    let mut translated = false;
    for order in &orders {
        let texts: Vec<&str> = order.iter().map(|(text, _)| *text).collect();
        // Up to 6.6, SDDM's reader, on Qt 6.
        expected.push(display_managers::sddm_user(&texts, Qt::Six));
        for locale in &locales {
            for frameworks in [Frameworks::Before6_29, Frameworks::Since6_29] {
                let read = kconfig::read(order, &groups, locale, frameworks);
                translated |= read.translated;
                expected.extend(read.users.into_iter().flatten());
            }
        }
    }
    let expected = normalized(expected);
    if translated {
        for account in &expected {
            assert!(
                listed.contains(account),
                "Plasma Login Manager: {account:?} missing from {listed:?}"
            );
        }
    } else {
        assert_eq!(listed, expected, "Plasma Login Manager");
    }
}

fn lightdm(main: &str, local: Option<&str>, vendor: Option<&str>) {
    let fixed = "[Seat:*]\nautologin-user=vendor\n";
    let mut files = vec![("/usr/share/lightdm/lightdm.conf.d/05-fixed.conf", fixed)];
    files.extend(vendor.map(|text| ("/usr/share/lightdm/lightdm.conf.d/10-vendor.conf", text)));
    files.extend(local.map(|text| ("/etc/lightdm/lightdm.conf.d/50-local.conf", text)));
    // LightDM reads only files whose names end in `.conf`.
    files.push((
        "/etc/lightdm/lightdm.conf.d/99-unread.conf.bak",
        "[Seat:*]\nautologin-user=unread\n",
    ));
    files.push(("/etc/lightdm/lightdm.conf", main));
    let listed = listed(&stage(&files));
    let mut drop_ins = vec![fixed];
    drop_ins.extend(vendor);
    drop_ins.extend(local);
    let expected = display_managers::lightdm(&drop_ins, Some(main));
    assert_eq!(
        listed,
        normalized(expected.into_iter().flatten()),
        "LightDM"
    );
}
