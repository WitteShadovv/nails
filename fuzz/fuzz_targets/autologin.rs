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
//! `.conf`), which names another. Every directory lists its files in reverse
//! order. For GDM they are the three files a GDM build may read. The target
//! checks that the accounts NAILS lists for each display manager are the
//! ones its model (`nails_fuzz::display_managers`, `nails_fuzz::kconfig`)
//! logs in: exactly, or, where a translated KConfig key leaves the choice to
//! the language the display manager runs in, at least every one the model
//! logs in for each of three languages.

#![no_main]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use libfuzzer_sys::fuzz_target;
use nails_base::MockFilesystem;
use nails_fuzz::{display_managers, kconfig};
use nails_session::persona::{InheritedSource, collect_inherited_persona};

/// The operator NAILS lists for a GDM turned on without naming an account.
const OPERATOR: &str = "operator";

/// The languages the KConfig model is run in.
const LOCALES: [&str; 3] = ["C", "en_US", "de_DE"];

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
        let Some((enabled, account)) = display_managers::gdm(text) else {
            return;
        };
        if enabled {
            // NAILS lists the operator for a GDM turned on for nobody.
            if account.trim().is_empty() {
                expected.push(OPERATOR.to_string());
            } else {
                expected.push(account);
            }
        }
    }
    assert_eq!(listed, normalized(expected), "GDM");
}

/// The files of a Qt display manager, in its reading order, beside the
/// fixed ones: `(path, text, read)`.
fn qt_files<'a>(
    vendor_dir: &str,
    local_dir: &str,
    main_path: &'a str,
    fixed: &'a str,
    texts: (&'a str, Option<&'a str>, Option<&'a str>),
) -> Vec<(String, &'a str, bool)> {
    let (main, local, vendor) = texts;
    let mut files = vec![(format!("{vendor_dir}/05-fixed.conf"), fixed, true)];
    files.extend(vendor.map(|text| (format!("{vendor_dir}/10-vendor.conf"), text, true)));
    // QDir lists no hidden file.
    files.push((
        format!("{local_dir}/.unread.conf"),
        "[Autologin]\nUser=unread\n",
        false,
    ));
    files.extend(local.map(|text| (format!("{local_dir}/50-local.conf"), text, true)));
    files.push((main_path.to_string(), main, true));
    files
}

fn staged(files: &[(String, &str, bool)]) -> MockFilesystem {
    let files: Vec<(&str, &str)> = files
        .iter()
        .map(|(path, text, _)| (path.as_str(), *text))
        .collect();
    stage(&files)
}

fn sddm(main: &str, local: Option<&str>, vendor: Option<&str>) {
    let files = qt_files(
        "/usr/lib/sddm/sddm.conf.d",
        "/etc/sddm.conf.d",
        "/etc/sddm.conf",
        "[Autologin]\nUser=vendor\n",
        (main, local, vendor),
    );
    let listed = listed(&staged(&files));
    let texts: Vec<&str> = files
        .iter()
        .filter(|(_, _, read)| *read)
        .map(|(_, text, _)| *text)
        .collect();
    let Some(account) = display_managers::sddm_user(&texts) else {
        return;
    };
    assert_eq!(listed, normalized([account]), "SDDM");
}

fn plasma_login(main: &str, local: Option<&str>, vendor: Option<&str>) {
    let main_path = "/etc/plasmalogin.conf";
    let files = qt_files(
        "/usr/lib/plasmalogin/plasmalogin.conf.d",
        "/etc/plasmalogin.conf.d",
        main_path,
        "[Autologin]\nUser=vendor\n",
        (main, local, vendor),
    );
    let listed = listed(&staged(&files));
    let read: Vec<(&str, bool)> = files
        .iter()
        .filter(|(_, _, read)| *read)
        .map(|(path, text, _)| (*text, path == main_path))
        .collect();
    let texts: Vec<&str> = read.iter().map(|(text, _)| *text).collect();
    // Up to 6.6, SDDM's reader.
    let Some(sddm) = display_managers::sddm_user(&texts) else {
        return;
    };
    let groups = ["Autologin", "Autologin\u{1d}seat0"];
    for locale in LOCALES {
        let kconfig::Read::Values { users, translated } = kconfig::read(&read, &groups, locale)
        else {
            return;
        };
        let expected = normalized(std::iter::once(sddm.clone()).chain(users.into_iter().flatten()));
        if translated {
            for account in &expected {
                assert!(
                    listed.contains(account),
                    "Plasma Login Manager in {locale}: {account:?} missing from {listed:?}"
                );
            }
        } else {
            assert_eq!(listed, expected, "Plasma Login Manager in {locale}");
        }
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
    let Some(account) = display_managers::lightdm(&drop_ins, Some(main)) else {
        return;
    };
    assert_eq!(listed, normalized(account), "LightDM");
}
