// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The accounts the decoy's display managers log in automatically.
//!
//! A display manager reads its files in an order of its own and with a
//! parser of its own, and a later file overrides an earlier one: it can name
//! another account, or empty the setting and turn autologin off. Each reader
//! here takes the files in that order and parses them the same way, so the
//! account it reports is the one the display manager logs in:
//!
//! - GDM reads one GLib key file ([`keyfile`]): `AutomaticLoginEnable` and
//!   `AutomaticLogin` in its `[daemon]` group, as far as GLib reads it. Which
//!   file depends on the build: `/etc/gdm/custom.conf` upstream,
//!   `/etc/gdm3/custom.conf` on Ubuntu, `/etc/gdm3/daemon.conf` on Debian.
//!   Each one that turns autologin on counts.
//! - SDDM reads every file in `/usr/lib/sddm/sddm.conf.d`, then in
//!   `/etc/sddm.conf.d`, then `/etc/sddm.conf` ([`sddm`]): `User=` in
//!   `[Autologin]`.
//! - LightDM reads the `*.conf` files in `lightdm/lightdm.conf.d` below
//!   `/usr/share`, `/usr/local/share` and `/etc/xdg`, then in
//!   `/etc/lightdm/lightdm.conf.d`, then `/etc/lightdm/lightdm.conf`, each a
//!   GLib key file it takes whole or not at all: `autologin-user=` in
//!   `[Seat:*]` (`[SeatDefaults]` in older files), then in each `[Seat:…]`
//!   group whose pattern matches the seat, in the order the groups first
//!   appear. When GLib refuses `lightdm.conf` itself, LightDM does not start.
//!
//! The seat judged is the first one, `seat0`: GDM logs in there only, and
//! every machine has it. The files of a directory are read in the byte order
//! of their names, LightDM's order. SDDM sorts them by the system's
//! collation instead, which can put names that differ in case or punctuation
//! in another order.
//!
//! GDM turned on without naming an account counts as the operator: GDM also
//! reads `/run/gdm/custom.conf` first, which can name one. So the inventory
//! may list an autologin that does not happen, rather than leave out one that
//! does.

mod keyfile;
mod sddm;

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::inventory::PersonaSource;

/// Where GDM may read its configuration, by build.
const GDM_FILES: [&str; 3] = [
    "/etc/gdm/custom.conf",
    "/etc/gdm3/custom.conf",
    "/etc/gdm3/daemon.conf",
];

/// SDDM's directories of drop-ins in reading order, then its main file.
const SDDM_DIRS: [&str; 2] = ["/usr/lib/sddm/sddm.conf.d", "/etc/sddm.conf.d"];
const SDDM_FILE: &str = "/etc/sddm.conf";

/// LightDM's directories of drop-ins in reading order: below the XDG data
/// directories (`/usr/local/share:/usr/share` when unset, as for its
/// service), the least important first, below the XDG config directory
/// (`/etc/xdg`), then its own. Its main file comes last.
const LIGHTDM_DIRS: [&str; 4] = [
    "/usr/share/lightdm/lightdm.conf.d",
    "/usr/local/share/lightdm/lightdm.conf.d",
    "/etc/xdg/lightdm/lightdm.conf.d",
    "/etc/lightdm/lightdm.conf.d",
];
const LIGHTDM_FILE: &str = "/etc/lightdm/lightdm.conf";

/// The seat judged.
const SEAT: &str = "seat0";

/// The accounts the decoy's display managers log in on their own, trimmed,
/// none empty, possibly repeated. `operator` stands in for the account of a
/// GDM turned on without naming one.
pub(super) fn accounts<F: PersonaSource>(fs: &F, operator: &str) -> Vec<String> {
    let mut accounts = gdm(fs, operator);
    accounts.extend(sddm_account(fs));
    accounts.extend(lightdm(fs));
    accounts
        .iter()
        .map(|account| account.trim())
        .filter(|account| !account.is_empty())
        .map(str::to_string)
        .collect()
}

/// The account of each GDM file that turns autologin on.
fn gdm<F: PersonaSource>(fs: &F, operator: &str) -> Vec<String> {
    GDM_FILES
        .iter()
        .filter_map(|path| fs.text(Path::new(path)))
        .filter_map(|text| {
            // GDM keeps what GLib read before a line it refuses.
            let file = keyfile::parse(&text).file;
            let enabled = file
                .value("daemon", "AutomaticLoginEnable")
                .is_some_and(gdm_true);
            let named = file.value("daemon", "AutomaticLogin").unwrap_or_default();
            enabled.then(|| {
                let account = if named.trim().is_empty() {
                    operator
                } else {
                    named
                };
                account.to_string()
            })
        })
        .collect()
}

/// Whether GDM reads `value` as true: `true` in any case, or `1`.
fn gdm_true(value: &str) -> bool {
    value.eq_ignore_ascii_case("true") || value == "1"
}

/// The account SDDM logs in.
fn sddm_account<F: PersonaSource>(fs: &F) -> Option<String> {
    let texts = texts(fs, &qt_files(fs, &SDDM_DIRS, SDDM_FILE));
    sddm::autologin_user(texts.iter().map(String::as_str))
}

/// The account LightDM logs in on the seat, if any.
fn lightdm<F: PersonaSource>(fs: &F) -> Option<String> {
    let mut config = keyfile::KeyFile::default();
    let conf = |name: &[u8]| name.ends_with(b".conf");
    for dir in LIGHTDM_DIRS {
        for path in sorted_entries(fs, Path::new(dir), conf) {
            let Some(text) = fs.text(&path) else {
                continue;
            };
            // LightDM skips a drop-in GLib refuses.
            let parsed = keyfile::parse(&text);
            if parsed.complete {
                merge(&mut config, &parsed.file);
            }
        }
    }
    if let Some(text) = fs.text(Path::new(LIGHTDM_FILE)) {
        let parsed = keyfile::parse(&text);
        if !parsed.complete {
            return None;
        }
        merge(&mut config, &parsed.file);
    }
    let account = keyfile::unescape(seat_value(&config, SEAT, "autologin-user")?)?;
    (!account.is_empty()).then_some(account)
}

/// LightDM's merge of one file into its configuration: every key replaces
/// the value set before it, and `[SeatDefaults]` is `[Seat:*]`.
fn merge(config: &mut keyfile::KeyFile, file: &keyfile::KeyFile) {
    for (group, key, value) in file.entries() {
        let group = if group == "SeatDefaults" {
            "Seat:*"
        } else {
            group
        };
        config.set(group, key, value);
    }
}

/// The raw value LightDM gives `key` on `seat`: from `[Seat:*]`, then from
/// each other `[Seat:…]` group whose pattern matches the seat, in the order
/// the groups first appeared; the last group that sets it wins.
fn seat_value<'a>(config: &'a keyfile::KeyFile, seat: &str, key: &str) -> Option<&'a str> {
    let matching = config.group_names().filter(|group| {
        group
            .strip_prefix("Seat:")
            .is_some_and(|pattern| pattern != "*" && glob_matches(pattern, seat))
    });
    std::iter::once("Seat:*")
        .chain(matching)
        .filter_map(|group| config.value(group, key))
        .last()
}

/// `g_pattern_match_simple()`: `*` matches any run of characters, `?` any
/// one character.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0, 0);
    // The last `*` seen and where in the text it began to match.
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&c) if c == '?' || c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((star_p, star_t)) => {
                    star = Some((star_p, star_t + 1));
                    p = star_p + 1;
                    t = star_t + 1;
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

/// The files a Qt display manager reads, in order: those of each of `dirs`,
/// sorted by name and without hidden ones (a leading `.`), as `QDir` lists
/// them, then `main`.
fn qt_files<F: PersonaSource>(fs: &F, dirs: &[&str], main: &str) -> Vec<PathBuf> {
    let visible = |name: &[u8]| !name.starts_with(b".");
    let mut files: Vec<PathBuf> = dirs
        .iter()
        .flat_map(|dir| sorted_entries(fs, Path::new(dir), visible))
        .collect();
    files.push(PathBuf::from(main));
    files
}

/// The entries of `dir` whose names `keep` accepts, sorted by name.
fn sorted_entries<F: PersonaSource>(
    fs: &F,
    dir: &Path,
    keep: impl Fn(&[u8]) -> bool,
) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = fs
        .entries(dir)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| keep(name.as_bytes())))
        .collect();
    entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    entries
}

/// The text of each of `files` that can be read.
fn texts<F: PersonaSource>(fs: &F, files: &[PathBuf]) -> Vec<String> {
    files.iter().filter_map(|path| fs.text(path)).collect()
}

#[cfg(test)]
mod tests;
