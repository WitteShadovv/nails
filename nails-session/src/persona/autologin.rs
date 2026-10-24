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
//! - Plasma Login Manager reads `/usr/lib/plasmalogin/plasmalogin.conf.d`,
//!   `/etc/plasmalogin.conf.d` and `/etc/plasmalogin.conf` in the same way:
//!   `User=` in `[Autologin]`, and since 6.8 in the `[Autologin][seat0]`
//!   group of the seat when it has one. Up to 6.6 it parsed them as SDDM
//!   does, since 6.7 through KConfig ([`kconfig`]); an account either way of
//!   reading names counts.
//! - LightDM reads the `*.conf` files in `lightdm/lightdm.conf.d` below
//!   `/usr/share`, `/usr/local/share` and `/etc/xdg`, then in
//!   `/etc/lightdm/lightdm.conf.d`, then `/etc/lightdm/lightdm.conf`, each a
//!   GLib key file it takes whole or not at all: `autologin-user=` in
//!   `[Seat:*]` (`[SeatDefaults]` in older files), then in each `[Seat:…]`
//!   group whose pattern matches the seat, in the order the groups first
//!   appear. When GLib refuses `lightdm.conf` itself, LightDM does not start.
//!
//! The seat judged is the first one, `seat0`: GDM logs in there only, and
//! every machine has it. Only regular files are read, once their links are
//! followed: a FIFO, socket or device in these places could block the read,
//! or never end it. A file the source cannot give as text, such as one that
//! is not valid UTF-8, counts as missing. LightDM reads a directory's files
//! in the byte order of their names. SDDM and Plasma Login Manager sort them
//! by the collation of the locale they run in, which the files do not tell,
//! so they are read in each order a collation may give ([`collation`]).
//!
//! Where the files alone do not tell, an account counts whenever it could be
//! the one logged in: the account any of those orders ends with; both
//! readings of a line that SDDM reads one way on Qt 5 and another on Qt 6,
//! or that GLib takes or refuses by its own Unicode tables; a KConfig `User`
//! translated for a language (the language the display manager runs in
//! decides) or expanded from the environment (`[$e]`); and GDM turned on
//! without naming an account, which counts as the operator (GDM also reads
//! `/run/gdm/custom.conf` first, which can name one).

mod collation;
mod kconfig;
mod keyfile;
mod sddm;

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::inventory::PersonaSource;
use sddm::Qt;

/// Where GDM may read its configuration, by build.
const GDM_FILES: [&str; 3] = [
    "/etc/gdm/custom.conf",
    "/etc/gdm3/custom.conf",
    "/etc/gdm3/daemon.conf",
];

/// SDDM's directories of drop-ins in reading order, then its main file.
const SDDM_DIRS: [&str; 2] = ["/usr/lib/sddm/sddm.conf.d", "/etc/sddm.conf.d"];
const SDDM_FILE: &str = "/etc/sddm.conf";

/// Plasma Login Manager's directories of drop-ins in reading order, then its
/// main file.
const PLASMA_LOGIN_DIRS: [&str; 2] = [
    "/usr/lib/plasmalogin/plasmalogin.conf.d",
    "/etc/plasmalogin.conf.d",
];
const PLASMA_LOGIN_FILE: &str = "/etc/plasmalogin.conf";

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

/// The most LightDM drop-ins that GLib may load or refuse, read with and
/// without each; past it, every account the files name counts.
const MAX_UNDECIDED_DROP_INS: usize = 8;

/// The accounts the decoy's display managers log in on their own, trimmed,
/// none empty, possibly repeated. `operator` stands in for the account of a
/// GDM turned on without naming one.
pub(super) fn accounts<F: PersonaSource>(fs: &F, operator: &str) -> Vec<String> {
    let mut accounts = gdm(fs, operator);
    accounts.extend(sddm_accounts(fs));
    accounts.extend(plasma_login(fs));
    accounts.extend(lightdm(fs));
    accounts
        .iter()
        .map(|account| account.trim())
        .filter(|account| !account.is_empty())
        .map(str::to_string)
        .collect()
}

/// The account of each GDM file that turns autologin on, in each way GLib
/// may read it: GDM keeps what GLib read before a line it refuses.
fn gdm<F: PersonaSource>(fs: &F, operator: &str) -> Vec<String> {
    let mut accounts = Vec::new();
    for path in GDM_FILES {
        let Some(text) = file_text(fs, Path::new(path)) else {
            continue;
        };
        let parsed = keyfile::parse(&text);
        for file in parsed.outcomes() {
            let enabled = file
                .value("daemon", "AutomaticLoginEnable")
                .is_some_and(gdm_true);
            let named = file.value("daemon", "AutomaticLogin").unwrap_or_default();
            if enabled {
                let account = if named.trim().is_empty() {
                    operator
                } else {
                    named
                };
                accounts.push(account.to_string());
            }
        }
    }
    accounts
}

/// Whether GDM reads `value` as true: `true` in any case, or `1`.
fn gdm_true(value: &str) -> bool {
    value.eq_ignore_ascii_case("true") || value == "1"
}

/// The accounts SDDM logs in, by a build on Qt 6 and, where a line holds a
/// NUL, by one on Qt 5.
fn sddm_accounts<F: PersonaSource>(fs: &F) -> Vec<String> {
    let config = QtConfig::read(fs, &SDDM_DIRS, SDDM_FILE);
    let mut builds = vec![Qt::Six];
    if config.texts().any(|(text, _)| text.contains('\0')) {
        builds.push(Qt::Five);
    }
    let orders = config.orders();
    let mut accounts = Vec::new();
    for qt in builds {
        match &orders {
            Some(orders) => {
                accounts.extend(orders.iter().filter_map(|order| {
                    sddm::autologin_user(order.iter().map(|(text, _)| *text), qt)
                }))
            }
            None => accounts.extend(sddm::every_user(config.texts().map(|(text, _)| text), qt)),
        }
    }
    accounts
}

/// The accounts Plasma Login Manager logs in, by SDDM's parser on Qt 6 and
/// by KConfig's.
fn plasma_login<F: PersonaSource>(fs: &F) -> Vec<String> {
    let config = QtConfig::read(fs, &PLASMA_LOGIN_DIRS, PLASMA_LOGIN_FILE);
    let seat = format!("Autologin\u{1d}{SEAT}");
    let groups = ["Autologin", seat.as_str()];
    let mut accounts = Vec::new();
    match config.orders() {
        Some(orders) => {
            for order in &orders {
                accounts.extend(sddm::autologin_user(
                    order.iter().map(|(text, _)| *text),
                    Qt::Six,
                ));
                accounts.extend(kconfig::users(&kconfig_sources(order), &groups));
            }
        }
        None => {
            let files: Vec<(&str, bool)> = config.texts().collect();
            accounts.extend(sddm::every_user(
                files.iter().map(|(text, _)| *text),
                Qt::Six,
            ));
            accounts.extend(kconfig::every_user(&kconfig_sources(&files), &groups));
        }
    }
    accounts
}

/// `files` as KConfig reads them.
fn kconfig_sources<'a>(files: &[(&'a str, bool)]) -> Vec<kconfig::Source<'a>> {
    files
        .iter()
        .map(|&(text, main)| kconfig::Source { text, main })
        .collect()
}

/// The files a Qt display manager reads: the drop-ins of each of its
/// directories, then its main file.
struct QtConfig {
    /// Each directory's regular files that can be read but the hidden ones,
    /// which `QDir` leaves out: their names and texts.
    dirs: Vec<Vec<(Vec<u8>, String)>>,
    main: Option<String>,
}

impl QtConfig {
    fn read<F: PersonaSource>(fs: &F, dirs: &[&str], main: &str) -> Self {
        let visible = |name: &[u8]| !name.starts_with(b".");
        let dirs = dirs
            .iter()
            .map(|dir| {
                files(fs, Path::new(dir), visible)
                    .into_iter()
                    .filter_map(|path| {
                        let name = path.file_name()?.as_bytes().to_vec();
                        Some((name, fs.text(&path)?))
                    })
                    .collect()
            })
            .collect();
        Self {
            dirs,
            main: file_text(fs, Path::new(main)),
        }
    }

    /// Every file's text, the main file last, each with whether it is the
    /// main file.
    fn texts(&self) -> impl Iterator<Item = (&str, bool)> {
        self.dirs
            .iter()
            .flatten()
            .map(|(_, text)| (text.as_str(), false))
            .chain(self.main.iter().map(|text| (text.as_str(), true)))
    }

    /// The texts in each order the display manager may read them in, as
    /// [`texts`](Self::texts) gives them; `None` when there are too many
    /// orders.
    fn orders(&self) -> Option<Vec<Vec<(&str, bool)>>> {
        let names: Vec<Vec<&[u8]>> = self
            .dirs
            .iter()
            .map(|files| files.iter().map(|(name, _)| name.as_slice()).collect())
            .collect();
        let orders = collation::reading_orders(&names, collation::MAX_ORDERS)?;
        Some(
            orders
                .into_iter()
                .map(|order| {
                    order
                        .into_iter()
                        .map(|(dir, file)| (self.dirs[dir][file].1.as_str(), false))
                        .chain(self.main.iter().map(|text| (text.as_str(), true)))
                        .collect()
                })
                .collect(),
        )
    }
}

/// The accounts LightDM logs in on the seat. A drop-in GLib may load or
/// refuse is read once with it and once without, and a `lightdm.conf` it
/// may refuse once with it and once as the display manager that does not
/// start.
fn lightdm<F: PersonaSource>(fs: &F) -> Vec<String> {
    let conf = |name: &[u8]| name.ends_with(b".conf");
    let drop_ins: Vec<keyfile::Parsed> = LIGHTDM_DIRS
        .iter()
        .flat_map(|dir| files(fs, Path::new(dir), conf))
        .filter_map(|path| fs.text(&path))
        .map(|text| keyfile::parse(&text))
        .collect();
    let main = file_text(fs, Path::new(LIGHTDM_FILE)).map(|text| keyfile::parse(&text));
    // LightDM skips a drop-in GLib refuses.
    let undecided: Vec<usize> = (0..drop_ins.len())
        .filter(|&i| drop_ins[i].may_load() && drop_ins[i].may_fail())
        .collect();
    if undecided.len() > MAX_UNDECIDED_DROP_INS {
        return every_lightdm_user(drop_ins.iter().chain(&main));
    }
    let mut accounts = Vec::new();
    for read in 0..1_usize << undecided.len() {
        let mut config = keyfile::KeyFile::default();
        for (i, drop_in) in drop_ins.iter().enumerate() {
            let skipped = match undecided.iter().position(|&u| u == i) {
                Some(bit) => read & (1 << bit) == 0,
                None => !drop_in.may_load(),
            };
            if !skipped {
                merge(&mut config, &drop_in.file);
            }
        }
        match &main {
            None => accounts.extend(seat_account(&config)),
            Some(main) => {
                // A main file GLib refuses keeps LightDM from starting.
                if main.may_load() {
                    merge(&mut config, &main.file);
                    accounts.extend(seat_account(&config));
                }
            }
        }
    }
    accounts
}

/// The account `config` names for the seat, if any.
fn seat_account(config: &keyfile::KeyFile) -> Option<String> {
    let account = keyfile::unescape(seat_value(config, SEAT, "autologin-user")?)?;
    (!account.is_empty()).then_some(account)
}

/// Every account a LightDM file may set for the seat, in any group that can
/// apply to it.
fn every_lightdm_user<'a>(files: impl Iterator<Item = &'a keyfile::Parsed>) -> Vec<String> {
    files
        .flat_map(keyfile::Parsed::outcomes)
        .flat_map(keyfile::KeyFile::entries)
        .filter(|&(group, key, _)| key == "autologin-user" && seat_group_applies(group, SEAT))
        .filter_map(|(_, _, value)| keyfile::unescape(value))
        .filter(|account| !account.is_empty())
        .collect()
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

/// Whether LightDM applies the settings of `group` to `seat`: `[Seat:*]`,
/// `[SeatDefaults]`, or a `[Seat:…]` whose pattern matches it.
fn seat_group_applies(group: &str, seat: &str) -> bool {
    group == "SeatDefaults"
        || group
            .strip_prefix("Seat:")
            .is_some_and(|pattern| glob_matches(pattern, seat))
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

/// The regular files of `dir` whose names `keep` accepts, sorted by the
/// bytes of their names.
fn files<F: PersonaSource>(fs: &F, dir: &Path, keep: impl Fn(&[u8]) -> bool) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs
        .entries(dir)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| keep(name.as_bytes())))
        .filter(|path| fs.is_file(path))
        .collect();
    files.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    files
}

/// The text of the regular file at `path`, if it can be read.
fn file_text<F: PersonaSource>(fs: &F, path: &Path) -> Option<String> {
    if fs.is_file(path) {
        fs.text(path)
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
