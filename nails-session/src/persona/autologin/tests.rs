// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::Filesystem;
use crate::filesystem::{MockFilesystem, PathKind, RealFilesystem};

/// The accounts reported for `fs`, sorted, each once.
fn accounts_of(fs: &MockFilesystem) -> Vec<String> {
    let mut accounts = accounts(fs, "operator");
    accounts.sort();
    accounts.dedup();
    accounts
}

/// A file in `dir`, listed there after the entries it already lists.
fn drop_in(fs: &MockFilesystem, dir: &str, name: &str, text: &str) {
    let path = Path::new(dir).join(name);
    let mut listing = fs.list_directory(Path::new(dir)).unwrap_or_default();
    listing.push(path.clone());
    fs.mock_set_directory_contents(Path::new(dir), listing);
    fs.mock_set_file_content(path.to_str().unwrap(), text);
}

fn one(fs: &MockFilesystem, path: &str, text: &str) -> Vec<String> {
    fs.mock_set_file_content(path, text);
    accounts_of(fs)
}

fn names(names: &[&str]) -> Vec<String> {
    names.iter().map(ToString::to_string).collect()
}

// --- GDM ---

#[test]
fn gdm_counts_each_file_a_build_may_read() {
    let fs = MockFilesystem::new();
    for (path, user) in [
        ("/etc/gdm/custom.conf", "fedora"),
        ("/etc/gdm3/custom.conf", "ubuntu"),
        ("/etc/gdm3/daemon.conf", "debian"),
    ] {
        fs.mock_set_file_content(
            path,
            &format!("[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin={user}\n"),
        );
    }
    assert_eq!(accounts_of(&fs), names(&["debian", "fedora", "ubuntu"]));
}

#[test]
fn gdm_reads_its_daemon_group_only() {
    let fs = MockFilesystem::new();
    let elsewhere = "# AutomaticLoginEnable=true\n[security]\nAutomaticLoginEnable=true\n\
                     AutomaticLogin=eve\n[daemon]\n";
    assert!(one(&fs, "/etc/gdm/custom.conf", elsewhere).is_empty());
    // Group names are matched exactly.
    let cased = "[Daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=eve\n";
    assert!(one(&fs, "/etc/gdm/custom.conf", cased).is_empty());
    // The account in another group names none: the operator stands in.
    let split = "[daemon]\nAutomaticLoginEnable=true\n[xdmcp]\nAutomaticLogin=eve\n";
    assert_eq!(
        one(&fs, "/etc/gdm/custom.conf", split),
        names(&["operator"])
    );
}

#[test]
fn gdm_takes_the_last_value_and_continues_a_group_named_again() {
    let fs = MockFilesystem::new();
    let text = "[daemon]\nAutomaticLogin=alice\nAutomaticLoginEnable=true\n[security]\n\
                [daemon]\nAutomaticLogin=bob\n";
    assert_eq!(one(&fs, "/etc/gdm/custom.conf", text), names(&["bob"]));
    let off =
        "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=bob\nAutomaticLoginEnable=false\n";
    assert!(one(&fs, "/etc/gdm/custom.conf", off).is_empty());
}

#[test]
fn gdm_reads_true_as_gdm_does() {
    let fs = MockFilesystem::new();
    for (value, on) in [
        ("true", true),
        ("TRUE", true),
        ("1", true),
        ("  true", true),
        ("yes", false),
        ("on", false),
        // GDM compares the raw value, which keeps trailing whitespace.
        ("true ", false),
        ("", false),
    ] {
        let text = format!("[daemon]\nAutomaticLoginEnable={value}\nAutomaticLogin=bob\n");
        assert_eq!(
            !one(&fs, "/etc/gdm/custom.conf", &text).is_empty(),
            on,
            "{value:?}"
        );
    }
}

#[test]
fn gdm_keeps_what_glib_read_before_a_line_it_refuses() {
    let fs = MockFilesystem::new();
    let text = "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=bob\nnot a key\n\
                AutomaticLogin=eve\n";
    assert_eq!(one(&fs, "/etc/gdm/custom.conf", text), names(&["bob"]));
    let early = "[daemon]\nnot a key\nAutomaticLoginEnable=true\nAutomaticLogin=bob\n";
    assert!(one(&fs, "/etc/gdm/custom.conf", early).is_empty());
}

#[test]
fn gdm_without_its_file_or_turned_off_logs_nobody_in() {
    let fs = MockFilesystem::new();
    assert!(accounts_of(&fs).is_empty());
    let off = "[daemon]\nAutomaticLoginEnable=false\nAutomaticLogin=bob\n";
    assert!(one(&fs, "/etc/gdm3/daemon.conf", off).is_empty());
}

#[test]
fn gdm_turned_on_for_nobody_counts_without_a_resolved_operator() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(
        "/etc/gdm/custom.conf",
        "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=  \n",
    );
    assert_eq!(accounts_of(&fs), names(&["operator"]));
    assert!(accounts(&fs, "").is_empty(), "no name to stand in");
}

// --- SDDM ---

const SDDM_VENDOR: &str = "/usr/lib/sddm/sddm.conf.d";
const SDDM_LOCAL: &str = "/etc/sddm.conf.d";

#[test]
fn sddm_reads_its_vendor_directory() {
    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        SDDM_VENDOR,
        "default.conf",
        "[Autologin]\nUser=carol\n",
    );
    assert_eq!(accounts_of(&fs), names(&["carol"]));
}

#[test]
fn sddm_reads_the_vendor_files_then_the_local_ones_then_sddm_conf() {
    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        SDDM_VENDOR,
        "default.conf",
        "[Autologin]\nUser=vendor\n",
    );
    drop_in(
        &fs,
        SDDM_LOCAL,
        "kde_settings.conf",
        "[Autologin]\nUser=local\n",
    );
    assert_eq!(accounts_of(&fs), names(&["local"]));
    // A main file that does not set it changes nothing.
    assert_eq!(
        one(&fs, "/etc/sddm.conf", "[General]\nNumlock=on\n"),
        names(&["local"])
    );
    assert_eq!(
        one(&fs, "/etc/sddm.conf", "[Autologin]\nUser=main\n"),
        names(&["main"])
    );
}

#[test]
fn sddm_turns_autologin_off_with_an_empty_user_in_a_later_file() {
    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        SDDM_VENDOR,
        "default.conf",
        "[Autologin]\nUser=carol\n",
    );
    drop_in(&fs, SDDM_LOCAL, "off.conf", "[Autologin]\nUser=\n");
    assert!(accounts_of(&fs).is_empty());

    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        SDDM_LOCAL,
        "kde_settings.conf",
        "[Autologin]\nUser=carol\n",
    );
    assert!(one(&fs, "/etc/sddm.conf", "[Autologin]\nUser=\n").is_empty());
}

#[test]
fn sddm_sorts_the_files_of_a_directory_by_name() {
    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        SDDM_LOCAL,
        "20-later.conf",
        "[Autologin]\nUser=later\n",
    );
    drop_in(
        &fs,
        SDDM_LOCAL,
        "10-first.conf",
        "[Autologin]\nUser=first\n",
    );
    assert_eq!(accounts_of(&fs), names(&["later"]));
}

#[test]
fn sddm_reads_every_file_but_the_hidden_ones() {
    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        SDDM_LOCAL,
        "10-autologin.conf",
        "[Autologin]\nUser=carol\n",
    );
    drop_in(
        &fs,
        SDDM_LOCAL,
        ".hidden.conf",
        "[Autologin]\nUser=hidden\n",
    );
    assert_eq!(accounts_of(&fs), names(&["carol"]));
    // A backup is read like any other file.
    drop_in(
        &fs,
        SDDM_LOCAL,
        "10-autologin.conf.bak",
        "[Autologin]\nUser=backup\n",
    );
    assert_eq!(accounts_of(&fs), names(&["backup"]));
}

#[test]
fn sddm_reads_user_in_the_autologin_section_only() {
    let fs = MockFilesystem::new();
    let text =
        "User=before\n[Users]\nUser=users\n[autologin]\nUser=cased\n[ Autologin ]\nUser=spaced\n";
    assert!(one(&fs, "/etc/sddm.conf", text).is_empty());
    let text = "[Autologin]\nRelogin=true\n[General]\nUser=general\n";
    assert!(one(&fs, "/etc/sddm.conf", text).is_empty());
}

#[test]
fn sddm_starts_each_file_outside_any_section() {
    let fs = MockFilesystem::new();
    drop_in(&fs, SDDM_LOCAL, "10-section.conf", "[Autologin]\n");
    drop_in(&fs, SDDM_LOCAL, "20-user.conf", "User=carol\n");
    assert!(accounts_of(&fs).is_empty());
}

#[test]
fn sddm_cuts_a_line_at_its_first_hash() {
    let fs = MockFilesystem::new();
    let text = "[Autologin] # the autologin section\nUser = carol # who\n";
    assert_eq!(one(&fs, "/etc/sddm.conf", text), names(&["carol"]));
    assert!(one(&fs, "/etc/sddm.conf", "[Autologin]\nUser=#carol\n").is_empty());
    assert!(one(&fs, "/etc/sddm.conf", "#[Autologin]\nUser=carol\n").is_empty());
}

#[test]
fn sddm_drops_a_byte_order_mark_and_carriage_returns() {
    let fs = MockFilesystem::new();
    let text = "\u{feff}[Autologin]\r\nUser=carol\r\n";
    assert_eq!(one(&fs, "/etc/sddm.conf", text), names(&["carol"]));
}

#[test]
fn sddm_takes_the_line_with_an_equals_sign_as_an_assignment() {
    // `[Autologin=x]` assigns; it opens no section.
    assert_eq!(
        sddm::autologin_user(["[Autologin]\n[Autologin=x]\nUser=carol\n"]),
        Some("carol".to_string())
    );
    assert_eq!(sddm::autologin_user(["[Autologin]\nUser\n"]), None);
}

// --- Plasma Login Manager ---

const PLASMA_VENDOR: &str = "/usr/lib/plasmalogin/plasmalogin.conf.d";
const PLASMA_LOCAL: &str = "/etc/plasmalogin.conf.d";
const PLASMA_MAIN: &str = "/etc/plasmalogin.conf";

#[test]
fn plasma_login_reads_its_three_places_in_order() {
    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        PLASMA_VENDOR,
        "10-vendor.conf",
        "[Autologin]\nUser=vendor\n",
    );
    assert_eq!(accounts_of(&fs), names(&["vendor"]));
    drop_in(
        &fs,
        PLASMA_LOCAL,
        "kde_settings.conf",
        "[Autologin]\nUser=local\n",
    );
    assert_eq!(accounts_of(&fs), names(&["local"]));
    assert_eq!(
        one(&fs, PLASMA_MAIN, "[Autologin]\nSession=plasma\nUser=main\n"),
        names(&["main"])
    );
    assert!(one(&fs, PLASMA_MAIN, "[Autologin]\nUser=\n").is_empty());
}

#[test]
fn plasma_login_reads_files_as_qt_lists_them() {
    let fs = MockFilesystem::new();
    drop_in(&fs, PLASMA_LOCAL, "20-later", "[Autologin]\nUser=later\n");
    drop_in(
        &fs,
        PLASMA_LOCAL,
        "10-first.conf",
        "[Autologin]\nUser=first\n",
    );
    drop_in(
        &fs,
        PLASMA_LOCAL,
        ".zz-hidden.conf",
        "[Autologin]\nUser=hidden\n",
    );
    assert_eq!(accounts_of(&fs), names(&["later"]));
}

#[test]
fn plasma_login_reads_the_group_of_the_seat() {
    let fs = MockFilesystem::new();
    let text = "[Autologin]\nUser=everyone\n\n[Autologin][seat0]\nUser=first-seat\n\n\
                [Autologin][seat1]\nUser=second-seat\n";
    assert_eq!(
        one(&fs, PLASMA_MAIN, text),
        names(&["everyone", "first-seat"])
    );
}

#[test]
fn plasma_login_counts_what_either_parser_reads() {
    let fs = MockFilesystem::new();
    // SDDM's parser, before 6.7, takes `#` for a comment anywhere and
    // knows no escapes; KConfig's, since, does the opposite.
    let text = "[Autologin]\nUser=al\\x69ce # set by hand\n";
    assert_eq!(
        one(&fs, PLASMA_MAIN, text),
        names(&["al\\x69ce", "alice # set by hand"])
    );
    // A byte order mark hides the header from KConfig only.
    assert_eq!(
        one(&fs, PLASMA_MAIN, "\u{feff}[Autologin]\nUser=carol\n"),
        names(&["carol"])
    );
}

#[test]
fn plasma_login_keeps_an_account_kconfig_makes_immutable() {
    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        PLASMA_VENDOR,
        "10-kiosk.conf",
        "[Autologin][$i]\nUser=kiosk\n",
    );
    assert_eq!(
        one(&fs, PLASMA_MAIN, "[Autologin]\nUser=\n"),
        names(&["kiosk"])
    );
}

#[test]
fn plasma_login_takes_a_key_that_decodes_to_nothing_for_the_group_marker() {
    // `\[$i]=x` makes [Autologin] immutable at once, so the main file's
    // empty user is skipped and alice is logged in.
    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        PLASMA_LOCAL,
        "50-local.conf",
        "[Autologin]\nUser=alice\n\\[$i]=x\n",
    );
    assert_eq!(
        one(&fs, PLASMA_MAIN, "[Autologin]\nUser=\n"),
        names(&["alice"])
    );

    // `\=x` clears what an earlier file made immutable, so a takes.
    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        PLASMA_VENDOR,
        "10-vendor.conf",
        "[Autologin][seat0][$i]\nSession=plasma\n",
    );
    drop_in(
        &fs,
        PLASMA_LOCAL,
        "50-local.conf",
        "[Autologin][seat0]\n\\=x\nUser=a\n",
    );
    assert_eq!(accounts_of(&fs), names(&["a"]));
}

// --- KConfig, as Plasma Login Manager reads it since 6.7 ---

/// What KConfig reads for `[Autologin]` and the first seat's group from
/// drop-ins `extras` and then the main file `main`.
fn kconfig(extras: &[&str], main: Option<&str>) -> Vec<String> {
    let mut sources: Vec<kconfig::Source<'_>> = extras
        .iter()
        .map(|text| kconfig::Source { text, main: false })
        .collect();
    sources.extend(main.map(|text| kconfig::Source { text, main: true }));
    kconfig::users(&sources, &["Autologin", "Autologin\u{1d}seat0"])
}

#[test]
fn kconfig_takes_the_last_file_that_sets_the_key() {
    assert_eq!(
        kconfig(&["[Autologin]\nUser=a\n", "[Autologin]\nUser=b\n"], None),
        names(&["b"])
    );
    assert_eq!(
        kconfig(&["[Autologin]\nUser=a\n"], Some("[Autologin]\nUser=\n")),
        names(&[""])
    );
    assert_eq!(
        kconfig(&["[Autologin]\nUser=a\n"], Some("[General]\nUser=b\n")),
        names(&["a"])
    );
}

#[test]
fn kconfig_reads_nested_groups_and_escapes_in_names() {
    assert_eq!(
        kconfig(
            &[],
            Some("[Auto\\x6cogin]\nUser=a\n[Autologin][seat0]\nUser=b\n")
        ),
        names(&["a", "b"])
    );
    // Without a backslash a name is taken as written, spaces too.
    assert!(kconfig(&[], Some("[ Autologin ]\nUser=a\n")).is_empty());
}

#[test]
fn kconfig_ignores_what_follows_a_header_and_keeps_the_group_after_a_broken_one() {
    assert_eq!(
        kconfig(&[], Some("[Autologin] the autologin group\nUser=a\n")),
        names(&["a"])
    );
    assert_eq!(
        kconfig(
            &[],
            Some("[Autologin]\n[broken\nUser=a\n[Autologin][\nUser=b\n")
        ),
        names(&["b"])
    );
}

#[test]
fn kconfig_reads_comments_only_at_the_start_of_a_line() {
    assert_eq!(
        kconfig(&[], Some("[Autologin]\n  # User=a\nUser = b # c\n")),
        names(&["b # c"])
    );
}

#[test]
fn kconfig_decodes_values_as_printable_to_string_does() {
    for (value, read) in [
        ("a\\sb", "a b"),
        ("\\x61lice", "alice"),
        ("a\\tb\\nc\\rd\\\\e", "a\tb\nc\rd\\e"),
        ("a\\;b\\,c", "a\\;b\\,c"),
        // A bad hex digit gives `x`; a `\x` too close to the end ends it.
        ("a\\xzzb", "axb"),
        ("ab\\x1", "abx"),
        // A `\` at the very end is dropped.
        ("bob\\", "bob"),
        // An unknown escape leaves the rest as it was.
        ("a\\sb\\qc", "a b\\\\qc"),
    ] {
        assert_eq!(
            kconfig(&[], Some(&format!("[Autologin]\nUser={value}\n"))),
            names(&[read]),
            "{value:?}"
        );
    }
}

#[test]
fn kconfig_deletes_a_key_marked_d() {
    assert!(kconfig(&["[Autologin]\nUser=a\n"], Some("[Autologin]\nUser[$d]\n")).is_empty());
    // The deletion names the key left of its bracket.
    assert_eq!(
        kconfig(
            &["[Autologin]\nUser=a\n"],
            Some("[Autologin]\nUser[x][$d]\n")
        ),
        names(&["a"])
    );
}

#[test]
fn kconfig_keeps_immutable_keys_and_groups() {
    // An immutable key.
    assert_eq!(
        kconfig(
            &["[Autologin]\nUser[$i]=kiosk\n"],
            Some("[Autologin]\nUser=b\n")
        ),
        names(&["kiosk"])
    );
    // An immutable group takes no new key, from a drop-in or the main file.
    assert!(
        kconfig(
            &["[Autologin][$i]\nSession=plasma\n", "[Autologin]\nUser=a\n"],
            Some("[Autologin]\nUser=b\n")
        )
        .is_empty()
    );
    // A key it had before stays open to a drop-in, not to the main file.
    assert_eq!(
        kconfig(
            &[
                "[Autologin]\nUser=a\n",
                "[Autologin][$i]\nSession=plasma\n",
                "[Autologin]\nUser=b\n"
            ],
            Some("[Autologin]\nUser=c\n")
        ),
        names(&["b"])
    );
    // In a group marked immutable, the first value of a key stands.
    assert_eq!(
        kconfig(&["[Autologin][$i]\nUser=a\nUser=b\n"], None),
        names(&["a"])
    );
}

#[test]
fn kconfig_takes_a_key_that_decodes_to_nothing_for_its_group_marker() {
    // The marker takes the line's immutability at once, not at the end of
    // the file: the main file skips the group.
    assert_eq!(
        kconfig(
            &["[Autologin]\nUser=alice\n\\[$i]=x\n"],
            Some("[Autologin]\nUser=\n")
        ),
        names(&["alice"])
    );
    // A new key after it in the same file is refused too.
    assert!(kconfig(&["[Autologin]\n\\[$i]=x\nUser=alice\n"], None).is_empty());
    // A marker that is not immutable clears an earlier file's mark, also
    // through a deletion and with the spaces a key may hold before its
    // brackets.
    for clear in ["\\=x", "\\[$d]", "\\ [$e]=x"] {
        assert_eq!(
            kconfig(
                &[
                    "[Autologin][seat0][$i]\nSession=plasma\n",
                    &format!("[Autologin][seat0]\n{clear}\nUser=a\n")
                ],
                None
            ),
            names(&["a"]),
            "{clear:?}"
        );
    }
}

#[test]
fn kconfig_stops_after_a_file_that_marks_itself_immutable() {
    assert_eq!(
        kconfig(
            &["[$i]\n[Autologin]\nUser=kiosk\n", "[Autologin]\nUser=a\n"],
            Some("[Autologin]\nUser=b\n")
        ),
        names(&["kiosk"])
    );
    // A header that is only `[$i]` marks the file wherever it stands.
    assert_eq!(
        kconfig(
            &["[Autologin]\nUser=kiosk\n[$i]\n", "[Autologin]\nUser=a\n"],
            None
        ),
        names(&["kiosk"])
    );
    // An `[$i]` marks only when it closes the header.
    assert_eq!(
        kconfig(
            &[
                "[Autologin][$i] trailing\nUser=kiosk\n",
                "[Autologin]\nUser=a\n"
            ],
            None
        ),
        names(&["a"])
    );
}

#[test]
fn kconfig_counts_every_translated_user() {
    assert_eq!(
        kconfig(
            &[],
            Some("[Autologin]\nUser[de]=hans\nUser[]=any\nUser=b\n")
        ),
        names(&["hans", "any", "b"])
    );
    // Two languages, or a bracket left open, break the line.
    assert!(kconfig(&[], Some("[Autologin]\nUser[de][fr]=a\nUser[de=b\n")).is_empty());
}

#[test]
fn kconfig_reads_a_file_up_to_its_hundredth_broken_line() {
    let broken = "no equals sign\n".repeat(100);
    assert!(kconfig(&[], Some(&format!("[Autologin]\n{broken}User=a\n"))).is_empty());
    let broken = "no equals sign\n".repeat(99);
    assert_eq!(
        kconfig(&[], Some(&format!("[Autologin]\n{broken}User=a\n"))),
        names(&["a"])
    );
    // A key that is all brackets, or none at all, is no error.
    let empty = "=x\n".repeat(150);
    assert_eq!(
        kconfig(&[], Some(&format!("[Autologin]\n{empty}User=a\n"))),
        names(&["a"])
    );
}

#[test]
fn kconfig_takes_whitespace_as_qt_trims_it() {
    assert_eq!(
        kconfig(&[], Some("\u{b}[Autologin]\u{b}\r\n\tUser\t=\u{c}a\u{b}\n")),
        names(&["a"])
    );
}

// --- LightDM ---

const LIGHTDM_SHARE: &str = "/usr/share/lightdm/lightdm.conf.d";
const LIGHTDM_LOCAL_SHARE: &str = "/usr/local/share/lightdm/lightdm.conf.d";
const LIGHTDM_XDG: &str = "/etc/xdg/lightdm/lightdm.conf.d";
const LIGHTDM_ETC: &str = "/etc/lightdm/lightdm.conf.d";
const LIGHTDM_MAIN: &str = "/etc/lightdm/lightdm.conf";

fn seat(user: &str) -> String {
    format!("[Seat:*]\nautologin-user={user}\n")
}

#[test]
fn lightdm_reads_its_directories_in_order_and_its_main_file_last() {
    let fs = MockFilesystem::new();
    for (dir, user) in [
        (LIGHTDM_SHARE, "share"),
        (LIGHTDM_LOCAL_SHARE, "local-share"),
        (LIGHTDM_XDG, "xdg"),
        (LIGHTDM_ETC, "etc"),
    ] {
        drop_in(&fs, dir, "50-autologin.conf", &seat(user));
        assert_eq!(accounts_of(&fs), names(&[user]), "{dir}");
    }
    assert_eq!(one(&fs, LIGHTDM_MAIN, &seat("main")), names(&["main"]));
    assert!(one(&fs, LIGHTDM_MAIN, &seat("")).is_empty());
}

#[test]
fn lightdm_reads_conf_files_sorted_by_name_hidden_ones_too() {
    let fs = MockFilesystem::new();
    drop_in(&fs, LIGHTDM_ETC, "50-b.conf", &seat("b"));
    drop_in(&fs, LIGHTDM_ETC, "10-a.conf", &seat("a"));
    assert_eq!(accounts_of(&fs), names(&["b"]));
    drop_in(&fs, LIGHTDM_ETC, "60-c.conf.bak", &seat("backup"));
    assert_eq!(accounts_of(&fs), names(&["b"]));

    let fs = MockFilesystem::new();
    drop_in(&fs, LIGHTDM_ETC, ".hidden.conf", &seat("hidden"));
    assert_eq!(accounts_of(&fs), names(&["hidden"]));
}

#[test]
fn lightdm_reads_seat_defaults_as_the_default_seat() {
    let fs = MockFilesystem::new();
    let text = "[SeatDefaults]\nautologin-user=old\n";
    assert_eq!(one(&fs, LIGHTDM_MAIN, text), names(&["old"]));
    // Both name one group: the later key wins.
    let text = "[Seat:*]\nautologin-user=new\n[SeatDefaults]\nautologin-user=old\n";
    assert_eq!(one(&fs, LIGHTDM_MAIN, text), names(&["old"]));
}

#[test]
fn lightdm_applies_the_seat_groups_that_match_the_first_seat() {
    let fs = MockFilesystem::new();
    // The default group first, whatever the order in the file.
    let text = "[Seat:seat0]\nautologin-user=seat\n[Seat:*]\nautologin-user=default\n";
    assert_eq!(one(&fs, LIGHTDM_MAIN, text), names(&["seat"]));
    let text = "[Seat:*]\nautologin-user=default\n[Seat:seat0]\nautologin-user=\n";
    assert!(one(&fs, LIGHTDM_MAIN, text).is_empty());
    for (pattern, applies) in [
        ("seat0", true),
        ("seat*", true),
        ("s?at0", true),
        ("*0", true),
        ("seat1", false),
        ("seat?*1", false),
        ("", false),
    ] {
        let text =
            format!("[Seat:*]\nautologin-user=default\n[Seat:{pattern}]\nautologin-user=seat\n");
        let expected = if applies { "seat" } else { "default" };
        assert_eq!(
            one(&fs, LIGHTDM_MAIN, &text),
            names(&[expected]),
            "{pattern:?}"
        );
    }
    // The groups apply in the order they first appear across the files.
    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        LIGHTDM_ETC,
        "10-a.conf",
        "[Seat:seat*]\nautologin-user=pattern\n",
    );
    let text = "[Seat:seat0]\nautologin-user=exact\n[Seat:seat*]\nautologin-user=pattern2\n";
    assert_eq!(one(&fs, LIGHTDM_MAIN, text), names(&["exact"]));
}

#[test]
fn lightdm_reads_autologin_user_in_seat_groups_only() {
    let fs = MockFilesystem::new();
    let text = "[LightDM]\nautologin-user=x\n[XDMCPServer]\nautologin-user=y\n";
    assert!(one(&fs, LIGHTDM_MAIN, text).is_empty());
}

#[test]
fn lightdm_skips_a_drop_in_glib_refuses_and_does_not_start_on_such_a_main_file() {
    let fs = MockFilesystem::new();
    drop_in(&fs, LIGHTDM_ETC, "10-a.conf", &seat("a"));
    drop_in(
        &fs,
        LIGHTDM_ETC,
        "20-b.conf",
        &format!("{}broken line\n", seat("b")),
    );
    assert_eq!(accounts_of(&fs), names(&["a"]));
    assert!(one(&fs, LIGHTDM_MAIN, "[LightDM]\nbroken line\n").is_empty());
}

#[test]
fn lightdm_reads_the_value_as_glib_does() {
    let fs = MockFilesystem::new();
    let text = "[Seat:*]\nautologin-user = \\sbob\\t # mine\n";
    assert_eq!(one(&fs, LIGHTDM_MAIN, text), names(&["bob\t # mine"]));
    // GLib refuses an unknown escape: no account.
    assert!(one(&fs, LIGHTDM_MAIN, &seat("bob\\q")).is_empty());
    assert!(one(&fs, LIGHTDM_MAIN, &seat("bob\\")).is_empty());
}

// --- What is read ---

#[test]
fn only_regular_files_are_read() {
    let fs = MockFilesystem::new();
    for (dir, text) in [
        (SDDM_LOCAL, "[Autologin]\nUser=sddm\n"),
        (PLASMA_LOCAL, "[Autologin]\nUser=plasma\n"),
        (LIGHTDM_ETC, "[Seat:*]\nautologin-user=lightdm\n"),
    ] {
        drop_in(&fs, dir, "50-entry.conf", text);
        fs.mock_set_path_type(&format!("{dir}/50-entry.conf"), PathKind::Dir);
    }
    for (path, text) in [
        (
            "/etc/gdm/custom.conf",
            "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=gdm\n",
        ),
        ("/etc/sddm.conf", "[Autologin]\nUser=sddm-main\n"),
        (PLASMA_MAIN, "[Autologin]\nUser=plasma-main\n"),
        (LIGHTDM_MAIN, "[Seat:*]\nautologin-user=lightdm-main\n"),
    ] {
        fs.mock_set_file_content(path, text);
        fs.mock_set_path_type(path, PathKind::Dir);
    }
    assert!(accounts_of(&fs).is_empty());
}

#[test]
fn a_fifo_or_a_device_is_never_opened() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("10-file.conf"), "[Autologin]\nUser=a\n").unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        dir.path().join("20-fifo.conf"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    std::os::unix::fs::symlink("/dev/zero", dir.path().join("30-device.conf")).unwrap();
    std::os::unix::fs::symlink("10-file.conf", dir.path().join("40-link.conf")).unwrap();
    // Opened, the FIFO would block the read until a writer came along.
    let listed = files(&RealFilesystem, dir.path(), |_| true);
    assert_eq!(
        listed,
        vec![
            dir.path().join("10-file.conf"),
            dir.path().join("40-link.conf")
        ]
    );
    assert_eq!(
        file_text(&RealFilesystem, &dir.path().join("20-fifo.conf")),
        None
    );
    assert_eq!(file_text(&RealFilesystem, Path::new("/dev/zero")), None);
}

// --- GLib's key-file reader ---

fn loads(text: &str) -> bool {
    keyfile::parse(text).complete
}

#[test]
fn keyfile_takes_comments_whitespace_and_line_ends_as_glib_does() {
    let parsed = keyfile::parse("  # c\n\n \t\n[g]  \t\r\n  key \t= \tvalue \r\r\n");
    assert!(parsed.complete);
    assert_eq!(parsed.file.value("g", "key"), Some("value \r"));
    assert_eq!(parsed.file.value("g", "other"), None);
    assert_eq!(parsed.file.value("h", "key"), None);
    // A last line without a newline keeps its carriage return.
    assert!(!loads("[g]\r"));
    assert!(loads("[g]\r\n"));
}

#[test]
fn keyfile_refuses_what_glib_refuses() {
    for text in [
        "key=value\n",
        "[g]\nno equals sign\n",
        "[g]\n=value\n",
        "[]\n",
        "[a[b]\n",
        "[a\u{7}]\n",
        "[g] junk\n",
        "[g]\nkey [de]=v\n",
        "[g]\nkey]=v\n",
        "[g]\nkey[d e]=v\n",
        "[g]\nkey[de]x=v\n",
        "[g]\nEncoding=latin1\n",
        "[g]\nEncoding=UTF-8 \n",
    ] {
        assert!(!loads(text), "{text:?}");
    }
    for text in [
        "[g]\nkey with spaces=v\n",
        "[g]\nkey[de_DE.UTF-8@euro]=v\n",
        "[g]\nkey[]=v\n",
        "[g]\nEncoding=utf-8\n",
        "[g]\n[h]\nEncoding=latin1\n",
        "[a b]\n",
    ] {
        assert!(loads(text), "{text:?}");
    }
}

#[test]
fn keyfile_unescapes_as_glib_does() {
    assert_eq!(
        keyfile::unescape("a\\sb\\tc\\nd\\re\\\\f").as_deref(),
        Some("a b\tc\nd\re\\f")
    );
    assert_eq!(
        keyfile::unescape("# not a comment").as_deref(),
        Some("# not a comment")
    );
    assert_eq!(keyfile::unescape("a\\x"), None);
    assert_eq!(keyfile::unescape("a\\"), None);
}

#[test]
fn glob_matches_as_glib_does() {
    for (pattern, text, matches) in [
        ("seat0", "seat0", true),
        ("*", "seat0", true),
        ("**", "", true),
        ("s*t0", "seat0", true),
        ("s*0*", "seat0", true),
        ("?eat?", "seat0", true),
        ("*a*a*", "seat0", false),
        ("seat", "seat0", false),
        ("seat00", "seat0", false),
        ("", "seat0", false),
        ("?", "", false),
    ] {
        assert_eq!(glob_matches(pattern, text), matches, "{pattern:?} {text:?}");
    }
}
