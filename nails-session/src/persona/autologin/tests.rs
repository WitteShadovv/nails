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
fn gdm_counts_what_glib_holds_before_a_key_it_may_refuse_and_after() {
    let fs = MockFilesystem::new();
    // GLib's own Unicode tables decide whether the circled letter is one:
    // when it is not, GLib stops at that line and GDM logs bob in.
    let text = "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=bob\nX[\u{24d0}]=1\n\
                AutomaticLoginEnable=false\n";
    assert_eq!(one(&fs, "/etc/gdm/custom.conf", text), names(&["bob"]));
    // And when it is, GLib reads on.
    let text = "[daemon]\nX[\u{e9}]=1\nAutomaticLoginEnable=true\nAutomaticLogin=bob\n";
    assert_eq!(one(&fs, "/etc/gdm/custom.conf", text), names(&["bob"]));
}

#[test]
fn gdm_reads_a_value_up_to_a_nul_as_glib_does() {
    let fs = MockFilesystem::new();
    let text = "[daemon]\nAutomaticLoginEnable=true\0x\nAutomaticLogin=bob\0 # set\n";
    assert_eq!(one(&fs, "/etc/gdm/custom.conf", text), names(&["bob"]));
    // A line that starts with a NUL is a comment to GLib.
    let text = "[daemon]\n\0junk\nAutomaticLoginEnable=true\nAutomaticLogin=bob\n";
    assert_eq!(one(&fs, "/etc/gdm/custom.conf", text), names(&["bob"]));
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
fn sddm_sorts_names_that_differ_in_a_digit_as_every_collation_does() {
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
    drop_in(&fs, SDDM_LOCAL, "30-off.conf", "[Autologin]\nUser=\n");
    assert!(accounts_of(&fs).is_empty());
}

#[test]
fn sddm_counts_each_order_the_collation_of_a_locale_may_give() {
    // en_US with ICU reads kde_settings.conf first (`_` before `-`), the C
    // locale reads kde-autologin.conf first: alice is logged in one way.
    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        SDDM_LOCAL,
        "kde-autologin.conf",
        "[Autologin]\nUser=alice\n",
    );
    drop_in(&fs, SDDM_LOCAL, "kde_settings.conf", "[Autologin]\nUser=\n");
    assert_eq!(accounts_of(&fs), names(&["alice"]));

    // A collation sorts autologin.conf before KDE.conf, the C locale after.
    let fs = MockFilesystem::new();
    drop_in(&fs, SDDM_LOCAL, "KDE.conf", "[Autologin]\nUser=alice\n");
    drop_in(&fs, SDDM_LOCAL, "autologin.conf", "[Autologin]\nUser=\n");
    assert_eq!(accounts_of(&fs), names(&["alice"]));
    drop_in(&fs, SDDM_LOCAL, "kiosk.conf", "[Autologin]\nUser=kiosk\n");
    assert_eq!(accounts_of(&fs), names(&["alice", "kiosk"]));

    // Whatever the drop-ins' order, the main file comes last.
    assert_eq!(
        one(&fs, "/etc/sddm.conf", "[Autologin]\nUser=main\n"),
        names(&["main"])
    );
    assert!(one(&fs, "/etc/sddm.conf", "[Autologin]\nUser=\n").is_empty());

    // Welsh takes `ng` for one letter before `n`, so 10-loging.conf comes
    // before 10-login there and alice is logged in.
    let fs = MockFilesystem::new();
    drop_in(&fs, SDDM_LOCAL, "10-login", "[Autologin]\nUser=alice\n");
    drop_in(&fs, SDDM_LOCAL, "10-loging.conf", "[Autologin]\nUser=\n");
    assert_eq!(accounts_of(&fs), names(&["alice"]));
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
    // A backup is read like any other file, after the file its name starts
    // with.
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
fn sddm_reads_a_line_with_a_nul_as_qt_5_and_qt_6_do() {
    let fs = MockFilesystem::new();
    // Qt 5 decodes the line up to the NUL, Qt 6 whole.
    let accounts = one(&fs, "/etc/sddm.conf", "[Autologin]\nUser=carol\0 # x\n");
    assert_eq!(accounts, names(&["carol", "carol\0"]));
    assert_eq!(
        sddm::autologin_user(["[Autologin]\0\nUser=carol\n"], Qt::Five),
        Some("carol".to_string())
    );
    assert_eq!(
        sddm::autologin_user(["[Autologin]\0\nUser=carol\n"], Qt::Six),
        None
    );
}

#[test]
fn sddm_takes_the_line_with_an_equals_sign_as_an_assignment() {
    // `[Autologin=x]` assigns; it opens no section.
    assert_eq!(
        sddm::autologin_user(["[Autologin]\n[Autologin=x]\nUser=carol\n"], Qt::Six),
        Some("carol".to_string())
    );
    assert_eq!(sddm::autologin_user(["[Autologin]\nUser\n"], Qt::Six), None);
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
fn plasma_login_counts_each_order_the_collation_of_a_locale_may_give() {
    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        PLASMA_LOCAL,
        "kde-autologin.conf",
        "[Autologin]\nUser=alice\n",
    );
    drop_in(
        &fs,
        PLASMA_LOCAL,
        "kde_settings.conf",
        "[Autologin]\nUser=\n",
    );
    assert_eq!(accounts_of(&fs), names(&["alice"]));

    // Through KConfig the order decides more than the last value: read
    // first, as in the C locale, a group marked immutable keeps the other
    // file's account out; read after it, as with ICU, it does not. Only
    // KConfig decodes the escape.
    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        PLASMA_LOCAL,
        "Kiosk.conf",
        "[Autologin][$i]\nSession=plasma\n",
    );
    drop_in(
        &fs,
        PLASMA_LOCAL,
        "autologin.conf",
        "[Autologin]\nUser=b\\x6fb\n",
    );
    assert_eq!(accounts_of(&fs), names(&["b\\x6fb", "bob"]));
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

#[test]
fn plasma_login_reads_the_main_file_past_a_value_only_the_defaults_hold() {
    // The drop-ins' alice is immutable in the defaults alone: the main file
    // sets the entry Plasma Login Manager reads, and bob is logged in.
    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        PLASMA_VENDOR,
        "10-a.conf",
        "[Autologin][seat0]\nUser[$d]\n[Autologin][seat0][$i]\n",
    );
    drop_in(
        &fs,
        PLASMA_LOCAL,
        "50-b.conf",
        "[Autologin][seat0]\nUser[$i]=alice\n\\=x\n",
    );
    assert_eq!(
        one(&fs, PLASMA_MAIN, "[Autologin][seat0]\nUser=bob\n"),
        names(&["bob"])
    );
}

#[test]
fn plasma_login_reads_as_kconfig_before_6_29_too() {
    // On KDE Frameworks 6.26 to 6.28 the deletion makes no entry, so bob is
    // logged in; since 6.29 it locks the key, and SDDM's parser reads no
    // `[Autologin][$i]`.
    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        PLASMA_LOCAL,
        "50-lock.conf",
        "[Autologin][$i]\nUser[$d]\nUser=bob\n",
    );
    assert_eq!(accounts_of(&fs), names(&["bob"]));

    // There the immutable group refuses the first alice and lets the last
    // one in as a new key; since 6.29 the last one changes nothing. Only
    // KConfig decodes the escape.
    let fs = MockFilesystem::new();
    drop_in(
        &fs,
        PLASMA_LOCAL,
        "10-a.conf",
        "[Autologin]\nUser[$d]\n[Autologin][$i]\n",
    );
    drop_in(
        &fs,
        PLASMA_LOCAL,
        "50-b.conf",
        "[Autologin]\nUs\\x65r=alice\n\\=x\n",
    );
    drop_in(
        &fs,
        PLASMA_LOCAL,
        "60-c.conf",
        "[Autologin]\nUs\\x65r=alice\n",
    );
    assert_eq!(accounts_of(&fs), names(&["alice"]));
}

// --- KConfig, as Plasma Login Manager reads it since 6.7 ---

/// What KConfig with the entry map of `frameworks` reads for `[Autologin]`
/// and the first seat's group from drop-ins `extras` and then the main file
/// `main`, sorted, each once.
fn kconfig_on(frameworks: Frameworks, extras: &[&str], main: Option<&str>) -> Vec<String> {
    let mut sources: Vec<kconfig::Source<'_>> = extras
        .iter()
        .map(|text| kconfig::Source { text, main: false })
        .collect();
    sources.extend(main.map(|text| kconfig::Source { text, main: true }));
    let groups = ["Autologin", "Autologin\u{1d}seat0"];
    let mut users = kconfig::users(&sources, &groups, frameworks);
    users.sort();
    users.dedup();
    users
}

/// What KConfig of KDE Frameworks 6.29 and later reads, as [`kconfig_on`].
fn kconfig(extras: &[&str], main: Option<&str>) -> Vec<String> {
    kconfig_on(Frameworks::Since6_29, extras, main)
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
fn kconfig_keeps_the_entry_of_the_defaults_apart_from_the_one_it_reads() {
    // A drop-in's deletion of a key no file set makes only the defaults'
    // entry. The immutable group then refuses the other one the drop-ins'
    // value, and once `\=x` clears the mark the main file sets it.
    let vendor = "[Autologin][seat0]\nUser[$d]\n[Autologin][seat0][$i]\n";
    for local in [
        "[Autologin][seat0]\nUser[$i]=alice\n\\=x\n",
        "[Autologin][seat0]\nUser[$i]=\n\\=x\n",
    ] {
        assert_eq!(
            kconfig(&[vendor, local], Some("[Autologin][seat0]\nUser=bob\n")),
            names(&["bob"]),
            "{local:?}"
        );
    }
    // A drop-in that leaves the defaults' entry as it was passes nothing on,
    // so alice stays out of the entry read; `[$e]` makes it another entry.
    let deleted = "[Autologin]\nUser[$d]\n[Autologin][$i]\n";
    let refused = "[Autologin]\nUser=alice\n\\=x\n";
    let again = "[Autologin]\nUser=alice\n";
    assert!(kconfig(&[deleted, refused, again], None).is_empty());
    assert_eq!(
        kconfig(&[deleted, refused, "[Autologin]\nUser[$e]=alice\n"], None),
        names(&["alice"])
    );
    // Before 6.29 the deletion made no entry and the immutable group
    // refused the first alice, so the last one is a new key.
    assert_eq!(
        kconfig_on(Frameworks::Before6_29, &[deleted, refused, again], None),
        names(&["alice"])
    );
}

#[test]
fn kconfig_before_6_29_deletes_the_entry_it_reads_and_copies_the_defaults_over_it() {
    let before = |extras: &[&str]| kconfig_on(Frameworks::Before6_29, extras, None);
    // A drop-in's `[$d]` deletes the entry read and keeps the defaults'
    // alice, which a later alice leaves as it was. Since 6.29 the deletion
    // reaches both, and the later alice comes back.
    let deleted = [
        "[Autologin]\nUser=alice\n",
        "[Autologin]\nUser[$d]\n",
        "[Autologin]\nUser=alice\n",
    ];
    assert!(before(&deleted).is_empty());
    assert_eq!(kconfig(&deleted, None), names(&["alice"]));
    // A change to the defaults' entry is copied over the entry read
    // unchecked: bob replaces a deletion marked immutable, which since 6.29
    // locks the defaults' entry first. The main file cannot replace it.
    let locked = ["[Autologin]\nUser=alice\n", "[Autologin]\nUser[$id]\n"];
    let bob = "[Autologin]\nUser=bob\n";
    assert_eq!(before(&[locked[0], locked[1], bob]), names(&["bob"]));
    assert!(kconfig(&[locked[0], locked[1], bob], None).is_empty());
    assert!(kconfig_on(Frameworks::Before6_29, &locked, Some(bob)).is_empty());
    // Deleting a key that had no entry makes nothing, so bob is a new key,
    // and the group turns immutable only once the file is read.
    let lock = ["[Autologin][$i]\nUser[$d]\nUser=bob\n"];
    assert_eq!(before(&lock), names(&["bob"]));
    assert!(kconfig(&lock, None).is_empty());
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
        names(&["any", "b", "hans"])
    );
    // Two languages, or a bracket left open, break the line.
    assert!(kconfig(&[], Some("[Autologin]\nUser[de][fr]=a\nUser[de=b\n")).is_empty());
    // en_US reads a `C` translation as its own.
    assert_eq!(
        kconfig(&[], Some("[Autologin]\nUser[Cx]=vic\n")),
        names(&["vic"])
    );
}

#[test]
fn kconfig_reads_a_translation_in_its_language_only() {
    // In German, `\[de][$i]` makes the group immutable and alice stays;
    // in any other language the main file turns autologin off.
    assert_eq!(
        kconfig(
            &["[Autologin]\nUser=alice\n\\[de][$i]=x\n"],
            Some("[Autologin]\nUser=\n")
        ),
        names(&["", "alice"])
    );
    // A bad escape in a translation counts as a broken line only in its
    // language, where it ends the file at its hundredth.
    let broken = "no equals sign\n".repeat(99);
    assert_eq!(
        kconfig(
            &["[Autologin]\nUser=alice\n"],
            Some(&format!("[Autologin]\n{broken}Session[de_DE]=\\q\nUser=\n"))
        ),
        names(&["", "alice"])
    );
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
    // A line with no key before its `=` is no error.
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

#[test]
fn kconfig_every_user_names_each_value_any_reading_could_end_with() {
    let sources = [
        kconfig::Source {
            text: "[Autologin][$i]\nUser=kiosk\n[Other]\nUser=other\n",
            main: false,
        },
        kconfig::Source {
            text: "[Autologin]\nUser[de]=hans\nUser = gus\nUser[$d]\n[broken\nUser=\n",
            main: true,
        },
    ];
    let mut users = kconfig::every_user(&sources, &["Autologin"]);
    users.sort();
    assert_eq!(users, names(&["", "gus", "hans", "kiosk"]));
}

// --- The order of a Qt display manager's drop-ins ---

#[test]
fn collation_orders_keep_only_what_every_collation_agrees_on() {
    let orders = |names: &[&str]| {
        let names: Vec<&[u8]> = names.iter().map(|name| name.as_bytes()).collect();
        collation::orders(&names, 100)
    };
    // A first difference in a digit is the same everywhere, and so is a name
    // the other goes on past with a digit, or with punctuation and then a
    // digit or letter.
    assert_eq!(orders(&["20-b.conf", "10-a.conf"]), Some(vec![vec![1, 0]]));
    assert_eq!(orders(&["a.conf.bak", "a.conf"]), Some(vec![vec![1, 0]]));
    assert_eq!(orders(&["1.conf", "1"]), Some(vec![vec![1, 0]]));
    assert_eq!(orders(&["a1", "a"]), Some(vec![vec![1, 0]]));
    // Punctuation, case and letters are not, nor is what follows a name
    // beyond ASCII. A letter past it may make one letter with its last:
    // Welsh sorts `ng` before `n`, so `ang` before `an`, and Igbo sorts `ch`
    // before `c`. Punctuation alone past it counts for nothing in Thai.
    for pair in [
        ["kde_settings.conf", "kde-autologin.conf"],
        ["KDE.conf", "autologin.conf"],
        ["a.conf", "b.conf"],
        ["1.conf", "10.conf"],
        ["a", "a\u{ad}"],
        ["an", "ang"],
        ["10-plasman", "10-plasmang.conf"],
        ["xc", "xch"],
        ["a", "a."],
        ["a.conf", "a.conf-"],
    ] {
        assert_eq!(
            orders(&pair),
            Some(vec![vec![0, 1], vec![1, 0]]),
            "{pair:?}"
        );
    }
    assert_eq!(
        orders(&["c", "b", "10", "2"]).map(|orders| orders.len()),
        Some(12)
    );
    assert_eq!(orders(&[]), Some(vec![vec![]]));
    assert_eq!(orders(&["a", "b", "c", "d", "e"]), None, "120 orders");
    // Too many files have no orders worked out, even with one order.
    let numbered: Vec<String> = (10..80).map(|i| format!("{i}.conf")).collect();
    let numbered: Vec<&str> = numbered.iter().map(String::as_str).collect();
    assert_eq!(orders(&numbered[..64]).map(|orders| orders.len()), Some(1));
    assert_eq!(orders(&numbered), None);
}

#[test]
fn collation_reads_the_directories_one_after_the_other() {
    let names = |names: &[&'static str]| -> Vec<&'static [u8]> {
        names.iter().map(|name| name.as_bytes()).collect()
    };
    let dirs = [names(&["b", "a"]), names(&["10", "2"]), names(&["y", "x"])];
    let readings = collation::reading_orders(&dirs, 100).unwrap();
    assert_eq!(readings.len(), 4);
    assert!(readings.contains(&vec![(0, 0), (0, 1), (1, 0), (1, 1), (2, 0), (2, 1)]));
    assert!(readings.contains(&vec![(0, 1), (0, 0), (1, 0), (1, 1), (2, 1), (2, 0)]));
    assert_eq!(collation::reading_orders(&dirs, 3), None);
}

#[test]
fn too_many_orders_count_every_account_the_files_name() {
    let fs = MockFilesystem::new();
    for (i, name) in ["a", "b", "c", "d", "e", "f", "g"].iter().enumerate() {
        let text = format!("[Autologin]\nUser=user{i}\n");
        drop_in(&fs, SDDM_LOCAL, &format!("{name}.conf"), &text);
        drop_in(&fs, PLASMA_LOCAL, &format!("{name}.conf"), &text);
    }
    fs.mock_set_file_content("/etc/sddm.conf", "[Autologin]\nUser=\n");
    fs.mock_set_file_content(PLASMA_MAIN, "[Autologin]\nUser=\n");
    let expected: Vec<String> = (0..7).map(|i| format!("user{i}")).collect();
    assert_eq!(accounts_of(&fs), expected);
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
    // Byte order, whatever the locale: `K` before `a`.
    drop_in(&fs, LIGHTDM_ETC, "a.conf", &seat(""));
    drop_in(&fs, LIGHTDM_ETC, "KDE.conf", &seat("kde"));
    assert!(accounts_of(&fs).is_empty());

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
fn lightdm_reads_a_file_glib_may_refuse_with_it_and_without_it() {
    // Refused, the drop-in that empties the setting is skipped and bob is
    // logged in; loaded, it turns autologin off.
    let fs = MockFilesystem::new();
    drop_in(&fs, LIGHTDM_ETC, "10-a.conf", &seat("bob"));
    drop_in(
        &fs,
        LIGHTDM_ETC,
        "20-b.conf",
        "[Seat:*]\nautologin-user=\nX[\u{24d0}]=1\n",
    );
    assert_eq!(accounts_of(&fs), names(&["bob"]));
    drop_in(
        &fs,
        LIGHTDM_ETC,
        "30-c.conf",
        "[Seat:*]\nautologin-user=carol\nY[\u{e9}]=1\n",
    );
    assert_eq!(accounts_of(&fs), names(&["bob", "carol"]));
    // A main file GLib may refuse keeps LightDM from starting, or names its
    // account.
    assert_eq!(
        one(
            &fs,
            LIGHTDM_MAIN,
            "[Seat:*]\nautologin-user=dave\nZ[\u{e9}]=1\n"
        ),
        names(&["dave"])
    );
}

#[test]
fn lightdm_with_too_many_files_glib_may_refuse_counts_every_account_they_name() {
    let fs = MockFilesystem::new();
    for i in 0..9 {
        drop_in(
            &fs,
            LIGHTDM_ETC,
            &format!("{i}.conf"),
            &format!(
                "[Seat:*]\nautologin-user=user{i}\nX[\u{e9}]=1\n[Seat:seat1]\nautologin-user=other\n"
            ),
        );
    }
    fs.mock_set_file_content(LIGHTDM_MAIN, &seat(""));
    let expected: Vec<String> = (0..9).map(|i| format!("user{i}")).collect();
    assert_eq!(accounts_of(&fs), expected);
}

#[test]
fn lightdm_reads_as_many_files_glib_may_refuse_as_its_limit_each_way() {
    // Each file GLib may load or refuse names an account, and so does each
    // file GLib always loads or always refuses, which do not count toward
    // the limit. Read each way, every reading ends with the main file's
    // account, and no other is listed.
    let fs = MockFilesystem::new();
    for i in 0..MAX_UNDECIDED_DROP_INS {
        drop_in(
            &fs,
            LIGHTDM_ETC,
            &format!("{i}-may.conf"),
            &format!("[Seat:*]\nautologin-user=may{i}\nX[\u{e9}]=1\n"),
        );
        drop_in(
            &fs,
            LIGHTDM_ETC,
            &format!("{i}-loads.conf"),
            &seat(&format!("loads{i}")),
        );
    }
    drop_in(
        &fs,
        LIGHTDM_ETC,
        "refused.conf",
        &format!("{}broken line\n", seat("refused")),
    );
    fs.mock_set_file_content(LIGHTDM_MAIN, &seat("main"));
    assert_eq!(accounts_of(&fs), names(&["main"]));
}

#[test]
fn lightdm_reads_the_value_as_glib_does() {
    let fs = MockFilesystem::new();
    let text = "[Seat:*]\nautologin-user = \\sbob\\t # mine\n";
    assert_eq!(one(&fs, LIGHTDM_MAIN, text), names(&["bob\t # mine"]));
    // GLib refuses an unknown escape: no account.
    assert!(one(&fs, LIGHTDM_MAIN, &seat("bob\\q")).is_empty());
    assert!(one(&fs, LIGHTDM_MAIN, &seat("bob\\")).is_empty());
    // A value ends at a NUL.
    assert_eq!(one(&fs, LIGHTDM_MAIN, &seat("bob\0x")), names(&["bob"]));
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
        "[g]\nkey[\u{e9} ]=v\n",
        "[g]\nkey[\u{e9}=v\n",
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
fn keyfile_keeps_both_outcomes_of_a_key_glib_judges_by_its_tables() {
    let parsed = keyfile::parse("[g]\nkey=a\nkey[\u{e9}]=x\nkey=b\nother[\u{24d0}]=y\n");
    assert!(parsed.complete);
    assert!(parsed.may_load() && parsed.may_fail());
    let values: Vec<Option<&str>> = parsed
        .outcomes()
        .map(|file| file.value("g", "key"))
        .collect();
    assert_eq!(values, vec![Some("a"), Some("b"), Some("b")]);
    // Refused for good further on, the file never loads.
    let parsed = keyfile::parse("[g]\nkey[\u{e9}]=x\nbroken\n");
    assert!(!parsed.may_load() && parsed.may_fail());
    // Keys only translations set in between hold what the last one held.
    let parsed = keyfile::parse(&format!("[g]\nkey=a\n{}", "key[\u{e9}]=x\n".repeat(1000)));
    assert_eq!(parsed.refused.len(), 1);
}

#[test]
fn keyfile_takes_a_nul_as_glib_does() {
    // A line that starts with a NUL is a comment.
    assert!(loads("[g]\n\0junk\n"));
    // Past a NUL a group line holds anything but another `]`, for the name
    // runs to the last one.
    let parsed = keyfile::parse("[g]\0junk\nkey=v\0w\n");
    assert!(parsed.complete);
    assert_eq!(parsed.file.value("g", "key"), Some("v"));
    assert!(!loads("[g]\0]\n"));
    // A NUL before the `=` leaves no key-value line, and the encoding check
    // counts the bytes past it.
    assert!(!loads("[g]\nkey\0=v\n"));
    assert!(!loads("[g]\nEncoding=UTF-8\0\n"));
    assert!(loads("[g]\nEncoding=UTF-8\n"));
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
        ("**", "seat0", true),
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
