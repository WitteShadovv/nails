// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::Filesystem;
use crate::filesystem::MockFilesystem;

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
