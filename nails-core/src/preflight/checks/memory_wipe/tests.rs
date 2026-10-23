// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::RealFilesystem;
use std::path::Path;

/// The spellings of Linux 6.16 and later, which read `enable`/`disable`.
const CURRENT: BoolSpellings = BoolSpellings::EnableDisable;

/// The spellings of Linux 6.15 and earlier.
const CLASSIC: BoolSpellings = BoolSpellings::Classic;

/// A kernel config as a kernel build compresses it for `/proc/config.gz`
/// (`gzip -n -9`): `# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set` and
/// `CONFIG_PAGE_POISONING=y`, as the NixOS kernel is configured.
const CONFIG_GZ: &[u8] = include_bytes!("fixtures/config.gz");

#[test]
fn classifies_the_parameter() {
    assert_eq!(parse_init_on_free("quiet", CURRENT), InitOnFree::Unset);
    assert_eq!(parse_init_on_free("", CURRENT), InitOnFree::Unset);
    assert_eq!(
        parse_init_on_free("BOOT_IMAGE=/vmlinuz init_on_free=1 quiet\n", CURRENT),
        InitOnFree::Enabled
    );
    assert_eq!(
        parse_init_on_free("init_on_free=on", CURRENT),
        InitOnFree::Enabled
    );
    assert_eq!(
        parse_init_on_free("init-on-free=Y", CURRENT),
        InitOnFree::Enabled
    );
    assert_eq!(
        parse_init_on_free("init_on_free", CURRENT),
        InitOnFree::Unset
    );
    assert_eq!(
        parse_init_on_free("init_on_free=maybe", CURRENT),
        InitOnFree::Unset
    );
    assert_eq!(
        parse_init_on_free("init_on_free=1 init_on_free=bogus", CURRENT),
        InitOnFree::Enabled
    );
    assert_eq!(
        parse_init_on_free("init_on_free=0", CURRENT),
        InitOnFree::Disabled
    );
    assert_eq!(
        parse_init_on_free("init_on_free=off", CURRENT),
        InitOnFree::Disabled
    );
}

#[test]
fn enable_and_disable_count_where_the_kernel_reads_them() {
    // Linux 6.16 and later read `enable` and `disable` (and their first
    // letters) as kstrtobool values, so the kernel applies them.
    for (cmdline, state) in [
        ("init_on_free=disable", InitOnFree::Disabled),
        ("init_on_free=D", InitOnFree::Disabled),
        ("init_on_free=enable", InitOnFree::Enabled),
        ("init_on_free=1 init_on_free=disabled", InitOnFree::Disabled),
        ("init_on_free=0 init_on_free=e", InitOnFree::Enabled),
    ] {
        assert_eq!(parse_init_on_free(cmdline, CURRENT), state, "{cmdline}");
    }
    // An older kernel rejects them and keeps what came before.
    for (cmdline, state) in [
        ("init_on_free=disable", InitOnFree::Unset),
        ("init_on_free=enable", InitOnFree::Unset),
        ("init_on_free=1 init_on_free=disabled", InitOnFree::Enabled),
        ("init_on_free=0 init_on_free=e", InitOnFree::Disabled),
    ] {
        assert_eq!(parse_init_on_free(cmdline, CLASSIC), state, "{cmdline}");
    }
}

#[test]
fn the_last_occurrence_wins() {
    assert_eq!(
        parse_init_on_free("init_on_free=1 init_on_free=0", CURRENT),
        InitOnFree::Disabled
    );
    assert_eq!(
        parse_init_on_free("init_on_free=0 init_on_free=1", CURRENT),
        InitOnFree::Enabled
    );
}

#[test]
fn init_arguments_after_double_dash_are_ignored() {
    assert_eq!(
        parse_init_on_free("quiet -- init_on_free=1", CURRENT),
        InitOnFree::Unset
    );
}

#[test]
fn a_similar_parameter_does_not_count() {
    assert_eq!(
        parse_init_on_free("init_on_alloc=1", CURRENT),
        InitOnFree::Unset
    );
    assert_eq!(
        parse_init_on_free("xinit_on_free=1", CURRENT),
        InitOnFree::Unset
    );
}

/// The `init_on_free` default a config text sets.
fn default_in(config: &str) -> Option<bool> {
    KernelConfig::parse(config).init_on_free_default
}

#[test]
fn config_default_is_read_from_the_kernel_config() {
    assert_eq!(default_in("CONFIG_INIT_ON_FREE_DEFAULT_ON=y\n"), Some(true));
    assert_eq!(
        default_in("# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set\n"),
        Some(false)
    );
    assert_eq!(
        default_in("CONFIG_INIT_ON_FREE_DEFAULT_ON=n\n"),
        Some(false)
    );
    // A different, similarly named symbol does not decide it.
    assert_eq!(default_in("CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y\n"), None);
    assert_eq!(default_in("CONFIG_FOO=y\n"), None);
}

#[test]
fn a_comment_that_is_not_the_disabled_form_leaves_it_unknown() {
    // The disabled default is recognised only from the exact form
    // `# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set`. A line with only some of
    // it says nothing about init_on_free and must leave the answer unknown
    // (`None`); otherwise the check would warn on a kernel whose default it has
    // not actually determined.

    // A *different* symbol being "not set": common in real configs right
    // beside the real line.
    assert_eq!(
        default_in("# CONFIG_INIT_ON_ALLOC_DEFAULT_ON is not set\n"),
        None
    );
    // This symbol named in a comment that is not the "is not set" form.
    assert_eq!(
        default_in("# CONFIG_INIT_ON_FREE_DEFAULT_ON: see docs\n"),
        None
    );
    // An ordinary generated-config header comment, mentioning neither.
    assert_eq!(
        default_in("# Automatically generated file; DO NOT EDIT\n"),
        None
    );
}

#[test]
fn page_poisoning_is_read_from_its_own_symbol_only() {
    let poisoning = |config| KernelConfig::parse(config).page_poisoning;
    assert_eq!(poisoning("CONFIG_PAGE_POISONING=y\n"), Some(true));
    assert_eq!(
        poisoning("# CONFIG_PAGE_POISONING is not set\n"),
        Some(false)
    );
    // Symbols whose names start the same are others, set or not.
    assert_eq!(
        poisoning("# CONFIG_PAGE_POISONING_ZERO is not set\nCONFIG_PAGE_POISONING_NO_SANITY=y\n"),
        None
    );
}

fn write(dir: &Path, rel: &str, content: impl AsRef<[u8]>) {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

/// A decoy kernel for the check to read: what each source holds, nothing
/// where a field is `None`.
#[derive(Default)]
struct Decoy<'a> {
    cmdline: Option<&'a str>,
    release: Option<&'a str>,
    proc_config_gz: Option<&'a [u8]>,
    boot_config: Option<&'a str>,
    modules_config: Option<&'a str>,
    ram_wipe: bool,
}

impl Decoy<'_> {
    /// Run the check over a tmpdir that holds this decoy's sources.
    fn check(&self) -> CheckResult {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        if let Some(cmdline) = self.cmdline {
            write(root, "cmdline", cmdline);
        }
        if let Some(release) = self.release {
            write(root, "osrelease", format!("{release}\n"));
        }
        if let Some(compressed) = self.proc_config_gz {
            write(root, "config.gz", compressed);
        }
        let release = self.release.unwrap_or("unknown");
        if let Some(config) = self.boot_config {
            write(root, &format!("boot/config-{release}"), config);
        }
        if let Some(config) = self.modules_config {
            write(root, &format!("modules/{release}/config"), config);
        }
        if self.ram_wipe {
            std::fs::create_dir_all(root.join("dracut-modules.d/40ram-wipe")).unwrap();
        }
        let check = MemoryWipeCheck {
            cmdline_path: root.join("cmdline"),
            osrelease_path: root.join("osrelease"),
            config: ConfigSources {
                proc_config: root.join("config.gz"),
                boot_dir: root.join("boot"),
                modules_dir: root.join("modules"),
            },
            dracut_modules_dir: root.join("dracut-modules.d"),
        };
        check.run(&RealFilesystem).unwrap()
    }
}

/// Run the check over the command line, the booted kernel's `/boot` config
/// (for release `test-kernel`) and a dracut RAM-wipe module, as asked.
fn run_with(cmdline: Option<&str>, config: Option<&str>, ram_wipe: bool) -> CheckResult {
    Decoy {
        cmdline,
        release: config.map(|_| "test-kernel"),
        boot_config: config,
        ram_wipe,
        ..Decoy::default()
    }
    .check()
}

#[test]
fn the_command_line_enabling_it_passes() {
    let result = run_with(Some("root=/dev/sda1 init_on_free=1\n"), None, false);
    assert!(result.is_pass(), "{}", result.message());
    assert!(
        result.message().contains("zeroes freed memory"),
        "{}",
        result.message()
    );
}

#[test]
fn the_command_line_disabling_it_warns() {
    let result = run_with(Some("init_on_free=0\n"), None, false);
    assert!(result.is_warn(), "{}", result.message());
    assert!(
        result.message().contains("does not zero freed memory"),
        "{}",
        result.message()
    );
    assert!(
        result.message().contains("init_on_free=1"),
        "a fix is named"
    );
}

#[test]
fn the_kernel_config_decides_when_the_command_line_is_silent() {
    let on = run_with(
        Some("quiet\n"),
        Some("CONFIG_INIT_ON_FREE_DEFAULT_ON=y\n"),
        false,
    );
    assert!(on.is_pass(), "{}", on.message());

    let off = run_with(
        Some("quiet\n"),
        Some("# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set\n"),
        false,
    );
    assert!(off.is_warn(), "{}", off.message());
}

#[test]
fn the_command_line_overrides_the_kernel_config() {
    // init_on_free=1 wins over a config default of off.
    let forced_on = run_with(
        Some("init_on_free=1\n"),
        Some("# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set\n"),
        false,
    );
    assert!(forced_on.is_pass(), "{}", forced_on.message());
    // init_on_free=0 wins over a config default of on.
    let forced_off = run_with(
        Some("init_on_free=0\n"),
        Some("CONFIG_INIT_ON_FREE_DEFAULT_ON=y\n"),
        false,
    );
    assert!(forced_off.is_warn(), "{}", forced_off.message());
}

#[test]
fn the_booted_release_decides_whether_disable_counts() {
    // On a 6.12 kernel `init_on_free=disable` is rejected, so the built-in
    // default stays on; from 6.16 it turns init_on_free off.
    let decoy = |release| Decoy {
        cmdline: Some("init_on_free=disable\n"),
        release: Some(release),
        boot_config: Some("CONFIG_INIT_ON_FREE_DEFAULT_ON=y\n"),
        ..Decoy::default()
    };
    let older = decoy("6.12.48+deb13-amd64").check();
    assert!(older.is_pass(), "{}", older.message());
    let current = decoy("6.16.3-arch1-1").check();
    assert!(current.is_warn(), "{}", current.message());
    assert!(
        current.message().contains("does not zero freed memory"),
        "{}",
        current.message()
    );
}

#[test]
fn page_poisoning_turns_init_on_free_off() {
    // With CONFIG_PAGE_POISONING built in, page_poison=1 takes precedence over
    // init_on_free, whether the command line or the config turns it on.
    for (cmdline, config) in [
        (
            "init_on_free=1 page_poison=1\n",
            "CONFIG_PAGE_POISONING=y\n# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set\n",
        ),
        (
            "page_poison=on\n",
            "CONFIG_PAGE_POISONING=y\nCONFIG_INIT_ON_FREE_DEFAULT_ON=y\n",
        ),
    ] {
        let result = run_with(Some(cmdline), Some(config), false);
        assert!(result.is_warn(), "{cmdline}: {}", result.message());
        let message = result.message();
        assert!(message.contains("page poisoning"), "{message}");
        assert!(message.contains("slab objects"), "{message}");
        // The fix rides on the warning, after the finding.
        assert!(
            message.contains("Remove page_poison from the decoy kernel command line"),
            "{message}"
        );
    }
}

#[test]
fn page_poisoning_counts_only_where_the_kernel_honours_it() {
    // A kernel without CONFIG_PAGE_POISONING does not know page_poison= and
    // leaves it to init, so init_on_free stays on.
    let unbuilt = run_with(
        Some("init_on_free=1 page_poison=1\n"),
        Some("# CONFIG_PAGE_POISONING is not set\n"),
        false,
    );
    assert!(unbuilt.is_pass(), "{}", unbuilt.message());
    // Poisoning turned off, last: init_on_free decides.
    let off = run_with(
        Some("init_on_free=1 page_poison=1 page_poison=0\n"),
        Some("CONFIG_PAGE_POISONING=y\n"),
        false,
    );
    assert!(off.is_pass(), "{}", off.message());
    // Without a config the kernel may have it: the reading that does not
    // overstate what is wiped.
    let unknown = run_with(Some("init_on_free=1 page_poison=1\n"), None, false);
    assert!(unknown.is_warn(), "{}", unknown.message());
}

#[test]
fn the_running_kernels_own_config_is_read_first() {
    // NixOS installs no config on disk; its kernel has /proc/config.gz, which
    // leaves init_on_free off by default.
    let nixos = Decoy {
        cmdline: Some("init=/nix/var/nix/profiles/system/init loglevel=4\n"),
        release: Some("6.12.48"),
        proc_config_gz: Some(CONFIG_GZ),
        ..Decoy::default()
    }
    .check();
    assert!(nixos.is_warn(), "{}", nixos.message());
    assert!(
        nixos.message().contains("does not zero freed memory"),
        "{}",
        nixos.message()
    );
    // It is the running kernel's own copy, so it wins over a file on disk.
    let both = Decoy {
        cmdline: Some("quiet\n"),
        release: Some("6.12.48"),
        proc_config_gz: Some(CONFIG_GZ),
        boot_config: Some("CONFIG_INIT_ON_FREE_DEFAULT_ON=y\n"),
        ..Decoy::default()
    }
    .check();
    assert!(both.is_warn(), "{}", both.message());
}

#[test]
fn the_installed_copies_are_read_when_proc_has_none() {
    // Fedora also installs the config as /usr/lib/modules/<release>/config.
    let modules = Decoy {
        cmdline: Some("quiet\n"),
        release: Some("6.17.2-200.fc42.x86_64"),
        modules_config: Some("CONFIG_INIT_ON_FREE_DEFAULT_ON=y\n"),
        ..Decoy::default()
    }
    .check();
    assert!(modules.is_pass(), "{}", modules.message());
    // A /proc/config.gz that does not decode is passed over.
    let undecodable = Decoy {
        cmdline: Some("quiet\n"),
        release: Some("6.8.0-45-generic"),
        proc_config_gz: Some(b"not gzip"),
        boot_config: Some("# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set\n"),
        ..Decoy::default()
    }
    .check();
    assert!(undecodable.is_warn(), "{}", undecodable.message());
}

#[test]
fn without_a_readable_source_it_stays_an_informational_pass() {
    // Command line silent and no kernel config: the answer is unknown, so the
    // check stays an informational pass rather than warning on a guess.
    let silent = run_with(Some("quiet\n"), None, false);
    assert!(silent.is_pass(), "{}", silent.message());
    assert!(silent.message().contains("unknown"), "{}", silent.message());

    // Nothing readable at all.
    let nothing = run_with(None, None, false);
    assert!(nothing.is_pass(), "{}", nothing.message());
}

#[test]
fn a_ram_wipe_module_is_noted() {
    let result = run_with(Some("init_on_free=0\n"), None, true);
    assert!(result.is_warn(), "{}", result.message());
    assert!(
        result.message().contains("RAM-wipe mechanism"),
        "{}",
        result.message()
    );
}

#[test]
fn without_a_ram_wipe_module_the_report_adds_no_note() {
    // With no dracut ram-wipe module installed, the report must not claim one
    // is: the present case is covered by `a_ram_wipe_module_is_noted`, and this
    // is its mirror. (A check that always appended the note would falsely
    // reassure the user that RAM is wiped on shutdown.)
    let result = run_with(Some("init_on_free=0\n"), None, false);
    assert!(result.is_warn(), "{}", result.message());
    assert!(
        !result.message().contains("RAM-wipe mechanism"),
        "no RAM-wipe note without the module: {}",
        result.message()
    );
}

#[test]
fn the_description_names_what_it_reports() {
    // The description is surfaced to the user, so it must be present and name
    // its subject rather than be blank or a placeholder.
    let check = MemoryWipeCheck::new();
    let description = PreFlightCheck::<RealFilesystem>::description(&check);
    assert!(!description.is_empty(), "{description:?}");
    assert!(description.contains("freed memory"), "{description:?}");
}
