// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the `lsm-status` check: the verdict table row by row, the facts it
//! reads through the mock filesystem, the reading of an SELinux context, and
//! the facts the distribution probes recorded.

use super::*;
use crate::MockFilesystem;

/// Debian's and Ubuntu's list: AppArmor is the module that labels processes.
const APPARMOR_LSMS: &str = "lockdown,capability,landlock,yama,apparmor,ima,evm";
/// A list with SELinux.
const SELINUX_LSMS: &str = "lockdown,capability,yama,selinux,bpf,landlock";
/// What an unconfined login runs in under the targeted policy.
const UNCONFINED_LOGIN: &str = "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023";
/// The domain the targeted policy gives a service without a policy of its own.
const SERVICE: &str = "unconfined_service_t";
/// A mount table with selinuxfs at its usual place.
const SELINUX_MOUNTS: &str = "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n\
                              selinuxfs /sys/fs/selinux selinuxfs rw,nosuid,noexec,relatime 0 0\n";
/// A mount table without selinuxfs.
const PLAIN_MOUNTS: &str = "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n\
                            proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n";
/// When the judged hosts booted, in seconds since the epoch.
const BOOT: u64 = 1_790_000_000;
/// What `/proc/stat` shows of that boot.
const STAT: &str = "cpu  10 0 10 100 0 0 0 0 0 0\nintr 0\nctxt 0\nbtime 1790000000\nprocesses 1\n";

/// The LSM list as the kernel writes it, split.
fn lsms(list: &str) -> Vec<String> {
    list.split(',').map(str::to_string).collect()
}

/// SELinux with selinuxfs mounted, the runtime mode `enforce`, and the
/// configuration's mode and policy.
fn status(
    enforce: Option<SelinuxMode>,
    config_mode: Option<&str>,
    config_policy: Option<&str>,
) -> SelinuxStatus {
    SelinuxStatus {
        selinuxfs: Selinuxfs::Mounted,
        enforce,
        config_mode: config_mode.map(str::to_string),
        config_policy: config_policy.map(str::to_string),
    }
}

/// A host that enforces the targeted policy, configured so, where this process
/// carries `label`.
fn enforcing(label: &str) -> Facts {
    Facts {
        lsms: lsms(SELINUX_LSMS),
        selinux: Some(status(
            Some(SelinuxMode::Enforcing),
            Some("enforcing"),
            Some("targeted"),
        )),
        label: Some(label.to_string()),
        config_age: ConfigAge::Older,
    }
}

/// The processes systemd and udev start for NAILS, both in the domain a
/// backdoor-style unit gets: unconfined, so the verdict turns on the other
/// facts.
fn known_units() -> UnitDomains {
    UnitDomains {
        systemd: UnitDomain::Known(SERVICE.to_string()),
        udev: UnitDomain::Known(SERVICE.to_string()),
    }
}

/// The check's verdict on what `fs` holds.
fn run_on(fs: &MockFilesystem, units: UnitDomains) -> CheckResult {
    PreFlightCheck::<MockFilesystem>::run(&LsmStatusCheck::new(units), fs).unwrap()
}

#[test]
fn the_row_is_named_lsm_status() {
    let check = LsmStatusCheck::new(UnitDomains::UNKNOWN);
    assert_eq!(PreFlightCheck::<MockFilesystem>::name(&check), "lsm-status");
    assert!(PreFlightCheck::<MockFilesystem>::description(&check).contains("targeted"));
}

// ---------------------------------------------------------------------------
// SELinux does not run: pass, naming the active LSMs
// ---------------------------------------------------------------------------

#[test]
fn an_apparmor_host_passes_naming_its_lsms() {
    // Debian and Ubuntu: AppArmor labels processes, and the check reads its
    // label for this process, unconfined, as no SELinux context.
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(host_facts::LSM_LIST, &format!("{APPARMOR_LSMS}\n"));
    fs.mock_set_file_content(PROCESS_LABEL, "unconfined\n");
    for units in [UnitDomains::UNKNOWN, known_units()] {
        let result = run_on(&fs, units);
        assert!(result.is_pass(), "{result:?}");
        assert_eq!(
            result.message(),
            "SELinux does not run. Active LSMs: lockdown, capability, landlock, yama, \
             apparmor, ima, evm."
        );
    }
}

#[test]
fn hosts_with_landlock_yama_or_no_labelling_module_pass() {
    for list in [
        "capability",
        "capability,landlock",
        "lockdown,capability,yama",
        "lockdown,capability,landlock,yama,bpf",
        // AppArmor in complain mode is still AppArmor: no profile name reads
        // as an SELinux context.
        "capability,apparmor",
    ] {
        let fs = MockFilesystem::new();
        fs.mock_set_file_content(host_facts::LSM_LIST, list);
        fs.mock_set_file_content(PROCESS_LABEL, "/usr/bin/sudo (complain)\n");
        let result = run_on(&fs, UnitDomains::UNKNOWN);
        assert!(result.is_pass(), "{list}: {result:?}");
        assert_eq!(
            result.message(),
            format!(
                "SELinux does not run. Active LSMs: {}.",
                list.replace(',', ", ")
            )
        );
    }
}

#[test]
fn a_host_without_any_sign_of_selinux_passes_without_the_lsm_list() {
    // A kernel that shows no LSM list, no selinuxfs, no /sys/fs/selinux, no
    // configuration and no label for this process: nothing shows SELinux.
    let result = run_on(&MockFilesystem::new(), UnitDomains::UNKNOWN);
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        result.message(),
        "SELinux does not run. The kernel's list of active LSMs could not be read \
         (/sys/kernel/security/lsm)."
    );
}

#[test]
fn a_configuration_selinux_does_not_run_with_is_named_but_passes() {
    // A Debian host that once installed the SELinux packages and boots with
    // AppArmor: the kernel's list decides.
    for (config, said) in [
        (
            "SELINUX=permissive\nSELINUXTYPE=default\n",
            Some("permissive"),
        ),
        (
            "SELINUX=enforcing\nSELINUXTYPE=targeted\n",
            Some("enforcing"),
        ),
        ("SELINUX=disabled\nSELINUXTYPE=targeted\n", None),
        ("SELINUXTYPE=default\n", None),
    ] {
        let fs = MockFilesystem::new();
        fs.mock_set_file_content(host_facts::LSM_LIST, APPARMOR_LSMS);
        fs.mock_set_file_content("/proc/self/mounts", "proc /proc proc rw 0 0\n");
        fs.mock_set_file_content(SELINUX_CONFIG, config);
        let result = run_on(&fs, UnitDomains::UNKNOWN);
        assert!(result.is_pass(), "{config:?}: {result:?}");
        let lsm_list = "Active LSMs: lockdown, capability, landlock, yama, apparmor, ima, evm.";
        assert_eq!(
            result.message(),
            match said {
                Some(mode) => format!(
                    "SELinux does not run, though /etc/selinux/config sets SELINUX={mode}. \
                     {lsm_list}"
                ),
                None => format!("SELinux does not run. {lsm_list}"),
            },
            "{config:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// SELinux enforces the targeted policy and NAILS runs unconfined: pass
// ---------------------------------------------------------------------------

#[test]
fn enforcing_targeted_with_nails_unconfined_passes() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(host_facts::LSM_LIST, SELINUX_LSMS);
    fs.mock_set_file_content("/proc/self/mounts", SELINUX_MOUNTS);
    fs.mock_set_file_content(SELINUX_ENFORCE, "1");
    fs.mock_set_file_content(
        SELINUX_CONFIG,
        "# This file controls the state of SELinux on the system.\n\
         SELINUX=enforcing\nSELINUXTYPE=targeted\n",
    );
    fs.mock_set_file_content(PROCESS_LABEL, &format!("{UNCONFINED_LOGIN}\0"));
    fs.mock_set_file_content(PROC_STAT, STAT);
    fs.mock_set_change_time(
        SELINUX_CONFIG,
        UNIX_EPOCH + std::time::Duration::from_secs(BOOT - 3600),
    );
    let result = run_on(&fs, known_units());
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        result.message(),
        "SELinux enforces, /etc/selinux/config names the targeted policy and has not changed \
         since the boot, and NAILS runs unconfined: this process in unconfined_t, the \
         processes systemd starts for it in unconfined_service_t, and the disk guard udev \
         starts in unconfined_service_t. Active LSMs: lockdown, capability, yama, selinux, \
         bpf, landlock."
    );
}

#[test]
fn both_unconfined_domains_pass_for_this_process() {
    for label in [
        UNCONFINED_LOGIN,
        "system_u:system_r:unconfined_service_t:s0",
        // A context without categories, and one with a category list.
        "unconfined_u:unconfined_r:unconfined_t:s0",
        "unconfined_u:unconfined_r:unconfined_t:s0:c1,c5.c9",
    ] {
        let result = judge(&enforcing(label), &known_units());
        assert!(result.is_pass(), "{label}: {result:?}");
    }
}

// ---------------------------------------------------------------------------
// The processes systemd and udev start for NAILS
// ---------------------------------------------------------------------------

/// The finding for processes systemd starts in a domain nothing shows.
const SYSTEMD_UNKNOWN: &str = "NAILS does not choose the SELinux domain of the processes \
     systemd starts from its copy in /run (the transition step at each switch, the watcher \
     and the sleep guard of the hidden session, and the boot-record steps after the way \
     back), so nothing shows they run unconfined.";

/// The finding for a disk guard udev starts in a domain nothing shows.
const UDEV_UNKNOWN: &str = "NAILS does not choose the SELinux domain of the hidden \
     session's disk guard, which udev runs itself from the rule NAILS installs in /run, so \
     nothing shows it runs unconfined.";

/// What `units` makes of an enforcing targeted host where this process runs
/// unconfined.
fn units_verdict(systemd: UnitDomain, udev: UnitDomain) -> CheckResult {
    judge(&enforcing(UNCONFINED_LOGIN), &UnitDomains { systemd, udev })
}

#[test]
fn units_in_an_unknown_domain_fail_where_selinux_runs() {
    // What the registry gives on every host today: NAILS starts neither kind
    // in a domain it chose, so an enforcing targeted host fails too.
    let result = judge(&enforcing(UNCONFINED_LOGIN), &UnitDomains::UNKNOWN);
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        result.message(),
        format!(
            "{SYSTEMD_UNKNOWN} {UDEV_UNKNOWN} Active LSMs: lockdown, capability, yama, selinux, \
             bpf, landlock."
        )
    );
    // Either one unknown fails by itself.
    let known = UnitDomain::Known(SERVICE.to_string());
    let result = units_verdict(UnitDomain::Unknown, known.clone());
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        result.message(),
        format!(
            "{SYSTEMD_UNKNOWN} Active LSMs: lockdown, capability, yama, selinux, bpf, landlock."
        )
    );
    let result = units_verdict(known, UnitDomain::Unknown);
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        result.message(),
        format!("{UDEV_UNKNOWN} Active LSMs: lockdown, capability, yama, selinux, bpf, landlock.")
    );
}

#[test]
fn a_domain_shown_for_what_systemd_starts_does_not_stand_for_the_disk_guard() {
    // A mechanism on systemd's side that puts the units in an unconfined
    // domain does not reach the disk guard, which udev executes itself: the
    // guard is judged by what is known of it alone.
    let systemd = UnitDomain::Known(SERVICE.to_string());
    let result = units_verdict(systemd.clone(), UnitDomain::Unknown);
    assert!(result.is_fail(), "{result:?}");
    assert!(result.message().starts_with(UDEV_UNKNOWN), "{result:?}");
    assert!(!result.message().contains("systemd starts"), "{result:?}");
    // udev_t, the domain udev itself runs in, is not one NAILS counts as
    // unconfined: whether the guard may run there is for a run under the
    // policy to show, and until the check takes it, the guard fails there.
    let result = units_verdict(systemd, UnitDomain::Known("udev_t".to_string()));
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        result.message(),
        "udev starts NAILS's disk guard in the SELinux domain udev_t, not in one NAILS counts as \
         unconfined (unconfined_t, unconfined_service_t). Active LSMs: lockdown, capability, \
         yama, selinux, bpf, landlock."
    );
}

#[test]
fn units_in_a_confined_domain_fail() {
    let known = UnitDomain::Known(SERVICE.to_string());
    for domain in ["init_t", "initrc_t", "udev_t", "unconfined"] {
        let confined = UnitDomain::Known(domain.to_string());
        let result = units_verdict(confined.clone(), known.clone());
        assert!(result.is_fail(), "{domain}: {result:?}");
        assert!(
            result.message().starts_with(&format!(
                "systemd starts NAILS's processes in the SELinux domain {domain}, not in one \
                 NAILS counts as unconfined (unconfined_t, unconfined_service_t)."
            )),
            "{result:?}"
        );
        let result = units_verdict(known.clone(), confined);
        assert!(result.is_fail(), "{domain}: {result:?}");
        assert!(
            result.message().starts_with(&format!(
                "udev starts NAILS's disk guard in the SELinux domain {domain}, not in one NAILS \
                 counts as unconfined (unconfined_t, unconfined_service_t)."
            )),
            "{result:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Permissive, or a configuration that differs from the running mode: warn
// ---------------------------------------------------------------------------

#[test]
fn permissive_selinux_warns() {
    let mut facts = enforcing(UNCONFINED_LOGIN);
    facts.selinux = Some(status(
        Some(SelinuxMode::Permissive),
        Some("permissive"),
        Some("targeted"),
    ));
    let result = judge(&facts, &known_units());
    assert!(result.is_warn(), "{result:?}");
    assert_eq!(
        result.message(),
        "SELinux is permissive: it logs what its policy would deny and denies nothing. \
         Active LSMs: lockdown, capability, yama, selinux, bpf, landlock."
    );
}

#[test]
fn a_mode_that_differs_from_the_configuration_warns() {
    for (runtime, configured, said) in [
        // setenforce 0 on an enforcing host: both warnings.
        (
            SelinuxMode::Permissive,
            "enforcing",
            "SELinux is permissive: it logs what its policy would deny and denies nothing. \
             /etc/selinux/config sets SELINUX=enforcing, but SELinux runs permissive.",
        ),
        (
            SelinuxMode::Enforcing,
            "permissive",
            "/etc/selinux/config sets SELINUX=permissive, but SELinux runs enforcing.",
        ),
        // A policy loaded by hand, and set to enforce, after a boot with
        // SELINUX=disabled. A kernel told to enforce on its command line while
        // the configuration turns SELinux off does not get here: systemd stops
        // its boot ("Failed to load SELinux policy."), so no nails runs there.
        (
            SelinuxMode::Enforcing,
            "disabled",
            "/etc/selinux/config sets SELINUX=disabled, but SELinux runs enforcing.",
        ),
    ] {
        let mut facts = enforcing(UNCONFINED_LOGIN);
        facts.selinux = Some(status(Some(runtime), Some(configured), Some("targeted")));
        let result = judge(&facts, &known_units());
        assert!(result.is_warn(), "{configured}: {result:?}");
        assert_eq!(
            result.message(),
            format!("{said} Active LSMs: lockdown, capability, yama, selinux, bpf, landlock.")
        );
    }
}

// ---------------------------------------------------------------------------
// A policy other than targeted: fail, as untested
// ---------------------------------------------------------------------------

#[test]
fn a_policy_other_than_targeted_fails_as_untested() {
    // The value names a directory below /etc/selinux, so its case counts.
    for policy in ["mls", "minimum", "default", "Targeted", "targeted2", ""] {
        let mut facts = enforcing(UNCONFINED_LOGIN);
        facts.selinux = Some(status(
            Some(SelinuxMode::Enforcing),
            Some("enforcing"),
            Some(policy),
        ));
        let result = judge(&facts, &known_units());
        assert!(result.is_fail(), "{policy}: {result:?}");
        assert!(
            result.message().starts_with(&format!(
                "/etc/selinux/config names the {policy:?} policy (SELINUXTYPE=): this check \
                 takes only the targeted policy, and NAILS is untested under any other."
            )),
            "{result:?}"
        );
    }
}

#[test]
fn a_level_of_a_multi_level_policy_fails_whatever_the_configuration_names() {
    // An MLS policy put where the configuration names the targeted one.
    for label in [
        "staff_u:sysadm_r:unconfined_t:s0-s15:c0.c1023",
        "root:sysadm_r:unconfined_t:s15:c0.c1023",
        "unconfined_u:unconfined_r:unconfined_t:s2",
    ] {
        let result = judge(&enforcing(label), &known_units());
        assert!(result.is_fail(), "{label}: {result:?}");
        assert!(
            result.message().contains(
                "and Fedora's targeted policy has none but s0: SELinux runs another policy, \
                 such as a multi-level (MLS) one, and NAILS is untested under any other."
            ),
            "{result:?}"
        );
    }
    // A context without a level is no context of the targeted policy either.
    let result = judge(
        &enforcing("unconfined_u:unconfined_r:unconfined_t"),
        &known_units(),
    );
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().starts_with(
            "The SELinux context of this nails process has no level, which every context of \
             Fedora's targeted policy has: SELinux runs another policy, and NAILS is untested \
             under any other."
        ),
        "{result:?}"
    );
}

// ---------------------------------------------------------------------------
// NAILS in a confined domain: fail
// ---------------------------------------------------------------------------

#[test]
fn nails_in_a_confined_domain_fails() {
    // A confined administrator, a process systemd-run starts from a file it
    // gives no domain, and a container.
    for (label, domain) in [
        ("staff_u:sysadm_r:sysadm_t:s0-s0:c0.c1023", "sysadm_t"),
        ("staff_u:staff_r:staff_t:s0-s0:c0.c1023", "staff_t"),
        ("system_u:system_r:init_t:s0", "init_t"),
        ("system_u:system_r:container_t:s0:c12,c345", "container_t"),
    ] {
        let result = judge(&enforcing(label), &known_units());
        assert!(result.is_fail(), "{label}: {result:?}");
        assert_eq!(
            result.message(),
            format!(
                "This nails process runs in the SELinux domain {domain}, not in one NAILS counts \
                 as unconfined (unconfined_t, unconfined_service_t). Active LSMs: lockdown, \
                 capability, yama, selinux, bpf, landlock."
            )
        );
    }
}

// ---------------------------------------------------------------------------
// A fact that cannot be read where SELinux runs: fail
// ---------------------------------------------------------------------------

#[test]
fn an_unreadable_mode_fails() {
    let mut facts = enforcing(UNCONFINED_LOGIN);
    facts.selinux = Some(status(None, Some("enforcing"), Some("targeted")));
    let result = judge(&facts, &known_units());
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().starts_with(
            "SELinux runs, but whether it enforces could not be read (/sys/fs/selinux/enforce)."
        ),
        "{result:?}"
    );
}

#[test]
fn a_configuration_without_a_mode_or_a_policy_fails() {
    let mut facts = enforcing(UNCONFINED_LOGIN);
    facts.selinux = Some(status(Some(SelinuxMode::Enforcing), None, Some("targeted")));
    let result = judge(&facts, &known_units());
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().starts_with(
            "/etc/selinux/config sets no mode NAILS can read (SELINUX=), so whether SELinux \
             runs in the mode it is configured for cannot be told."
        ),
        "{result:?}"
    );

    facts.selinux = Some(status(
        Some(SelinuxMode::Enforcing),
        Some("enforcing"),
        None,
    ));
    let result = judge(&facts, &known_units());
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().starts_with(
            "/etc/selinux/config could not be read or names no policy (SELINUXTYPE=), so the \
             policy SELinux runs cannot be told."
        ),
        "{result:?}"
    );
}

#[test]
fn a_context_that_cannot_be_read_fails() {
    let mut facts = enforcing(UNCONFINED_LOGIN);
    facts.label = None;
    let result = judge(&facts, &known_units());
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().starts_with(
            "The SELinux context of this nails process could not be read \
             (/proc/self/attr/current)."
        ),
        "{result:?}"
    );

    // Labels that read as no context: another module's, and one that holds a
    // control character, shown escaped. The label of a process before any
    // policy is loaded has its own finding.
    for (label, shown) in [
        ("unconfined", "\"unconfined\""),
        ("a:b\x1b[2J", "\"a:b\\u{1b}[2J\""),
    ] {
        facts.label = Some(label.to_string());
        let result = judge(&facts, &known_units());
        assert!(result.is_fail(), "{result:?}");
        assert!(
            result.message().starts_with(&format!(
                "This nails process is labelled {shown} (/proc/self/attr/current), which does \
                 not read as an SELinux context."
            )),
            "{result:?}"
        );
    }
}

#[test]
fn selinux_in_the_lsm_list_without_selinuxfs_fails_as_unreadable() {
    // SELinux runs, as the kernel lists it, but no selinuxfs shows its mode:
    // a container, or a system that did not mount it.
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(host_facts::LSM_LIST, SELINUX_LSMS);
    fs.mock_set_file_content("/proc/self/mounts", "proc /proc proc rw 0 0\n");
    fs.mock_set_file_content(PROCESS_LABEL, "system_u:system_r:container_t:s0:c1,c2\0");
    let result = run_on(&fs, known_units());
    assert!(result.is_fail(), "{result:?}");
    let message = result.message();
    for finding in [
        "SELinux runs, but whether it enforces could not be read (/sys/fs/selinux/enforce).",
        "/etc/selinux/config sets no mode NAILS can read (SELINUX=)",
        "/etc/selinux/config could not be read or names no policy (SELINUXTYPE=)",
        "This nails process runs in the SELinux domain container_t",
    ] {
        assert!(message.contains(finding), "{finding}: {message}");
    }
}

#[test]
fn a_selinux_context_runs_selinux_where_the_lsm_list_cannot_be_read() {
    // A container that shows neither the LSM list nor selinuxfs, while the
    // kernel labels its processes.
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(PROCESS_LABEL, "system_u:system_r:container_t:s0:c1,c2\0");
    let result = run_on(&fs, UnitDomains::UNKNOWN);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().ends_with(
            "The kernel's list of active LSMs could not be read (/sys/kernel/security/lsm)."
        ),
        "{result:?}"
    );
    assert!(result.message().contains("container_t"), "{result:?}");
}

#[test]
fn a_mounted_selinuxfs_runs_selinux_whatever_the_lsm_list_says() {
    let mut facts = enforcing(UNCONFINED_LOGIN);
    facts.lsms = lsms(APPARMOR_LSMS);
    let result = judge(&facts, &known_units());
    assert!(result.is_pass(), "{result:?}");
    assert!(
        result.message().starts_with("SELinux enforces"),
        "{result:?}"
    );
}

#[test]
fn selinux_that_cannot_be_ruled_out_without_the_lsm_list_fails() {
    for (selinux, why) in [
        (
            SelinuxStatus {
                selinuxfs: Selinuxfs::NotMounted,
                enforce: None,
                config_mode: Some("enforcing".to_string()),
                config_policy: Some("targeted".to_string()),
            },
            "no selinuxfs is mounted, and /etc/selinux/config sets SELINUX=enforcing",
        ),
        (
            SelinuxStatus {
                selinuxfs: Selinuxfs::Unknown,
                enforce: None,
                config_mode: None,
                config_policy: None,
            },
            "neither could the mount table (/proc/self/mounts), and /sys/fs/selinux is there or cannot be looked up",
        ),
        (
            SelinuxStatus {
                selinuxfs: Selinuxfs::NotMounted,
                enforce: None,
                config_mode: None,
                config_policy: Some("mls".to_string()),
            },
            "no selinuxfs is mounted, and /etc/selinux/config names the \"mls\" policy",
        ),
    ] {
        let facts = Facts {
            lsms: Vec::new(),
            selinux: Some(selinux),
            label: None,
            config_age: ConfigAge::Older,
        };
        let result = judge(&facts, &known_units());
        assert!(result.is_fail(), "{result:?}");
        assert_eq!(
            result.message(),
            format!(
                "Cannot tell whether SELinux runs: the kernel's list of active LSMs could not \
                 be read (/sys/kernel/security/lsm), {why}."
            )
        );
    }
}

#[test]
fn every_finding_is_listed_failures_first() {
    let facts = Facts {
        lsms: lsms(SELINUX_LSMS),
        selinux: Some(status(
            Some(SelinuxMode::Permissive),
            Some("enforcing"),
            Some("mls"),
        )),
        label: Some("staff_u:sysadm_r:sysadm_t:s0-s15:c0.c1023".to_string()),
        config_age: ConfigAge::Changed,
    };
    let result = judge(&facts, &UnitDomains::UNKNOWN);
    assert!(result.is_fail(), "{result:?}");
    let message = result.message();
    let order = [
        "/etc/selinux/config names the \"mls\" policy",
        "runs at the sensitivity s15",
        "runs in the SELinux domain sysadm_t",
        "NAILS does not choose the SELinux domain of the processes systemd starts",
        "NAILS does not choose the SELinux domain of the hidden session's disk guard",
        "SELinux is permissive",
        "/etc/selinux/config sets SELINUX=enforcing, but SELinux runs permissive.",
        "Active LSMs:",
    ];
    let at: Vec<usize> = order
        .iter()
        .map(|part| {
            message
                .find(part)
                .unwrap_or_else(|| panic!("{part}: {message}"))
        })
        .collect();
    assert!(at.windows(2).all(|pair| pair[0] < pair[1]), "{message}");
    // A configuration that changed since the boot adds nothing to the failure
    // of a policy it names that is not targeted.
    assert!(!message.contains("after this boot"), "{message}");
}

// ---------------------------------------------------------------------------
// SELinux on in the kernel without a policy: fail, with the remedy
// ---------------------------------------------------------------------------

/// The host a kernel that started SELinux leaves where `/etc/selinux/config`
/// sets `SELINUX=disabled`: libselinux loads no policy and unmounts
/// selinuxfs, so only the empty mount point is left, and every process is
/// labelled `kernel`.
fn unloaded_host(config: &str) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(
        host_facts::LSM_LIST,
        "lockdown,capability,landlock,yama,selinux,bpf,ipe,ima,evm",
    );
    fs.mock_set_path_type("/sys/fs/selinux", crate::filesystem::PathKind::Dir);
    fs.mock_set_file_content("/proc/self/mounts", PLAIN_MOUNTS);
    fs.mock_set_file_content(SELINUX_CONFIG, config);
    fs.mock_set_file_content(PROCESS_LABEL, "kernel\0");
    fs.mock_set_file_content(PROC_STAT, STAT);
    fs
}

#[test]
fn selinux_on_without_a_policy_fails_with_its_own_finding_and_the_remedy() {
    let fs = unloaded_host("SELINUX=disabled\nSELINUXTYPE=targeted\n");
    // The domain of NAILS's units means nothing without a policy: the
    // verdict is the same whatever the registry knows of it.
    for units in [UnitDomains::UNKNOWN, known_units()] {
        let result = run_on(&fs, units);
        assert!(result.is_fail(), "{result:?}");
        assert_eq!(
            result.message(),
            "SELinux is on in this kernel, but no policy is loaded: this nails process is \
             labelled \"kernel\" (/proc/self/attr/current), as SELinux labels every process \
             until a policy is loaded. /etc/selinux/config sets SELINUX=disabled, which kept a \
             policy from loading but left SELinux on in this kernel. NAILS is untested on such \
             a host. Active LSMs: lockdown, capability, landlock, yama, selinux, bpf, ipe, ima, \
             evm."
        );
        assert_eq!(
            result.remediation(),
            Some("Start the kernel with SELinux off: add selinux=0 to the kernel command line.")
        );
    }
    // Debian's policy, named where its packages set SELinux up: the same.
    let result = run_on(
        &unloaded_host("SELINUX=disabled\nSELINUXTYPE=default\n"),
        UnitDomains::UNKNOWN,
    );
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .starts_with("SELinux is on in this kernel, but no policy is loaded"),
        "{result:?}"
    );
    assert!(!result.message().contains("default"), "{result:?}");
}

#[test]
fn a_policy_that_did_not_load_is_named_without_the_disabled_cause() {
    // selinuxfs mounted and a configuration that sets another mode: a policy
    // that failed to load leaves the kernel so too. The label alone decides,
    // also where the kernel's list cannot be read.
    for list in [Some(SELINUX_LSMS), None] {
        let mut facts = enforcing("kernel");
        facts.selinux = Some(status(
            Some(SelinuxMode::Permissive),
            Some("permissive"),
            Some("targeted"),
        ));
        if list.is_none() {
            facts.lsms = Vec::new();
        }
        let result = judge(&facts, &known_units());
        assert!(result.is_fail(), "{list:?}: {result:?}");
        assert!(
            result.message().starts_with(
                "SELinux is on in this kernel, but no policy is loaded: this nails process is \
                 labelled \"kernel\" (/proc/self/attr/current), as SELinux labels every \
                 process until a policy is loaded. NAILS is untested on such a host."
            ),
            "{result:?}"
        );
        assert!(!result.message().contains("SELINUX="), "{result:?}");
        assert!(result.remediation().is_some(), "{result:?}");
    }
}

#[test]
fn a_kernel_label_where_nothing_shows_selinux_runs_is_not_taken_for_it() {
    // Without the kernel's list or a mounted selinuxfs, "kernel" is no
    // context: whether SELinux runs is not told by it, and the check fails
    // without deciding, as where only the configuration shows SELinux.
    let facts = Facts {
        lsms: Vec::new(),
        selinux: Some(SelinuxStatus {
            selinuxfs: Selinuxfs::NotMounted,
            enforce: None,
            config_mode: Some("disabled".to_string()),
            config_policy: Some("targeted".to_string()),
        }),
        label: Some("kernel".to_string()),
        config_age: ConfigAge::Older,
    };
    let result = judge(&facts, &known_units());
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .starts_with("Cannot tell whether SELinux runs:"),
        "{result:?}"
    );
    // And where the list leaves SELinux out, the label changes nothing.
    let mut facts = facts;
    facts.lsms = lsms(APPARMOR_LSMS);
    assert!(judge(&facts, &known_units()).is_pass());
}

// ---------------------------------------------------------------------------
// A configuration that names the targeted policy but changed since the boot
// ---------------------------------------------------------------------------

#[test]
fn a_configuration_that_changed_since_the_boot_fails_the_targeted_policy() {
    let mut facts = enforcing(UNCONFINED_LOGIN);
    facts.config_age = ConfigAge::Changed;
    let result = judge(&facts, &known_units());
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        result.message(),
        "/etc/selinux/config changed after this boot (its change time is not before the boot \
         time in /proc/stat), so SELinux may run another policy than the targeted one it names \
         now. A reboot loads the one it names. Active LSMs: lockdown, capability, yama, \
         selinux, bpf, landlock."
    );

    facts.config_age = ConfigAge::Unknown("it is a symbolic link, and so on".to_string());
    let result = judge(&facts, &known_units());
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        result.message(),
        "Whether /etc/selinux/config changed after this boot cannot be told (it is a symbolic \
         link, and so on), so whether SELinux runs the targeted policy it names cannot be told \
         either. Active LSMs: lockdown, capability, yama, selinux, bpf, landlock."
    );
}

/// What [`ConfigAge::read`] makes of a host whose `/proc/stat` holds `stat`
/// and whose `/etc/selinux/config` last changed `offset` seconds after the
/// boot (before it where negative).
fn age_of(stat: Option<&str>, offset: i64) -> ConfigAge {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(SELINUX_CONFIG, "SELINUX=enforcing\nSELINUXTYPE=targeted\n");
    let changed = BOOT.checked_add_signed(offset).unwrap();
    fs.mock_set_change_time(
        SELINUX_CONFIG,
        UNIX_EPOCH
            + std::time::Duration::from_secs(changed)
            + std::time::Duration::from_millis(500),
    );
    if let Some(stat) = stat {
        fs.mock_set_file_content(PROC_STAT, stat);
    }
    ConfigAge::read(&fs)
}

#[test]
fn the_age_of_the_configuration_is_its_change_time_against_the_boot() {
    assert_eq!(age_of(Some(STAT), -1), ConfigAge::Older);
    assert_eq!(age_of(Some(STAT), -86_400), ConfigAge::Older);
    // A change in the second of the boot counts, as a filesystem may keep its
    // change times to the second.
    assert_eq!(age_of(Some(STAT), 0), ConfigAge::Changed);
    assert_eq!(age_of(Some(STAT), 60), ConfigAge::Changed);
    // A boot time that cannot be read leaves it untold.
    assert!(matches!(age_of(None, -60), ConfigAge::Unknown(why) if why.contains("/proc/stat")));
    assert_eq!(
        age_of(Some("cpu  1 2 3\nprocesses 1\n"), -60),
        ConfigAge::Unknown("/proc/stat gives no boot time (btime)".to_string())
    );
    assert_eq!(
        age_of(Some("btime soon\n"), -60),
        ConfigAge::Unknown("/proc/stat gives no boot time (btime)".to_string())
    );
}

#[test]
fn a_configuration_behind_a_link_has_no_age_to_tell() {
    // A link: the change of what it leads to would not show on the link.
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(PROC_STAT, STAT);
    fs.mock_set_path_type(SELINUX_CONFIG, crate::filesystem::PathKind::Symlink);
    match ConfigAge::read(&fs) {
        ConfigAge::Unknown(why) => assert!(why.contains("symbolic link"), "{why}"),
        other => panic!("expected an untold age, got {other:?}"),
    }
}

#[test]
fn a_configuration_that_changed_since_the_boot_fails_through_the_check() {
    // The whole check, on a host that enforces the targeted policy: the
    // configuration was edited after the boot.
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(host_facts::LSM_LIST, SELINUX_LSMS);
    fs.mock_set_file_content("/proc/self/mounts", SELINUX_MOUNTS);
    fs.mock_set_file_content(SELINUX_ENFORCE, "1");
    fs.mock_set_file_content(SELINUX_CONFIG, "SELINUX=enforcing\nSELINUXTYPE=targeted\n");
    fs.mock_set_file_content(PROCESS_LABEL, &format!("{UNCONFINED_LOGIN}\0"));
    fs.mock_set_file_content(PROC_STAT, STAT);
    fs.mock_set_change_time(
        SELINUX_CONFIG,
        UNIX_EPOCH + std::time::Duration::from_secs(BOOT + 600),
    );
    let result = run_on(&fs, known_units());
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .starts_with("/etc/selinux/config changed after this boot"),
        "{result:?}"
    );
    // Without the boot time the check cannot tell, and fails too.
    fs.mock_set_file_content(PROC_STAT, "cpu 1\n");
    let result = run_on(&fs, known_units());
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .starts_with("Whether /etc/selinux/config changed after this boot cannot be told"),
        "{result:?}"
    );
}

// ---------------------------------------------------------------------------
// Reading an SELinux context
// ---------------------------------------------------------------------------

#[test]
fn a_context_reads_as_user_role_type_and_level() {
    for (label, domain, sensitivities) in [
        (UNCONFINED_LOGIN, "unconfined_t", vec!["s0", "s0"]),
        ("system_u:system_r:init_t:s0", "init_t", vec!["s0"]),
        (
            "staff_u:sysadm_r:sysadm_t:s0-s15:c0.c1023",
            "sysadm_t",
            vec!["s0", "s15"],
        ),
        ("u:r:a.b-c_d:s0:c1,c2.c3-s1", "a.b-c_d", vec!["s0", "s1"]),
        ("user_u:user_r:user_t", "user_t", vec![]),
    ] {
        assert_eq!(
            Context::parse(label),
            Some(Context {
                domain,
                sensitivities,
            }),
            "{label}"
        );
    }
}

#[test]
fn labels_of_other_modules_and_broken_contexts_read_as_none() {
    for label in [
        // AppArmor: no profile, a profile, a stacked label, a namespaced one,
        // and a profile name with colons and its mode.
        "unconfined",
        "/usr/sbin/cupsd (enforce)",
        "/usr/bin/a//&/usr/bin/b (mixed)",
        ":ns:/usr/bin/foo (enforce)",
        "a:b:c:d (enforce)",
        // Not enough fields, empty fields, bad identifiers.
        "",
        "kernel",
        "a:b",
        "a::c:s0",
        ":b:c:s0",
        "1u:r:t:s0",
        "u:r:t t:s0",
        // Levels that read as none.
        "u:r:t:",
        "u:r:t:s",
        "u:r:t:x0",
        "u:r:t:s0:",
        "u:r:t:s0:c1 c2",
        "u:r:t:s0-s1-s2",
        "u:r:t:s0-",
        "u:r:t:SystemLow-SystemHigh",
    ] {
        assert_eq!(Context::parse(label), None, "{label:?}");
    }
}

proptest::proptest! {
    /// Reading a label is total: no text makes it panic, and a context read
    /// from a label names a domain that is an identifier.
    #[test]
    fn reading_a_label_never_panics(label in "\\PC{0,80}") {
        if let Some(context) = Context::parse(&label) {
            proptest::prop_assert!(is_identifier(context.domain));
            proptest::prop_assert!(context.sensitivities.len() <= 2);
        }
    }

    /// The verdict is total too, and a host where SELinux does not run passes
    /// whatever its other facts.
    #[test]
    fn a_host_whose_lsm_list_lacks_selinux_passes(
        label in proptest::option::of("\\PC{0,40}"),
        mode in proptest::option::of(proptest::bool::ANY),
    ) {
        let facts = Facts {
            lsms: lsms(APPARMOR_LSMS),
            selinux: Some(SelinuxStatus {
                selinuxfs: Selinuxfs::NotMounted,
                enforce: mode.map(|on| {
                    if on { SelinuxMode::Enforcing } else { SelinuxMode::Permissive }
                }),
                config_mode: Some("enforcing".to_string()),
                config_policy: Some("mls".to_string()),
            }),
            label,
            config_age: ConfigAge::Changed,
        };
        proptest::prop_assert!(judge(&facts, &UnitDomains::UNKNOWN).is_pass());
    }
}

// ---------------------------------------------------------------------------
// The facts the distribution probes recorded
// ---------------------------------------------------------------------------

/// The committed probe fixtures (nix/distro-tests/probe), each as its JSON.
fn probe_fixtures() -> Vec<(String, serde_json::Value)> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../nix/distro-tests/probe");
    let mut fixtures: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {dir}: {e}"))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .map(|path| {
            let text = std::fs::read_to_string(&path).unwrap();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, serde_json::from_str(&text).unwrap())
        })
        .collect();
    fixtures.sort_by(|a, b| a.0.cmp(&b.0));
    fixtures
}

/// The probes record the mode SELinux ran in and the domain of the harness's
/// backdoor unit, from whose shell the VM tests run `nails`: a unit systemd
/// starts from a program that has no policy of its own. Those two facts are
/// taken as recorded, the domain for this process and for the processes
/// systemd starts for NAILS alike; what the probes do not record (the LSM
/// list, the configuration file, the user, role and level of the context) is
/// filled in as Fedora's cloud image has it. Nor do they record the domain
/// udev runs a program in, so the disk guard's is given as unconfined, and
/// only the recorded facts decide. Enforcing passes and permissive warns; an
/// image without SELinux passes.
#[test]
fn the_probed_hosts_pass_enforcing_and_warn_permissive() {
    let mut judged = Vec::new();
    for (name, fixture) in probe_fixtures() {
        if fixture["recorded"] != serde_json::Value::Bool(true) {
            continue;
        }
        let facts = &fixture["facts"];
        let mode = match facts["selinuxMode"].as_str() {
            Some("enforcing") => Some(SelinuxMode::Enforcing),
            Some("permissive") => Some(SelinuxMode::Permissive),
            Some("disabled") | None => None,
            Some(other) => panic!("{name}: an SELinux mode the probe does not record: {other}"),
        };
        let result = match mode {
            None => judge(
                &Facts {
                    lsms: lsms("lockdown,capability,landlock,yama,bpf"),
                    selinux: None,
                    label: None,
                    config_age: ConfigAge::Unknown("no such file".to_string()),
                },
                &UnitDomains::UNKNOWN,
            ),
            Some(mode) => {
                let domain = facts["selinuxBackdoorDomain"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{name}: SELinux runs, but no domain is recorded"));
                let mut probed = enforcing(&format!("system_u:system_r:{domain}:s0"));
                probed.selinux = Some(status(Some(mode), Some(mode_word(mode)), Some("targeted")));
                let units = UnitDomains {
                    systemd: UnitDomain::Known(domain.to_string()),
                    udev: known_units().udev,
                };
                judge(&probed, &units)
            }
        };
        match mode {
            None => assert!(result.is_pass(), "{name}: {result:?}"),
            Some(SelinuxMode::Enforcing) => assert!(result.is_pass(), "{name}: {result:?}"),
            Some(SelinuxMode::Permissive) => {
                assert!(result.is_warn(), "{name}: {result:?}");
                assert!(
                    result.message().starts_with("SELinux is permissive"),
                    "{name}: {result:?}"
                );
            }
        }
        judged.push(name);
    }
    // The recorded probes of Fedora 44, enforcing and permissive, and of
    // Arch's arch-boxes image are among them.
    for name in [
        "arch-boxes.json",
        "fedora-44-enforcing.json",
        "fedora-44.json",
    ] {
        assert!(
            judged.iter().any(|judged| judged == name),
            "{name}: {judged:?}"
        );
    }
}
