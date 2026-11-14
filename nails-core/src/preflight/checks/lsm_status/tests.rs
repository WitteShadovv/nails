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
    }
}

/// Units that run in the domain a backdoor-style unit gets.
fn known_units() -> UnitDomain {
    UnitDomain::Known(SERVICE.to_string())
}

/// The check's verdict on what `fs` holds.
fn run_on(fs: &MockFilesystem, units: UnitDomain) -> CheckResult {
    PreFlightCheck::<MockFilesystem>::run(&LsmStatusCheck::new(units), fs).unwrap()
}

#[test]
fn the_row_is_named_lsm_status() {
    let check = LsmStatusCheck::new(UnitDomain::Unknown);
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
    for units in [UnitDomain::Unknown, known_units()] {
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
        let result = run_on(&fs, UnitDomain::Unknown);
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
    let result = run_on(&MockFilesystem::new(), UnitDomain::Unknown);
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
        let result = run_on(&fs, UnitDomain::Unknown);
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
    let result = run_on(&fs, known_units());
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        result.message(),
        "SELinux enforces the targeted policy, and NAILS runs unconfined: this process in \
         unconfined_t, the processes systemd and udev start for it in unconfined_service_t. \
         Active LSMs: lockdown, capability, yama, selinux, bpf, landlock."
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

#[test]
fn units_in_an_unknown_domain_fail_where_selinux_runs() {
    // What the registry gives on every host today: NAILS starts its units
    // without choosing a domain, so an enforcing targeted host fails too.
    let result = judge(&enforcing(UNCONFINED_LOGIN), &UnitDomain::Unknown);
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        result.message(),
        "NAILS does not choose the SELinux domain of the processes systemd and udev start \
         from its copy in /run (the transition step at each switch, the watcher, the sleep \
         guard and the disk guard of the hidden session, and the boot-record steps after the \
         way back), so nothing shows they run unconfined. Active LSMs: lockdown, capability, \
         yama, selinux, bpf, landlock."
    );
}

#[test]
fn units_in_a_confined_domain_fail() {
    for domain in ["init_t", "initrc_t", "unconfined"] {
        let result = judge(
            &enforcing(UNCONFINED_LOGIN),
            &UnitDomain::Known(domain.to_string()),
        );
        assert!(result.is_fail(), "{domain}: {result:?}");
        assert!(
            result.message().starts_with(&format!(
                "systemd and udev start NAILS's processes in the SELinux domain {domain}, not \
                 in an unconfined one (unconfined_t, unconfined_service_t)."
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
        // A kernel told to enforce on its command line while the configuration
        // turns SELinux off.
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
                "SELinux runs the {policy:?} policy (/etc/selinux/config, SELINUXTYPE=): this \
                 check takes only the targeted policy, and NAILS is untested under any other."
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
                "and the targeted policy has none but s0: the policy SELinux runs is a \
                 multi-level (MLS) one."
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
             the targeted policy has: the policy SELinux runs is not targeted."
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
                "This nails process runs in the SELinux domain {domain}, not in an unconfined \
                 one (unconfined_t, unconfined_service_t). Active LSMs: lockdown, capability, \
                 yama, selinux, bpf, landlock."
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

    // What the kernel answers for a process before any policy is loaded, and a
    // label that holds a control character, shown escaped.
    for (label, shown) in [
        ("kernel", "\"kernel\""),
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
    let result = run_on(&fs, UnitDomain::Unknown);
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
            "neither could the mount table (/proc/self/mounts), and /sys/fs/selinux exists",
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
    };
    let result = judge(&facts, &UnitDomain::Unknown);
    assert!(result.is_fail(), "{result:?}");
    let message = result.message();
    let order = [
        "SELinux runs the \"mls\" policy",
        "runs at the sensitivity s15",
        "runs in the SELinux domain sysadm_t",
        "NAILS does not choose the SELinux domain",
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
        };
        proptest::prop_assert!(judge(&facts, &UnitDomain::Unknown).is_pass());
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
/// taken as recorded, for this process and for NAILS's units alike; what the
/// probes do not record (the LSM list, the configuration file, the user, role
/// and level of the context) is filled in as Fedora's cloud image has it.
/// Enforcing passes and permissive warns; an image without SELinux passes.
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
                },
                &UnitDomain::Unknown,
            ),
            Some(mode) => {
                let domain = facts["selinuxBackdoorDomain"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{name}: SELinux runs, but no domain is recorded"));
                let mut probed = enforcing(&format!("system_u:system_r:{domain}:s0"));
                probed.selinux = Some(status(Some(mode), Some(mode_word(mode)), Some("targeted")));
                judge(&probed, &UnitDomain::Known(domain.to_string()))
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
