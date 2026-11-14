// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `lsm-status` pre-flight check: the Linux Security Modules the kernel
//! runs, and, where SELinux is one of them, whether it runs as NAILS needs.
//!
//! Every result names the active LSMs, from the kernel's list in
//! `/sys/kernel/security/lsm`. The verdicts:
//!
//! - **SELinux does not run: pass.** AppArmor, Landlock, Yama and the other
//!   modules change nothing this check judges.
//! - **SELinux runs, enforcing, `/etc/selinux/config` names the targeted
//!   policy, has not changed since the boot and sets the mode SELinux runs in,
//!   and NAILS runs unconfined: pass.**
//! - **SELinux runs permissive, or `/etc/selinux/config` sets another mode than
//!   the one it runs in: warn.**
//! - **`/etc/selinux/config` names another policy than targeted, or the
//!   context of this process shows another: fail**, as untested.
//! - **SELinux is on in the kernel, but no policy is loaded: fail**, as
//!   untested, with the remedy to start the kernel with SELinux off.
//! - **NAILS runs in a confined domain: fail.**
//! - **SELinux runs, or may run, and a fact this check needs cannot be read:
//!   fail.** Where SELinux runs or may run, it never passes on a fact it could
//!   not read.
//!
//! # Whether SELinux runs
//!
//! The kernel's list of active LSMs decides: SELinux runs where it lists
//! `selinux`, and does not run where it lists other modules only. A selinuxfs
//! in the mount table means SELinux runs whatever the list says. Where the list
//! cannot be read, SELinux runs if selinuxfs is mounted or this process carries
//! an SELinux context, cannot be told apart from not running where only
//! `/sys/fs/selinux` or `/etc/selinux/config` shows it (that fails), and does
//! not run where nothing shows it.
//!
//! Where SELinux runs by these rules and this process is labelled `kernel`,
//! the kernel has loaded no policy: SELinux labels every process so until the
//! first policy load. `SELINUX=disabled` leaves a host so where the kernel
//! started SELinux at boot and cannot turn it off at runtime, as Linux 6.4 and
//! later cannot: libselinux then loads no policy and unmounts selinuxfs, and
//! only an empty `/sys/fs/selinux` is left. NAILS is untested there, so the
//! check fails with that one finding, and says to start the kernel with
//! SELinux off.
//!
//! # The policy
//!
//! The kernel does not know the name of the policy it loaded. systemd loads it
//! at boot from the directory `SELINUXTYPE=` names in `/etc/selinux/config`,
//! which [`host_facts`] reads the way libselinux reads it, its case kept, so
//! only a value of exactly `targeted` passes. That is the name the file gives
//! when the check runs, so where it names `targeted` the check also fails
//! when the file changed since the boot, by its change time against the boot
//! time in `/proc/stat`, to the second, or when that cannot be told (the file
//! is a symbolic link, or a time cannot be read): SELinux may then run another
//! policy than the one the file names now. The level of this process is
//! checked too: every context of Fedora's targeted policy has a level, whose
//! one sensitivity is `s0`, so a context without a level, or with another
//! sensitivity, as a multi-level (MLS) policy gives, fails whatever the
//! configuration names.
//!
//! # The domain NAILS runs in
//!
//! NAILS runs as two kinds of process, and both must run in an unconfined
//! domain ([`UNCONFINED_DOMAINS`]):
//!
//! - the `nails` process that runs this check, and the activation: its domain
//!   is the type of its context in `/proc/self/attr/current`. A login whose
//!   SELinux user is `unconfined_u` runs in `unconfined_t`, which `sudo`
//!   keeps. `unconfined_service_t` is what the targeted policy gives a service
//!   whose program has no policy of its own: the probe of the Fedora 44 cloud
//!   image recorded it for the harness's backdoor unit, from which the VM tests
//!   run `nails`.
//! - the processes systemd and udev start from NAILS's copy in `/run`: the
//!   transition step at each switch, the watcher, the sleep guard and the
//!   disk guard of the hidden session, and the boot-record steps after the way
//!   back. They run in whatever domain the decoy's policy gives that program
//!   when systemd or udev executes it, which no fact read at check time shows.
//!   The registry says what is known of it ([`UnitDomain`]): NAILS does not
//!   choose it yet, so it is [`UnitDomain::Unknown`], and on a host where
//!   SELinux runs this check fails until NAILS starts them in a domain a run
//!   under the policy has shown to be unconfined.
//!
//! Every SELinux fact is read through the host-fact readers detection uses,
//! without libselinux; the change time of `/etc/selinux/config` and the boot
//! time come through the same [`Filesystem`] trait. Everything is only read:
//! nothing here writes.

use super::super::{CheckResult, PreFlightCheck};
use crate::platform::host_facts::{self, LSM_LIST, PROCESS_LABEL, SELINUX_CONFIG, SELINUX_ENFORCE};
use crate::platform::{SelinuxMode, SelinuxStatus, Selinuxfs};
use crate::{Filesystem, Result};
use std::path::Path;
use std::time::UNIX_EPOCH;

/// The SELinux domains NAILS counts as unconfined: that of a login whose
/// SELinux user is `unconfined_u`, and that of a service the targeted policy
/// gives no domain of its own.
pub const UNCONFINED_DOMAINS: [&str; 2] = ["unconfined_t", "unconfined_service_t"];

/// The one policy this check passes, as `SELINUXTYPE=` names it.
const TARGETED: &str = "targeted";

/// The one sensitivity of the levels of Fedora's targeted policy.
const TARGETED_SENSITIVITY: &str = "s0";

/// The name the kernel gives SELinux in its list of active LSMs.
const SELINUX: &str = "selinux";

/// What SELinux shows as the context of every process before a policy is
/// loaded.
const UNLOADED: &str = "kernel";

/// Where the kernel gives the time it booted (`btime`).
const PROC_STAT: &str = "/proc/stat";

/// The SELinux domain of the processes systemd and udev start from NAILS's
/// copy in `/run`: the transition step at each switch, the watcher, the sleep
/// guard and the disk guard of the hidden session, and the boot-record steps
/// after the way back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitDomain {
    /// Not known: NAILS starts them without choosing a domain, so they run in
    /// whatever domain the decoy's policy gives the program systemd or udev
    /// executes.
    Unknown,
    /// This domain, as a run under the decoy's policy showed it.
    Known(String),
}

/// `lsm-status`: the active LSMs, and where SELinux runs, that it enforces the
/// targeted policy and NAILS runs unconfined.
#[derive(Debug, Clone)]
pub struct LsmStatusCheck {
    units: UnitDomain,
}

impl LsmStatusCheck {
    /// The check for a NAILS whose processes systemd and udev start in
    /// `units`.
    pub fn new(units: UnitDomain) -> Self {
        Self { units }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for LsmStatusCheck {
    fn name(&self) -> &'static str {
        "lsm-status"
    }

    fn description(&self) -> &'static str {
        "The Linux Security Modules that run; where SELinux runs, it enforces the targeted \
         policy and NAILS runs unconfined"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        Ok(judge(&Facts::read(fs), &self.units))
    }
}

/// What the check judges, read when it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Facts {
    /// The active LSMs in kernel order, empty where the list cannot be read.
    lsms: Vec<String>,
    /// The host's SELinux facts, `None` where none shows SELinux.
    selinux: Option<SelinuxStatus>,
    /// What `/proc/self/attr/current` holds for this process.
    label: Option<String>,
    /// Whether `/etc/selinux/config` changed since the boot.
    config_age: ConfigAge,
}

impl Facts {
    fn read<F: Filesystem>(fs: &F) -> Self {
        Self {
            lsms: host_facts::read_lsms(fs),
            selinux: host_facts::read_selinux(fs),
            label: host_facts::read_process_label(fs),
            config_age: ConfigAge::read(fs),
        }
    }
}

/// Whether `/etc/selinux/config` changed since the kernel booted. Where it
/// did, its `SELINUXTYPE=` may name another policy than the one SELinux
/// loaded at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConfigAge {
    /// It last changed before the boot.
    Older,
    /// It changed in the second of the boot or later.
    Changed,
    /// Which of the two cannot be told, for the reason given.
    Unknown(String),
}

impl ConfigAge {
    /// The file's change time, of the file itself (`lstat`), against the boot
    /// time in `/proc/stat`, to the second, as a filesystem may keep its
    /// change times to the second. Unlike the modification time, nothing but
    /// a change of the system clock sets a change time back. A symbolic link
    /// is not followed: what it leads to may change without changing the
    /// link.
    fn read<F: Filesystem>(fs: &F) -> Self {
        let config = Path::new(SELINUX_CONFIG);
        match fs.is_symlink(config) {
            Ok(false) => {}
            Ok(true) => {
                return Self::Unknown(
                    "it is a symbolic link, and NAILS does not follow when what it leads to \
                     changed"
                        .to_string(),
                );
            }
            Err(e) => return Self::Unknown(format!("it cannot be looked up: {e}")),
        }
        let changed = match fs.change_time(config) {
            Ok(changed) => changed,
            Err(e) => return Self::Unknown(format!("its change time cannot be read: {e}")),
        };
        let boot = match fs.read_file_content(Path::new(PROC_STAT)) {
            Ok(stat) => boot_time(&stat),
            Err(e) => {
                return Self::Unknown(format!("the boot time cannot be read ({PROC_STAT}: {e})"));
            }
        };
        let Some(boot) = boot else {
            return Self::Unknown(format!("{PROC_STAT} gives no boot time (btime)"));
        };
        let changed = changed
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        if changed >= boot {
            Self::Changed
        } else {
            Self::Older
        }
    }
}

/// The boot time `/proc/stat` gives (`btime`), in whole seconds since the
/// epoch.
fn boot_time(stat: &str) -> Option<u64> {
    stat.lines()
        .find_map(|line| line.strip_prefix("btime "))
        .and_then(|value| value.trim().parse().ok())
}

/// An SELinux context, `user:role:type:level`, as the kernel shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Context<'a> {
    /// The type of a process's context: its domain.
    domain: &'a str,
    /// The sensitivities of its level (`s0` of `s0-s0:c0.c1023`), low first;
    /// empty for a context without a level.
    sensitivities: Vec<&'a str>,
}

impl<'a> Context<'a> {
    /// `label` as an SELinux context, or `None` where it is none: AppArmor's
    /// `unconfined` or the name of a profile, or anything else that does not
    /// read as user, role and type identifiers and an MLS level.
    fn parse(label: &'a str) -> Option<Self> {
        let mut fields = label.splitn(4, ':');
        let (user, role, domain) = (fields.next()?, fields.next()?, fields.next()?);
        if ![user, role, domain].into_iter().all(is_identifier) {
            return None;
        }
        let sensitivities = match fields.next() {
            Some(level) => sensitivities(level)?,
            None => Vec::new(),
        };
        Some(Self {
            domain,
            sensitivities,
        })
    }
}

/// Whether `name` reads as an SELinux identifier: a letter or `_`, then
/// letters, digits, `_`, `.` or `-`.
fn is_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// The sensitivities of an MLS level or range (`s0`, `s0-s0:c0.c1023`,
/// `s0:c1,c2-s15:c0.c1023`), low first, or `None` where it reads as none.
fn sensitivities(level: &str) -> Option<Vec<&str>> {
    let mut found = Vec::new();
    for part in level.split('-') {
        let (sensitivity, categories) = match part.split_once(':') {
            Some((sensitivity, categories)) => (sensitivity, Some(categories)),
            None => (part, None),
        };
        let number = sensitivity.strip_prefix('s')?;
        if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        if categories.is_some_and(|categories| {
            categories.is_empty()
                || !categories
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b','))
        }) {
            return None;
        }
        found.push(sensitivity);
    }
    (found.len() <= 2).then_some(found)
}

/// Whether NAILS counts `domain` as unconfined.
fn unconfined(domain: &str) -> bool {
    UNCONFINED_DOMAINS.contains(&domain)
}

/// Whether SELinux runs, by [the rules](self#whether-selinux-runs).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Presence {
    /// SELinux does not run.
    Absent,
    /// SELinux is on in the kernel, but no policy is loaded: this process is
    /// labelled `kernel`.
    Unloaded,
    /// SELinux runs.
    Running,
    /// Whether it runs cannot be told, for the reason given.
    Undecided(String),
}

fn presence(facts: &Facts, labelled: bool) -> Presence {
    let mounted = facts
        .selinux
        .as_ref()
        .is_some_and(|status| status.selinuxfs == Selinuxfs::Mounted);
    let runs = if facts.lsms.is_empty() {
        mounted || labelled
    } else {
        mounted || facts.lsms.iter().any(|lsm| lsm == SELINUX)
    };
    if runs {
        return if facts.label.as_deref() == Some(UNLOADED) {
            Presence::Unloaded
        } else {
            Presence::Running
        };
    }
    if !facts.lsms.is_empty() {
        return Presence::Absent;
    }
    match &facts.selinux {
        None => Presence::Absent,
        Some(status) => Presence::Undecided(format!(
            "the kernel's list of active LSMs could not be read ({LSM_LIST}), {}, and {}",
            match status.selinuxfs {
                Selinuxfs::Unknown => "neither could the mount table (/proc/self/mounts)",
                _ => "no selinuxfs is mounted",
            },
            evidence(status)
        )),
    }
}

/// What shows SELinux on a host where selinuxfs is not mounted.
fn evidence(status: &SelinuxStatus) -> String {
    match (&status.config_mode, &status.config_policy) {
        (Some(mode), _) => format!("{SELINUX_CONFIG} sets SELINUX={mode}"),
        (None, Some(policy)) => format!("{SELINUX_CONFIG} names the {policy:?} policy"),
        (None, None) => "/sys/fs/selinux exists".to_string(),
    }
}

/// The sentence that names the active LSMs.
fn lsm_sentence(lsms: &[String]) -> String {
    if lsms.is_empty() {
        format!("The kernel's list of active LSMs could not be read ({LSM_LIST}).")
    } else {
        format!("Active LSMs: {}.", lsms.join(", "))
    }
}

/// The word for a mode, as `/etc/selinux/config` spells it.
fn mode_word(mode: SelinuxMode) -> &'static str {
    match mode {
        SelinuxMode::Enforcing => "enforcing",
        SelinuxMode::Permissive => "permissive",
    }
}

/// The check's verdict on `facts`, for units that run in `units`.
fn judge(facts: &Facts, units: &UnitDomain) -> CheckResult {
    let lsms = lsm_sentence(&facts.lsms);
    let context = facts.label.as_deref().and_then(Context::parse);
    match presence(facts, context.is_some()) {
        Presence::Absent => {
            let configured = facts
                .selinux
                .as_ref()
                .and_then(|status| status.config_mode.as_deref())
                .filter(|mode| *mode != "disabled");
            CheckResult::Pass(match configured {
                Some(mode) => format!(
                    "SELinux does not run, though {SELINUX_CONFIG} sets SELINUX={mode}. {lsms}"
                ),
                None => format!("SELinux does not run. {lsms}"),
            })
        }
        // Only where the LSM list could not be read, which the reason says.
        Presence::Undecided(why) => {
            CheckResult::fail(format!("Cannot tell whether SELinux runs: {why}."))
        }
        Presence::Unloaded => unloaded(facts, &lsms),
        Presence::Running => running(facts, context.as_ref(), units, &lsms),
    }
}

/// The verdict on a host whose kernel has SELinux on without a policy: the
/// one finding, whatever else the facts say, since no domain, mode or level
/// means anything before a policy is loaded.
fn unloaded(facts: &Facts, lsms: &str) -> CheckResult {
    let disabled = facts
        .selinux
        .as_ref()
        .and_then(|status| status.config_mode.as_deref())
        == Some("disabled");
    let cause = if disabled {
        format!(
            " {SELINUX_CONFIG} sets SELINUX=disabled, which kept a policy from loading but \
             left SELinux on in this kernel."
        )
    } else {
        String::new()
    };
    CheckResult::fail_with(
        format!(
            "SELinux is on in this kernel, but no policy is loaded: this nails process is \
             labelled {UNLOADED:?} ({PROCESS_LABEL}), as SELinux labels every process until a \
             policy is loaded.{cause} NAILS is untested on such a host. {lsms}"
        ),
        "Start the kernel with SELinux off: add selinux=0 to the kernel command line.",
    )
}

/// The verdict on a host where SELinux runs: every finding, failures first,
/// in one result.
fn running(
    facts: &Facts,
    context: Option<&Context<'_>>,
    units: &UnitDomain,
    lsms: &str,
) -> CheckResult {
    let status = facts.selinux.as_ref();
    let mut fails = Vec::new();
    let mut warns = Vec::new();

    let enforce = status.and_then(|status| status.enforce);
    match enforce {
        None => fails.push(format!(
            "SELinux runs, but whether it enforces could not be read ({SELINUX_ENFORCE})."
        )),
        Some(SelinuxMode::Permissive) => {
            warns.push(
                "SELinux is permissive: it logs what its policy would deny and denies nothing."
                    .to_string(),
            );
        }
        Some(SelinuxMode::Enforcing) => {}
    }
    match (
        status.and_then(|status| status.config_mode.as_deref()),
        enforce,
    ) {
        (None, _) => fails.push(format!(
            "{SELINUX_CONFIG} sets no mode NAILS can read (SELINUX=), so whether SELinux runs \
             in the mode it is configured for cannot be told."
        )),
        (Some(configured), Some(mode)) if configured != mode_word(mode) => warns.push(format!(
            "{SELINUX_CONFIG} sets SELINUX={configured}, but SELinux runs {}.",
            mode_word(mode)
        )),
        _ => {}
    }
    match status.and_then(|status| status.config_policy.as_deref()) {
        None => fails.push(format!(
            "{SELINUX_CONFIG} could not be read or names no policy (SELINUXTYPE=), so the \
             policy SELinux runs cannot be told."
        )),
        Some(TARGETED) => fails.extend(age_finding(&facts.config_age)),
        Some(policy) => fails.push(format!(
            "{SELINUX_CONFIG} names the {policy:?} policy (SELINUXTYPE=): this check takes \
             only the targeted policy, and NAILS is untested under any other."
        )),
    }

    let process = match (facts.label.as_deref(), context) {
        (None, _) => {
            fails.push(format!(
                "The SELinux context of this nails process could not be read ({PROCESS_LABEL})."
            ));
            None
        }
        (Some(label), None) => {
            fails.push(format!(
                "This nails process is labelled {label:?} ({PROCESS_LABEL}), which does not \
                 read as an SELinux context."
            ));
            None
        }
        (Some(_), Some(context)) => {
            fails.extend(level_finding(context));
            if !unconfined(context.domain) {
                fails.push(format!(
                    "This nails process runs in the SELinux domain {}, not in an unconfined \
                     one ({}).",
                    context.domain,
                    UNCONFINED_DOMAINS.join(", ")
                ));
            }
            Some(context.domain)
        }
    };
    let units = match units {
        UnitDomain::Unknown => {
            fails.push(
                "NAILS does not choose the SELinux domain of the processes systemd and udev \
                 start from its copy in /run (the transition step at each switch, the \
                 watcher, the sleep guard and the disk guard of the hidden session, and the \
                 boot-record steps after the way back), so nothing shows they run \
                 unconfined."
                    .to_string(),
            );
            None
        }
        UnitDomain::Known(domain) => {
            if !unconfined(domain) {
                fails.push(format!(
                    "systemd and udev start NAILS's processes in the SELinux domain {domain}, \
                     not in an unconfined one ({}).",
                    UNCONFINED_DOMAINS.join(", ")
                ));
            }
            Some(domain.as_str())
        }
    };

    if fails.is_empty()
        && let (Some(process), Some(units)) = (process, units)
    {
        return if warns.is_empty() {
            CheckResult::Pass(format!(
                "SELinux enforces, {SELINUX_CONFIG} names the targeted policy and has not \
                 changed since the boot, and NAILS runs unconfined: this process in {process}, \
                 the processes systemd and udev start for it in {units}. {lsms}"
            ))
        } else {
            CheckResult::Warn(format!("{} {lsms}", warns.join(" ")))
        };
    }
    fails.append(&mut warns);
    CheckResult::fail(format!("{} {lsms}", fails.join(" ")))
}

/// The finding on when `/etc/selinux/config`, which names the targeted
/// policy, last changed, where SELinux may run another policy than that.
fn age_finding(age: &ConfigAge) -> Option<String> {
    match age {
        ConfigAge::Older => None,
        ConfigAge::Changed => Some(format!(
            "{SELINUX_CONFIG} changed after this boot (its change time is not before the boot \
             time in {PROC_STAT}), so SELinux may run another policy than the targeted one it \
             names now. A reboot loads the one it names."
        )),
        ConfigAge::Unknown(why) => Some(format!(
            "Whether {SELINUX_CONFIG} changed after this boot cannot be told ({why}), so \
             whether SELinux runs the targeted policy it names cannot be told either."
        )),
    }
}

/// The finding on the level of this process's `context`, where it shows a
/// policy that is not Fedora's targeted one: no level at all, or a
/// sensitivity other than `s0`.
fn level_finding(context: &Context<'_>) -> Option<String> {
    if context.sensitivities.is_empty() {
        return Some(
            "The SELinux context of this nails process has no level, which every context of \
             Fedora's targeted policy has: SELinux runs another policy, and NAILS is untested \
             under any other."
                .to_string(),
        );
    }
    context
        .sensitivities
        .iter()
        .find(|sensitivity| **sensitivity != TARGETED_SENSITIVITY)
        .map(|other| {
            format!(
                "This nails process runs at the sensitivity {other}, and Fedora's targeted \
                 policy has none but {TARGETED_SENSITIVITY}: SELinux runs another policy, such \
                 as a multi-level (MLS) one, and NAILS is untested under any other."
            )
        })
}

#[cfg(test)]
mod tests;
