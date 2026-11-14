// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether the RAM copies of the binary take the SELinux label of the
//! system's programs on this host, and the refusals of a switch whose copy is
//! not ready.
//!
//! On a host whose kernel runs or may run SELinux, as the host facts tell it
//! (never a flag or a setting), every RAM copy of the binary gets the label
//! [`PROGRAM_LABEL`]: [`nails_teardown::whole_root::program_label`] says why
//! (PID 1 starts NAILS's own steps from those copies, in the domain the loaded
//! policy gives their label) and which copies. That is a host where the
//! labels of the uppers are required ([`Labels::for_host`]), one whose kernel
//! lists SELinux among its security modules though no selinuxfs is mounted
//! where the activation runs, since the kernel enforces a loaded policy all
//! the same, and one that reports SELinux without a list of security modules
//! to rule it out ([`Why`]). The activation decides it once ([`for_host`]),
//! and the entry records the label in the plan, which every later step takes
//! it from. Where SELinux does not run, as on a stock Debian, Ubuntu or NixOS,
//! the plan records none: no label is written or read and nothing is asked of
//! the kernel. The unit files and drop-ins are the same on every host.
//!
//! The entry ([`super::entry`]):
//!
//! - refuses before it writes anything where the loaded policy would not
//!   start a program of that label from PID 1 in the unconfined service domain
//!   ([`require`]): the step of each switch would not start, and the switch
//!   would go on without it, or it would run in a domain the policy confines;
//! - gives its copy the label right after it writes it, and refuses where the
//!   copy does not read it back ([`label_copy`]);
//! - refuses where the decoy's PID 1, once the reload has loaded the drop-in,
//!   starts `systemd-soft-reboot.service`, whose start runs the step, in an
//!   `SELinuxContext=` of its own, in which the policy's change of domain does
//!   not apply ([`check_switch_unit`]);
//! - gives the copy the label again and asks the policy again right before it
//!   arms the switch ([`ready_for_entry`]).
//!
//! `deactivate` refuses a return before it prepares anything where the policy
//! would not start the way back's step from the copy as it needs, or the
//! hidden session's PID 1 starts that unit in an `SELinuxContext=` of its own
//! ([`check_way_back`]), and gives the copy the label again and asks the
//! policy again right before it arms the switch ([`ready_for_way_back`]). The
//! emergency's way back gives the label again and asks the policy too, and
//! powers off where either fails
//! ([`nails_teardown::whole_root::emergency`]); it asks PID 1 nothing, as for
//! the runtime guards, so it does not see an `SELinuxContext=` of that unit,
//! and a refusal for one names only the power-offs besides deactivating
//! again. The way back's last step gives the copy it leaves for the decoy's
//! first start the label, or leaves that copy out
//! ([`nails_teardown::whole_root::boot_records::install`]). The units PID 1
//! starts from a copy after a switch check their own domain when they start
//! ([`nails_teardown::whole_root::program_label::enter_domain`]).

use super::guards::GuardHost;
use super::labels::{Labels, Reason};
use crate::error::{NailsError, Result};
use nails_base::next_step::{NextStep, sudo_line};
use nails_platform::HostProfile;
use nails_teardown::whole_root::plan::Plan;
use nails_teardown::whole_root::program_label::{
    self, DOMAIN, Effect, NotReady, Unfit, Unlabelled, check_start,
};
use nails_teardown::whole_root::selinux::Selinux;
use std::path::Path;

pub use nails_teardown::whole_root::program_label::PROGRAM_LABEL;

/// The name the refusals go by.
pub const CHECK: &str = "program-label";

/// The unit whose start command runs the transition step from the copy
/// ([`nails_teardown::whole_root::transition::DROPIN_DIR`]).
pub const SWITCH_UNIT: &str = "systemd-soft-reboot.service";

/// The name the kernel lists SELinux by among its security modules
/// ([`HostProfile::lsms`]).
const SELINUX_MODULE: &str = "selinux";

/// Why the RAM copies of the binary take the label on a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The labels of the uppers are required, for this reason
    /// ([`Labels::for_host`]).
    Labels(Reason),
    /// The kernel lists SELinux among its security modules, though the mount
    /// table lists no selinuxfs: the kernel enforces a policy it has loaded
    /// whether or not selinuxfs is mounted, and there has been no way to turn
    /// SELinux off at run time since Linux 6.4.
    Kernel,
    /// The host facts report SELinux, the mount table lists no selinuxfs, and
    /// the kernel's list of security modules, which would rule SELinux out,
    /// could not be read.
    ModulesUnread,
}

/// Why SELinux runs or may run, as the start of a sentence a refusal goes on
/// with: "SELinux runs on this host (selinuxfs is mounted), so ...".
impl std::fmt::Display for Why {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Why::Labels(reason) => write!(f, "{reason}"),
            Why::Kernel => f.write_str(
                "the kernel lists SELinux among its security modules (/sys/kernel/security/lsm), \
                 and may enforce a policy, though no selinuxfs is mounted here",
            ),
            Why::ModulesUnread => f.write_str(
                "the host facts report SELinux, no selinuxfs is mounted here, and \
                 /sys/kernel/security/lsm could not be read to rule it out",
            ),
        }
    }
}

/// Whether the RAM copies of the binary take the label on the host `profile`
/// describes (`None` where the detection failed), and why: where
/// [`Labels::for_host`] requires the labels of the uppers, for its reason,
/// and where the kernel lists SELinux among its security modules, or the
/// facts report SELinux and the list could not be read ([`Why`]). `None`
/// elsewhere: no copy takes a label there.
pub fn for_host(profile: Option<&HostProfile>) -> Option<Why> {
    if let Labels::Required(reason) = Labels::for_host(profile) {
        return Some(Why::Labels(reason));
    }
    let profile = profile?;
    if profile.lsms.iter().any(|lsm| lsm == SELINUX_MODULE) {
        Some(Why::Kernel)
    } else if profile.lsms.is_empty() && profile.selinux.is_some() {
        Some(Why::ModulesUnread)
    } else {
        None
    }
}

/// What a step PID 1 starts from a copy whose start is `unfit` comes to,
/// after "the last step before each switch and the hidden session's own
/// units".
fn effect(unfit: &Unfit) -> &'static str {
    match unfit.effect() {
        Effect::NotStarted => "would not start, and a switch would go on without its step",
        Effect::Confined => "would run in a domain the policy confines",
        Effect::Unknown => "might not start, or might run in a domain the policy confines",
    }
}

/// The fix of an entry refused for what the policy makes of the start.
fn policy_fix(unfit: &Unfit) -> String {
    if matches!(unfit, Unfit::Unjudged(_)) {
        return "Run nails where it can ask the loaded SELinux policy (selinuxfs mounted at \
                /sys/fs/selinux, nails started as root from an unconfined domain) and activate \
                again"
            .to_string();
    }
    format!(
        "Activate on a host whose loaded SELinux policy starts the system's programs \
         ({PROGRAM_LABEL}) from PID 1 in {DOMAIN}, as a targeted policy with its unconfined \
         module does: NAILS installs nothing into the policy to make it so"
    )
}

/// The entry's refusal for what the policy makes of PID 1's start of a copy
/// labelled [`PROGRAM_LABEL`].
fn unfit_entry(why: Why, unfit: &Unfit) -> NailsError {
    refusal(
        format!(
            "{why}, so NAILS gives the RAM copy of the binary, which PID 1 starts NAILS's own \
             steps from, the label of the system's programs ({PROGRAM_LABEL}), but PID 1's start \
             of a file so labelled {unfit}: the last step before each switch and the hidden \
             session's own units {}",
            effect(unfit)
        ),
        policy_fix(unfit),
    )
}

/// The entry's refusal of a copy at `copy` that does not carry the label.
fn unlabelled_entry(why: Why, copy: &Path, unlabelled: &Unlabelled) -> NailsError {
    refusal(
        format!(
            "{why}, so the RAM copy of the binary at {}, which PID 1 starts NAILS's own steps \
             from, must carry the SELinux label {PROGRAM_LABEL}, but it {unlabelled}",
            copy.display()
        ),
        "Run nails as root from an unconfined domain, which the policy lets relabel the files \
         in /run, and activate again"
            .to_string(),
    )
}

/// Refuse the entry, before it writes anything, where the loaded policy, as
/// `selinux` tells it, would not start a program labelled [`PROGRAM_LABEL`]
/// from PID 1 in [`DOMAIN`] ([`check_start`]). Nothing to ask where the copy
/// takes no label (`why` is `None`).
pub fn require(why: Option<Why>, selinux: &dyn Selinux) -> Result<()> {
    let Some(why) = why else {
        return Ok(());
    };
    check_start(selinux, PROGRAM_LABEL).map_err(|unfit| unfit_entry(why, &unfit))
}

/// Give the entry's copy at `copy` the label right after it is written, and
/// refuse the entry where it does not read it back
/// ([`program_label::label_path`]). Nothing is written where the copy takes
/// no label (`why` is `None`).
pub fn label_copy(why: Option<Why>, selinux: &dyn Selinux, copy: &Path) -> Result<()> {
    let Some(why) = why else {
        return Ok(());
    };
    program_label::label_path(selinux, copy, PROGRAM_LABEL)
        .map_err(|unlabelled| unlabelled_entry(why, copy, &unlabelled))
}

/// Give the entry's copy at `copy` the label again and ask the policy again,
/// right before the entry is armed ([`program_label::ready`]), so that
/// whatever relabelled `/run` since the copy was written does not decide the
/// domain of the step. Nothing where the copy takes no label.
pub fn ready_for_entry(why: Option<Why>, selinux: &dyn Selinux, copy: &Path) -> Result<()> {
    let Some(why) = why else {
        return Ok(());
    };
    program_label::ready(selinux, copy, PROGRAM_LABEL).map_err(|not_ready| match not_ready {
        NotReady::Unlabelled(unlabelled) => unlabelled_entry(why, copy, &unlabelled),
        NotReady::Unfit(unfit) => unfit_entry(why, &unfit),
    })
}

/// Why the PID 1 that `host` asks would not start [`SWITCH_UNIT`] in the
/// domain the policy gives the copy: `None` where nothing keeps it from it.
/// An `SELinuxContext=` of the unit, with every drop-in loaded, does: PID 1
/// then starts the step in that context. An answer PID 1 does not give is an
/// error.
fn switch_unit_unheld(host: &(impl GuardHost + ?Sized)) -> Result<Option<String>> {
    let context = host.selinux_context(SWITCH_UNIT)?;
    let context = context.trim();
    Ok((!context.is_empty()).then(|| {
        format!(
            "{SWITCH_UNIT}, whose start runs the last step before the switch, has \
             SELinuxContext={context} with every drop-in loaded: PID 1 then starts the step in \
             that context, not in {DOMAIN}, the domain the policy gives the RAM copy of the binary"
        )
    }))
}

/// Refuse the entry where the decoy's PID 1, which `host` asks once the
/// reload has loaded the drop-in, starts [`SWITCH_UNIT`] in an
/// `SELinuxContext=` of its own ([`switch_unit_unheld`]). An answer PID 1
/// does not give refuses too. Nothing to ask where the copy takes no label.
pub fn check_switch_unit(why: Option<Why>, host: &(impl GuardHost + ?Sized)) -> Result<()> {
    let Some(why) = why else {
        return Ok(());
    };
    let Some(unheld) = switch_unit_unheld(host)? else {
        return Ok(());
    };
    Err(refusal(
        format!(
            "{why}, so PID 1 starts NAILS's own steps from a RAM copy of the binary labelled \
             {PROGRAM_LABEL}, but {unheld}: the last step before each switch could run in a \
             domain the policy confines"
        ),
        format!(
            "Remove that setting from the drop-in of {SWITCH_UNIT} that sets it (`systemctl cat \
             {SWITCH_UNIT}` shows where it is) and activate again"
        ),
    ))
}

/// The fix of a way back refused for its copy or for what the policy makes
/// of its start: the power-off, which a plain emergency also comes to here,
/// since it gives the copy the label again and asks the policy as well.
fn way_back_fix() -> String {
    format!(
        "End the session with `{}`, which powers off, as `{}` does here",
        sudo_line(NextStep::DeactivatePoweroff),
        sudo_line(NextStep::Emergency)
    )
}

/// The fix of a way back refused for how the hidden session's PID 1 starts
/// [`SWITCH_UNIT`], or because it could not be asked (`asked` false). A plain
/// emergency asks PID 1 nothing: its last step starts in that context, then
/// starts itself again in the domain the copy's label gives it or powers off
/// ([`nails_teardown::whole_root::transition`]). So only the power-offs,
/// whose end that context does not decide, are named besides deactivating
/// again.
fn switch_unit_fix(asked: bool) -> String {
    let first = if asked {
        format!(
            "Remove that setting from the hidden session's drop-in of {SWITCH_UNIT} that sets \
             it (`systemctl cat {SWITCH_UNIT}` shows where it is) and deactivate again"
        )
    } else {
        "Deactivate again once PID 1 answers".to_string()
    };
    format!(
        "{first}, or end the session with `{}` or `{}`, which power off",
        sudo_line(NextStep::DeactivatePoweroff),
        sudo_line(NextStep::EmergencyPoweroff)
    )
}

/// What a step of the way back from a copy whose start is `unfit` comes to,
/// after "that step".
fn way_back_effect(unfit: &Unfit) -> &'static str {
    way_back_effect_of(unfit.effect())
}

/// What a step of the way back comes to where its start has `effect`.
fn way_back_effect_of(effect: Effect) -> &'static str {
    match effect {
        Effect::NotStarted => {
            "would not start, and the switch to the decoy would go on without it: the decoy \
             would start with the hidden session's files in /run"
        }
        Effect::Confined => {
            "would run in a domain the policy confines, which keeps it from taking the kernel \
             log's cursor: the decoy's journal would take in the hidden session's kernel log"
        }
        Effect::Unknown => "might not start, or might run in a domain the policy confines",
    }
}

/// Refuse a return to the decoy, before anything is prepared, where `plan`
/// records a label for the RAM copy and the loaded policy, as `host`'s SELinux
/// tells it, would not start a program of that label from PID 1 in
/// [`DOMAIN`] ([`check_start`]), or the hidden session's PID 1, which `host`
/// asks, starts [`SWITCH_UNIT`] in an `SELinuxContext=` of its own; a PID 1
/// that cannot be asked refuses the return too. The way back's last step
/// starts from that copy. A power-off needs no such step and asks nothing.
pub fn check_way_back(plan: &Plan, host: &(impl GuardHost + ?Sized)) -> Result<()> {
    let Some(label) = plan.program_label.as_deref() else {
        return Ok(());
    };
    check_start(host.selinux(), label).map_err(|unfit| {
        refusal(
            format!(
                "PID 1 starts the last step of the way back from the RAM copy of the binary, \
                 labelled {label}, but its start of a file so labelled {unfit}: that step {}",
                way_back_effect(&unfit)
            ),
            way_back_fix(),
        )
    })?;
    let (unheld, asked) = match switch_unit_unheld(host) {
        Ok(None) => return Ok(()),
        Ok(Some(unheld)) => (unheld, true),
        Err(error) => (
            format!(
                "the hidden session's PID 1 could not be asked how it starts {SWITCH_UNIT}: {}",
                match error {
                    NailsError::InvalidState(why) => why,
                    other => other.to_string(),
                }
            ),
            false,
        ),
    };
    Err(refusal(
        format!(
            "PID 1 starts the last step of the way back from the RAM copy of the binary, labelled \
             {label}, but {unheld}: that step could run in a domain the policy confines"
        ),
        switch_unit_fix(asked),
    ))
}

/// Give the copy at `copy` the label `plan` records again and ask the policy
/// again, right before the way back is armed ([`program_label::ready`]), so
/// that whatever relabelled `/run` during the session does not decide the
/// domain of the way back's step. Nothing where the plan records no label.
pub fn ready_for_way_back(plan: &Plan, selinux: &dyn Selinux, copy: &Path) -> Result<()> {
    let Some(label) = plan.program_label.as_deref() else {
        return Ok(());
    };
    program_label::ready(selinux, copy, label).map_err(|not_ready| {
        let what = program_label::not_ready_text(copy, label, &not_ready);
        let effect = match &not_ready {
            // No copy to start, or something else in its place.
            NotReady::Unlabelled(Unlabelled::Open(_) | Unlabelled::NotAFile) => {
                way_back_effect_of(Effect::NotStarted)
            }
            // A copy that keeps another label, which PID 1 starts in its
            // own domain, as it does the files in /run.
            NotReady::Unlabelled(_) => way_back_effect_of(Effect::Confined),
            NotReady::Unfit(unfit) => way_back_effect(unfit),
        };
        refusal(
            format!("{what}: the last step of the way back, which starts from it, {effect}"),
            way_back_fix(),
        )
    })
}

/// The refusal of a switch, under [`CHECK`].
fn refusal(reason: String, fix: String) -> NailsError {
    NailsError::PreFlightCheckFailed(vec![(CHECK.to_string(), reason, Some(fix))])
}

#[cfg(test)]
#[path = "program_label_tests.rs"]
mod tests;
