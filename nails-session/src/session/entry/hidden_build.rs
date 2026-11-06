// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Step 6 of the entry, on NixOS with a hidden configuration (see [`super`]):
//! the hidden toplevel built into the next root's store, the fstab it brings
//! decided before anything runs from the build, its closure copied onto the
//! hidden volume so a decoy garbage collection cannot break it
//! ([`crate::session::store`]), the toplevel activated chrooted
//! ([`crate::session::nixos`]), and then the policy applied to the hidden
//! generation's own fstab, as the activated root resolves it, for what the
//! decoy's did not cover.

use super::{Decided, EntryHost, EntryInputs, decide_fstab, io};
use crate::error::Result;
use crate::reporter::progress::{ActivationPhase, activation_step};
use crate::session::fstab::{self, FstabEntry};
use crate::session::layout::{Layout, Paths};
use crate::session::nixos;
use crate::session::policy::Whose;
use nails_teardown::mountinfo::MountEntry;
use nails_teardown::whole_root::plan::{Plan, RootSide};
use std::path::{Path, PathBuf};

/// Build the hidden NixOS system that `inputs.builder` describes into the
/// next root and activate it there, recording it in `plan`, and put in place
/// what its fstab calls for that the decoy's did not (`decided`). The fstab
/// is decided against `decoy_mounts`, the decoy's mounts as its fstab names
/// them. Returns the warnings; an entry without a builder builds nothing.
pub(super) fn build(
    paths: &Paths,
    inputs: &EntryInputs<'_>,
    host: &dyn EntryHost,
    layout: &Layout,
    plan: &mut Plan,
    decided: &mut Decided,
    decoy_mounts: &[MountEntry],
) -> Result<Vec<String>> {
    let Some(builder) = inputs.builder else {
        return Ok(Vec::new());
    };
    let nextroot = paths.nextroot();
    let present = |device: &Path| host.device_present(device);
    let decide = |entries: &[FstabEntry]| {
        decide_fstab(
            entries,
            decoy_mounts,
            inputs.hidden_root,
            &present,
            Whose::HiddenSystem,
        )
    };
    activation_step(ActivationPhase::BuildSystem, true);
    nixos::ensure_build_space(&layout.upper(), inputs.rebuild_space_mb)?;
    let system = host.build_hidden_system(builder, &nextroot, &layout.cache())?;
    crate::cancel::checkpoint()?;
    // The fstab the build brings is decided before anything runs from it,
    // and decided again below as the activated root resolves it: a build
    // refused for it is never activated, so its /etc never reaches the root
    // upper, which an entry without a build runs with.
    let built = fstab::of_system_in_root(&nextroot, &system)
        .map_err(|e| io(&paths.in_nextroot(&system.join("etc/fstab")), e))?;
    decide(&built)?;
    activation_step(ActivationPhase::KeepClosure, true);
    // Before anything runs from it: the decoy may garbage-collect its store
    // before the next session, so the closure is kept on the hidden volume.
    let kept = host.keep_hidden_closure(&nextroot, &system, &layout.store_kept())?;
    tracing::debug!(
        paths = kept.paths,
        copied = kept.copied,
        files = kept.files,
        bytes = kept.bytes,
        seconds = kept.elapsed.as_secs_f64(),
        "hidden system kept on the hidden volume"
    );
    // The last stop before the activation, which runs to its end once it has
    // begun.
    crate::cancel::checkpoint()?;
    activation_step(ActivationPhase::ActivateSystem, true);
    host.activate_hidden_system(&nextroot, &system)?;
    crate::cancel::checkpoint()?;
    let mut warnings = Vec::new();
    if let Some(decoy) = &plan.decoy.system
        && nixos::kernel_of(&nextroot, &system) != nixos::kernel_of(&nextroot, decoy)
    {
        warnings.push(
            "the hidden NixOS system was built for another kernel; kernel modules come \
             from the running (decoy) kernel"
                .to_string(),
        );
    }
    plan.hidden = RootSide {
        init: PathBuf::from(nixos::NIXOS_INIT),
        system: Some(system),
    };
    // The hidden generation brings its own /etc/fstab: decide its entries
    // too, resolved in the next root as the hidden systemd resolves them, and
    // put in place what the decoy's fstab did not already cover.
    let text = fstab::read_in_root(&nextroot).map_err(|e| io(&nextroot.join("etc/fstab"), e))?;
    let activated = fstab::parse_in_root(&text, &nextroot);
    let more = decide(&activated)?;
    decided.add(paths, layout, plan, activated, more, inputs)?;
    Ok(warnings)
}
