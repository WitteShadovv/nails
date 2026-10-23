// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Preparing the entry into the hidden root.
//!
//! [`prepare`] builds everything the soft-reboot needs and arms the plan; the
//! caller then commits the state and enqueues `soft-reboot.target`:
//!
//! 1. snapshot `/run` and save `utab`, before NAILS adds anything to `/run`;
//! 2. the runtime directory: the snapshot, the RAM copy of the binary and
//!    configuration, the plan; `noexec` cleared on `/run` when it is set
//!    (Debian, Ubuntu), recorded in the plan;
//! 3. the transition drop-in installed and the service manager reloaded,
//!    before anything is mounted at `/run/nextroot`: an activation killed
//!    later leaves an unarmed next root that any soft-reboot disarms;
//! 4. the root overlay at `/run/nextroot`: the decoy root as a read-only lower,
//!    the upper on the hidden volume;
//! 5. the fstab policy on the decoy's fstab ([`super::policy`]): the hidden
//!    volume bound at its path, boot filesystems read-only, other decoy
//!    filesystems overlaid, the rest masked at entry. This comes before the
//!    hidden build, because a separate `/nix` (or a VM's store share) must be
//!    in place before anything reads the next root's store;
//! 6. on NixOS with a hidden configuration: the hidden toplevel built into the
//!    next root's store, its closure copied onto the hidden volume so a decoy
//!    garbage collection cannot break it ([`super::store`]), and activated
//!    chrooted (see [`super::nixos`]), then the policy applied to the hidden
//!    generation's own fstab for what the decoy's did not cover;
//! 7. the decoy filesystems the way back needs carried onto the hidden volume,
//!    and the decoy's mounts recorded for the way back to make again
//!    ([`super::way_back`]); `/run` bound in and everything below the next
//!    root made private (its own mount stays shared until the switch, so a
//!    rollback reaches the copies other mount namespaces hold; see
//!    [`nextroot`]); the init checked the way PID 1 will, and the soft-reboot
//!    units the way back needs found in the next root;
//! 8. the plan armed for the entry.
//!
//! Any failure undoes all of it ([`rollback`]): a populated `/run/nextroot`
//! must never be left behind, or a later plain reboot would enter it. A
//! SIGINT or SIGTERM (Ctrl+C) is a failure too: each step boundary and the
//! store copy ask [`crate::cancel`], and the entry stops at the first one
//! after the signal.

use super::fstab::FstabEntry;
use super::layout::{Layout, Paths};
use super::network_state;
use super::nixos;
use super::policy::{self, Decision};
use super::store;
use crate::error::{NailsError, Result};
use crate::nixos::NixOSBuilder;
use crate::reporter::progress::{ActivationPhase, activation_step};
use nails_teardown::mountinfo::{MountEntry, SELF_MOUNTINFO, read_mountinfo, top_mount_at};
use nails_teardown::whole_root::nextroot;
use nails_teardown::whole_root::plan::{
    Arm, DecoyRoot, Direction, Owner, PLAN_VERSION, Plan, PolicyMount, PolicyMountKind, RootSide,
    SNAPSHOT_NAME, Tools, UTAB_MOUNTS_NAME, UTAB_NAME,
};
use nails_teardown::whole_root::run_scrub::Snapshot;
use nails_teardown::whole_root::runtime_units::{self, RuntimeUnit};
use nails_teardown::whole_root::{kernel_helpers, network, ret, transition, utab};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The configuration copy's name in the runtime directory.
pub const CONFIG_COPY_NAME: &str = "settings.toml";

/// Inits an FHS root may run, in the order systemd's own build would pick.
const FHS_INITS: &[&str] = &["/usr/lib/systemd/systemd", "/lib/systemd/systemd"];

/// What the host does for the entry beyond mounts: tests replace it.
pub trait EntryHost {
    /// Reload the service manager after the drop-in is written.
    fn daemon_reload(&self) -> Result<()>;
    /// Build the hidden NixOS toplevel into the store under `store_root`.
    fn build_hidden_system(
        &self,
        builder: &NixOSBuilder,
        store_root: &Path,
        cache: &Path,
    ) -> Result<PathBuf>;
    /// Copy the closure of `system` that the store under `store_root` still
    /// reads from the decoy store onto the hidden volume (see
    /// [`super::store`]); `record` lists the paths kept before.
    fn keep_hidden_closure(
        &self,
        store_root: &Path,
        system: &Path,
        record: &Path,
    ) -> Result<store::KeepReport>;
    /// Activate `system` chrooted into `root`.
    fn activate_hidden_system(&self, root: &Path, system: &Path) -> Result<()>;
    /// The stop commands `unit` runs with every drop-in loaded, as
    /// `systemctl show --property=ExecStop --value` prints them: empty when it
    /// runs none, or when the unit does not exist.
    fn unit_stop_commands(&self, unit: &str) -> Result<String>;
    /// The units PID 1 holds in the failed state now, recorded in the plan so
    /// the way back resets only the failures the session caused.
    fn failed_units(&self) -> Vec<String> {
        Vec::new()
    }
    /// The kernel's helper paths as the decoy has them now
    /// ([`kernel_helpers::HELPER_PATHS`]), which every way back writes back.
    fn kernel_settings(&self) -> Vec<kernel_helpers::KernelSetting> {
        kernel_helpers::read(&kernel_helpers::HELPER_PATHS)
    }
}

/// The real host.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealEntryHost;

impl EntryHost for RealEntryHost {
    fn unit_stop_commands(&self, unit: &str) -> Result<String> {
        let systemctl = nails_teardown::whole_root::tools::find(None, "systemctl")
            .ok_or_else(|| NailsError::InvalidState("systemctl not found".to_string()))?;
        nails_teardown::whole_root::tools::run_output(
            &systemctl,
            &["show", "--property=ExecStop", "--value", unit],
            std::time::Duration::from_secs(30),
        )
        .ok_or_else(|| NailsError::InvalidState(format!("systemctl show {unit} failed")))
    }

    fn failed_units(&self) -> Vec<String> {
        nails_teardown::whole_root::tools::find(None, "systemctl")
            .and_then(|systemctl| nails_teardown::whole_root::tools::failed_units(&systemctl))
            .unwrap_or_default()
    }

    fn daemon_reload(&self) -> Result<()> {
        let systemctl = nails_teardown::whole_root::tools::find(None, "systemctl")
            .ok_or_else(|| NailsError::InvalidState("systemctl not found".to_string()))?;
        if nails_teardown::whole_root::tools::daemon_reload(&systemctl) {
            Ok(())
        } else {
            Err(NailsError::InvalidState(
                "systemctl daemon-reload failed".to_string(),
            ))
        }
    }

    fn build_hidden_system(
        &self,
        builder: &NixOSBuilder,
        store_root: &Path,
        cache: &Path,
    ) -> Result<PathBuf> {
        let runner = crate::process::RealProcessRunner;
        store::forget_vanished(&runner, store_root);
        nixos::build_into(&runner, builder, store_root, cache)
    }

    fn keep_hidden_closure(
        &self,
        store_root: &Path,
        system: &Path,
        record: &Path,
    ) -> Result<store::KeepReport> {
        let closure = store::closure(&crate::process::RealProcessRunner, store_root, system)?;
        let mounts = read_mountinfo().map_err(|e| io(Path::new("/proc/self/mountinfo"), e))?;
        store::keep_closure(store_root, &closure, record, &mounts)
    }

    fn activate_hidden_system(&self, root: &Path, system: &Path) -> Result<()> {
        nixos::activate_in(root, system)
    }
}

/// What the entry is built from.
pub struct EntryInputs<'a> {
    /// The hidden volume root.
    pub hidden_root: &'a Path,
    /// The decoy root device, as [`decoy_root_of`] reads it.
    pub decoy_root: DecoyRoot,
    /// Whether the host is NixOS.
    pub nixos: bool,
    /// The hidden NixOS configuration to build, if any. `None` on NixOS enters
    /// with the decoy's own system and the hidden `/etc` and home.
    pub builder: Option<&'a NixOSBuilder>,
    /// The running binary, copied to RAM.
    pub binary: &'a Path,
    /// The effective configuration as TOML, copied to RAM.
    pub config_toml: Option<String>,
    /// The hidden session's runtime units.
    pub session_units: Vec<RuntimeUnit>,
    /// The hidden backend's device-mapper names, top first.
    pub backend: Vec<String>,
    /// The persona: fresh home and masks of inherited entries.
    pub persona: crate::config::PersonaConfig,
    /// The operator (from `SUDO_UID`/`SUDO_USER`), whose home the persona
    /// applies to.
    pub operator: Option<crate::target_user::TargetUser>,
    /// The free space a hidden NixOS build needs on the hidden volume, in MB.
    pub rebuild_space_mb: u64,
    /// Keep the disks the session does not use read-only for the session
    /// (`[session_mounts] read_only`).
    pub read_only_disks: bool,
    /// Why the hidden root is not a volume of its own, when the operator
    /// overrode that (recorded in the plan as `accepted_decoy_storage`).
    pub accepted_decoy_storage: Option<String>,
}

/// The prepared entry.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The armed plan, as written.
    pub plan: Plan,
    /// The fstab decisions.
    pub decisions: Vec<Decision>,
    /// Things the operator should know (a hidden kernel mismatch).
    pub warnings: Vec<String>,
}

/// The decoy root device from the mount table: what the way back mounts at
/// `/run/nextroot`. Refuses a root that cannot be mounted again by device: a
/// RAM root (an impermanent decoy), an overlay, a ZFS dataset, or a bind of a
/// subdirectory other than a btrfs subvolume.
pub fn decoy_root_of(entries: &[MountEntry], root: &Path) -> Result<DecoyRoot> {
    let mount = top_mount_at(entries, root)
        .ok_or_else(|| NailsError::InvalidState("the root is not a mount point".to_string()))?;
    let refuse = |why: String| Err(NailsError::InvalidState(why));
    if !mount.source.starts_with("/dev/") {
        return refuse(format!(
            "the decoy root ({} on {}) is not on a block device; a RAM or overlay root cannot be \
             mounted again for the way back",
            mount.fstype,
            mount.source.display()
        ));
    }
    if matches!(
        mount.fstype.as_str(),
        "zfs" | "overlay" | "tmpfs" | "squashfs" | "erofs"
    ) {
        return refuse(format!(
            "a {} decoy root is not supported by the whole-root session",
            mount.fstype
        ));
    }
    let data = if mount.root == Path::new("/") {
        None
    } else if mount.fstype == "btrfs"
        && mount_subvol(mount).is_some_and(|subvol| Path::new(&subvol) == mount.root)
    {
        // A btrfs mount whose root is exactly its `subvol=` is a subvolume: the
        // way back mounts it again with that `subvol=`. A mount root that is a
        // deeper path (a bind of a plain folder inside the subvolume) has no
        // `subvol=` of its own and cannot be mounted again that way, so it is
        // refused like any other bind below.
        if mount.root.to_string_lossy().contains(',') {
            // mount(2) splits its options at every comma, so the way back
            // could not name this subvolume.
            return refuse(format!(
                "the decoy root's btrfs subvolume {} has a comma in its path, which the way \
                 back cannot pass to mount(2) to mount it again",
                mount.root.display()
            ));
        }
        Some(format!("subvol={}", mount.root.display()))
    } else {
        return refuse(format!(
            "the decoy root is a bind of {} on {}",
            mount.root.display(),
            mount.source.display()
        ));
    };
    Ok(DecoyRoot {
        source: mount.source.clone(),
        fstype: mount.fstype.clone(),
        data,
    })
}

/// The `subvol=` a btrfs mount's options name, if any, decoded. btrfs records
/// it in both the per-superblock and the per-mount option fields of the mount
/// table, where the kernel writes a space, tab, newline, comma or backslash in
/// it as an octal escape (`\040`); the mount root it is compared with is
/// decoded already.
fn mount_subvol(mount: &MountEntry) -> Option<String> {
    mount
        .super_opts
        .split(',')
        .chain(mount.mount_opts.split(','))
        .find_map(|opt| opt.strip_prefix("subvol="))
        .map(nails_teardown::mountinfo::unescape_octal)
}

fn io(path: &Path, e: std::io::Error) -> NailsError {
    NailsError::io(path, e)
}

/// Give `dir` the mode and owner of `like`: an overlay's root directory takes
/// its attributes from the upper, so the hidden `/` must look like the decoy's.
fn match_attributes(dir: &Path, like: &Path) -> Result<()> {
    let meta = std::fs::metadata(like).map_err(|e| io(like, e))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(meta.mode() & 0o7777))
        .map_err(|e| io(dir, e))?;
    std::os::unix::fs::chown(dir, Some(meta.uid()), Some(meta.gid())).map_err(|e| io(dir, e))
}

fn make_layer(upper: &Path, work: &Path, like: &Path) -> Result<()> {
    std::fs::create_dir_all(upper).map_err(|e| io(upper, e))?;
    std::fs::create_dir_all(work).map_err(|e| io(work, e))?;
    std::fs::set_permissions(work, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| io(work, e))?;
    match_attributes(upper, like)
}

/// The init PID 1 will execute in `root` on an FHS host.
fn fhs_init(root: &Path) -> PathBuf {
    FHS_INITS
        .iter()
        .map(PathBuf::from)
        .find(|init| nextroot::precheck(root, init).is_ok())
        .unwrap_or_else(|| PathBuf::from(FHS_INITS[0]))
}

/// Undo a failed or abandoned entry: detach `/run/nextroot`, remove the
/// drop-in, the masks the entry transition wrote (an entry whose switch
/// failed) and the runtime directory, and give the kernel back the helper
/// paths a hidden NixOS activation changed. Returns the mounts still left.
pub fn rollback(paths: &Paths) -> Vec<PathBuf> {
    let plan = Plan::load(&paths.plan()).ok();
    let kept = Snapshot::load(&paths.runtime().join(SNAPSHOT_NAME)).unwrap_or_default();
    let remaining = nextroot::detach_tree(&paths.nextroot());
    transition::remove_dropin(&paths.run, &kept);
    if let Some(plan) = &plan {
        runtime_units::remove_masks(&paths.run, &plan.masks, &plan.boot_masks, &kept);
        kernel_helpers::restore(&plan.kernel_settings);
    }
    nextroot::remove_runtime_dir(&paths.runtime());
    if plan.is_some_and(|plan| plan.run_noexec) {
        let _ = nextroot::set_noexec(&paths.run, true);
    }
    remaining
}

/// Prepare the entry. See the module docs.
pub fn prepare(paths: &Paths, inputs: &EntryInputs<'_>, host: &dyn EntryHost) -> Result<Entry> {
    let mut dropin = false;
    let result = build(paths, inputs, host, &mut dropin);
    if result.is_err() {
        rollback(paths);
        if dropin {
            let _ = host.daemon_reload();
        }
    }
    // A Ctrl+C reaches the hidden build's processes too: their failure is
    // the cancel's doing.
    result.map_err(|e| {
        if crate::cancel::is_cancelled() {
            NailsError::Cancelled
        } else {
            e
        }
    })
}

fn write_runtime(paths: &Paths, inputs: &EntryInputs<'_>, snapshot: &Snapshot) -> Result<()> {
    let runtime = paths.runtime();
    std::fs::create_dir_all(&runtime).map_err(|e| io(&runtime, e))?;
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| io(&runtime, e))?;
    let saved_utab = std::fs::read(paths.run.join(utab::UTAB)).unwrap_or_default();
    // Read after the copy, so every mount it names by ID is in it: the way
    // back finds each one again where it was (`utab::restored_lines`).
    let mountinfo = std::fs::read_to_string(SELF_MOUNTINFO).unwrap_or_default();
    let named = utab::named_mounts(&saved_utab, &mountinfo).into_bytes();
    for (name, bytes) in [
        (SNAPSHOT_NAME, snapshot.to_text()),
        (UTAB_NAME, saved_utab),
        (UTAB_MOUNTS_NAME, named),
    ] {
        nails_teardown::whole_root::plan::write_private_atomic(&runtime.join(name), &bytes)
            .map_err(|e| io(&runtime.join(name), e))?;
    }
    // The decoy's network identity, for the way back. Best effort: a failure
    // leaves no record, and the way back then leaves the network alone.
    network_state::record(
        Path::new(network::SYS_CLASS_NET),
        Path::new(network::PROC_HOSTNAME),
        Path::new("/etc/hostname"),
        &paths.run,
        &runtime.join(network::RECORD_NAME),
    );
    let copy = paths.binary_copy();
    std::fs::copy(inputs.binary, &copy).map_err(|e| io(&copy, e))?;
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| io(&copy, e))?;
    if let Some(toml) = &inputs.config_toml {
        let path = runtime.join(CONFIG_COPY_NAME);
        nails_teardown::whole_root::plan::write_private_atomic(&path, toml.as_bytes())
            .map_err(|e| io(&path, e))?;
    }
    Ok(())
}

fn skeleton(paths: &Paths, inputs: &EntryInputs<'_>, layout: &Layout) -> Plan {
    let pid = std::process::id();
    let owner = nails_teardown::proc::stat(pid).map(|s| Owner {
        pid,
        start_time: s.start_time,
    });
    let decoy = if inputs.nixos {
        RootSide {
            init: PathBuf::from(nixos::NIXOS_INIT),
            system: nixos::decoy_system(&paths.run),
        }
    } else {
        RootSide {
            init: fhs_init(&paths.root),
            system: None,
        }
    };
    Plan {
        version: PLAN_VERSION,
        hidden_root: inputs.hidden_root.to_path_buf(),
        hidden_dev: None,
        accepted_decoy_storage: inputs.accepted_decoy_storage.clone(),
        upper: layout.upper(),
        work: layout.work(),
        owner,
        decoy_root: inputs.decoy_root.clone(),
        hidden: decoy.clone(),
        decoy,
        policy_mounts: Vec::new(),
        masks: Vec::new(),
        boot_masks: Vec::new(),
        session_units: inputs.session_units.clone(),
        backend: inputs.backend.clone(),
        tools: Tools {
            systemctl: nails_teardown::whole_root::tools::find(None, "systemctl")
                .and_then(|p| std::fs::canonicalize(p).ok()),
            dmsetup: nails_teardown::whole_root::tools::find(None, "dmsetup")
                .and_then(|p| std::fs::canonicalize(p).ok()),
        },
        armed: None,
        entered_at: None,
        run_noexec: false,
        carried: Vec::new(),
        decoy_mounts: Vec::new(),
        read_only_disks: inputs.read_only_disks,
        failed_at_entry: Vec::new(),
        kernel_settings: Vec::new(),
    }
}

/// The device (`major:minor`) of the mount a lookup of `hidden_root` reaches,
/// which the attach gate holds the session's hidden root to.
fn hidden_dev(mounts: &[MountEntry], hidden_root: &Path) -> Option<String> {
    let root = std::fs::canonicalize(hidden_root).unwrap_or_else(|_| hidden_root.to_path_buf());
    top_mount_at(mounts, &root).map(|mount| mount.dev.clone())
}

fn build(
    paths: &Paths,
    inputs: &EntryInputs<'_>,
    host: &dyn EntryHost,
    dropin: &mut bool,
) -> Result<Entry> {
    let nextroot = paths.nextroot();
    let mounts = read_mountinfo().map_err(|e| io(Path::new("/proc/self/mountinfo"), e))?;
    if nextroot::is_mount_point(&mounts, &nextroot) {
        use nails_base::next_step::{NextStep, sudo_line};
        return Err(NailsError::InvalidState(format!(
            "{} is already populated; run `{}` first",
            nextroot.display(),
            sudo_line(NextStep::Recover)
        )));
    }
    let building = inputs.builder.is_some();
    activation_step(ActivationPhase::Runtime, building);
    let snapshot = Snapshot::take(&paths.run);
    write_runtime(paths, inputs, &snapshot)?;
    let layout = Layout::new(inputs.hidden_root);
    let mut plan = skeleton(paths, inputs, &layout);
    plan.hidden_dev = hidden_dev(&mounts, inputs.hidden_root);
    plan.failed_at_entry = host.failed_units();
    // Recorded at every entry, before anything runs: a NixOS activation points
    // the kernel's module loader and firmware path at its own store, the
    // hidden build's as well as a `nixos-rebuild test` in a session entered
    // without one, and every way back writes the decoy's values back.
    plan.kernel_settings = host.kernel_settings();
    // Recorded before it is cleared, so a rollback always knows to set it again.
    plan.run_noexec = nextroot::is_mount_point(&mounts, &paths.run)
        && nextroot::is_noexec(&paths.run).unwrap_or(false);
    plan.write_atomic(&paths.plan())
        .map_err(|e| io(&paths.plan(), e))?;
    if plan.run_noexec {
        nextroot::set_noexec(&paths.run, false).map_err(|e| io(&paths.run, e))?;
    }
    install_transition(paths, host, dropin)?;
    crate::cancel::checkpoint()?;

    activation_step(ActivationPhase::Overlay, building);
    let decoy_mounts = relative_mounts(&mounts, &paths.root);
    if inputs.persona.mode == crate::config::PersonaMode::FreshHome {
        fresh_home(paths, inputs, &layout, &decoy_mounts)?;
    }
    make_layer(&layout.upper(), &layout.work(), &paths.root)?;
    std::fs::create_dir_all(&nextroot).map_err(|e| io(&nextroot, e))?;
    nextroot::overlay_over(
        &paths.root,
        &paths.runtime().join("lower"),
        &layout.upper(),
        &layout.work(),
        &nextroot,
    )
    .map_err(|e| io(&nextroot, e))?;

    activation_step(ActivationPhase::MountPolicy, building);
    // The decoy's own fstab first, read and resolved the way the decoy resolves
    // it: its filesystems (a separate /nix, the VM store) must be in place
    // inside the next root before anything reads the next root's store.
    let decoy_text = super::fstab::read_in_root(&paths.root)
        .map_err(|e| io(&paths.root.join("etc/fstab"), e))?;
    let decoy_fstab = super::fstab::parse_in_root(&decoy_text, &paths.root);
    let mut decided = Decided {
        decisions: decide_fstab(&decoy_fstab, &decoy_mounts, inputs.hidden_root)?,
        fstab: decoy_fstab.clone(),
    };
    plan.policy_mounts = apply_mounts(paths, &layout, &decided.decisions, inputs.hidden_root, &[])?;
    // The hidden systemd resolves the same entries in the next root, where the
    // hidden session's own changes to a symlink on a mount point's path can
    // lead elsewhere: an entry that resolves to another mount point there is
    // decided at that one too, so what the hidden systemd would mount there is
    // masked or put in place as well.
    let elsewhere = resolved_elsewhere(
        &decoy_fstab,
        super::fstab::parse_in_root(&decoy_text, &nextroot),
    );
    decided.add(
        paths,
        &layout,
        &mut plan,
        elsewhere,
        &decoy_mounts,
        inputs.hidden_root,
    )?;
    crate::cancel::checkpoint()?;

    let mut warnings = Vec::new();
    if let Some(builder) = inputs.builder {
        activation_step(ActivationPhase::BuildSystem, building);
        ensure_build_space(&layout.upper(), inputs.rebuild_space_mb)?;
        let system = host.build_hidden_system(builder, &nextroot, &layout.cache())?;
        crate::cancel::checkpoint()?;
        activation_step(ActivationPhase::KeepClosure, building);
        // Before anything runs from it: the decoy may garbage-collect its
        // store before the next session, so the closure is kept on the
        // hidden volume.
        let kept = host.keep_hidden_closure(&nextroot, &system, &layout.store_kept())?;
        tracing::debug!(
            paths = kept.paths,
            copied = kept.copied,
            files = kept.files,
            bytes = kept.bytes,
            seconds = kept.elapsed.as_secs_f64(),
            "hidden system kept on the hidden volume"
        );
        // The last stop before the activation, which runs to its end once it
        // has begun.
        crate::cancel::checkpoint()?;
        activation_step(ActivationPhase::ActivateSystem, building);
        host.activate_hidden_system(&nextroot, &system)?;
        crate::cancel::checkpoint()?;
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
        // too, resolved in the next root as the hidden systemd resolves them,
        // and put in place what the decoy's fstab did not already cover.
        let hidden_text = super::fstab::read_in_root(&nextroot)
            .map_err(|e| io(&nextroot.join("etc/fstab"), e))?;
        let hidden_fstab = super::fstab::parse_in_root(&hidden_text, &nextroot);
        decided.add(
            paths,
            &layout,
            &mut plan,
            hidden_fstab,
            &decoy_mounts,
            inputs.hidden_root,
        )?;
    } else if !inputs.nixos {
        plan.hidden.init = fhs_init(&nextroot);
    }
    activation_step(ActivationPhase::MaskUnits, building);
    plan.masks = policy::masks(&decided.fstab, &decided.decisions);
    plan.boot_masks = super::systemd::units_in_root(&nextroot, policy::BOOT_WRITER_UNITS)
        .into_iter()
        .filter(|unit| !plan.masks.contains(unit))
        .collect();
    if let Some(operator) = &inputs.operator {
        super::persona::write_masks(&nextroot, &inputs.persona, operator);
    }

    activation_step(ActivationPhase::WayBack, building);
    warnings.extend(super::way_back::keep(
        paths,
        &layout,
        &mut plan,
        &decoy_fstab,
        &decoy_mounts,
    )?);
    nextroot::bind(&paths.run, &paths.in_nextroot(Path::new("/run")), false)
        .map_err(|e| io(&nextroot, e))?;
    nextroot::make_below_private(&nextroot).map_err(|e| io(&nextroot, e))?;
    nextroot::precheck(&nextroot, &ret::init_before_repoint(&plan.hidden))
        .map_err(|e| NailsError::InvalidState(e.to_string()))?;
    let missing = super::systemd::missing_soft_reboot_units(&nextroot);
    if !missing.is_empty() {
        return Err(NailsError::InvalidState(format!(
            "the hidden root cannot leave again: it lacks {}. The hidden configuration needs \
             the soft-reboot units; on NixOS add:\n{}",
            missing.join(" and "),
            super::systemd::NIXOS_UNITS_SNIPPET
        )));
    }

    crate::cancel::checkpoint()?;
    activation_step(ActivationPhase::Arm, building);
    plan.armed = Some(Arm::now(Direction::Enter));
    plan.write_atomic(&paths.plan())
        .map_err(|e| io(&paths.plan(), e))?;
    Ok(Entry {
        plan,
        decisions: decided.decisions,
        warnings,
    })
}

/// Refuse a hidden NixOS build when the hidden volume holding `upper` has less
/// than `floor_mb` free: the store delta of a full build is often several GB.
fn ensure_build_space(upper: &Path, floor_mb: u64) -> Result<()> {
    let stat = rustix::fs::statvfs(upper).map_err(|e| io(upper, e.into()))?;
    let available_mb = stat.f_bavail.saturating_mul(stat.f_frsize) / (1024 * 1024);
    if available_mb < floor_mb {
        return Err(NailsError::InvalidState(format!(
            "the hidden volume has {available_mb} MB free; the hidden NixOS build needs \
             {floor_mb} MB (rebuild_space_mb)"
        )));
    }
    Ok(())
}

/// Fresh-home: the operator's home becomes an opaque directory in the upper
/// that covers it (the root upper, or the upper of the decoy filesystem it
/// lives on), created at the first entry.
fn fresh_home(
    paths: &Paths,
    inputs: &EntryInputs<'_>,
    layout: &Layout,
    decoy_mounts: &[MountEntry],
) -> Result<()> {
    let operator = inputs.operator.as_ref().ok_or_else(|| {
        NailsError::InvalidState(
            "persona mode fresh-home needs the operator (run through sudo)".to_string(),
        )
    })?;
    // Resolve the home inside the decoy root first, so a `/home` the decoy
    // keeps at `var/home` places the fresh home at `var/home/<user>` and never
    // creates a directory where the decoy has a symlink.
    let home = nextroot::canonical_in_root(&paths.root, operator.passwd_home());
    let home = home.as_path();
    let mount = decoy_mounts
        .iter()
        .filter(|m| home.starts_with(&m.mount_point))
        .max_by_key(|m| m.mount_point.components().count())
        .map_or(Path::new("/"), |m| m.mount_point.as_path());
    let upper_home = if mount == Path::new("/") {
        layout.in_upper(home)
    } else {
        let rest = home.strip_prefix(mount).unwrap_or(home);
        layout.mount_layers(mount).0.join(rest)
    };
    super::persona::prepare_fresh_home(&upper_home, &paths.decoy(home), operator)?;
    Ok(())
}

/// Install the transition drop-in and reload the service manager.
fn install_transition(paths: &Paths, host: &dyn EntryHost, dropin: &mut bool) -> Result<()> {
    let binary = if paths.is_system() {
        paths.binary_copy()
    } else {
        // Tests: the drop-in names the copy where the real system would run it.
        Path::new(nails_teardown::whole_root::plan::RUNTIME_DIR)
            .join(nails_teardown::whole_root::plan::BINARY_NAME)
    };
    transition::install_dropin(&paths.run, &binary).map_err(|e| io(&paths.run, e))?;
    *dropin = true;
    host.daemon_reload()?;
    check_stop_guards(host)
}

/// Refuse the entry when a guarded unit still runs stop commands once the
/// drop-ins are loaded: a drop-in that sorts after the guard set `ExecStop=`
/// again, and that stop would undo what the switch needs (see
/// [`transition::STOP_GUARDED_UNITS`]). A prefix guard has no unit of its own
/// to ask about; its units carry their stop in the unit file, which every
/// drop-in follows.
fn check_stop_guards(host: &dyn EntryHost) -> Result<()> {
    for unit in transition::STOP_GUARDED_UNITS
        .iter()
        .filter(|unit| !transition::is_unit_prefix(unit))
    {
        let stop = host.unit_stop_commands(unit)?;
        if !stop.trim().is_empty() {
            return Err(NailsError::PreFlightCheckFailed(vec![(
                "stop-guard".to_string(),
                format!(
                    "{unit} would still run a stop command during the switch ({}): a drop-in \
                     that sorts after /run/systemd/system/{unit}.d/{} sets ExecStop= again, \
                     and that stop undoes what the switch needs",
                    stop.trim(),
                    transition::STOP_GUARD_NAME
                ),
                Some(format!(
                    "Remove the ExecStop= from that drop-in (`systemctl cat {unit}` shows \
                     where it is) and activate again"
                )),
            )]));
        }
    }
    Ok(())
}

/// The mounts below `root`, with their mount points made relative to it (as
/// the fstab names them). The identity for the real root.
fn relative_mounts(mounts: &[MountEntry], root: &Path) -> Vec<MountEntry> {
    mounts
        .iter()
        .filter_map(|m| {
            let rest = m.mount_point.strip_prefix(root).ok()?;
            let mut entry = m.clone();
            entry.mount_point = Path::new("/").join(rest);
            Some(entry)
        })
        .collect()
}

/// Decide every entry; an entry with no safe decision refuses the entry. The
/// entries come resolved ([`super::fstab::parse_in_root`]), so a `/home` that
/// the decoy keeps at `var/home` is decided, mounted and masked as `var/home`
/// (`var-home.mount`), the way systemd mounts it.
fn decide_fstab(
    entries: &[FstabEntry],
    mounts: &[MountEntry],
    hidden_root: &Path,
) -> Result<Vec<Decision>> {
    let decisions = policy::decide_all(entries, mounts, hidden_root);
    if let Some(Decision::Refuse { target, reason }) = decisions
        .iter()
        .find(|d| matches!(d, Decision::Refuse { .. }))
    {
        return Err(NailsError::InvalidState(format!(
            "fstab entry {}: {reason}",
            target.display()
        )));
    }
    Ok(decisions)
}

/// The entries of `in_nextroot`, the fstab `decoy` came from resolved in the
/// next root, whose mount point resolves elsewhere than in the decoy root.
fn resolved_elsewhere(decoy: &[FstabEntry], in_nextroot: Vec<FstabEntry>) -> Vec<FstabEntry> {
    in_nextroot
        .into_iter()
        .zip(decoy)
        .filter(|(there, here)| there.file != here.file)
        .map(|(there, _)| there)
        .collect()
}

/// The fstab decisions the entry made, and every entry the hidden systemd may
/// read, resolved: the decoy's, those the next root resolves elsewhere, and
/// those of the hidden generation. The masks are named from these.
struct Decided {
    decisions: Vec<Decision>,
    fstab: Vec<FstabEntry>,
}

impl Decided {
    /// Decide `entries` as well and put in place what they call for that is
    /// not in place yet, recording it in `plan`.
    fn add(
        &mut self,
        paths: &Paths,
        layout: &Layout,
        plan: &mut Plan,
        entries: Vec<FstabEntry>,
        mounts: &[MountEntry],
        hidden_root: &Path,
    ) -> Result<()> {
        let more = decide_fstab(&entries, mounts, hidden_root)?;
        let done: Vec<PathBuf> = plan
            .policy_mounts
            .iter()
            .map(|m| m.target.clone())
            .collect();
        let added = apply_mounts(paths, layout, &more, hidden_root, &done)?;
        plan.policy_mounts.extend(added);
        for decision in more {
            if !self.decisions.contains(&decision) {
                self.decisions.push(decision);
            }
        }
        self.fstab.extend(entries);
        Ok(())
    }
}

/// The mount point `target` (absolute, as the hidden root sees it) inside the
/// next root, created where missing: resolved as the hidden root will resolve
/// it, so an absolute symlink on the way (a decoy whose `/mnt` links
/// elsewhere) stays inside the next root, and returned as a path without
/// symlinks for the mount calls. A plain path would follow such a link on the
/// running system and mount, or create a directory, on the decoy.
pub(super) fn target_in_nextroot(paths: &Paths, target: &Path) -> Result<PathBuf> {
    let nextroot = paths.nextroot();
    let shown = paths.in_nextroot(target);
    let real = nextroot::create_dir_all_in_root(&nextroot, target, &mut |_, _| Ok(()))
        .and_then(|fd| nextroot::real_path(&fd))
        .map_err(|e| io(&shown, e))?;
    let root = nextroot::open_dir_in_root(&nextroot, Path::new("/"))
        .and_then(|fd| nextroot::real_path(&fd))
        .map_err(|e| io(&nextroot, e))?;
    if !real.starts_with(&root) {
        return Err(NailsError::InvalidState(format!(
            "{} resolves to {}, outside the next root",
            shown.display(),
            real.display()
        )));
    }
    Ok(real)
}

/// Put the mounts `decisions` call for in place inside the next root, parents
/// first, skipping the targets in `done`. The hidden volume is bound unless it
/// is in `done` already.
fn apply_mounts(
    paths: &Paths,
    layout: &Layout,
    decisions: &[Decision],
    hidden_root: &Path,
    done: &[PathBuf],
) -> Result<Vec<PolicyMount>> {
    let mut wanted: Vec<PolicyMount> = decisions
        .iter()
        .filter_map(|d| match d {
            Decision::ReadOnlyBind { target } => Some(PolicyMount {
                target: target.clone(),
                kind: PolicyMountKind::ReadOnlyBind,
            }),
            Decision::Overlay { target } => Some(PolicyMount {
                target: target.clone(),
                kind: PolicyMountKind::Overlay,
            }),
            _ => None,
        })
        .collect();
    wanted.push(PolicyMount {
        target: hidden_root.to_path_buf(),
        kind: PolicyMountKind::HiddenVolume,
    });
    wanted.retain(|m| !done.contains(&m.target));
    wanted.sort_by_key(|m| m.target.components().count());
    let first = done.len();
    for (offset, mount) in wanted.iter().enumerate() {
        let index = first + offset;
        let source = if mount.kind == PolicyMountKind::HiddenVolume {
            mount.target.clone()
        } else {
            paths.decoy(&mount.target)
        };
        let target = target_in_nextroot(paths, &mount.target)?;
        let done = match mount.kind {
            PolicyMountKind::ReadOnlyBind => nextroot::bind_read_only(&source, &target),
            PolicyMountKind::HiddenVolume => nextroot::bind(&source, &target, false),
            PolicyMountKind::Overlay => {
                let (upper, work) = layout.mount_layers(&mount.target);
                make_layer(&upper, &work, &source)?;
                nextroot::overlay_over(
                    &source,
                    &paths.runtime().join(format!("lower-{index}")),
                    &upper,
                    &work,
                    &target,
                )
                .and_then(|()| nextroot::make_private(&target))
            }
        };
        done.map_err(|e| io(&target, e))?;
    }
    Ok(wanted)
}

#[cfg(test)]
#[path = "entry_tests.rs"]
mod tests;
