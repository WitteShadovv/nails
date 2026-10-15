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
//! 7. `/run` bound in and the tree made private; the init checked the way
//!    PID 1 will, and the soft-reboot units the way back needs found in the
//!    next root;
//! 8. the plan armed for the entry.
//!
//! Any failure undoes all of it ([`rollback`]): a populated `/run/nextroot`
//! must never be left behind, or a later plain reboot would enter it.

use super::layout::{Layout, Paths};
use super::nixos;
use super::policy::{self, Decision};
use super::store;
use crate::error::{NailsError, Result};
use crate::nixos::NixOSBuilder;
use nails_teardown::mountinfo::{MountEntry, read_mountinfo, top_mount_at};
use nails_teardown::whole_root::nextroot;
use nails_teardown::whole_root::plan::{
    Arm, CarriedMount, DecoyRoot, Direction, Owner, PLAN_VERSION, Plan, PolicyMount,
    PolicyMountKind, RootSide, SNAPSHOT_NAME, Tools, UTAB_NAME,
};
use nails_teardown::whole_root::run_scrub::{Snapshot, UTAB};
use nails_teardown::whole_root::runtime_units::RuntimeUnit;
use nails_teardown::whole_root::{carry, ret, transition};
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
    } else if mount.fstype == "btrfs" {
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
/// drop-in and the runtime directory. Returns the mounts still left.
pub fn rollback(paths: &Paths) -> Vec<PathBuf> {
    let run_noexec = Plan::load(&paths.plan()).is_ok_and(|plan| plan.run_noexec);
    let remaining = nextroot::detach_tree(&paths.nextroot());
    transition::remove_dropin(&paths.run);
    nextroot::remove_runtime_dir(&paths.runtime());
    if run_noexec {
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
    result
}

fn write_runtime(paths: &Paths, inputs: &EntryInputs<'_>, snapshot: &Snapshot) -> Result<()> {
    let runtime = paths.runtime();
    std::fs::create_dir_all(&runtime).map_err(|e| io(&runtime, e))?;
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| io(&runtime, e))?;
    let utab = std::fs::read(paths.run.join(UTAB)).unwrap_or_default();
    for (name, bytes) in [(SNAPSHOT_NAME, snapshot.to_text()), (UTAB_NAME, utab)] {
        nails_teardown::whole_root::plan::write_private_atomic(&runtime.join(name), &bytes)
            .map_err(|e| io(&runtime.join(name), e))?;
    }
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
        read_only_disks: inputs.read_only_disks,
        failed_at_entry: Vec::new(),
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
        return Err(NailsError::InvalidState(format!(
            "{} is already populated; run `nails recover` first",
            nextroot.display()
        )));
    }
    let snapshot = Snapshot::take(&paths.run);
    write_runtime(paths, inputs, &snapshot)?;
    let layout = Layout::new(inputs.hidden_root);
    let mut plan = skeleton(paths, inputs, &layout);
    plan.hidden_dev = hidden_dev(&mounts, inputs.hidden_root);
    plan.failed_at_entry = host.failed_units();
    // Recorded before it is cleared, so a rollback always knows to set it again.
    plan.run_noexec = nextroot::is_mount_point(&mounts, &paths.run)
        && nextroot::is_noexec(&paths.run).unwrap_or(false);
    plan.write_atomic(&paths.plan())
        .map_err(|e| io(&paths.plan(), e))?;
    if plan.run_noexec {
        nextroot::set_noexec(&paths.run, false).map_err(|e| io(&paths.run, e))?;
    }
    install_transition(paths, host, dropin)?;

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

    // The decoy's own fstab first, read the way the decoy resolves it: its
    // filesystems (a separate /nix, the VM store) must be in place inside the
    // next root before anything reads the next root's store.
    let decoy_fstab =
        nextroot::read_in_root(&paths.root, Path::new("/etc/fstab")).unwrap_or_default();
    let mut decisions = decide_fstab(&decoy_fstab, &decoy_mounts, inputs.hidden_root)?;
    plan.policy_mounts = apply_mounts(paths, &layout, &decisions, inputs.hidden_root, &[])?;

    let mut warnings = Vec::new();
    if let Some(builder) = inputs.builder {
        ensure_build_space(&layout.upper(), inputs.rebuild_space_mb)?;
        let system = host.build_hidden_system(builder, &nextroot, &layout.cache())?;
        // Before anything runs from it: the decoy may garbage-collect its
        // store before the next session, so the closure is kept on the
        // hidden volume.
        let kept = host.keep_hidden_closure(&nextroot, &system, &layout.store_kept())?;
        tracing::info!(
            paths = kept.paths,
            copied = kept.copied,
            files = kept.files,
            bytes = kept.bytes,
            seconds = kept.elapsed.as_secs_f64(),
            "hidden system kept on the hidden volume"
        );
        host.activate_hidden_system(&nextroot, &system)?;
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
        // too, and put in place what the decoy's fstab did not already cover.
        let hidden_fstab =
            nextroot::read_in_root(&nextroot, Path::new("/etc/fstab")).unwrap_or_default();
        let hidden = decide_fstab(&hidden_fstab, &decoy_mounts, inputs.hidden_root)?;
        let done: Vec<PathBuf> = plan
            .policy_mounts
            .iter()
            .map(|m| m.target.clone())
            .collect();
        let added = apply_mounts(paths, &layout, &hidden, inputs.hidden_root, &done)?;
        plan.policy_mounts.extend(added);
        for decision in hidden {
            if !decisions.contains(&decision) {
                decisions.push(decision);
            }
        }
    } else if !inputs.nixos {
        plan.hidden.init = fhs_init(&nextroot);
    }
    plan.masks = policy::masked_units(&decisions);
    plan.masks.dedup();
    if let Some(operator) = &inputs.operator {
        let home = paths.in_nextroot(operator.passwd_home());
        super::persona::write_masks(&home, &inputs.persona, operator);
    }

    plan.carried = carry_decoy_mounts(paths, &layout, &plan.policy_mounts, &decoy_mounts)?;
    nextroot::bind(&paths.run, &paths.in_nextroot(Path::new("/run")), false)
        .map_err(|e| io(&nextroot, e))?;
    nextroot::make_rprivate(&nextroot).map_err(|e| io(&nextroot, e))?;
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

    plan.armed = Some(Arm::now(Direction::Enter));
    plan.write_atomic(&paths.plan())
        .map_err(|e| io(&paths.plan(), e))?;
    Ok(Entry {
        plan,
        decisions,
        warnings,
    })
}

/// Carry every decoy filesystem the fstab policy placed into the hidden
/// session, so the way back can put it in place again (see
/// [`nails_teardown::whole_root::carry`]).
fn carry_decoy_mounts(
    paths: &Paths,
    layout: &Layout,
    policy_mounts: &[PolicyMount],
    decoy_mounts: &[MountEntry],
) -> Result<Vec<CarriedMount>> {
    let mut carried = Vec::new();
    for mount in policy_mounts {
        if mount.kind == PolicyMountKind::HiddenVolume {
            continue;
        }
        let at = layout.carried(&mount.target);
        let in_nextroot = paths.in_nextroot(&at);
        carry::carry(&paths.decoy(&mount.target), &at, &in_nextroot)
            .map_err(|e| io(&in_nextroot, e))?;
        carried.push(CarriedMount {
            read_only: top_mount_at(decoy_mounts, &mount.target).is_some_and(MountEntry::read_only),
            target: mount.target.clone(),
            at,
        });
    }
    Ok(carried)
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
    let home = operator.passwd_home();
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

/// Parse `fstab` and decide every entry; an entry with no safe decision
/// refuses the entry.
fn decide_fstab(fstab: &[u8], mounts: &[MountEntry], hidden_root: &Path) -> Result<Vec<Decision>> {
    let entries = super::fstab::parse_fstab(&String::from_utf8_lossy(fstab));
    let decisions = policy::decide_all(&entries, mounts, hidden_root);
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
        let target = paths.in_nextroot(&mount.target);
        std::fs::create_dir_all(&target).map_err(|e| io(&target, e))?;
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
            }
        };
        done.map_err(|e| io(&target, e))?;
    }
    Ok(wanted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_teardown::mountinfo::parse_mountinfo;

    #[test]
    fn the_decoy_root_is_read_from_the_mount_table() {
        let ext4 = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");
        let root = decoy_root_of(&ext4, Path::new("/")).unwrap();
        assert_eq!(root.source, Path::new("/dev/vda2"));
        assert_eq!(root.fstype, "ext4");
        assert_eq!(root.data, None);
        let btrfs = parse_mountinfo("1 0 0:30 /@ / rw - btrfs /dev/nvme0n1p2 rw,subvol=/@\n");
        assert_eq!(
            decoy_root_of(&btrfs, Path::new("/"))
                .unwrap()
                .data
                .as_deref(),
            Some("subvol=/@")
        );
    }

    /// A host that only answers the stop-command query.
    struct StopHost(&'static str);

    impl EntryHost for StopHost {
        fn daemon_reload(&self) -> Result<()> {
            Ok(())
        }
        fn build_hidden_system(&self, _: &NixOSBuilder, _: &Path, _: &Path) -> Result<PathBuf> {
            unreachable!("not used by the stop-guard check")
        }
        fn keep_hidden_closure(&self, _: &Path, _: &Path, _: &Path) -> Result<store::KeepReport> {
            unreachable!("not used by the stop-guard check")
        }
        fn activate_hidden_system(&self, _: &Path, _: &Path) -> Result<()> {
            unreachable!("not used by the stop-guard check")
        }
        fn unit_stop_commands(&self, _: &str) -> Result<String> {
            Ok(self.0.to_string())
        }
    }

    #[test]
    fn a_prefix_guard_is_not_asked_about_by_name() {
        /// Answers with a stop command for anything but blk-availability.
        struct PrefixOnly;
        impl EntryHost for PrefixOnly {
            fn daemon_reload(&self) -> Result<()> {
                Ok(())
            }
            fn build_hidden_system(&self, _: &NixOSBuilder, _: &Path, _: &Path) -> Result<PathBuf> {
                unreachable!()
            }
            fn keep_hidden_closure(
                &self,
                _: &Path,
                _: &Path,
                _: &Path,
            ) -> Result<store::KeepReport> {
                unreachable!()
            }
            fn activate_hidden_system(&self, _: &Path, _: &Path) -> Result<()> {
                unreachable!()
            }
            fn unit_stop_commands(&self, unit: &str) -> Result<String> {
                assert!(
                    !unit.ends_with("-.service"),
                    "asked about the prefix {unit}"
                );
                Ok(if unit == "blk-availability.service" {
                    String::new()
                } else {
                    "{ path=/bin/true }".to_string()
                })
            }
        }
        assert!(check_stop_guards(&PrefixOnly).is_ok());
    }

    #[test]
    fn a_stop_command_left_after_the_guard_refuses_the_entry() {
        assert!(check_stop_guards(&StopHost("\n")).is_ok());
        let error = check_stop_guards(&StopHost(
            "{ path=/usr/sbin/blkdeactivate ; argv[]=/usr/sbin/blkdeactivate -u ; }\n",
        ))
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("blk-availability.service"), "{text}");
        assert!(text.contains("zz-overlay-runtime.conf"), "{text}");
        assert!(matches!(error, NailsError::PreFlightCheckFailed(_)));
    }

    #[test]
    fn a_build_is_refused_below_the_space_floor() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ensure_build_space(dir.path(), 0).is_ok());
        let error = ensure_build_space(dir.path(), u64::MAX).unwrap_err();
        assert!(error.to_string().contains("rebuild_space_mb"), "{error}");
    }

    #[test]
    fn a_root_that_cannot_be_mounted_again_is_refused() {
        for table in [
            "1 0 0:20 / / rw - tmpfs none rw\n",
            "1 0 0:21 / / rw - overlay overlay rw,lowerdir=/a\n",
            "1 0 0:22 / / rw - zfs /dev/zd0 rw\n",
            "1 0 8:2 /sub / rw - ext4 /dev/vda2 rw\n",
        ] {
            let entries = parse_mountinfo(table);
            assert!(decoy_root_of(&entries, Path::new("/")).is_err(), "{table}");
        }
    }
}
