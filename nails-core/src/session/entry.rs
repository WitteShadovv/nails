// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Preparing the entry into the hidden root (ADR 0008, sections 2 and 3).
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
//! 5. on NixOS with a hidden configuration: the hidden toplevel built into the
//!    next root's store and activated chrooted (see [`super::nixos`]);
//! 6. the fstab policy on the next root's own fstab ([`super::policy`]): the
//!    hidden volume bound at its path, boot filesystems read-only, other decoy
//!    filesystems overlaid, the rest masked at entry;
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
use crate::error::{NailsError, Result};
use crate::nixos::NixOSBuilder;
use nails_teardown::mountinfo::{MountEntry, read_mountinfo, top_mount_at};
use nails_teardown::whole_root::nextroot;
use nails_teardown::whole_root::plan::{
    Arm, DecoyRoot, Direction, Owner, PLAN_VERSION, Plan, PolicyMount, PolicyMountKind, RootSide,
    SNAPSHOT_NAME, Tools, UTAB_NAME,
};
use nails_teardown::whole_root::run_scrub::{Snapshot, UTAB};
use nails_teardown::whole_root::runtime_units::RuntimeUnit;
use nails_teardown::whole_root::{ret, transition};
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
    /// Activate `system` chrooted into `root`.
    fn activate_hidden_system(&self, root: &Path, system: &Path) -> Result<()>;
}

/// The real host.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealEntryHost;

impl EntryHost for RealEntryHost {
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
        nixos::build_into(
            &crate::process::RealProcessRunner,
            builder,
            store_root,
            cache,
        )
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
    let _ = std::fs::remove_dir_all(paths.runtime());
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
    }
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

    let mut warnings = Vec::new();
    if let Some(builder) = inputs.builder {
        let system = host.build_hidden_system(builder, &nextroot, &layout.cache())?;
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
    } else if !inputs.nixos {
        plan.hidden.init = fhs_init(&nextroot);
    }

    let fstab = nextroot::read_in_root(&nextroot, Path::new("/etc/fstab")).unwrap_or_default();
    let entries = super::fstab::parse_fstab(&String::from_utf8_lossy(&fstab));
    let decisions = policy::decide_all(&entries, &decoy_mounts, inputs.hidden_root);
    if let Some(Decision::Refuse { target, reason }) = decisions
        .iter()
        .find(|d| matches!(d, Decision::Refuse { .. }))
    {
        return Err(NailsError::InvalidState(format!(
            "fstab entry {}: {reason}",
            target.display()
        )));
    }
    plan.policy_mounts = apply_mounts(paths, &layout, &decisions, inputs.hidden_root)?;
    plan.masks = policy::masked_units(&decisions);
    if let Some(operator) = &inputs.operator {
        let home = paths.in_nextroot(operator.passwd_home());
        super::persona::write_masks(&home, &inputs.persona, operator);
    }

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
    host.daemon_reload()
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

/// Put the fstab decisions and the hidden volume in place inside the next
/// root, parents first.
fn apply_mounts(
    paths: &Paths,
    layout: &Layout,
    decisions: &[Decision],
    hidden_root: &Path,
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
    wanted.sort_by_key(|m| m.target.components().count());
    for (index, mount) in wanted.iter().enumerate() {
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
