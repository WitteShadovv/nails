// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Leaving the hidden root the orderly way (`nails deactivate`).
//!
//! In the hidden session: unmount the disks the session mounted itself (a USB
//! drive, a decoy partition mounted by hand), mount the decoy root at
//! `/run/nextroot` with `/run` bound in, check its init, mark the hidden backend for deferred removal, arm
//! the plan and enqueue `soft-reboot.target`. The orderly shutdown stops every
//! hidden unit (applications flush, the hidden journal reaches the upper), the
//! transition scrubs `/run` and writes the kmsg cursor, and PID 1 switches back
//! into the plain decoy root. The hidden volume is detached with the old root
//! and its mapping closes on its own, because it was marked for deferred
//! removal: nothing of the hidden session survives the switch. `--poweroff`
//! powers off instead, and needs no way back.

use super::layout::Paths;
use crate::error::{NailsError, Result};
use nails_teardown::mountinfo::{MountEntry, read_mountinfo};
use nails_teardown::whole_root::nextroot;
use nails_teardown::whole_root::plan::{PLAN_NAME, Plan, RUNTIME_DIR};
use nails_teardown::whole_root::{disk_guard, logind, network, ret, tools};
use rustix::mount::UnmountFlags;
use std::path::{Path, PathBuf};

/// Enqueues a systemd target: tests replace it.
pub trait TargetHost {
    /// Enqueue `target`. An error means it is known not to have been taken:
    /// nothing is left that would start it later.
    fn start_target(&self, target: &str) -> Result<()>;
    /// Refuse to end the session while a program blocks shutdown outright:
    /// it is in the middle of something the switch would cut short.
    fn may_switch(&self) -> Result<()> {
        Ok(())
    }
}

/// The real host, through the plan's `systemctl` and the system's `busctl`.
#[derive(Debug, Clone)]
pub struct RealTargetHost {
    systemctl: Option<PathBuf>,
    busctl: Option<PathBuf>,
    /// The session plan, which a soft-reboot waits on only while it is armed.
    plan: PathBuf,
    /// What kills the interactive shells around the soft-reboot: the entry's
    /// does, the way back's does not.
    kill_shells: Option<fn()>,
}

/// SIGKILL every interactive shell on the decoy, the invocation's own last.
fn kill_decoy_shells() {
    nails_teardown::shells::kill_all_interactive_shells(&[]);
}

impl RealTargetHost {
    /// The host for `plan` (its recorded `systemctl`, else the system's).
    pub fn for_plan(plan: Option<&Plan>) -> Self {
        Self {
            systemctl: tools::find(plan.and_then(|p| p.tools.systemctl.as_deref()), "systemctl"),
            busctl: tools::find(plan.and_then(|p| p.tools.busctl.as_deref()), logind::BUSCTL),
            plan: Path::new(RUNTIME_DIR).join(PLAN_NAME),
            kill_shells: None,
        }
    }

    /// The host of an entry, which kills the decoy's interactive shells
    /// around its soft-reboot. Stopping a login session sends its shells
    /// SIGHUP, on which bash writes its history (on the decoy: to the decoy
    /// disk), and the switch stops them the moment PID 1 holds its job. So
    /// the shells die right before logind is asked, then again between two
    /// looks while logind holds the soft-reboot back (the desktop runs on
    /// meanwhile, and a shell opened then lives about a tenth of a second,
    /// too short to have anything to write), and once more when PID 1 holds
    /// the job.
    pub fn killing_shells(mut self) -> Self {
        self.kill_shells = Some(kill_decoy_shells);
        self
    }

    /// The soft-reboot of the entry or of the way back, through logind as
    /// `systemctl soft-reboot` does ([`logind::request_soft_reboot`]): the
    /// programs waiting for its shutdown signal end on it first. `Ok` once
    /// PID 1 holds the job. While it waits, an activation stays the plan's
    /// owner, so `status` reports the entry under way and `recover` leaves it
    /// alone; once the plan is no longer armed (an emergency on the decoy took
    /// the entry down), the wait is called off.
    fn soft_reboot(&self, systemctl: &Path) -> Result<()> {
        let kill_shells = || {
            if let Some(kill) = self.kill_shells {
                kill();
            }
        };
        kill_shells();
        let mut wanted = || match Plan::load(&self.plan) {
            Ok(plan) if plan.armed.is_some() => {
                kill_shells();
                logind::Wanted::Yes
            }
            _ => logind::Wanted::No("the switch was called off".to_string()),
        };
        match logind::request_soft_reboot(
            systemctl,
            self.busctl.as_deref(),
            logind::Waits::SWITCH,
            &mut wanted,
        ) {
            logind::Request::Queued => {
                kill_shells();
                Ok(())
            }
            logind::Request::Refused(why) | logind::Request::Held(why) => Err(
                NailsError::InvalidState(format!("the soft-reboot was not started: {why}")),
            ),
        }
    }
}

impl TargetHost for RealTargetHost {
    fn may_switch(&self) -> Result<()> {
        let blocked = logind::blocking(self.busctl.as_deref(), self.systemctl.as_deref());
        let why = blocked.refusal();
        match (blocked, why) {
            (logind::Blocking::By(_), Some(why)) => Err(NailsError::InvalidState(format!(
                "{why}: the switch would cut it short. Let it finish, then try again"
            ))),
            (logind::Blocking::Unknown, Some(why)) => Err(NailsError::InvalidState(format!(
                "{why}, and the switch would cut such a program short. Try again once logind \
                 answers"
            ))),
            _ => Ok(()),
        }
    }

    fn start_target(&self, target: &str) -> Result<()> {
        let systemctl = self
            .systemctl
            .as_deref()
            .ok_or_else(|| NailsError::InvalidState("systemctl not found".to_string()))?;
        if target == tools::SOFT_REBOOT_TARGET {
            return self.soft_reboot(systemctl);
        }
        // A power-off is enqueued with PID 1 directly. A call cut short (by
        // the very stop it enqueued, typically) counts as enqueued.
        match tools::start_target(systemctl, target) {
            tools::Outcome::Done | tools::Outcome::Unknown => Ok(()),
            tools::Outcome::Refused => Err(NailsError::InvalidState(format!(
                "systemctl could not enqueue {target}"
            ))),
        }
    }
}

/// How the session ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaveTo {
    /// Soft-reboot back into the plain decoy root.
    Decoy,
    /// Power off.
    Poweroff,
}

/// What [`leave`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeaveReport {
    /// Device-mapper names marked for deferred removal, with the result.
    pub deferred: Vec<(String, bool)>,
    /// Disks mounted during the session that were unmounted (or, busy,
    /// detached) before the way back.
    pub unmounted: Vec<PathBuf>,
}

impl LeaveReport {
    /// The hidden backend's device-mapper devices whose mark for deferred
    /// removal did not take (no `dmsetup`, or it refused), top first: they
    /// stay open after the switch, their key in RAM, until power-off.
    pub fn left_open(&self) -> Vec<String> {
        self.deferred
            .iter()
            .filter(|(_, marked)| !marked)
            .map(|(name, _)| name.clone())
            .collect()
    }
}

/// The disks mounted during the session, deepest first: every mount under
/// `paths.root` backed by a block device (`is_block`) that is not the
/// session's own (inside the hidden volume, the decoy root at
/// `/run/nextroot`, or a policy target such as the read-only ESP).
pub fn session_disk_mounts(
    paths: &Paths,
    plan: &Plan,
    mounts: &[MountEntry],
    is_block: &dyn Fn(&MountEntry) -> bool,
) -> Vec<PathBuf> {
    let nextroot = paths.nextroot();
    let policy: Vec<PathBuf> = plan
        .policy_mounts
        .iter()
        .map(|m| paths.decoy(&m.target))
        .collect();
    let mut found: Vec<PathBuf> = mounts
        .iter()
        .filter(|m| {
            m.mount_point.starts_with(&paths.root)
                && m.mount_point != paths.root
                && !m.mount_point.starts_with(&plan.hidden_root)
                && !m.mount_point.starts_with(&nextroot)
                && !policy.contains(&m.mount_point)
                && is_block(m)
        })
        .map(|m| m.mount_point.clone())
        .collect();
    found.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    found.dedup();
    found
}

/// Unmount the disks mounted during the session before the way back,
/// so a filesystem the decoy mounts again is not still held, read-only, by the
/// hidden session. A busy mount is detached instead; the soft-reboot ends its
/// users.
fn unmount_session_disks(paths: &Paths, plan: &Plan) -> Vec<PathBuf> {
    let mounts = read_mountinfo().unwrap_or_default();
    let is_block = |m: &MountEntry| disk_guard::mount_device(m).is_some();
    session_disk_mounts(paths, plan, &mounts, &is_block)
        .into_iter()
        .filter(|target| {
            rustix::mount::unmount(target, UnmountFlags::empty()).is_ok()
                || rustix::mount::unmount(target, UnmountFlags::DETACH).is_ok()
        })
        .collect()
}

/// A tool the last step of the way back runs to put the decoy's network state
/// back ([`network::restore`]). Where the step does not find one, it leaves
/// that tool's part of the state as the session left it, until power-off, but
/// for what it sees without the tool (a device's changed MAC address, a link
/// still there): over that it powers off instead of returning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkTool {
    /// `ip` (iproute2), which deletes the virtual links and the policy-routing
    /// rules the session added and sets each device's recorded MAC address
    /// back.
    Ip,
    /// `nft` (nftables), which deletes the nftables tables the session added.
    /// Entry lists the decoy's own tables with it, in the decoy: without that
    /// list the step cannot tell the session's tables from the decoy's, and
    /// deletes none.
    Nft,
    /// `iw`, which deletes the Wi-Fi interfaces the session added on one of
    /// the decoy's radios (a monitor or access point interface, or the one iwd
    /// makes in place of the decoy's by default).
    Iw,
}

impl NetworkTool {
    /// Every one, in the order a report names them.
    pub const ALL: [Self; 3] = [Self::Ip, Self::Nft, Self::Iw];

    /// The command the step runs, by the name it looks for.
    pub fn command(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Nft => "nft",
            Self::Iw => "iw",
        }
    }
}

/// Whether the last step of the way back will find `tool`, such as `ip`
/// (iproute2), which it runs to delete the virtual links and the
/// policy-routing rules the session added and to set each device's recorded
/// MAC address back. The step runs in the hidden root (`root`: `/`, but in
/// tests) once every hidden unit has stopped, and on NixOS only after it
/// repointed `/run/current-system` to the decoy's system (`decoy_system`, as
/// the plan records it): it looks in the system directories as they resolve
/// then ([`tools::find_for_system`]). It cannot report anything itself, so the
/// hidden session checks before the switch.
pub fn way_back_finds(root: &Path, decoy_system: Option<&Path>, tool: &str) -> bool {
    tools::find_for_system(root, decoy_system, tool).is_some()
}

/// The [network tools](NetworkTool) the last step of the way back runs on this
/// machine and will not find where it looks ([`way_back_finds`]), in the order
/// of [`NetworkTool::ALL`]. It runs `iw` only to delete a Wi-Fi interface on
/// one of the decoy's radios, so `iw` counts only where a link the kernel
/// lists below the tree's `/sys/class/net` is a Wi-Fi interface, read as entry
/// reads the links ([`network::observe_links`]).
///
/// In the hidden session `decoy_system` is the decoy's system its plan records.
/// Before a session, in the decoy, it is the system `/run/current-system`
/// names now, which entry records: the directories are then also those entry
/// looks for the `nft` in that it lists the decoy's own firewall tables with.
pub fn way_back_lacks(root: &Path, decoy_system: Option<&Path>) -> Vec<NetworkTool> {
    let links = root.join(network::SYS_CLASS_NET.trim_start_matches('/'));
    let wifi = network::observe_links(&links)
        .is_some_and(|links| links.iter().any(|link| link.phy.is_some()));
    NetworkTool::ALL
        .into_iter()
        .filter(|tool| wifi || *tool != NetworkTool::Iw)
        .filter(|tool| !way_back_finds(root, decoy_system, tool.command()))
        .collect()
}

/// Prepare the way back and enqueue the soft-reboot (or power off).
pub fn leave(
    paths: &Paths,
    plan: &mut Plan,
    to: LeaveTo,
    host: &dyn TargetHost,
) -> Result<LeaveReport> {
    // Before anything is prepared for the switch, so a refusal leaves the
    // session as it was.
    host.may_switch()?;
    if to == LeaveTo::Poweroff {
        host.start_target("poweroff.target")?;
        return Ok(LeaveReport::default());
    }
    let unmounted = unmount_session_disks(paths, plan);
    let nextroot = paths.nextroot();
    if let Err(e) = ret::mount_decoy_root(plan, &nextroot, &paths.run) {
        return Err(still_unmounted(
            NailsError::InvalidState(e.to_string()),
            &unmounted,
        ));
    }
    let deferred = ret::close_backend_deferred(plan);
    let armed = ret::arm_leave(plan, &paths.plan())
        .map_err(|e| NailsError::InvalidState(e.to_string()))
        .and_then(|()| host.start_target(tools::SOFT_REBOOT_TARGET));
    if let Err(e) = armed {
        nextroot::detach_tree(&nextroot);
        plan.armed = None;
        let _ = plan.write_atomic(&paths.plan());
        return Err(still_unmounted(e, &unmounted));
    }
    Ok(LeaveReport {
        deferred,
        unmounted,
    })
}

/// `error` of a way back that did not start, which leaves the session running
/// without the disks it unmounted for the switch (`unmounted`): it says so,
/// naming them.
fn still_unmounted(error: NailsError, unmounted: &[PathBuf]) -> NailsError {
    if unmounted.is_empty() {
        return error;
    }
    let list: Vec<String> = unmounted.iter().map(|p| p.display().to_string()).collect();
    let note = format!(
        "The session goes on, but the disks it had mounted stay unmounted ({}): mount them \
         again to use them",
        list.join(", ")
    );
    match error {
        NailsError::InvalidState(why) => NailsError::InvalidState(format!("{why}. {note}")),
        other => NailsError::InvalidState(format!("{other}. {note}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_teardown::mountinfo::parse_mountinfo;
    use nails_teardown::whole_root::plan::{PolicyMount, PolicyMountKind};

    fn plan() -> Plan {
        let text = r#"{"version":2,"hidden_root":"/mnt/data","upper":"/mnt/data/root/upper",
            "work":"/mnt/data/root/work","decoy_root":{"source":"/dev/vda2","fstype":"ext4"},
            "decoy":{"init":"/sbin/init"},"hidden":{"init":"/sbin/init"}}"#;
        let mut plan = Plan::from_json(text).unwrap();
        plan.policy_mounts = vec![PolicyMount {
            target: PathBuf::from("/boot"),
            kind: PolicyMountKind::ReadOnlyBind,
        }];
        plan
    }

    /// A real host on a stand-in `systemctl` that records its calls in
    /// `calls` and answers `soft-reboot` with `soft_reboot` (shell code), and
    /// an armed plan.
    fn real_host(dir: &Path, soft_reboot: &str) -> RealTargetHost {
        let d = dir.display();
        let systemctl = dir.join("systemctl");
        nails_base::test_support::write_executable(
            &systemctl,
            format!(
                "#!/bin/sh\necho \"$*\" >> {d}/calls\n\
                 case \"$*\" in\n\
                 '--no-wall soft-reboot') {soft_reboot} ;;\n\
                 list-jobs*) [ -e {d}/job ] \
                 && echo '7 soft-reboot.target start waiting'; exit 0 ;;\n\
                 esac\nexit 0\n"
            ),
            0o755,
        );
        let plan_path = dir.join("plan.json");
        let mut armed = plan();
        armed.armed = Some(nails_teardown::whole_root::plan::Arm::now(
            nails_teardown::whole_root::plan::Direction::Leave,
        ));
        armed.write_atomic(&plan_path).unwrap();
        RealTargetHost {
            systemctl: Some(systemctl),
            busctl: None,
            plan: plan_path,
            kill_shells: None,
        }
    }

    fn calls(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("calls"))
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.starts_with("list-jobs"))
            .map(str::to_string)
            .collect()
    }

    /// The real host asks logind for the soft-reboot, as `systemctl
    /// soft-reboot` does, and returns once PID 1 holds the job; a power-off
    /// it enqueues with PID 1 directly.
    #[test]
    fn the_real_host_soft_reboots_through_logind_and_powers_off_directly() {
        let dir = tempfile::tempdir().unwrap();
        let host = real_host(
            dir.path(),
            &format!("touch {}/job; exit 0", dir.path().display()),
        );
        host.start_target(tools::SOFT_REBOOT_TARGET).unwrap();
        host.start_target("poweroff.target").unwrap();
        assert_eq!(
            calls(dir.path()),
            [
                "--no-wall soft-reboot",
                "start --no-block --job-mode=replace-irreversibly -- poweroff.target",
            ]
        );
    }

    static KILLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn count_kill() {
        KILLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// The entry's host kills the decoy's interactive shells right before it
    /// asks logind, again between two looks while logind holds the
    /// soft-reboot back, and once more when PID 1 holds the job; the way
    /// back's host kills none.
    #[test]
    fn the_entry_kills_the_shells_until_pid_1_holds_the_job() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().display();
        let mut host = real_host(dir.path(), "exit 0");
        // PID 1 holds the job from the third look on.
        nails_base::test_support::write_executable(
            host.systemctl.as_deref().unwrap(),
            format!(
                "#!/bin/sh\necho \"$*\" >> {d}/calls\n\
                 case \"$*\" in\n\
                 list-jobs*) n=$(cat {d}/polls 2>/dev/null || echo 0)\n\
                 echo $((n + 1)) > {d}/polls\n\
                 [ \"$n\" -ge 2 ] && echo '7 soft-reboot.target start waiting'; exit 0 ;;\n\
                 esac\nexit 0\n"
            ),
            0o755,
        );
        assert!(RealTargetHost::for_plan(None).kill_shells.is_none());
        assert!(
            RealTargetHost::for_plan(None)
                .killing_shells()
                .kill_shells
                .is_some()
        );
        host.kill_shells = Some(count_kill);
        host.start_target(tools::SOFT_REBOOT_TARGET).unwrap();
        // Before, at the two looks without a job, and once it is there.
        assert_eq!(KILLS.load(std::sync::atomic::Ordering::SeqCst), 4);
        assert_eq!(calls(dir.path()), ["--no-wall soft-reboot"]);
    }

    /// A way back that did not start says that the disks it unmounted for the
    /// switch stay unmounted.
    #[test]
    fn a_way_back_that_did_not_start_names_the_disks_it_unmounted() {
        let error = NailsError::InvalidState("the soft-reboot was not started: no".into());
        assert_eq!(
            still_unmounted(error, &[]).to_string(),
            "Invalid state: the soft-reboot was not started: no"
        );
        let error = NailsError::InvalidState("the soft-reboot was not started: no".into());
        let named = still_unmounted(
            error,
            &[PathBuf::from("/mnt/usb/inner"), PathBuf::from("/mnt/usb")],
        );
        assert_eq!(
            named.to_string(),
            "Invalid state: the soft-reboot was not started: no. The session goes on, but the \
             disks it had mounted stay unmounted (/mnt/usb/inner, /mnt/usb): mount them again \
             to use them"
        );
    }

    /// A soft-reboot logind refuses is an error that says why, and nothing is
    /// enqueued in its place.
    #[test]
    fn a_soft_reboot_logind_refuses_is_an_error_with_its_reason() {
        let dir = tempfile::tempdir().unwrap();
        let host = real_host(dir.path(), "echo 'Operation denied' >&2; exit 1");
        let error = host.start_target(tools::SOFT_REBOOT_TARGET).unwrap_err();
        assert_eq!(
            error.to_string(),
            NailsError::InvalidState(
                "the soft-reboot was not started: Operation denied".to_string()
            )
            .to_string()
        );
        assert_eq!(calls(dir.path()), ["--no-wall soft-reboot"]);
    }

    /// A program that blocks shutdown outright refuses the way back before
    /// anything is prepared for it: no plan armed, nothing enqueued.
    #[test]
    fn a_program_that_blocks_shutdown_refuses_the_way_back_before_anything_is_prepared() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = real_host(dir.path(), "exit 0");
        let busctl = dir.path().join("busctl");
        nails_base::test_support::write_executable(
            &busctl,
            "#!/bin/sh\necho '{\"type\":\"a(ssssuu)\",\"data\":[[[\"shutdown\",\"apt\",\
             \"Installing\",\"block\",0,4242]]]}'\n",
            0o755,
        );
        host.busctl = Some(busctl);
        let paths = Paths {
            root: dir.path().join("root"),
            run: dir.path().join("run"),
        };
        let mut session = plan();
        for to in [LeaveTo::Decoy, LeaveTo::Poweroff] {
            let error = leave(&paths, &mut session, to, &host).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("apt blocks shutdown (Installing, PID 4242)"),
                "{error}"
            );
        }
        assert!(session.armed.is_none());
        assert!(calls(dir.path()).is_empty());
    }

    #[test]
    fn only_the_disks_the_session_mounted_itself_are_unmounted_deepest_first() {
        let mounts = parse_mountinfo(
            "1 0 0:30 / / rw - overlay overlay rw\n\
             2 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
             3 2 8:3 / /mnt/data/root/decoy/home rw - ext4 /dev/vda3 rw\n\
             4 1 8:1 / /boot ro - vfat /dev/vda1 ro\n\
             5 1 8:2 / /run/nextroot rw - ext4 /dev/vda2 rw\n\
             6 1 8:33 / /mnt/usb rw - vfat /dev/sdc1 rw\n\
             7 6 8:34 / /mnt/usb/inner ro - ext4 /dev/sdc2 ro\n\
             8 1 0:40 / /tmp rw - tmpfs tmpfs rw\n",
        );
        let is_block = |m: &MountEntry| m.source.starts_with("/dev/");
        assert_eq!(
            session_disk_mounts(&Paths::system(), &plan(), &mounts, &is_block),
            vec![PathBuf::from("/mnt/usb/inner"), PathBuf::from("/mnt/usb")]
        );
    }

    #[test]
    fn a_test_tree_only_sees_its_own_mounts() {
        let paths = Paths {
            root: PathBuf::from("/scratch/decoy"),
            run: PathBuf::from("/scratch/run"),
        };
        let mounts = parse_mountinfo(
            "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n\
             2 1 8:3 / /home rw - ext4 /dev/vda3 rw\n\
             3 1 8:33 / /scratch/decoy/mnt rw - vfat /dev/sdc1 rw\n",
        );
        let is_block = |m: &MountEntry| m.source.starts_with("/dev/");
        assert_eq!(
            session_disk_mounts(&paths, &plan(), &mounts, &is_block),
            vec![PathBuf::from("/scratch/decoy/mnt")]
        );
    }

    #[test]
    fn a_device_whose_mark_did_not_take_is_left_open() {
        let report = LeaveReport {
            deferred: vec![
                ("hidden-crypt".to_string(), false),
                ("hidden-loop".to_string(), true),
                ("hidden-base".to_string(), false),
            ],
            unmounted: Vec::new(),
        };
        assert_eq!(report.left_open(), ["hidden-crypt", "hidden-base"]);
        assert!(LeaveReport::default().left_open().is_empty());
    }

    /// Put an empty file at `path` below `root`.
    fn put(root: &Path, path: &str) {
        let file = root.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, "").unwrap();
    }

    /// The decoy's NixOS system the step repoints `/run/current-system` to.
    const DECOY_SYSTEM: &str = "/nix/store/aaa-nixos-system-decoy";

    /// On NixOS the step looks in the decoy's system it repoints to, never in
    /// the hidden system the link names during the session.
    #[test]
    fn the_way_back_looks_for_a_tool_in_the_decoy_system_it_returns_to() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let decoy = Some(Path::new(DECOY_SYSTEM));
        put(root, "nix/store/bbb-nixos-system-hidden/sw/bin/ip");
        put(root, "run/current-system/sw/bin/ip");
        assert!(!way_back_finds(root, decoy, "ip"));
        put(root, "nix/store/aaa-nixos-system-decoy/sw/bin/ip");
        assert!(way_back_finds(root, decoy, "ip"));
    }

    /// Elsewhere the step looks in the hidden root's system directories.
    #[test]
    fn the_way_back_looks_for_a_tool_in_the_system_directories() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        assert!(!way_back_finds(root, None, "ip"));
        put(root, "usr/sbin/ip");
        assert!(way_back_finds(root, None, "ip"));
    }

    /// Make `name` a link below the tree's `/sys/class/net`, as the kernel
    /// lists it: a hardware device with a Wi-Fi interface of radio `phy`
    /// when one is given, else virtual.
    fn link(root: &Path, name: &str, index: u32, phy: Option<&str>) {
        let dir = root.join("sys/class/net").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ifindex"), format!("{index}\n")).unwrap();
        if let Some(phy) = phy {
            std::fs::create_dir(dir.join("device")).unwrap();
            std::os::unix::fs::symlink(format!("../../ieee80211/{phy}"), dir.join("phy80211"))
                .unwrap();
        }
    }

    /// `ip` and `nft` count on every machine, `iw` only where a link is a
    /// Wi-Fi interface; each is lacking until it is where the step looks.
    #[test]
    fn the_way_back_lacks_each_network_tool_it_will_not_find() {
        use NetworkTool::{Ip, Iw, Nft};
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        assert_eq!(way_back_lacks(root, None), [Ip, Nft]);
        link(root, "lo", 1, None);
        assert_eq!(way_back_lacks(root, None), [Ip, Nft]);
        // A wired link has a device and no radio, so iw still does not count.
        link(root, "eth0", 2, None);
        std::fs::create_dir(root.join("sys/class/net/eth0/device")).unwrap();
        assert_eq!(way_back_lacks(root, None), [Ip, Nft]);
        link(root, "wlan0", 3, Some("phy0"));
        assert_eq!(way_back_lacks(root, None), NetworkTool::ALL);
        put(root, "usr/sbin/nft");
        assert_eq!(way_back_lacks(root, None), [Ip, Iw]);
        put(root, "sbin/iw");
        assert_eq!(way_back_lacks(root, None), [Ip]);
        put(root, "bin/ip");
        assert!(way_back_lacks(root, None).is_empty());
    }

    /// Links that cannot be read count as no Wi-Fi interface: entry records
    /// such links as unknown, and the way back then deletes none of them.
    #[test]
    fn unreadable_links_need_no_iw() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        link(root, "wlan0", 3, Some("phy0"));
        std::fs::write(root.join("sys/class/net/wlan0/ifindex"), "three\n").unwrap();
        assert_eq!(
            way_back_lacks(root, None),
            [NetworkTool::Ip, NetworkTool::Nft]
        );
    }

    /// On NixOS every tool counts only in the decoy's system: one the hidden
    /// system or the link it names during the session holds is still lacking.
    #[test]
    fn on_nixos_the_way_back_lacks_what_the_decoy_system_does_not_hold() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let decoy = Some(Path::new(DECOY_SYSTEM));
        link(root, "wlan0", 3, Some("phy0"));
        for tool in NetworkTool::ALL {
            let name = tool.command();
            put(
                root,
                &format!("nix/store/bbb-nixos-system-hidden/sw/bin/{name}"),
            );
            put(root, &format!("run/current-system/sw/bin/{name}"));
        }
        assert_eq!(way_back_lacks(root, decoy), NetworkTool::ALL);
        put(root, "nix/store/aaa-nixos-system-decoy/sw/bin/ip");
        assert_eq!(
            way_back_lacks(root, decoy),
            [NetworkTool::Nft, NetworkTool::Iw]
        );
        put(root, "nix/store/aaa-nixos-system-decoy/sw/bin/nft");
        put(root, "nix/store/aaa-nixos-system-decoy/sw/bin/iw");
        assert!(way_back_lacks(root, decoy).is_empty());
    }
}
