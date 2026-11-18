// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What happens to each decoy filesystem in the hidden root.
//!
//! The root overlay covers only the root filesystem. Every other filesystem
//! in the fstab the hidden systemd reads would be mounted by it **directly and
//! read-write**: a separate `/home` or `/var` would take hidden writes on the
//! decoy disk, the ESP would get `loader/random-seed` rewritten, and decoy swap
//! would take hidden RAM. Before the switch NAILS therefore decides for every
//! entry, and puts the result in place inside `/run/nextroot` (an already
//! mounted path counts as active for systemd) or masks the unit in `/run`:
//!
//! | Entry | Decision |
//! | --- | --- |
//! | `/` | the root overlay itself |
//! | swap | kept off: never activated |
//! | a mount point at or below the hidden root: the hidden volume itself, a disk, a `noauto`, automount or RAM entry | refused: the hidden session could mount it over or inside the hidden volume (kept off in the next root's own fstab, see below) |
//! | RAM and kernel filesystems | left to the hidden systemd (nothing reaches a disk) |
//! | a VM host share (9p, virtiofs) or an overlay entry mounted in the decoy | an overlay with its upper on the hidden volume |
//! | a VM host share not mounted now | left to the hidden systemd |
//! | `/boot`, `/boot/efi`, `/efi` (the ESP and boot partitions) | read-only bind of the decoy mount |
//! | a local filesystem mounted read-only in the decoy | read-only bind |
//! | any other local filesystem mounted in the decoy | an overlay with its upper on the hidden volume |
//! | a local filesystem not mounted now, mounted at boot | kept unmounted (and its automount off) |
//! | `noauto` without an automount or a unit named to pull it in, not for `/usr`, and with only options NAILS reads | left alone: no boot target pulls it in (a skip whose pulls reach it is masked, see [`super::mount_units`]; another unit that pulls it in mounts it) |
//! | `noauto` with an option NAILS does not read | masked, its automount too: the option may have the boot mount it. Where NAILS does not read what the option pulls in either, it may have a boot target require the line, which is warned of |
//! | `noauto`, whose mount the unit of a line the boot starts, left to the hidden systemd or put in place, needs (a mount below it, a source, a path `x-systemd.requires-mounts-for=` or `wants-mounts-for=` names, a unit or path `x-systemd.requires=` or `wants=` names) | kept unmounted: that unit pulls it in, so the boot mounts it ([`decide_all`]) |
//! | a network filesystem | kept unmounted: the hidden session would write to the server |
//! | an overlay entry not mounted now, its upper in RAM | left to the hidden systemd |
//! | an overlay entry not mounted now, its upper on a disk | kept unmounted |
//!
//! A unit kept off is masked in `/run`, or skipped where a boot target
//! requires it ([`Decision::Skip`]): `local-fs.target` requires the mount of
//! an entry without `nofail` (or its automount), `remote-fs.target` that of a
//! network filesystem, `swap.target` a swap line without `nofail` or
//! `noauto` ([`super::fstab::required_by`]). PID 1 cannot pull a masked unit
//! into a transaction, so it drops the job of a target that requires one,
//! silently, and with the target every unit only it pulls in: the hidden
//! session would run without `local-fs.target`. A skipped unit gets a runtime
//! drop-in whose start condition never holds
//! ([`nails_teardown::whole_root::skips`]); the units its fstab line has it
//! pull in that act on its device ([`super::fstab::checkers`]) are skipped
//! with it: its fsck, makefs or mkswap would start before that condition is
//! tested, and its growfs, pcrfs, validatefs and quota units, which are bound
//! to the mount, are skipped for caution. A skipped mount or swap still waits
//! for its device, and one that is not there would hold the hidden session up
//! until the device timeout and then start emergency mode: an entry whose
//! device is not there now is masked, with a warning that its target will not
//! be reached
//! ([`Decision::warning`]). A mount behind a skipped automount stays masked:
//! the target does not pull it in.
//!
//! Each option is read by its name, alone or with a value, as systemd's fstab
//! generator reads it ([`super::fstab`]): `noauto,auto=1` and
//! `noauto,x-systemd.automount=0` are mounted at boot, `x-systemd.makefs=1`
//! pulls in a makefs, `nofail=1` is `nofail`. A line counts as one the boot
//! never mounts only where NAILS also reads every option it gives, by the
//! lists the `backend-entries` check reads a plain line by
//! ([`unread_fstab_options`]): any other option, or a known one with a value
//! NAILS does not read (`x-systemd.wanted-by=` naming a unit other than
//! `local-fs.target`, `X-mount.subdir=`, a flag with a value), may change
//! whether the boot mounts it. Such a `noauto` line is masked, its mount and
//! its automount, with a reason that names the option. A line the policy
//! keeps off anyway, swap too, is masked rather than skipped where such an
//! option is one of systemd's own (`x-systemd.`, `x-initrd.`) whose effect on
//! what its units pull in the session does not read, or holds a backslash
//! ([`reads_pulls_of`]): what it pulls in is then more than NAILS can tell,
//! and a skip would leave that free to start. systemd splits the options at
//! every comma, as the parser does, quotes or not; only a backslash, after
//! which it keeps a comma in the option, or a `\054`, which it reads as a
//! comma, makes it split them otherwise. systemd reads no other option for
//! what a unit pulls in, so a line with `hard` or `vers=4.2` for `mount.nfs`
//! is skipped as before. Where a boot target requires the units, the warning
//! says it will not be reached ([`Decision::warning`]); where such an option
//! on a masked `noauto` line may have a target require it, the warning says
//! that target is then not reached. On a line the boot mounts, other than
//! one for `/usr`, a backslash may hide a comma before `noauto` or `nofail`,
//! so that nothing requires the line: the warning then says the same as for
//! a `noauto` line, and the mask is not recorded as a required one.
//!
//! A mounted host share or overlay is overlaid rather than left to the hidden
//! systemd because the next root must already hold its contents when PID 1
//! checks the init: NixOS test VMs mount `/nix/store` as an overlay of a 9p
//! share and a tmpfs, and the next root would otherwise have an empty store.
//!
//! An entry behind an automount (`x-systemd.automount`, often the ESP) whose
//! filesystem the policy binds or overlays itself keeps its automount off too
//! ([`runtime_units`]): the hidden systemd would find the mount point taken
//! and fail to set the automount up, and `local-fs.target`, which requires it
//! unless the entry is `nofail`, would fail with it and start the hidden
//! session in emergency mode. The automount is skipped where the target
//! requires it, and masked where the target only wants it.
//!
//! An entry of the decoy's fstab that the next root resolves to another path
//! than the decoy root does (a symlink on the way that a session replaced or
//! added) is decided at that path as well ([`decide_redirected`]). A link that
//! leads the entry into the hidden volume is not refused: the decoy's line
//! names a path outside it, and only a link in the hidden root leads it
//! there. It still names a decoy filesystem, which the hidden systemd would
//! mount read-write inside the hidden volume, so it is kept off. A RAM or
//! kernel filesystem a link leads there is left to the hidden systemd, as one
//! elsewhere is: nothing of it reaches a disk.
//!
//! Two kinds of entry are refused outright, and activation with them: one
//! whose mount point is not a plain absolute path, which cannot be mounted
//! inside the next root, and one whose mount point lies at or below the hidden
//! root (unless that root is `/`). The hidden volume is bound at its own path
//! in the hidden root, so the hidden systemd would mount such an entry's
//! filesystem over the hidden volume or inside it, a decoy disk read-write
//! among the hidden files. That holds for a `noauto` line too, which any unit
//! or a plain `mount` can pull in, for an automount, for a RAM filesystem,
//! which would hide what lies below it, and for a line that names the hidden
//! volume itself. The hidden volume has to be mounted where the decoy mounts
//! nothing ([`Decision::remedy`]). The same holds for the fstab a hidden NixOS
//! build brings and for the mount and automount units a boot target links
//! outside the fstab, which are decided as fstab lines
//! ([`super::mount_units`]); what the refusal says to do follows whose the
//! entry or unit is ([`Whose`]).
//!
//! An entry without a build (`--overlay-only` on NixOS, and every entry on
//! another host) decides the next root's own `/etc/fstab` as well, the one the
//! hidden systemd reads: on NixOS the hidden generation's, which the hidden
//! `/etc` the last activation of a hidden system wrote leads to, or one a
//! hidden session wrote over it, and elsewhere one a hidden session wrote over
//! the decoy's ([`decide_hidden_fstab`]). Its lines get the decisions the
//! decoy's get, but one at or below the hidden root is kept off rather than
//! refused, whatever it mounts: the session entered to remove such a line must
//! still start. Its units are kept off, so the hidden systemd does not mount
//! it; the line stays in the file, where a plain `mount` in the session still
//! finds it. The entry warns of each, naming the line, the root and what to
//! do in that session ([`kept_below_warning`]).

use super::fstab::{
    FstabEntry, automount_unit, boot_target, checkers, escape_path, mount_unit, option_named,
    reads_pulls_of, required_by, swap_unit, waits_for,
};
use nails_base::hidden_root::separation::unread_fstab_options;
use nails_teardown::mountinfo::{MountEntry, parse_overlay_opts};
use nails_teardown::whole_root::plan::{MaskCause, RequiredMask, Skip};
use std::borrow::Cow;
use std::path::{Component, Path, PathBuf};

mod needed;

/// Whether a device is there now: [`device_present`] on the running system,
/// a fixed answer in tests.
pub type Present<'a> = &'a dyn Fn(&Path) -> bool;

/// Whether `device` is there on the running system now, as systemd waits for
/// it: its node, or the link udev makes for it, resolves, and its device unit
/// is active. systemd makes a mount or swap wait for that unit, which udev's
/// record of the device makes active, in the hidden session as it does here;
/// a device udev marks not ready (`SYSTEMD_READY=0`) has a node but no active
/// unit. A unit that cannot be asked about counts as not there. `check` and
/// activation both decide with it.
pub fn device_present(device: &Path) -> bool {
    use nails_teardown::whole_root::tools;
    if !device.exists() {
        return false;
    }
    let unit = format!("{}.device", escape_path(device));
    tools::find(None, "systemctl")
        .and_then(|systemctl| {
            tools::run_output(
                &systemctl,
                &["show", "--property=ActiveState", "--value", &unit],
                std::time::Duration::from_secs(30),
            )
        })
        .is_some_and(|state| state.trim() == "active")
}

/// Mount points whose filesystem is kept read-only in the hidden root. The
/// units that write there at every start are masked in the hidden root
/// ([`super::hidden_masks`]).
pub const BOOT_PATHS: &[&str] = &["/boot", "/boot/efi", "/efi"];

/// What to do with one fstab entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Bind the decoy mount at `target` read-only into the next root.
    ReadOnlyBind {
        /// The mount point.
        target: PathBuf,
    },
    /// Mount an overlay over the decoy mount at `target`, upper on the hidden
    /// volume.
    Overlay {
        /// The mount point.
        target: PathBuf,
    },
    /// Mask these units in `/run`, so the hidden systemd never starts them.
    Mask {
        /// The entry's mount point (or swap spec).
        target: PathBuf,
        /// The units.
        units: Vec<String>,
        /// Why.
        reason: Cow<'static, str>,
        /// The boot target the mask keeps from being reached, when one
        /// requires the units and they cannot be skipped, or may require
        /// them as far as NAILS can tell ([`Unskippable::MayRequire`]).
        unreached: Option<Unreached>,
    },
    /// Skip these units in the hidden root: a boot target requires them, and
    /// a mask would keep the target from being reached (see the module docs).
    Skip {
        /// The entry's mount point (or swap spec).
        target: PathBuf,
        /// The units skipped, those they pull in, and their device.
        skip: Skip,
        /// Units masked with them: the mount behind a skipped automount.
        masked: Vec<String>,
        /// Why they must not start.
        reason: Cow<'static, str>,
    },
    /// Leave it to the hidden systemd, or leave it alone.
    Leave {
        /// The mount point.
        target: PathBuf,
        /// Why that is safe.
        reason: &'static str,
    },
    /// No safe decision: activation is refused.
    Refuse {
        /// The mount point.
        target: PathBuf,
        /// Why.
        reason: String,
        /// The hidden root, when the mount point lies at or below it: what to
        /// do about the refusal names it ([`Decision::remedy`]).
        below: Option<PathBuf>,
    },
}

/// Whose mounts a decision is about, which tells what to do about a refusal
/// ([`Decision::remedy`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Whose {
    /// The decoy's: its fstab, and the units its boot targets link outside
    /// it, as `check` and activation decide them.
    Decoy,
    /// The fstab of a hidden NixOS generation: the one a build brings, which
    /// activation decides after the build, before it activates the
    /// generation, and the next root's `/etc/fstab` on NixOS in an entry
    /// without a build where it leads into the store, to the generation the
    /// last activation of a hidden system linked ([`decide_hidden_fstab`]).
    HiddenSystem,
    /// The next root's own `/etc/fstab` in an entry without a build where it
    /// is no hidden NixOS generation's ([`decide_hidden_fstab`]): one a
    /// hidden session wrote over the decoy's, on NixOS a file in place of the
    /// link into the store.
    HiddenSession,
    /// The units outside the fstab that activation decides in the hidden
    /// root ([`super::mount_units`]): the decoy's, which `check` decided
    /// before, and those a hidden NixOS generation or an earlier hidden
    /// session added.
    HiddenRoot,
}

impl Whose {
    /// Whose fstab an entry is of, as a refusal or a warning names it: none
    /// for the decoy's, whose fstab `check` reads too.
    pub fn fstab_of(self) -> &'static str {
        match self {
            Whose::HiddenSystem => "the hidden NixOS system's ",
            Whose::HiddenSession => "the hidden session's ",
            Whose::Decoy | Whose::HiddenRoot => "",
        }
    }

    /// What to do in the hidden session about an entry of this fstab at or
    /// below `root`, which an entry without a build keeps off
    /// ([`decide_hidden_fstab`]): change the hidden NixOS configuration and
    /// rebuild, or the hidden session's `/etc/fstab`. `None` for the decoy's
    /// fstab and the units outside the fstab, whose entries there are refused.
    fn kept_off_remedy(self, root: &Path) -> Option<String> {
        let root = root.display();
        match self {
            Whose::HiddenSystem => Some(format!(
                "In the hidden session, remove this mount from the hidden NixOS configuration, \
                 or move it out from below {root} there, and rebuild."
            )),
            Whose::HiddenSession => Some(format!(
                "In the hidden session, remove this line from /etc/fstab, or move its mount out \
                 from below {root}."
            )),
            Whose::Decoy | Whose::HiddenRoot => None,
        }
    }
}

/// Why a mask keeps a boot target from being reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreached {
    /// The target that requires the masked unit (`local-fs.target`).
    pub target: String,
    /// Why the unit is masked rather than skipped.
    pub cause: Unskippable,
    /// Where the unit and the link that requires it come from, which tells
    /// what the operator can do about it.
    pub origin: Origin,
}

/// Where a unit kept off comes from, and so what makes a boot target want
/// it rather than require it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// An fstab line: `nofail` on it.
    Fstab,
    /// A unit a generator made and requires through a link of its own: an
    /// fstab line, also one gone since the decoy's start, or a
    /// `systemd.mount-extra=` of the kernel command line. `nofail` on that
    /// line, or a reload of systemd for a line that is gone. `nofail` in a
    /// unit file's `Options=` means nothing.
    Generated,
    /// A unit file installed for a target, which requires it by a link in
    /// its `.requires` directory: `WantedBy=` rather than `RequiredBy=`.
    Installed,
    /// A `noauto` fstab line that the units of other lines need, which a
    /// target requires, or may ([`decide_all`]): `nofail` on the lines the
    /// target requires that lead to it, or `x-systemd.wanted-by=` in place
    /// of an `x-systemd.required-by=` they give, which `nofail` does not
    /// change.
    Needed {
        /// Those lines: their mount points, or a swap's device.
        lines: Vec<PathBuf>,
        /// Whether NAILS only reads that the target may require the mount,
        /// through an option it does not read: the warning says so, and the
        /// mask is not recorded as a required one.
        may: bool,
    },
}

/// Why a unit a boot target requires is masked rather than skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unskippable {
    /// The device the unit waits for, which was not there: a skipped unit
    /// would have waited for it until the device timeout.
    NoDevice(PathBuf),
    /// NAILS cannot tell what the unit is (the mask's reason says why), so it
    /// keeps the unit from starting whatever it is
    /// ([`super::mount_units`]).
    Unread,
    /// A `noauto` line masked for an option whose effect on what pulls the
    /// line in NAILS does not read ([`reads_pulls_of`]), or a line the boot
    /// mounts, other than one for `/usr`, that is kept off and masked for an
    /// option with a backslash, which may hide a comma before `noauto` or
    /// `nofail` ([`mask_unread`]): NAILS cannot tell whether that option has
    /// a boot target require the line, and where it does, the target is not
    /// reached. Not recorded as a required mask.
    MayRequire,
}

impl Decision {
    /// The units to mask: a mask's, or those masked with a skip.
    pub fn masked_units(&self) -> &[String] {
        match self {
            Decision::Mask { units, .. } => units,
            Decision::Skip { masked, .. } => masked,
            _ => &[],
        }
    }

    /// The units to skip, if this is a skip.
    pub fn skip(&self) -> Option<&Skip> {
        match self {
            Decision::Skip { skip, .. } => Some(skip),
            _ => None,
        }
    }

    /// What the operator can do about a refusal of `whose` mounts, where
    /// fixing or removing the entry is not the whole answer: for one at or
    /// below the hidden root, mounting the hidden volume where nothing is
    /// mounted below it is the other. An entry of a hidden NixOS
    /// generation's fstab is that generation's configuration's to change,
    /// which a hidden session entered without the build can. `None` for the
    /// hidden session's own fstab: an entry of it at or below the hidden root
    /// is kept off, never refused ([`decide_hidden_fstab`]), and the warning
    /// says what to do ([`kept_below_warning`]).
    pub fn remedy(&self, whose: Whose) -> Option<String> {
        let Decision::Refuse {
            below: Some(root), ..
        } = self
        else {
            return None;
        };
        let root = root.display();
        Some(match whose {
            Whose::Decoy => format!(
                "Mount the hidden volume where the decoy mounts nothing, or move this mount out \
                 from below {root} or remove it, before activating."
            ),
            Whose::HiddenSystem => format!(
                "Remove this mount from the hidden NixOS configuration, or move it out from \
                 below {root} there, in a hidden session entered with `activate --overlay-only`."
            ),
            Whose::HiddenSession => return None,
            Whose::HiddenRoot => format!(
                "Mount the hidden volume where no mount unit mounts anything, or move this mount \
                 out from below {root} or remove its unit, before activating."
            ),
        })
    }

    /// The refusal of this decision's entry of `whose` fstab, with what to do
    /// about it ([`Decision::remedy`]); `None` for any other decision. One of
    /// a hidden fstab says whose it is ([`Whose::fstab_of`]).
    pub fn fstab_refusal(&self, whose: Whose) -> Option<String> {
        let Decision::Refuse { target, reason, .. } = self else {
            return None;
        };
        let refusal = format!(
            "{}fstab entry {}: {reason}",
            whose.fstab_of(),
            target.display()
        );
        Some(self.with_remedy(refusal, whose))
    }

    /// The refusal of a unit outside the fstab that activation decides in the
    /// hidden root, or of a directory of unit links it cannot list there,
    /// with what to do about it ([`Decision::remedy`]).
    pub fn unit_refusal(&self) -> String {
        self.with_remedy(self.describe(), Whose::HiddenRoot)
    }

    /// `refusal`, a refusal of this decision's entry in words, followed by
    /// what to do about it where the decision says ([`Decision::remedy`]).
    fn with_remedy(&self, refusal: String, whose: Whose) -> String {
        match self.remedy(whose) {
            Some(remedy) => format!("{refusal}. {remedy}"),
            None => refusal,
        }
    }

    /// A one-line description for `check` and the activation log.
    pub fn describe(&self) -> String {
        match self {
            Decision::ReadOnlyBind { target } => format!("{}: read-only", target.display()),
            Decision::Overlay { target } => format!("{}: overlaid", target.display()),
            Decision::Mask { target, reason, .. } => {
                format!("{}: masked ({reason})", target.display())
            }
            Decision::Skip { target, reason, .. } => {
                format!("{}: skipped ({reason})", target.display())
            }
            Decision::Leave { target, reason } => {
                format!("{}: left as is ({reason})", target.display())
            }
            Decision::Refuse { target, reason, .. } => {
                format!("{}: refused ({reason})", target.display())
            }
        }
    }

    /// What the operator should know about this decision before the switch:
    /// a mask that keeps a boot target from being reached.
    pub fn warning(&self) -> Option<String> {
        let Decision::Mask {
            target,
            reason,
            unreached:
                Some(Unreached {
                    target: boot,
                    cause,
                    origin,
                }),
            ..
        } = self
        else {
            return None;
        };
        let held;
        let remedy = match origin {
            Origin::Fstab => "give the fstab entry the nofail option",
            Origin::Generated => {
                "give the line its generator made it from the nofail option (an fstab entry, or \
                 systemd.mount-extra= on the kernel command line), or run systemctl daemon-reload \
                 if that line is gone"
            }
            Origin::Installed => {
                "install the unit with WantedBy= rather than RequiredBy=, so that the target \
                 wants it instead of requiring it"
            }
            Origin::Needed { lines, .. } => {
                held = needed::wanted_remedy(lines);
                held.as_str()
            }
        };
        // Several targets are named with " and " between them.
        let several = boot.contains(" and ");
        let (require, those, they) = if several {
            ("require", "those targets pull", "they do")
        } else {
            ("requires", "that target pulls", "it does")
        };
        let unreached = if matches!(origin, Origin::Needed { may: true, .. }) {
            format!(
                "{boot} may require it, and where {they}, the hidden session will not reach {}, \
                 and the units only {those} in will not start there",
                if several { "them" } else { "it" }
            )
        } else {
            format!(
                "the hidden session will not reach {boot}, which {require} it, and the units only \
                 {those} in will not start there"
            )
        };
        Some(match cause {
            Unskippable::NoDevice(device) => format!(
                "{} is masked rather than skipped, as its device {} is not there: {unreached}. \
                 Attach the device before activating, or {remedy}",
                target.display(),
                device.display()
            ),
            Unskippable::Unread => {
                format!("{} is masked, as {reason}: {unreached}", target.display())
            }
            Unskippable::MayRequire => format!(
                "{} is masked, as {reason}: where that option has {boot} or another unit \
                 require it, the hidden session will not reach that unit, and the units only it \
                 pulls in will not start there",
                target.display()
            ),
        })
    }
}

/// The decoy's live mount at exactly `target` (the topmost one).
fn mounted_at<'a>(mounts: &'a [MountEntry], target: &Path) -> Option<&'a MountEntry> {
    mounts.iter().rev().find(|m| m.mount_point == target)
}

/// The deepest decoy mount containing `path`.
fn mount_containing<'a>(mounts: &'a [MountEntry], path: &Path) -> Option<&'a MountEntry> {
    mounts
        .iter()
        .filter(|m| path.starts_with(&m.mount_point))
        .max_by_key(|m| m.mount_point.components().count())
}

fn plain_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

/// The units systemd makes for a mount or a swap, and what pulls them in at
/// boot: for an fstab entry what systemd's fstab generator makes of its line
/// ([`Units::of`]), for a unit outside the fstab what the decoy's unit files
/// say ([`super::mount_units`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Units {
    /// The `.mount` or `.swap` unit; none for a swap entry that names no
    /// device or file.
    pub unit: Option<String>,
    /// Its automount, if it has one.
    pub automount: Option<String>,
    /// What requires the unit, or its automount, at boot
    /// ([`super::fstab::required_by`]); `None` when nothing does.
    pub required_by: Option<String>,
    /// The units it pulls in that act on its device or filesystem
    /// ([`super::fstab::checkers`]).
    pub checkers: Vec<String>,
    /// Where they come from ([`Unreached::origin`]).
    pub origin: Origin,
}

impl Units {
    /// The units systemd's fstab generator makes for `entry`.
    pub fn of(entry: &FstabEntry) -> Self {
        let unit = if entry.is_swap() {
            swap_unit(&entry.spec)
        } else {
            Some(mount_unit(&entry.file))
        };
        Self {
            unit,
            automount: entry.is_automount().then(|| automount_unit(&entry.file)),
            required_by: required_by(entry),
            checkers: checkers(entry),
            origin: Origin::Fstab,
        }
    }
}

/// What an entry whose mount point lies at or below the hidden root gets,
/// by where the entry comes from (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Below {
    /// Refused: a line of the decoy's fstab or of the one a hidden build
    /// brings, or a unit outside the fstab.
    Refused,
    /// Kept off, a RAM or kernel filesystem left to the hidden systemd: a
    /// line of the decoy's that a link of the next root leads there.
    Redirected,
    /// Kept off, whatever it mounts: a line of the next root's own fstab in
    /// an entry without a build.
    KeptOff,
}

/// Why a `noauto` line is left alone, when no other line needs it
/// ([`needed::needed_below`]).
const NEVER_MOUNTED: &str = "noauto: never mounted";

/// Why a line of the next root's own fstab at or below the hidden root is
/// kept off ([`decide_hidden_fstab`]).
const KEPT_BELOW: &str = "it lies at or below the hidden volume's mount point, where the hidden \
                          session could mount it over the volume or inside it";

/// Decide one entry. `mounts` is the decoy's live mount table, and `present`
/// tells whether a device is there now ([`device_present`]).
pub fn decide(
    entry: &FstabEntry,
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
) -> Decision {
    decide_entry(
        entry,
        &Units::of(entry),
        mounts,
        hidden_root,
        Below::Refused,
        present,
    )
}

/// Decide an entry of the decoy's fstab at the path the next root resolves
/// it to, where that differs from the decoy root's (see the module docs): as
/// [`decide`], except that a path at or below the hidden root is kept
/// unmounted rather than refused, and a RAM or kernel filesystem there is
/// left to the hidden systemd.
pub fn decide_redirected(
    entry: &FstabEntry,
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
) -> Decision {
    decide_entry(
        entry,
        &Units::of(entry),
        mounts,
        hidden_root,
        Below::Redirected,
        present,
    )
}

/// Decide an entry of the next root's own `/etc/fstab`, which an entry
/// without a build reads there (see the module docs): as [`decide`], except
/// that an entry at or below the hidden root is kept off rather than
/// refused, whatever it mounts, a RAM filesystem and the hidden volume
/// itself included: masked, or skipped where a boot target requires it.
pub fn decide_hidden_fstab(
    entry: &FstabEntry,
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
) -> Decision {
    decide_entry(
        entry,
        &Units::of(entry),
        mounts,
        hidden_root,
        Below::KeptOff,
        present,
    )
}

/// Decide a mount or swap that `units` start, outside the fstab: `entry`
/// holds what its unit files say (the source, the mount point, the type and
/// the options), and the decision is the one an fstab line with them gets.
pub fn decide_units(
    entry: &FstabEntry,
    units: &Units,
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
) -> Decision {
    decide_entry(entry, units, mounts, hidden_root, Below::Refused, present)
}

/// Whether the mount point of `entry` lies at or below `hidden_root`, unless
/// that root is `/`, where the hidden volume is bound in the next root: the
/// entries the policy refuses, or keeps off in the next root's own fstab. A
/// swap line has no mount point.
pub fn lies_below(entry: &FstabEntry, hidden_root: &Path) -> bool {
    !entry.is_swap() && hidden_root != Path::new("/") && entry.file.starts_with(hidden_root)
}

/// The warning for `entry`, the line `line` of `whose` fstab, when an entry
/// without a build keeps it off at or below `hidden_root` rather than
/// refusing it ([`decide_hidden_fstab`]): it names the line and the root,
/// says that only its units are kept off, as the line stays in the file a
/// plain `mount` reads, and on a line of its own what to do about it in the
/// hidden session. `None` for an entry elsewhere.
pub fn kept_below_warning(
    entry: &FstabEntry,
    line: &str,
    hidden_root: &Path,
    whose: Whose,
) -> Option<String> {
    if !lies_below(entry, hidden_root) {
        return None;
    }
    let warning = format!(
        "{}fstab entry {} (`{line}`) lies at or below {}, where the hidden volume is mounted: \
         its units are kept off, so the hidden systemd does not mount it over the hidden volume \
         or inside it, though a plain `mount` in the session still would",
        whose.fstab_of(),
        entry.file.display(),
        hidden_root.display()
    );
    Some(match whose.kept_off_remedy(hidden_root) {
        Some(remedy) => format!("{warning}\n{remedy}"),
        None => warning,
    })
}

/// The options of the fstab line `entry` that NAILS does not read, by their
/// names ([`unread_fstab_options`]), when `units` are the ones the fstab
/// generator makes of the line: none for a unit outside the fstab, whose
/// options its unit files carry, and whose pulls NAILS reads from them
/// ([`super::mount_units`]).
fn unread_options(entry: &FstabEntry, units: &Units) -> Vec<String> {
    if units.origin == Origin::Fstab {
        unread_fstab_options(entry)
    } else {
        Vec::new()
    }
}

/// The name of the first option of the fstab line `entry` that NAILS does not
/// read ([`unread_options`]) and whose effect on what the line's units pull
/// in the session does not read itself either ([`reads_pulls_of`]): a skip of
/// such a line could leave free a unit that acts on its disk.
fn unread_pulls(entry: &FstabEntry, units: &Units) -> Option<String> {
    let unread = unread_options(entry, units);
    entry
        .options
        .iter()
        .map(|option| {
            (
                option
                    .split_once('=')
                    .map_or(option.as_str(), |(name, _)| name),
                option,
            )
        })
        .find(|(name, option)| unread.iter().any(|u| u == name) && !reads_pulls_of(option))
        .map(|(name, _)| name.to_string())
}

/// The mask of `kept`, units of the fstab line `entry` kept off for `reason`,
/// that gives an option whose pulls NAILS does not read, `option`
/// ([`unread_pulls`]): it may pull in more than NAILS can tell, which a skip
/// would leave free to start, so the units are masked whatever pulls them in,
/// and a boot target that requires them is not reached
/// ([`Unskippable::Unread`]). Where an option of the line holds a backslash,
/// which may hide a comma before `noauto` or `nofail` that systemd reads, so
/// that nothing requires the line, the target only may require them
/// ([`Unskippable::MayRequire`]), unless the generator mounts the line
/// whatever its options say ([`FstabEntry::is_mandatory`]).
fn mask_unread(
    entry: &FstabEntry,
    kept: Vec<String>,
    units: &Units,
    reason: &str,
    option: &str,
) -> Decision {
    let target = if entry.is_swap() {
        PathBuf::from(&entry.spec)
    } else {
        entry.file.clone()
    };
    let cause = if !entry.is_mandatory() && entry.options.iter().any(|o| o.contains('\\')) {
        Unskippable::MayRequire
    } else {
        Unskippable::Unread
    };
    Decision::Mask {
        target,
        units: kept,
        reason: format!("{reason}; NAILS cannot tell what its option {option} pulls in").into(),
        unreached: units.required_by.clone().map(|boot| Unreached {
            target: boot,
            cause,
            origin: units.origin.clone(),
        }),
    }
}

/// Keep `units` of `entry` from starting: its mount, and its automount when
/// it has one. They are skipped where a boot target requires them, unless
/// the device they wait for is not there now, and masked otherwise (see the
/// module docs). A line that gives an option NAILS does not read, and whose
/// pulls the session does not read either ([`unread_pulls`]), has both its
/// mount and its automount masked ([`mask_unread`]).
fn keep_off(
    entry: &FstabEntry,
    units: &Units,
    reason: Cow<'static, str>,
    present: Present<'_>,
) -> Decision {
    let target = entry.file.clone();
    let mount = units
        .unit
        .clone()
        .unwrap_or_else(|| mount_unit(&entry.file));
    if let Some(option) = unread_pulls(entry, units) {
        let kept = vec![mount, automount_unit(&entry.file)];
        return mask_unread(entry, kept, units, &reason, &option);
    }
    if let Some(automount) = units.automount.clone() {
        if units.required_by.is_none() {
            return Decision::Mask {
                target,
                units: vec![mount, automount],
                reason,
                unreached: None,
            };
        }
        // The target pulls in the automount alone, which waits for no device;
        // the mount, which nothing starts then, stays masked.
        return Decision::Skip {
            target,
            skip: Skip {
                units: vec![automount],
                pulled: Vec::new(),
                device: None,
            },
            masked: vec![mount],
            reason,
        };
    }
    gate(target, vec![mount], entry, units, reason, present)
}

/// The decision for `kept` of `entry` that must not start: a skip when
/// something requires them ([`Units::required_by`]) and the device they wait
/// for, if any, is there now; a mask otherwise.
fn gate(
    target: PathBuf,
    kept: Vec<String>,
    entry: &FstabEntry,
    units: &Units,
    reason: Cow<'static, str>,
    present: Present<'_>,
) -> Decision {
    let Some(required) = units.required_by.clone() else {
        return Decision::Mask {
            target,
            units: kept,
            reason,
            unreached: None,
        };
    };
    match waits_for(entry) {
        Some(device) if !present(&device) => Decision::Mask {
            target,
            units: kept,
            reason,
            unreached: Some(Unreached {
                target: required,
                cause: Unskippable::NoDevice(device),
                origin: units.origin.clone(),
            }),
        },
        device => Decision::Skip {
            target,
            skip: Skip {
                units: kept,
                pulled: units.checkers.clone(),
                device,
            },
            masked: Vec::new(),
            reason,
        },
    }
}

/// The upper directory the overlay line `entry` names: its one `upperdir=`
/// option, or, where it gives none, the one the decoy's overlay mounted at
/// its mount point has (`Ok(None)` where that has none either). `Err` where
/// it gives `upperdir` more than once, or with no value: the kernel takes
/// the last of several, and NAILS does not tell where it lies.
fn overlay_upper(entry: &FstabEntry, mounts: &[MountEntry]) -> Result<Option<PathBuf>, ()> {
    let given: Vec<Option<&str>> = entry
        .options
        .iter()
        .filter_map(|option| option_named(option, "upperdir"))
        .collect();
    match given.as_slice() {
        [] => Ok(mounted_at(mounts, &entry.file)
            .and_then(|m| parse_overlay_opts(&m.super_opts).upperdir)),
        [Some(upper)] => Ok(Some(PathBuf::from(upper))),
        _ => Err(()),
    }
}

fn decide_entry(
    entry: &FstabEntry,
    units: &Units,
    mounts: &[MountEntry],
    hidden_root: &Path,
    below: Below,
    present: Present<'_>,
) -> Decision {
    let target = entry.file.clone();
    if entry.is_swap() {
        let Some(unit) = units.unit.clone() else {
            return Decision::Leave {
                target,
                reason: "a swap entry without a device",
            };
        };
        let reason = "swap would take hidden RAM onto a decoy disk";
        if let Some(option) = unread_pulls(entry, units) {
            return mask_unread(entry, vec![unit], units, reason, &option);
        }
        return gate(
            PathBuf::from(&entry.spec),
            vec![unit],
            entry,
            units,
            reason.into(),
            present,
        );
    }
    if !plain_absolute(&target) {
        return Decision::Refuse {
            reason: "the mount point is not a plain absolute path".to_string(),
            target,
            below: None,
        };
    }
    let below_hidden_root = lies_below(entry, hidden_root);
    if below_hidden_root {
        match below {
            Below::Refused => return below_the_hidden_root(target, hidden_root),
            Below::KeptOff => return keep_off(entry, units, KEPT_BELOW.into(), present),
            Below::Redirected => {}
        }
    }
    if target == Path::new("/") {
        return Decision::Leave {
            target,
            reason: "the root overlay",
        };
    }
    if entry.is_virtual() {
        return Decision::Leave {
            target,
            reason: "RAM or kernel filesystem",
        };
    }
    if below_hidden_root {
        return keep_off(
            entry,
            units,
            "a link leads it into the hidden volume, where the hidden session would mount \
             a decoy filesystem read-write"
                .into(),
            present,
        );
    }
    let mounted = mounted_at(mounts, &target).is_some();
    if (entry.is_host_share() || entry.vfstype == "overlay") && mounted {
        return Decision::Overlay { target };
    }
    if entry.is_host_share() {
        return Decision::Leave {
            target,
            reason: "a host share, not mounted now",
        };
    }
    if entry.is_network() {
        return keep_off(
            entry,
            units,
            "the hidden session would write to the server".into(),
            present,
        );
    }
    if entry.vfstype == "overlay" {
        let Ok(upper) = overlay_upper(entry, mounts) else {
            return keep_off(
                entry,
                units,
                "an overlay that names its upper directory more than once, or with no value".into(),
                present,
            );
        };
        let in_ram = upper
            .as_deref()
            .and_then(|upper| mount_containing(mounts, upper))
            .is_some_and(|m| m.fstype == "tmpfs" || m.fstype == "ramfs");
        return if in_ram {
            Decision::Leave {
                target,
                reason: "an overlay with its upper in RAM",
            }
        } else {
            keep_off(
                entry,
                units,
                "an overlay with its upper on a disk".into(),
                present,
            )
        };
    }
    match mounted_at(mounts, &target) {
        Some(mount) if BOOT_PATHS.iter().any(|b| target == Path::new(b)) || mount.read_only() => {
            Decision::ReadOnlyBind { target }
        }
        Some(_) => Decision::Overlay { target },
        None if entry.is_noauto() => {
            // An option NAILS does not read may have the boot mount it all
            // the same: masked, with the automount it may set up. As NAILS
            // reads the line, nothing requires it. One whose effect on what
            // pulls the line in NAILS does not read either, a backslash in it
            // or an option of systemd's own, may have a target require it,
            // which the mask then keeps from being reached: named first, and
            // warned of.
            let pulls = unread_pulls(entry, units);
            let unreached = pulls.as_ref().map(|_| Unreached {
                target: boot_target(entry).to_string(),
                cause: Unskippable::MayRequire,
                origin: units.origin.clone(),
            });
            let Some(option) = pulls.or_else(|| unread_options(entry, units).into_iter().next())
            else {
                return Decision::Leave {
                    target,
                    reason: NEVER_MOUNTED,
                };
            };
            Decision::Mask {
                units: vec![
                    units.unit.clone().unwrap_or_else(|| mount_unit(&target)),
                    automount_unit(&target),
                ],
                target,
                reason: format!(
                    "noauto, but NAILS does not read its option {option} as the line gives it, \
                     so the boot may mount it"
                )
                .into(),
                unreached,
            }
        }
        None => keep_off(
            entry,
            units,
            "not mounted now; the hidden session would mount it read-write".into(),
            present,
        ),
    }
}

/// The refusal of an entry whose mount point `target` lies at or below the
/// hidden root (see the module docs).
fn below_the_hidden_root(target: PathBuf, hidden_root: &Path) -> Decision {
    Decision::Refuse {
        reason: format!(
            "it lies at or below {}, where the hidden volume is mounted: the hidden session \
             could mount it over the hidden volume or inside it",
            hidden_root.display()
        ),
        below: Some(hidden_root.to_path_buf()),
        target,
    }
}

/// Decide every entry, ordered by mount-point depth so a parent is in place
/// before a child mounted below it, a `noauto` line whose mount the unit of
/// another line needs kept off (see the module docs).
pub fn decide_all(
    entries: &[FstabEntry],
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
) -> Vec<Decision> {
    by_depth(entries, present, |entry| {
        decide(entry, mounts, hidden_root, present)
    })
}

/// [`decide_all`] for entries the next root resolves elsewhere, each decided
/// by [`decide_redirected`].
pub fn decide_all_redirected(
    entries: &[FstabEntry],
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
) -> Vec<Decision> {
    by_depth(entries, present, |entry| {
        decide_redirected(entry, mounts, hidden_root, present)
    })
}

/// [`decide_all`] for entries of the next root's own fstab, each decided by
/// [`decide_hidden_fstab`].
pub fn decide_all_hidden_fstab(
    entries: &[FstabEntry],
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
) -> Vec<Decision> {
    by_depth(entries, present, |entry| {
        decide_hidden_fstab(entry, mounts, hidden_root, present)
    })
}

/// The decision `decide` gives each of `entries`, a `noauto` line whose
/// mount another needs kept off ([`needed::needed_below`]), ordered by
/// mount-point depth.
fn by_depth(
    entries: &[FstabEntry],
    present: Present<'_>,
    decide: impl Fn(&FstabEntry) -> Decision,
) -> Vec<Decision> {
    let decided: Vec<Decision> = entries.iter().map(decide).collect();
    let mut decisions: Vec<(usize, Decision)> = entries
        .iter()
        .enumerate()
        .map(|(at, e)| {
            let decision = needed::needed_below(entries, &decided, at, present)
                .unwrap_or_else(|| decided[at].clone());
            (e.file.components().count(), decision)
        })
        .collect();
    decisions.sort_by_key(|(depth, _)| *depth);
    decisions.into_iter().map(|(_, d)| d).collect()
}

/// Every unit the decisions mask.
pub fn masked_units(decisions: &[Decision]) -> Vec<String> {
    decisions
        .iter()
        .flat_map(|d| d.masked_units().iter().cloned())
        .collect()
}

/// What the hidden session keeps from starting: the units it masks, each
/// once, and the units it skips.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeptOff {
    /// The units masked in `/run`.
    pub masks: Vec<String>,
    /// The units skipped, with those they pull in and their device.
    pub skips: Vec<Skip>,
    /// The units among [`masks`](Self::masks) that a boot target requires,
    /// each once with why it is masked rather than skipped.
    pub required_masks: Vec<RequiredMask>,
}

impl KeptOff {
    /// Record that `units`, which a boot target requires, are masked for
    /// `cause`, unless an earlier cause is recorded for one.
    pub fn record_masked(&mut self, units: &[String], cause: MaskCause, device: Option<&Path>) {
        for unit in units {
            if !self.required_masks.iter().any(|m| &m.unit == unit) {
                self.required_masks.push(RequiredMask {
                    unit: unit.clone(),
                    cause,
                    device: device.map(Path::to_path_buf),
                });
            }
        }
    }
}

/// The units of `decision` masked although a boot target requires them,
/// with why ([`Unreached`]).
fn required_masked(decision: &Decision) -> Option<(&[String], MaskCause, Option<&Path>)> {
    let Decision::Mask {
        units,
        unreached: Some(Unreached { cause, origin, .. }),
        ..
    } = decision
    else {
        return None;
    };
    if matches!(origin, Origin::Needed { may: true, .. }) {
        // NAILS cannot tell that a target requires it.
        return None;
    }
    match cause {
        Unskippable::NoDevice(device) => Some((units, MaskCause::DeviceAbsent, Some(device))),
        Unskippable::Unread => Some((units, MaskCause::Undetermined, None)),
        // NAILS cannot tell that a target requires it.
        Unskippable::MayRequire => None,
    }
}

/// What the hidden session keeps from starting for `decisions` and every
/// entry of `fstab` the hidden systemd may read: what the decisions mask and
/// skip, and the automount of each entry whose filesystem they put in place
/// themselves, read-only or overlaid (see the module docs), skipped where a
/// boot target requires it and masked otherwise.
///
/// The hidden systemd reads one fstab, but the entry decides several (the
/// decoy's, its entries resolved elsewhere, a hidden generation's), and two
/// of them can disagree about a unit. A unit that one of them masks is
/// masked, and its skip goes: a mask starts nothing, while a skip made for
/// another line could leave a checker of the line the hidden systemd reads
/// free to start. Two skips of the same unit become one, pulling in what
/// either pulls in; when they wait for different devices the unit is masked.
/// A unit a boot target requires that ends up masked is recorded with why
/// ([`KeptOff::required_masks`]).
pub fn runtime_units(fstab: &[FstabEntry], decisions: &[Decision]) -> KeptOff {
    let placed = |file: &Path| {
        decisions.iter().any(|decision| match decision {
            Decision::ReadOnlyBind { target } | Decision::Overlay { target } => target == file,
            _ => false,
        })
    };
    let mut masks: Vec<String> = masked_units(decisions);
    let mut skips: Vec<Skip> = decisions
        .iter()
        .filter_map(Decision::skip)
        .cloned()
        .collect();
    for entry in fstab
        .iter()
        .filter(|entry| entry.is_automount() && placed(&entry.file))
    {
        let automount = automount_unit(&entry.file);
        if required_by(entry).is_some() {
            skips.push(Skip {
                units: vec![automount],
                pulled: Vec::new(),
                device: None,
            });
        } else {
            masks.push(automount);
        }
    }
    let mut kept = KeptOff::default();
    for (units, cause, device) in decisions.iter().filter_map(required_masked) {
        kept.record_masked(units, cause, device);
    }
    let mut merged: Vec<Skip> = Vec::new();
    for skip in skips {
        match merged.iter_mut().find(|other| other.units == skip.units) {
            Some(other) if other.device == skip.device => {
                for unit in skip.pulled {
                    if !other.pulled.contains(&unit) {
                        other.pulled.push(unit);
                    }
                }
            }
            Some(_) => masks.extend(skip.units),
            None => merged.push(skip),
        }
    }
    for unit in masks {
        if !kept.masks.contains(&unit) {
            kept.masks.push(unit);
        }
    }
    for skip in merged {
        if skip.units.iter().any(|unit| kept.masks.contains(unit)) {
            kept.record_masked(&skip.units, MaskCause::ConflictingLines, None);
        } else {
            kept.skips.push(skip);
        }
    }
    kept
}

/// The units the hidden session keeps masked ([`runtime_units`]).
pub fn masks(fstab: &[FstabEntry], decisions: &[Decision]) -> Vec<String> {
    runtime_units(fstab, decisions).masks
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "policy_options_tests.rs"]
mod options_tests;
