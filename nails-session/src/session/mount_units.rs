// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy's mount, swap and automount units outside its fstab.
//!
//! The hidden systemd starts every unit a target pulls in, not only those
//! its fstab generator makes: a mount unit installed for a target
//! (`/etc/systemd/system/local-fs.target.wants/srv-x.mount`, NixOS's
//! `systemd.mounts`), a swap unit (zram-generator's `dev-zram0.swap`), an
//! automount (systemd's GPT auto-generator's `efi.automount`,
//! `proc-sys-fs-binfmt_misc.automount`), the mounts the fstab generator makes
//! from the kernel command line (`systemd.mount-extra=`). The fstab policy
//! ([`super::policy`]) never saw them: in the hidden root such a unit could
//! mount a decoy disk read-write or swap onto one, and a decoy filesystem the
//! decoy has mounted now would be missing from the hidden session.
//!
//! [`read`] finds every unit with a `.mount`, `.swap` or `.automount` suffix
//! linked into a target's `.wants`, `.requires` or `.upholds` directory, one
//! of a target name's prefix (`local-.target.wants`) or the one of every
//! target (`target.wants`), the initrd's targets aside, in the unit
//! directories of the next root
//! (`/etc/systemd/system`, `/usr/local/lib/systemd/system`,
//! `/usr/lib/systemd/system`, `/lib/systemd/system`) and of `/run`
//! (`/run/systemd/system` and the generator directories the decoy's start
//! filled), less those the fstab generator made from an fstab line whose
//! decision keeps them off or puts their mount point in place: a unit whose
//! file is in a generator directory and says `SourcePath=/etc/fstab`, and
//! that the fstab policy masks, skips, binds or overlays. A copy of a
//! generated unit elsewhere (`systemctl edit --full` writes one to
//! `/etc/systemd/system`, which outranks the generator's) is decided like any
//! other unit, and so is a generated unit of a line the policy leaves as it
//! is (its drop-ins, or a link to a `noauto` line's unit, can make it mount a
//! disk) or of no line at all. Each is read from the first unit
//! directory in systemd's order that has it, with its drop-ins, those of its
//! name's prefixes (`srv-.mount.d`) and of its type (`mount.d`) included
//! ([`unit_dirs`], [`unit_file`]); a `.requires` link says a target requires
//! it. A directory of links that cannot be listed refuses the entry
//! ([`Unlisted`]). No other unit is read: a mount unit that only another
//! unit pulls in (its `Requires=` or `Wants=`, a service's `.wants`
//! directory, a `RequiresMountsFor=` path) is not decided, and the hidden
//! systemd starts it as the decoy's would.
//!
//! [`decide`] gives each the decision an fstab line with its source, mount
//! point, type and options would get ([`policy::decide_units`]): a
//! filesystem the decoy has mounted now is bound read-only or overlaid, one
//! not mounted now is skipped or masked, RAM and kernel filesystems are left
//! to the hidden systemd. The mount point and a swap's device are the ones
//! the unit's name stands for, as systemd refuses a unit whose `Where=` or
//! `What=` does not match its name; a filesystem mounted now is judged by the
//! decoy's mount table, but a RAM or kernel filesystem mounted over the mount
//! point of a unit is not taken for the unit's own: the unit's files tell
//! what it mounts, and what is mounted there is put in place as for an fstab
//! line. A zram swap is left to the hidden systemd while its
//! zram device keeps its pages in RAM, with no backing device to write them
//! back to ([`ram_only_zram`]); one with a backing device, or whose device
//! NAILS cannot tell about, is decided as a disk swap. The hidden session's
//! zram-generator sets the device up again from its configuration, which
//! NAILS does not read. The automount of a filesystem put in place is kept
//! off, as for an fstab line. A unit the decoy masks is left alone, and one
//! whose files cannot be read, or that NAILS cannot resolve, is masked.
//!
//! A unit skipped in the hidden session starts what it requires and wants:
//! [`pulled_in`] names those that act on its device or file, from its unit
//! files and its own `.wants` and `.requires` directories, and they are
//! skipped with it ([`kept_off`]). Its fsck, makefs and mkswap units, and
//! NixOS's `mkswap-<name>.service`, would run before its condition is tested;
//! its growfs, pcrfs, validatefs and quota units are bound to the mount and
//! ordered after it, so they could not start while it is skipped, and are
//! skipped for caution. Every other unit it pulls in still starts. Where
//! NAILS cannot tell them all, the unit is masked instead, and the boot
//! target that requires it is not reached. So it is where one of them is a
//! mount, swap or automount the session neither keeps off nor puts in place,
//! the mount of a parent directory among them, which the hidden systemd
//! would mount from the decoy's disk ([`pulls`]). The generators run again in the
//! hidden session; what they made in the decoy is taken as what they make
//! there.

mod pulls;
pub mod unit_dirs;
pub mod unit_file;

use super::fstab::{FstabEntry, automount_unit, escape_path, is_virtual_type, mount_unit};
use super::policy::{self, Decision, KeptOff, Origin, Present, Units, Unreached, Unskippable};
use nails_teardown::mountinfo::MountEntry;
use nails_teardown::whole_root::plan::{MaskCause, Skip};
use nails_teardown::whole_root::runtime_units::valid_unit_name;
use nails_teardown::whole_root::skips::SKIP_DROPIN_NAME;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use unit_dirs::Load;
pub use unit_dirs::{UnitDirs, Unlisted};
use unit_file::{UnitFile, without_specifiers};

/// What the fstab generator writes as `SourcePath=` of a unit it made from
/// the fstab.
const FSTAB_SOURCE: &str = "/etc/fstab";

/// The units that act on the device or file of the mount or swap that pulls
/// them in: the instances of systemd's templates, by their prefix.
const DEVICE_UNIT_TEMPLATES: &[&str] = &[
    "systemd-fsck@",
    "systemd-makefs@",
    "systemd-mkswap@",
    "systemd-growfs@",
    "systemd-pcrfs@",
    "systemd-validatefs@",
    "systemd-quotacheck@",
    "quotaon@",
];

/// The prefix of NixOS's service that formats a swap file or partition
/// before its swap unit starts.
const NIXOS_MKSWAP: &str = "mkswap-";

/// The reason a unit whose files cannot be read is masked.
const UNREADABLE: &str = "its unit files cannot be read";

/// The reason a unit whose source NAILS cannot read is masked.
const UNRESOLVED: &str =
    "its unit names its source or options by a specifier NAILS does not resolve";

/// Why NAILS cannot tell what a unit pulls in, when its unit files name a
/// unit by a specifier.
const UNRESOLVED_PULL: &str =
    "its unit files name a unit it pulls in by a specifier NAILS does not resolve";

/// Why NAILS cannot tell what a unit pulls in, when a `.wants` or
/// `.requires` directory of it cannot be listed.
const UNLISTED_PULL: &str = "a directory of the units it pulls in cannot be listed";

/// A mount, swap or automount unit a target pulls in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeUnit {
    /// Its name (`srv-scratch.mount`).
    pub name: String,
    /// The target that requires it, when one links it in its `.requires`
    /// directory; `None` when targets only want it.
    pub required_by: Option<String>,
    /// Whether every link that requires it is in a generator directory: a
    /// generator, not an installed unit file, has the target require it.
    pub required_by_generator: bool,
}

impl NativeUnit {
    /// Where the unit and what requires it come from ([`Origin`]).
    pub fn origin(&self) -> Origin {
        if self.required_by.is_some() && self.required_by_generator {
            Origin::Generated
        } else {
            Origin::Installed
        }
    }
}

/// The targets a directory of links named `name` pulls units into, and
/// whether they require them, as systemd reads such a directory for a
/// target: `<target>.wants`, `.requires` (which requires them) and
/// `.upholds` of one target, of every target whose name begins with a
/// prefix ending in a dash (`local-.target.wants`), or of every target
/// (`target.wants`). `None` for any other name, and for the initrd's
/// targets, which only an initrd runs.
fn target_links(name: &str) -> Option<(String, bool)> {
    let (stem, required) = [(".wants", false), (".requires", true), (".upholds", false)]
        .into_iter()
        .find_map(|(suffix, required)| Some((name.strip_suffix(suffix)?, required)))?;
    if stem.starts_with("initrd") {
        return None;
    }
    let targets = if stem == "target" {
        "every target".to_string()
    } else {
        let prefix = stem.strip_suffix(".target")?;
        if prefix.ends_with('-') {
            format!("every target whose name begins with {prefix}")
        } else {
            stem.to_string()
        }
    };
    Some((targets, required))
}

/// The mount, swap and automount units the targets pull in, in the order
/// the unit directories list them (see the module docs), each once. `Err`
/// names a directory of them that cannot be listed.
pub fn read(dirs: UnitDirs<'_>) -> Result<Vec<NativeUnit>, Unlisted> {
    let mut units: Vec<NativeUnit> = Vec::new();
    let mut links: Vec<(String, String, bool)> = Vec::new();
    for name in dirs.list("")? {
        if let Some((targets, required)) = target_links(&name)
            && !links.iter().any(|(seen, ..)| *seen == name)
        {
            links.push((name, targets, required));
        }
    }
    for (link, targets, required) in links {
        let required_by = required.then_some(targets);
        for (name, generated) in dirs.list_marked(&link)? {
            if !valid_unit_name(&name)
                || ![".mount", ".swap", ".automount"]
                    .iter()
                    .any(|suffix| name.ends_with(suffix))
            {
                continue;
            }
            match units.iter_mut().find(|unit| unit.name == name) {
                Some(unit) => {
                    if required_by.is_some() {
                        unit.required_by_generator = if unit.required_by.is_none() {
                            generated
                        } else {
                            unit.required_by_generator && generated
                        };
                    }
                    if unit.required_by.is_none() {
                        unit.required_by = required_by.clone();
                    }
                }
                None => units.push(NativeUnit {
                    name,
                    required_by: required_by.clone(),
                    required_by_generator: required_by.is_some() && generated,
                }),
            }
        }
    }
    Ok(units)
}

/// The path a unit name with `suffix` stands for, as systemd's
/// `unit_name_to_path()` reads it, when the name is the one systemd makes
/// for that path: `-` alone is `/`, every other `-` a `/`, `\xNN` the byte
/// NN. A name that decodes to a path systemd refuses (a `..` component, a
/// NUL), or that is not the name systemd makes for its path, stands for
/// none.
pub fn unit_path(name: &str, suffix: &str) -> Option<PathBuf> {
    let stem = name.strip_suffix(suffix)?;
    if stem == "-" {
        return Some(PathBuf::from("/"));
    }
    // Each step takes its bytes off the front of what is left, so the walk
    // ends with the name whatever a step decodes.
    let mut path = vec![b'/'];
    let mut rest = stem.as_bytes();
    loop {
        rest = match rest {
            [] => break,
            [b'-', tail @ ..] => {
                path.push(b'/');
                tail
            }
            [b'\\', b'x', high, low, tail @ ..] => {
                let hex = [*high, *low];
                path.push(u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?);
                tail
            }
            [byte, tail @ ..] => {
                path.push(*byte);
                tail
            }
        };
    }
    if path.contains(&0) {
        return None;
    }
    let path = PathBuf::from(String::from_utf8(path).ok()?);
    if path.components().any(|c| c == Component::ParentDir) {
        return None;
    }
    (escape_path(&path) == stem).then_some(path)
}

/// Whether the unit `name`, pulled in by a mount or swap, acts on its device
/// or file.
fn acts_on_device(name: &str) -> bool {
    name.ends_with(".service")
        && (DEVICE_UNIT_TEMPLATES
            .iter()
            .any(|template| name.starts_with(template))
            || name.starts_with(NIXOS_MKSWAP))
}

/// The units the unit `name` pulls in that act on its device or file: those
/// its files require, bind to or want (`Requires=`, `BindsTo=`, `Wants=`),
/// and those in its `.requires` and `.wants` directories. `Err` with the
/// reason when NAILS cannot tell them all: its unit files cannot be read,
/// name a unit by a specifier it does not resolve, or a directory of them
/// cannot be listed.
pub fn pulled_in(dirs: UnitDirs<'_>, name: &str) -> Result<Vec<String>, &'static str> {
    let mut pulled: Vec<String> = Vec::new();
    match dirs.load(name) {
        Load::Loaded { unit, .. } => {
            for key in ["Requires", "BindsTo", "Wants"] {
                for value in unit.values("Unit", key) {
                    for word in value.split_ascii_whitespace() {
                        pulled.push(without_specifiers(word).ok_or(UNRESOLVED_PULL)?);
                    }
                }
            }
        }
        Load::Unreadable => return Err(UNREADABLE),
        Load::Masked | Load::Missing => {}
    }
    for kind in ["requires", "wants"] {
        pulled.extend(
            dirs.list(&format!("{name}.{kind}"))
                .map_err(|_| UNLISTED_PULL)?,
        );
    }
    let mut units: Vec<String> = Vec::new();
    for unit in pulled {
        if valid_unit_name(&unit) && acts_on_device(&unit) && !units.contains(&unit) {
            units.push(unit);
        }
    }
    Ok(units)
}

/// The warning for `unit`, which a boot target requires and which is masked
/// because what describes it disagrees ([`MaskCause::ConflictingLines`]).
fn conflict_warning(unit: &str) -> String {
    format!(
        "{unit} is masked rather than skipped, as the fstab lines or unit files that describe it \
         disagree (one has a boot target require it and another does not, or they name two \
         devices): where the one the hidden systemd reads has a target require it, the hidden \
         session will not reach that target, and the units only that target pulls in will not \
         start there. Make them agree before activating"
    )
}

/// Why the skip drop-in of `unit` would not hold, as the decoy's drop-ins
/// stand: one of the skip's name that systemd reads in its place (from a
/// directory it searches first, or at the very path the skip writes, which
/// the switch would overwrite), or one whose name sorts after it that resets
/// the unit's start conditions with an empty `Condition…=` assignment. `None`
/// when the skip holds. A drop-in that cannot be listed or read counts as one
/// that undoes the skip.
fn skip_undone(dirs: UnitDirs<'_>, unit: &str) -> Option<String> {
    let Ok(dropins) = dirs.dropins(unit) else {
        return Some(format!("a drop-in directory of {unit} cannot be listed"));
    };
    let skip = UnitDirs::runtime_rank(unit);
    let name = SKIP_DROPIN_NAME.as_bytes();
    for dropin in &dropins {
        let own = dropin.name.as_bytes();
        if own == name {
            if dropin.rank <= skip {
                return Some(format!(
                    "{unit} has a drop-in named {SKIP_DROPIN_NAME} of its own, which systemd \
                     reads in place of the skip"
                ));
            }
            continue;
        }
        if own < name {
            continue;
        }
        let resets = match dirs.read_dropin(dropin) {
            Ok(None) => false,
            Ok(Some(bytes)) => match unit_file::parse(&bytes) {
                Ok(file) => file.assignments.iter().any(|(section, key, value)| {
                    section == "Unit" && key.starts_with("Condition") && value.is_empty()
                }),
                Err(_) => true,
            },
            Err(()) => true,
        };
        if resets {
            return Some(format!(
                "a drop-in of {unit} that sorts after the skip's resets or hides its start \
                 conditions"
            ));
        }
    }
    None
}

/// What the hidden session keeps from starting for `fstab` and the
/// `decisions` made for it and for the units outside it
/// ([`policy::runtime_units`]), each skip with the units its units pull in
/// that act on their device or file ([`pulled_in`]), and a warning for each
/// skip masked instead: one whose units pull in units NAILS cannot tell,
/// any of which could act on its disk before its condition is tested
/// ([`MaskCause::Undetermined`]), one that a drop-in of the decoy's would
/// undo for one of its units or of those they pull in
/// ([`MaskCause::SkipUndone`]), and one whose units pull in a mount, swap
/// or automount that the hidden systemd would mount from the decoy's disk
/// ([`MaskCause::PullsInMount`], [`pulls`]). A warning goes too for each
/// unit masked because what describes it disagrees
/// ([`MaskCause::ConflictingLines`]), and for each skipped unit that
/// requires a unit the session masks, which keeps it, and the boot target
/// that requires it, from starting.
pub fn kept_off(
    dirs: UnitDirs<'_>,
    fstab: &[FstabEntry],
    decisions: &[Decision],
) -> (KeptOff, Vec<String>) {
    let mut kept = policy::runtime_units(fstab, decisions);
    let covered = covered_units(decisions);
    let mut warnings: Vec<String> = kept
        .required_masks
        .iter()
        .filter(|mask| mask.cause == MaskCause::ConflictingLines)
        .map(|mask| conflict_warning(&mask.unit))
        .collect();
    for mut skip in std::mem::take(&mut kept.skips) {
        let pulled: Result<Vec<Vec<String>>, &str> = skip
            .units
            .iter()
            .map(|unit| pulled_in(dirs, unit))
            .collect();
        let (why, cause) = match pulled {
            Ok(pulled) => {
                for unit in pulled.into_iter().flatten() {
                    if !skip.pulled.contains(&unit) {
                        skip.pulled.push(unit);
                    }
                }
                let undone = skip
                    .units
                    .iter()
                    .chain(&skip.pulled)
                    .find_map(|unit| skip_undone(dirs, unit));
                match undone {
                    None => match mounted_pull(dirs, &skip, &covered, &kept.masks, fstab) {
                        Ok(None) => {
                            kept.skips.push(skip);
                            continue;
                        }
                        Ok(Some(why)) => (why, MaskCause::PullsInMount),
                        Err(why) => (why.to_string(), MaskCause::Undetermined),
                    },
                    Some(why) => (why, MaskCause::SkipUndone),
                }
            }
            Err(why) => (why.to_string(), MaskCause::Undetermined),
        };
        warnings.push(format!(
            "{} is masked rather than skipped, as {why}: the hidden session will not reach the \
             boot target that requires it, and the units only that target pulls in will not \
             start there",
            skip.units.join(" and ")
        ));
        kept.record_masked(&skip.units, cause, None);
        for unit in skip.units {
            if !kept.masks.contains(&unit) {
                kept.masks.push(unit);
            }
        }
    }
    for skip in &kept.skips {
        for unit in &skip.units {
            let Ok(pulled) = pulls::mount_pulls(dirs, unit, fstab) else {
                continue;
            };
            for pull in pulled
                .iter()
                .filter(|pull| pull.required && kept.masks.contains(&pull.unit))
            {
                warnings.push(format!(
                    "{unit} is skipped, but it requires {} ({}), which the session masks: the \
                     hidden systemd cannot start {unit}, so the boot target that requires it is \
                     not reached",
                    pull.unit, pull.how
                ));
            }
        }
    }
    (kept, warnings)
}

/// Why `skip` would have the hidden systemd mount a decoy filesystem: a unit
/// of it, or one it pulls in, pulls in a mount, swap or automount that the
/// session neither keeps off nor puts in place ([`pulls::fate`]), given
/// `covered`, the units the decisions keep off or put in place, and `masks`.
/// `Ok(None)` when it pulls in none, `Err` when NAILS cannot tell what one
/// of its units pulls in.
fn mounted_pull(
    dirs: UnitDirs<'_>,
    skip: &Skip,
    covered: &[String],
    masks: &[String],
    fstab: &[FstabEntry],
) -> Result<Option<String>, &'static str> {
    for unit in skip.units.iter().chain(&skip.pulled) {
        for pull in pulls::mount_pulls(dirs, unit, fstab)? {
            if skip.units.contains(&pull.unit) {
                continue;
            }
            if pulls::fate(dirs, &pull.unit, covered, masks, fstab) == pulls::Fate::Mounted {
                return Ok(Some(format!(
                    "{unit} pulls in {} ({}), which the session does not keep off, and the hidden \
                     systemd would mount it from the decoy's disk",
                    pull.unit, pull.how
                )));
            }
        }
    }
    Ok(None)
}

/// The value of `key` in `section` of `unit`, with `%%` resolved: `Err` when
/// it holds another specifier.
fn value(unit: &UnitFile, section: &str, key: &str) -> Result<Option<String>, ()> {
    match unit.last(section, key) {
        None => Ok(None),
        Some(value) => without_specifiers(value).map(Some).ok_or(()),
    }
}

/// The fstab options that only the fstab generator reads, and which mean
/// nothing in a unit's `Options=`: a unit is pulled in by its links.
fn generator_option(option: &str) -> bool {
    matches!(
        option,
        "noauto" | "auto" | "nofail" | "fail" | "x-systemd.automount" | "comment=systemd.automount"
    ) || option.starts_with("x-systemd.wanted-by=")
        || option.starts_with("x-systemd.required-by=")
}

/// What the files of the mount or swap unit `name` say about it, as an fstab
/// line would: its source, mount point (`none` for swap), type and options,
/// the type and source of a filesystem mounted now as the decoy's mount
/// table has them. An automount point the decoy has not mounted a
/// filesystem on yet shows PID 1's autofs, which is not the filesystem: the
/// unit's files tell that. Nor is a RAM or kernel filesystem mounted over
/// the mount point: left to the hidden systemd, a unit of a disk would mount
/// the disk read-write there, so the unit's files tell what it mounts, and
/// the policy puts what is mounted there in place. `Err` with the reason
/// when they cannot be resolved.
fn as_entry(
    unit: &UnitFile,
    name: &str,
    path: &Path,
    live: Option<&MountEntry>,
) -> Result<FstabEntry, &'static str> {
    let live = live.filter(|live| live.fstype != "autofs" && !is_virtual_type(&live.fstype));
    let swap = name.ends_with(".swap");
    let section = if swap { "Swap" } else { "Mount" };
    let options = value(unit, section, "Options")
        .map_err(|()| UNRESOLVED)?
        .unwrap_or_default();
    let (spec, vfstype) = match (swap, live) {
        (true, _) => (path.to_string_lossy().into_owned(), "swap".to_string()),
        (false, Some(live)) => (
            live.source.to_string_lossy().into_owned(),
            live.fstype.clone(),
        ),
        (false, None) => {
            let what = value(unit, section, "What")
                .map_err(|()| UNRESOLVED)?
                .ok_or("its unit names no source, so it does not load")?;
            let fstype = value(unit, section, "Type").map_err(|()| UNRESOLVED)?;
            (what, fstype.unwrap_or_else(|| "auto".to_string()))
        }
    };
    Ok(FstabEntry {
        spec,
        file: if swap {
            PathBuf::from("none")
        } else {
            path.to_path_buf()
        },
        vfstype,
        options: options
            .split(',')
            .filter(|option| !option.is_empty() && !generator_option(option))
            .map(str::to_string)
            .collect(),
    })
}

/// The zram device a swap on `path` is (`zram0` for `/dev/zram0`).
fn zram_device(path: &Path) -> Option<&str> {
    let name = path.strip_prefix("/dev").ok()?.to_str()?;
    let number = name.strip_prefix("zram")?;
    (!number.is_empty() && number.bytes().all(|b| b.is_ascii_digit())).then_some(name)
}

/// Whether the zram device `name` keeps its pages in RAM, as the sysfs at
/// `sys` shows it: it is there and its `backing_dev` reads `none`, or it is
/// there and its kernel cannot give it a backing device (no `backing_dev`).
/// A device that is not there, or whose attribute cannot be read, does not
/// count.
pub fn ram_only_zram(sys: &Path, name: &str) -> bool {
    let device = sys.join("block").join(name);
    match std::fs::read_to_string(device.join("backing_dev")) {
        Ok(backing) => backing.trim() == "none",
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => device.is_dir(),
        Err(_) => false,
    }
}

/// A unit that cannot be decided is masked: it never starts. When `required`
/// names the boot target that requires it, that target is not reached
/// either.
fn mask(
    target: PathBuf,
    units: Vec<String>,
    reason: &'static str,
    required: Option<&String>,
    origin: Origin,
) -> Decision {
    Decision::Mask {
        target,
        units,
        reason,
        unreached: required.map(|boot| Unreached {
            target: boot.clone(),
            cause: Unskippable::Unread,
            origin,
        }),
    }
}

/// The decoy's live mount at exactly `target` (the topmost one).
fn mounted_at<'a>(mounts: &'a [MountEntry], target: &Path) -> Option<&'a MountEntry> {
    mounts.iter().rev().find(|m| m.mount_point == target)
}

/// The units the fstab policy's `decisions` keep from starting or put in
/// place: those they mask or skip, and the mount and automount units of a
/// mount point they bind or overlay, which the hidden systemd finds taken. A
/// line the policy leaves as it is covers no unit: its unit may differ from
/// the line (a drop-in, a link to a `noauto` line's unit) and is decided as
/// a unit of its own.
fn covered_units(decisions: &[Decision]) -> Vec<String> {
    let mut units = Vec::new();
    for decision in decisions {
        match decision {
            Decision::ReadOnlyBind { target } | Decision::Overlay { target } => {
                units.push(mount_unit(target));
                units.push(automount_unit(target));
            }
            Decision::Mask { units: masked, .. } => units.extend(masked.iter().cloned()),
            Decision::Skip { skip, masked, .. } => {
                units.extend(skip.units.iter().cloned());
                units.extend(masked.iter().cloned());
            }
            Decision::Leave { .. } | Decision::Refuse { .. } => {}
        }
    }
    units
}

/// Decide each of `units` as an fstab line with what its files say would be
/// decided (see the module docs). `fstab_decisions` are the fstab policy's
/// decisions, `mounts` is the decoy's live mount table, with the mount points
/// as the decoy sees them, `present` tells whether a device is there now,
/// and `sys` is the sysfs the decoy's zram devices show in.
pub fn decide(
    dirs: UnitDirs<'_>,
    units: &[NativeUnit],
    fstab_decisions: &[Decision],
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
    sys: &Path,
) -> Vec<Decision> {
    let from_fstab = covered_units(fstab_decisions);
    let mut decisions: Vec<Decision> = Vec::new();
    for unit in units {
        for decision in decide_one(dirs, unit, &from_fstab, mounts, hidden_root, present, sys) {
            if !decisions.contains(&decision) {
                decisions.push(decision);
            }
        }
    }
    decisions
}

/// The decisions for one unit: none for one the fstab generator made that a
/// decision of the fstab policy keeps off or puts in place (`from_fstab`).
fn decide_one(
    dirs: UnitDirs<'_>,
    native: &NativeUnit,
    from_fstab: &[String],
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
    sys: &Path,
) -> Vec<Decision> {
    let name = native.name.as_str();
    let required = native.required_by.as_ref();
    let (suffix, automount) = if name.ends_with(".automount") {
        (".automount", true)
    } else if name.ends_with(".swap") {
        (".swap", false)
    } else {
        (".mount", false)
    };
    let Some(path) = unit_path(name, suffix) else {
        return vec![mask(
            PathBuf::from(name),
            vec![name.to_string()],
            "its name is not the escape of a path",
            required,
            native.origin(),
        )];
    };
    let unit = match dirs.load(name) {
        Load::Masked => return Vec::new(),
        Load::Missing | Load::Unreadable => {
            return vec![mask(
                path,
                vec![name.to_string()],
                UNREADABLE,
                required,
                native.origin(),
            )];
        }
        Load::Loaded { unit, generated } => {
            if generated
                && unit.last("Unit", "SourcePath") == Some(FSTAB_SOURCE)
                && from_fstab.iter().any(|fstab| fstab == name)
            {
                return Vec::new();
            }
            unit
        }
    };
    if suffix == ".swap" && zram_device(&path).is_some_and(|zram| ram_only_zram(sys, zram)) {
        return vec![Decision::Leave {
            target: path,
            reason: "a RAM-only zram swap",
        }];
    }
    // An automount decides the mount it triggers, which only it starts.
    let (mount_name, mount_unit) = if automount {
        let mount_name = format!("{}.mount", escape_path(&path));
        match dirs.load(&mount_name) {
            Load::Loaded { unit: mount, .. } => (mount_name, mount),
            Load::Masked => return Vec::new(),
            Load::Missing | Load::Unreadable => {
                return vec![mask(
                    path,
                    vec![mount_name, name.to_string()],
                    "the unit files of the mount behind it cannot be read",
                    required,
                    native.origin(),
                )];
            }
        }
    } else {
        (name.to_string(), unit)
    };
    let live = (suffix != ".swap")
        .then(|| mounted_at(mounts, &path))
        .flatten();
    let entry = match as_entry(&mount_unit, &mount_name, &path, live) {
        Ok(entry) => entry,
        Err(reason) => {
            let mut kept = vec![mount_name];
            if automount {
                kept.push(name.to_string());
            }
            return vec![mask(path, kept, reason, required, native.origin())];
        }
    };
    let units = Units {
        unit: Some(mount_name.clone()),
        automount: automount.then(|| name.to_string()),
        required_by: native.required_by.clone(),
        // What NAILS cannot tell is masked with the skip ([`kept_off`]).
        checkers: pulled_in(dirs, &mount_name).unwrap_or_default(),
        origin: native.origin(),
    };
    let decision = policy::decide_units(&entry, &units, mounts, hidden_root, present);
    let placed = matches!(
        decision,
        Decision::ReadOnlyBind { .. } | Decision::Overlay { .. }
    );
    if !(automount && placed) {
        return vec![decision];
    }
    // The filesystem is put in place: the automount would find its mount
    // point taken and fail.
    let reason = "the session puts the filesystem behind it in place";
    let automount = name.to_string();
    let off = if native.required_by.is_some() {
        Decision::Skip {
            target: path,
            skip: Skip {
                units: vec![automount],
                pulled: Vec::new(),
                device: None,
            },
            masked: Vec::new(),
            reason,
        }
    } else {
        mask(path, vec![automount], reason, None, native.origin())
    };
    vec![decision, off]
}

#[cfg(test)]
#[path = "mount_units_tests.rs"]
mod tests;
