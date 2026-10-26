// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether a hidden session can load the running kernel's modules.
//!
//! A hidden session runs on the decoy's kernel, so it loads that kernel's
//! modules from `/usr/lib/modules/<release>` through the root overlay. A
//! kernel package update in a hidden session (a `pacman -Syu` that brings a
//! new `linux` on Arch Linux) deletes that tree, and the overlay keeps the
//! deletion in its upper: a whiteout at `usr/lib/modules/<release>`, or
//! whiteouts of the files below it, the module index `modules.dep` among
//! them. Every later hidden session then starts without modules for the
//! kernel it runs on, so a USB stick, a filesystem or a network card whose
//! driver is not loaded yet does not work there.
//!
//! The `kernel-modules` check reads what the upper holds on the way to that
//! tree, and [`judge`], a pure function, decides:
//!
//! - a whiteout, or anything but a directory, at `usr`, `usr/lib`,
//!   `usr/lib/modules` or `usr/lib/modules/<release>`: the tree is deleted or
//!   replaced;
//! - an opaque directory there (`trusted.overlay.opaque=y`, which the kernel
//!   sets on a directory a session deleted and made again): below it the
//!   decoy's tree no longer shows through, and only the upper's copy counts;
//! - the release's index: `modules.dep` or `modules.dep.bin` deleted (a
//!   whiteout) or replaced by something other than a file, or `modules.dep`
//!   rebuilt by a hidden session before the decoy last rebuilt its own.
//!
//! `modprobe` finds a module by name through `modules.dep.bin`, the binary
//! form of `modules.dep`, so either one deleted or replaced counts. `depmod`
//! writes the two together with the release's other index files (and Arch
//! Linux's kernel hook deletes them together), so `modules.dep` stands for
//! them all where one file has to: whether the upper holds an index of its
//! own, and how old it is.
//!
//! An index a hidden session wrote no earlier than the decoy's (a `depmod`
//! once it installed a module) passes with a note: it covers the decoy's
//! modules as they are. A decoy without the running kernel's tree warns too, since a
//! hidden session cannot load what the decoy lacks; a decoy without
//! `/usr/lib/modules` at all keeps its modules elsewhere (NixOS) and passes.
//!
//! The kernel shows `trusted.*` attributes only to a caller with
//! `CAP_SYS_ADMIN` in the initial user namespace, and to anyone else it reports
//! them missing (`ENODATA`) rather than refused. An unprivileged `nails check`
//! therefore cannot tell an opaque directory from a merged one: whenever the
//! verdict hangs on one, the check says it could not tell and names the `sudo`
//! line, never a silent pass.
//!
//! Every read is an `lstat`, a `statx` or an `lgetxattr`, none of which
//! changes an access time, and each lookup below the decoy root and the upper
//! passes only through entries already seen to be directories, so no symbolic
//! link's access time changes either. Nothing here writes.

use crate::error::Result;
use crate::filesystem::Filesystem;
use crate::preflight::{CheckResult, PreFlightCheck};
use nails_base::next_step::{NextStep, shell_word, sudo_line, sudo_line_for};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

mod read;

pub use read::{TrustedXattrs, read_decoy, read_upper, running_release};

/// The index `depmod` writes of a release's modules, in text form; it stands
/// for every index file `depmod` writes with it.
const INDEX: &str = "modules.dep";

/// The binary form of [`INDEX`], through which `modprobe` finds a module by
/// name.
const BINARY_INDEX: &str = "modules.dep.bin";

/// One path the judge reads below a root, from the root down: the
/// directories on the way to a release's modules, then its index files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// `usr`.
    Usr,
    /// `usr/lib`.
    UsrLib,
    /// `usr/lib/modules`, where every installed kernel keeps its modules.
    ModuleDir,
    /// `usr/lib/modules/<release>`, the running kernel's modules.
    Release,
    /// `usr/lib/modules/<release>/modules.dep`, their index.
    Index,
    /// `usr/lib/modules/<release>/modules.dep.bin`, the index's binary form.
    BinaryIndex,
}

impl Step {
    /// The directories on the way, in the order a lookup takes them.
    pub const DIRS: [Step; 4] = [Step::Usr, Step::UsrLib, Step::ModuleDir, Step::Release];

    /// The index files in the release's directory.
    pub const INDEXES: [Step; 2] = [Step::Index, Step::BinaryIndex];

    /// The step's path below a root, for the kernel `release`.
    pub fn path(self, release: &OsStr) -> PathBuf {
        let modules = Path::new("usr/lib/modules");
        match self {
            Step::Usr => PathBuf::from("usr"),
            Step::UsrLib => PathBuf::from("usr/lib"),
            Step::ModuleDir => modules.to_path_buf(),
            Step::Release => modules.join(release),
            Step::Index => modules.join(release).join(INDEX),
            Step::BinaryIndex => modules.join(release).join(BINARY_INDEX),
        }
    }
}

/// What the upper holds at one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Held {
    /// Nothing: the decoy's entry shows through, unless an opaque directory
    /// above cut it off.
    Nothing,
    /// A whiteout: a hidden session deleted the path.
    Whiteout,
    /// A directory, and whether it hides the decoy's directory of that name.
    Dir(Opacity),
    /// A regular file, last modified at the time given.
    File(SystemTime),
    /// Anything else: a symbolic link, a device, a socket or a FIFO.
    Other,
    /// The entry cannot be read, for the reason given.
    Unreadable(String),
}

/// Whether a directory in the upper hides the decoy's directory of its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opacity {
    /// No: the two are merged.
    Merged,
    /// Yes: the directory is opaque.
    Opaque,
    /// Not known.
    Unknown(Doubt),
}

/// Why a verdict could not be reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Doubt {
    /// It hangs on an opaque marker this process cannot see (only root can).
    NeedsRoot,
    /// Anything else, said as a reason.
    Other(String),
}

/// The decoy's side of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoy {
    /// No `/usr/lib/modules`: the decoy keeps its modules elsewhere (NixOS).
    NoModuleDir,
    /// `/usr/lib/modules` without the running kernel's directory.
    NoRelease,
    /// The running kernel's directory on the root filesystem, with the time
    /// its index was last rebuilt, when it has one.
    Release {
        /// When the decoy's `modules.dep` was last written.
        index: Option<SystemTime>,
    },
    /// The decoy's side cannot be judged.
    Unknown(String),
}

/// How the hidden sessions' changes keep the running kernel's modules away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hiding {
    /// The step is a whiteout.
    Deleted,
    /// The step is something other than a directory.
    Replaced,
    /// The step is an opaque directory without the release below it.
    Covered,
    /// The step is an opaque directory with the upper's own copy of the
    /// release, index included.
    OwnCopy,
    /// As [`OwnCopy`](Hiding::OwnCopy), but the copy has no index.
    CopyWithoutIndex,
    /// The index file at the step given, [`Step::Index`] or
    /// [`Step::BinaryIndex`], is a whiteout.
    IndexDeleted(Step),
    /// The index file at the step given is something other than a file.
    IndexReplaced(Step),
    /// The upper's own index is older than the decoy's.
    StaleIndex,
}

/// The judgement of the running kernel's modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing a hidden session changed keeps them away.
    Intact,
    /// As [`Intact`](Verdict::Intact), with an index a hidden session wrote
    /// no earlier than the decoy's.
    OwnIndex,
    /// The decoy keeps no modules in `/usr/lib/modules`.
    NoModuleDir,
    /// The decoy itself has no modules for the running kernel.
    MissingOnDecoy,
    /// The hidden sessions' changes keep them away (`how`); deleting the
    /// hidden sessions' copy of `at` brings the decoy's back.
    Hidden {
        /// The step whose hidden copy holds the change.
        at: Step,
        /// What the change is.
        how: Hiding,
    },
    /// No verdict could be reached.
    Unknown(Doubt),
}

/// Judge what the upper holds on the way to the running kernel's index
/// against the decoy's side. `upper` has one entry per step of
/// [`Step::DIRS`], then of [`Step::INDEXES`], and ends early at the first
/// directory step that holds no directory; an entry it lacks counts as
/// [`Held::Nothing`].
///
/// The decoy's side decides first: what a hidden session changed cannot hide
/// a tree the decoy does not have.
pub fn judge(decoy: &Decoy, upper: &[Held]) -> Verdict {
    match decoy {
        Decoy::Unknown(reason) => Verdict::Unknown(Doubt::Other(reason.clone())),
        Decoy::NoModuleDir => Verdict::NoModuleDir,
        Decoy::NoRelease => Verdict::MissingOnDecoy,
        Decoy::Release { index } => walk(*index, upper),
    }
}

/// The upper's side of [`judge`], for a decoy whose index was last rebuilt at
/// `decoy_index`. `cut` is the first opaque directory on the way, below which
/// the decoy no longer shows through; `doubt` the first directory whose
/// opacity is not known.
fn walk(decoy_index: Option<SystemTime>, upper: &[Held]) -> Verdict {
    let held = |i: usize| upper.get(i).unwrap_or(&Held::Nothing);
    let mut cut = None;
    let mut doubt = None;
    for (i, step) in Step::DIRS.into_iter().enumerate() {
        match held(i) {
            Held::Dir(Opacity::Merged) => {}
            Held::Dir(Opacity::Opaque) => {
                cut.get_or_insert(step);
            }
            Held::Dir(Opacity::Unknown(why)) => {
                doubt.get_or_insert_with(|| why.clone());
            }
            Held::Nothing => return unless_cut(cut, doubt, Hiding::Covered, Verdict::Intact),
            // Below an opaque directory nothing of the decoy's is left to
            // hide: the directory itself is what keeps the tree away.
            Held::Whiteout => {
                let deleted = Verdict::Hidden {
                    at: step,
                    how: Hiding::Deleted,
                };
                return unless_cut(cut, None, Hiding::Covered, deleted);
            }
            Held::File(_) | Held::Other => {
                let replaced = Verdict::Hidden {
                    at: step,
                    how: Hiding::Replaced,
                };
                return unless_cut(cut, None, Hiding::Covered, replaced);
            }
            Held::Unreadable(why) => return Verdict::Unknown(Doubt::Other(why.clone())),
        }
    }
    let dirs = Step::DIRS.len();
    index(held(dirs), held(dirs + 1), cut, doubt, decoy_index)
}

/// The index's part of [`walk`], once every directory on the way is one:
/// `text` and `binary` are what the upper holds at [`Step::Index`] and
/// [`Step::BinaryIndex`]. Either one deleted or replaced hides the modules;
/// whether the upper has an index of its own, and how old it is, `text`
/// tells.
fn index(
    text: &Held,
    binary: &Held,
    cut: Option<Step>,
    doubt: Option<Doubt>,
    decoy_index: Option<SystemTime>,
) -> Verdict {
    let at = cut.unwrap_or(Step::Release);
    for (file, held) in [(Step::Index, text), (Step::BinaryIndex, binary)] {
        let how = match held {
            Held::Whiteout => Hiding::IndexDeleted(file),
            Held::Dir(_) | Held::Other => Hiding::IndexReplaced(file),
            Held::Unreadable(why) => return Verdict::Unknown(Doubt::Other(why.clone())),
            Held::Nothing | Held::File(_) => continue,
        };
        return Verdict::Hidden { at, how };
    }
    let Held::File(rebuilt) = text else {
        return unless_cut(cut, doubt, Hiding::CopyWithoutIndex, Verdict::Intact);
    };
    let own = if decoy_index.is_some_and(|decoy| decoy > *rebuilt) {
        Verdict::Hidden {
            at: Step::Release,
            how: Hiding::StaleIndex,
        }
    } else {
        Verdict::OwnIndex
    };
    unless_cut(cut, doubt, Hiding::OwnCopy, own)
}

/// `otherwise`, unless an opaque directory cut the decoy off (`how` at it)
/// or one whose opacity is not known could have.
fn unless_cut(cut: Option<Step>, doubt: Option<Doubt>, how: Hiding, otherwise: Verdict) -> Verdict {
    match (cut, doubt) {
        (Some(at), _) => Verdict::Hidden { at, how },
        (None, Some(doubt)) => Verdict::Unknown(doubt),
        (None, None) => otherwise,
    }
}

/// Whether `release` names one directory: not empty, not `.` or `..`, and
/// without a `/`.
fn plain_name(release: &OsStr) -> bool {
    let bytes = release.as_bytes();
    !bytes.is_empty() && bytes != b"." && bytes != b".." && !bytes.contains(&b'/')
}

/// `kernel-modules`.
#[derive(Debug)]
pub struct KernelModulesCheck {
    /// The decoy root, `/` outside tests.
    root: PathBuf,
    /// The root overlay's upper on the hidden volume.
    upper: PathBuf,
    /// The running kernel's release.
    release: OsString,
    /// Whether the run accepted a hidden root on this computer's own storage
    /// (`--allow-decoy-storage`), which the `discard` the fix names then
    /// needs too.
    allow_decoy_storage: bool,
}

impl KernelModulesCheck {
    /// The check of the modules of the kernel `release` below the decoy
    /// `root`, against the root overlay's `upper`.
    pub fn new(root: PathBuf, upper: PathBuf, release: OsString) -> Self {
        Self {
            root,
            upper,
            release,
            allow_decoy_storage: false,
        }
    }

    /// The check for a run that accepted the hidden root on this computer's
    /// own storage: the `discard` its fix names takes the same flag.
    pub fn allowing_decoy_storage(mut self, allow: bool) -> Self {
        self.allow_decoy_storage = allow;
        self
    }

    /// The result for a process that sees `trusted.*` attributes as `xattrs`
    /// says. The upper is read only for a decoy that has the tree.
    pub fn result(&self, xattrs: TrustedXattrs) -> CheckResult {
        if !plain_name(&self.release) {
            return self.report(&Verdict::Unknown(Doubt::Other(format!(
                "the running kernel's release {:?} is not a plain directory name",
                self.release.to_string_lossy()
            ))));
        }
        let decoy = read_decoy(&self.root, &self.release);
        let upper = match decoy {
            Decoy::Release { .. } => read_upper(&self.upper, &self.release, xattrs),
            _ => Vec::new(),
        };
        self.report(&judge(&decoy, &upper))
    }

    /// `step` as hidden sessions see it.
    fn path(&self, step: Step) -> String {
        format!("/{}", step.path(&self.release).display())
    }

    /// The row for `verdict`.
    fn report(&self, verdict: &Verdict) -> CheckResult {
        let tree = self.path(Step::Release);
        match verdict {
            Verdict::Intact => CheckResult::Pass(format!(
                "no hidden session deleted or replaced the running kernel's modules ({tree})"
            )),
            Verdict::OwnIndex => CheckResult::Pass(format!(
                "no hidden session deleted or replaced the running kernel's modules ({tree}), \
                 and their index ({INDEX}) is one a hidden session wrote"
            )),
            Verdict::NoModuleDir => {
                CheckResult::Pass("the decoy keeps no kernel modules in /usr/lib/modules".into())
            }
            Verdict::MissingOnDecoy => CheckResult::warn_with(
                format!(
                    "the decoy has no {tree} for the running kernel, so hidden sessions get no \
                     modules for that kernel from the decoy"
                ),
                "Reboot the decoy into the kernel it has installed (a kernel update can remove \
                 the modules of the kernel it replaces), then activate.",
            ),
            Verdict::Hidden { at, how } => {
                CheckResult::warn_with(self.hidden(*at, *how), self.fix(*at, *how))
            }
            Verdict::Unknown(Doubt::NeedsRoot) => CheckResult::warn_with(
                format!(
                    "could not tell whether a hidden session hid the running kernel's modules \
                     ({tree}): only root can see whether a hidden session replaced a directory \
                     on the way with a new one"
                ),
                format!("Run `{}` to see it.", sudo_line(NextStep::Check)),
            ),
            Verdict::Unknown(Doubt::Other(reason)) => CheckResult::Warn(format!(
                "could not tell whether a hidden session hid the running kernel's modules \
                 ({tree}): {reason}"
            )),
        }
    }

    /// What the hidden sessions' change `how` at `at` did.
    fn hidden(&self, at: Step, how: Hiding) -> String {
        let tree = self.path(Step::Release);
        let place = self.path(at);
        let whole = at == Step::Release;
        match how {
            Hiding::Deleted if whole => format!(
                "a hidden session deleted {tree}, the running kernel's modules, so hidden \
                 sessions cannot load them (a kernel package update in a hidden session can do \
                 this)"
            ),
            Hiding::Deleted => format!(
                "a hidden session deleted {place}, and with it {tree}, the running kernel's \
                 modules, so hidden sessions cannot load them"
            ),
            Hiding::Replaced if whole => format!(
                "a hidden session replaced {tree}, the running kernel's modules, with something \
                 other than a directory, so hidden sessions cannot load them"
            ),
            Hiding::Replaced => format!(
                "a hidden session replaced {place} with something other than a directory, which \
                 hides {tree}, the running kernel's modules, so hidden sessions cannot load them"
            ),
            Hiding::Covered => format!(
                "a hidden session replaced the decoy's {place} with a new directory without \
                 {tree}, the running kernel's modules, so hidden sessions cannot load them"
            ),
            Hiding::OwnCopy if whole => format!(
                "a hidden session replaced the decoy's {tree}, the running kernel's modules, \
                 with a copy of its own, and hidden sessions load them from that copy"
            ),
            Hiding::OwnCopy => format!(
                "a hidden session replaced the decoy's {place} with a new directory, and hidden \
                 sessions load the running kernel's modules from the copy of {tree} in it"
            ),
            Hiding::CopyWithoutIndex if whole => format!(
                "a hidden session replaced the decoy's {tree}, the running kernel's modules, \
                 with a copy of its own that has no index ({INDEX}), so hidden sessions cannot \
                 load them"
            ),
            Hiding::CopyWithoutIndex => format!(
                "a hidden session replaced the decoy's {place} with a new directory whose copy \
                 of {tree}, the running kernel's modules, has no index ({INDEX}), so hidden \
                 sessions cannot load them"
            ),
            Hiding::IndexDeleted(file) => format!(
                "a hidden session deleted {}, the index of the running kernel's modules, so \
                 hidden sessions cannot load them (a kernel package update in a hidden session \
                 can do this)",
                self.path(file)
            ),
            Hiding::IndexReplaced(file) => format!(
                "a hidden session replaced {}, the index of the running kernel's modules, with \
                 something other than a file, so hidden sessions may not load them",
                self.path(file)
            ),
            Hiding::StaleIndex => format!(
                "the index of the running kernel's modules ({}) is one a hidden session wrote \
                 before the decoy last rebuilt its own, so modules the decoy added since may not \
                 load in hidden sessions",
                self.path(Step::Index)
            ),
        }
    }

    /// The fix for the change `how` at `at`: the `discard` that deletes the
    /// hidden sessions' copy of `at`, and, for a change to the running
    /// kernel's own tree, a kernel of a new release on the decoy, whose
    /// modules are in a tree of their own. A change above that tree hides the
    /// decoy's modules for every kernel, so there a kernel update is no fix.
    fn fix(&self, at: Step, how: Hiding) -> String {
        let place = self.path(at);
        let back = |also: &str| {
            format!(
                "the decoy's {place} back with `{}`, which deletes what hidden sessions changed \
                 there{also} (it lists what it deletes and asks first)",
                self.discard(&place)
            )
        };
        match how {
            Hiding::OwnCopy => format!(
                "If modules fail to load in hidden sessions, bring {}.",
                back("")
            ),
            Hiding::StaleIndex => format!(
                "Rebuild the index in a hidden session with `sudo depmod {}`, or bring {}.",
                shell_word(&self.release),
                back(", the modules they added included")
            ),
            _ if at == Step::Release => format!(
                "Update the decoy's kernel to a new release and reboot the decoy into it, or \
                 bring {}.",
                back("")
            ),
            _ => format!(
                "Bring {}. A kernel update on the decoy would not bring its modules back, since \
                 the change hides them for every kernel.",
                back("")
            ),
        }
    }

    /// The `discard` line that deletes the hidden sessions' copy of `place`,
    /// with `--allow-decoy-storage` when the run was given it.
    fn discard(&self, place: &str) -> String {
        let place = shell_word(OsStr::new(place));
        if self.allow_decoy_storage {
            sudo_line_for(NextStep::Discard, &format!("--allow-decoy-storage {place}"))
        } else {
            sudo_line_for(NextStep::Discard, &place)
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for KernelModulesCheck {
    fn name(&self) -> &'static str {
        "kernel-modules"
    }

    fn description(&self) -> &'static str {
        "a hidden session can load the running kernel's modules"
    }

    fn requires_hidden_volume(&self) -> bool {
        true
    }

    fn run(&self, _fs: &F) -> Result<CheckResult> {
        Ok(self.result(TrustedXattrs::of_this_process()))
    }
}

#[cfg(test)]
#[path = "kernel_modules_tests.rs"]
mod tests;
