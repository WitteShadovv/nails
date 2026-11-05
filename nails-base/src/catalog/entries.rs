// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The catalogue entries.
//!
//! Each is a `pub const` so a call site names it directly and the compiler
//! refuses a typo; [`CATALOG`] lists them for the copy lint to walk. Add an
//! entry here, add it to [`CATALOG`], and render it through
//! [`Message::render`](super::Message::render) at the call site.

use super::{Message, Surface};

/// The rehearsal's next step, shown inside an active hidden session.
pub const REHEARSE_GUIDE_PLANT_ACTIVE: Message = Message {
    id: "rehearse.guide.plant-active",
    text: "Step 1 of 3: run `{command}` in this hidden session.",
    note: "Rehearsal guidance, shown when a hidden session is already running. \
           {command} is the full `sudo <path> rehearse plant` line with the real binary path.",
    placeholders: &["command"],
    surface: Surface::Cli,
};

/// The rehearsal's next step, shown on the decoy before a session is running.
pub const REHEARSE_GUIDE_PLANT_INACTIVE: Message = Message {
    id: "rehearse.guide.plant-inactive",
    text: "Step 1 of 3: activate a hidden session, then run `{command}`.",
    note: "Rehearsal guidance, shown on the decoy when no hidden session is running yet. \
           {command} is the full `sudo <path> rehearse plant` line with the real binary path.",
    placeholders: &["command"],
    surface: Surface::Cli,
};

/// The rehearsal's next step after planting, when the canary was planted in
/// this very session: deactivate, mount again, then scan.
pub const REHEARSE_GUIDE_SCAN_NEXT_SESSION: Message = Message {
    id: "rehearse.guide.scan-next-session",
    text: "Step 2 of 3: deactivate as usual (`{deactivate}`, it soft-reboots back to the decoy), \
           then unlock and mount the hidden volume again and run `{scan}`.",
    note: "Rehearsal guidance after the canary was planted in the current session. \
           {deactivate} is the full `sudo <path> deactivate` line; {scan} is the full \
           `sudo <path> rehearse scan` line. Both use the real binary path.",
    placeholders: &["deactivate", "scan"],
    surface: Surface::Cli,
};

/// The rehearsal's next step after planting in an earlier session: scan now.
pub const REHEARSE_GUIDE_SCAN_NOW: Message = Message {
    id: "rehearse.guide.scan-now",
    text: "Step 3 of 3: run `{command}`.",
    note: "Rehearsal guidance when the canary is planted and ready to scan. \
           {command} is the full `sudo <path> rehearse scan` line with the real binary path.",
    placeholders: &["command"],
    surface: Surface::Cli,
};

/// The rehearsal is complete; how to scan again or remove it.
pub const REHEARSE_GUIDE_DONE: Message = Message {
    id: "rehearse.guide.done",
    text: "Done. Scan again any time, or run `{command}` to remove the rehearsal from the hidden volume.",
    note: "Rehearsal guidance once a scan has run. {command} is the full \
           `sudo <path> rehearse reset` line with the real binary path.",
    placeholders: &["command"],
    surface: Surface::Cli,
};

/// The notice an activation cancelled at the prompt or by Ctrl+C prints, unless
/// one of the three below applies: the one cancel shape, as the human neutral
/// line and the `--json` error message.
pub const CANCEL_ACTIVATE: Message = Message {
    id: "activate.cancelled",
    text: "Activation cancelled. It wrote nothing to this computer's disk.",
    note: "Shown when the operator answers no at the activation prompt, or presses Ctrl+C \
           before the point of no return, while no hidden NixOS system was being built, and \
           only when the attach gate found the hidden volume a volume of its own, with no \
           warning. \"It\" is the activation; \"this computer's disk\" is the storage the \
           decoy uses as the gate reads it (its mounts, fstab, crypttab and swap, and the \
           devices below them), which the gate found the hidden volume separate from. The same \
           text is the --json error message.",
    placeholders: &[],
    surface: Surface::Cli,
};

/// The notice of an activation that builds a hidden NixOS system, cancelled
/// once its entry began: what the build finished stays on the hidden volume.
pub const CANCEL_ACTIVATE_KEEPS_BUILD: Message = Message {
    id: "activate.cancelled-keeps-build",
    text: "Activation cancelled. It wrote nothing to this computer's disk.\n\
           Anything already built stays on the hidden volume for the next activation.",
    note: "Shown instead of activate.cancelled, on a hidden volume of its own as there, when \
           Ctrl+C stops an activation that builds a hidden NixOS system after its entry began: \
           what the build had finished stays on the hidden volume, and the next activation \
           uses it rather than building it again. \"Anything\" because the cancel may come \
           before the build wrote anything. Two lines; the same text is the --json error \
           message.",
    placeholders: &[],
    surface: Surface::Cli,
};

/// The notice of a cancelled activation whose hidden volume the attach gate
/// accepted with a warning of its own, without `--allow-decoy-storage`.
pub const CANCEL_ACTIVATE_WARNED_STORAGE: Message = Message {
    id: "activate.cancelled-warned-storage",
    text: "Activation cancelled. What it wrote to the hidden volume stays there.",
    note: "Shown instead of activate.cancelled and activate.cancelled-keeps-build when the \
           attach gate accepted the hidden volume with a warning of its own, shown before the \
           activation went on: an encrypted container file on a filesystem the decoy uses, or \
           a device the decoy shares only with storage it never mounts at boot. \
           What the activation wrote went to that storage, so the notice says only that it \
           stays, and nothing about this computer's disk. It is also the notice of a cancel \
           reported without knowing where the hidden volume lies. The same text is the --json \
           error message.",
    placeholders: &[],
    surface: Surface::Cli,
};

/// The notice of a cancelled activation whose hidden volume lies on storage
/// the operator allowed with `--allow-decoy-storage`.
pub const CANCEL_ACTIVATE_ALLOWED_STORAGE: Message = Message {
    id: "activate.cancelled-allowed-storage",
    text: "Activation cancelled. What it wrote to the storage you allowed stays there.",
    note: "Shown instead of the other activation cancel notices when the operator allowed a \
           hidden volume on storage the decoy uses (--allow-decoy-storage), which may be this \
           computer's own disk: what the activation wrote there before the cancel stays. The \
           same text is the --json error message.",
    placeholders: &[],
    surface: Surface::Cli,
};

/// The notice a deactivation cancelled at the prompt prints.
pub const CANCEL_DEACTIVATE: Message = Message {
    id: "deactivate.cancelled",
    text: "Deactivation cancelled; nothing was changed.",
    note: "Shown when the operator answers no at the deactivation prompt, or presses Ctrl+C \
           there. The same text is the --json error message.",
    placeholders: &[],
    surface: Surface::Cli,
};

/// The notice a discard of a path's hidden upper cancelled at the prompt
/// prints.
pub const CANCEL_DISCARD: Message = Message {
    id: "discard.cancelled",
    text: "Discard cancelled; nothing was removed.",
    note: "Shown when the operator answers no at the prompt that discards a path's hidden \
           changes, or presses Ctrl+C there. The same text is the --json error message.",
    placeholders: &[],
    surface: Surface::Cli,
};

/// The notice an emergency stopped during its countdown prints, before it
/// acted.
pub const CANCEL_EMERGENCY: Message = Message {
    id: "emergency.cancelled",
    text: "Emergency cancelled; nothing was changed.",
    note: "Shown when the operator presses Ctrl+C during the countdown of \
           `emergency --countdown`, before anything was done. The same text is the --json \
           error message.",
    placeholders: &[],
    surface: Surface::Cli,
};

/// The notice a change of the configuration stopped by a cancel prints,
/// before the file was replaced.
pub const CANCEL_CONFIG: Message = Message {
    id: "config.cancelled",
    text: "Change cancelled; nothing was written.",
    note: "Shown when a Ctrl+C or a SIGTERM reaches `config set` or `config unset` before the \
           new file replaced the old one, which stays as it was. A signal after that does not \
           stop the command, which then reports the change it made. The same text is the --json \
           error message.",
    placeholders: &[],
    surface: Surface::Cli,
};

/// The `--json` error message of a command a signal ended before it printed
/// its result.
pub const CANCEL_INTERRUPTED: Message = Message {
    id: "command.interrupted",
    text: "Interrupted before it finished.",
    note: "The --json error message (code `cancelled`) of a command that a Ctrl+C or a \
           SIGTERM ended before it printed its result: status, verify, check, the config views \
           (path, show and validate), init or rehearse. The commands that only read (status, \
           verify, the config views and the rehearse status view) changed nothing. An interrupted check may leave a probe file or directory on the \
           hidden volume, since its probes remove what they wrote only once they finish; init and \
           the rehearse steps that write may have done part of their work.",
    placeholders: &[],
    surface: Surface::Json,
};

/// The failure of the hidden-volume check when the volume's filesystem is
/// mounted at another place as well, as a desktop that mounts a drive by
/// itself does.
pub const CHECK_MOUNTED_TWICE: Message = Message {
    id: "check.mounted-twice",
    text: "the volume at {root} is also mounted at {places}: a desktop may have mounted it \
           there by itself when it was unlocked",
    note: "The failure of the hidden-volume check, in `check` and before an activation, when \
           the filesystem mounted at the root folder is mounted at another place too, most \
           often by a desktop that mounts a drive by itself under /media or /run/media once it \
           is unlocked. \"It\" is the volume. {root} is the root folder as configured, such as \
           /mnt/data; {places} is the other mount point, or several joined by commas and a last \
           \"and\". It starts in lower case because it follows the check's name and a colon. The \
           same text is the --json message of that check.",
    placeholders: &["root", "places"],
    surface: Surface::Cli,
};

/// What to do about [`CHECK_MOUNTED_TWICE`]: unmount the other mounts.
pub const CHECK_MOUNTED_TWICE_FIX: Message = Message {
    id: "check.mounted-twice-fix",
    text: "Run `sudo umount {mount_points}`, then run the command again.",
    note: "The first line of the fix shown below check.mounted-twice. {mount_points} is every \
           other mount point that umount reaches by its path, each quoted for the shell where \
           it needs it, the deepest first, so the line pastes as it is. \"The command\" is the \
           one that failed (check or activate). A line of check.mounted-twice-hidden for each \
           mount another one hides, then the two lines of check.mounted-twice-advice, follow \
           it. All of them together are the --json fix of that check.",
    placeholders: &["mount_points"],
    surface: Surface::Cli,
};

/// What to do about [`CHECK_MOUNTED_TWICE`] when another mount of the volume
/// holds the root folder, and the mount at the root shows all of the volume:
/// the other mount can only go once the root is unmounted too.
pub const CHECK_MOUNTED_TWICE_FIX_HOLDING_ROOT: Message = Message {
    id: "check.mounted-twice-fix-holding-root",
    text: "Run `sudo umount {mount_points}`, mount the volume at {root} alone, then run the \
           command again.",
    note: "Shown instead of check.mounted-twice-fix when one of the other mounts of the volume \
           is on a parent folder of the root folder (the volume mounted at /mnt and again at \
           /mnt/data, say), which cannot be unmounted while the root is mounted below it, and \
           the mount at the root shows the whole volume. {mount_points} is the root folder and \
           every other mount point that umount reaches by its path, each quoted for the shell \
           where it needs it, the deepest first; {root} is the root folder as configured. The \
           lines that follow are those of check.mounted-twice-fix.",
    placeholders: &["mount_points", "root"],
    surface: Surface::Cli,
};

/// What to do about [`CHECK_MOUNTED_TWICE`] when another mount of the volume
/// holds the root folder, and the mount at the root is a folder of the volume
/// bound there: mounting the volume itself there would show its top instead.
pub const CHECK_MOUNTED_TWICE_FIX_HOLDING_FOLDER: Message = Message {
    id: "check.mounted-twice-fix-holding-folder",
    text: "Run `sudo umount {mount_points}`. Then mount the volume at another folder, bind its \
           folder {folder} at {root}, unmount that other folder and run the command again.",
    note: "Shown instead of check.mounted-twice-fix-holding-root when the mount at the root is \
           a bind of a folder of the volume (the volume mounted at /mnt and its folder /vol \
           bound at /mnt/data, say): the folder holds what NAILS keeps, so mounting the volume \
           itself at the root would show the wrong folder. {folder} is the path of that folder \
           inside the volume, such as /vol. \"Another folder\" is any empty folder the \
           volume is mounted at only until the bind is made. The other placeholders and lines \
           are those of check.mounted-twice-fix-holding-root.",
    placeholders: &["mount_points", "folder", "root"],
    surface: Surface::Cli,
};

/// What to do about [`CHECK_MOUNTED_TWICE`] when another mount of the volume
/// holds the root folder, and the mount at the root is a btrfs subvolume of
/// the volume: mounting the volume itself there would show another one.
pub const CHECK_MOUNTED_TWICE_FIX_HOLDING_SUBVOLUME: Message = Message {
    id: "check.mounted-twice-fix-holding-subvolume",
    text: "Run `sudo umount {mount_points}`, mount the btrfs subvolume {subvolume} of the volume \
           at {root} alone (mount option subvol={subvolume}), then run the command again.",
    note: "Shown instead of check.mounted-twice-fix-holding-root when the mount at the root is \
           a btrfs subvolume of the volume (the volume's top mounted at /mnt and its subvolume \
           /data at /mnt/data, say): mounting the volume without that option would show its \
           default subvolume instead. {subvolume} is the subvolume's path inside the volume, \
           such as /data, and the option is written as the mount command takes it. The other \
           placeholders and lines are those of check.mounted-twice-fix-holding-root.",
    placeholders: &["mount_points", "subvolume", "root"],
    surface: Surface::Cli,
};

/// A line of the fix for [`CHECK_MOUNTED_TWICE`] about another mount of the
/// volume that a later mount hides, which `umount` cannot reach by its path.
pub const CHECK_MOUNTED_TWICE_HIDDEN: Message = Message {
    id: "check.mounted-twice-hidden",
    text: "The mount at {place} is hidden under another mount at {cover}, so umount cannot \
           reach it by that path: unmount that one first, then {place}, and mount it again if \
           it is needed.",
    note: "One line below the unmount line of check.mounted-twice-fix (or in its place, when \
           every other mount is hidden), for each other mount of the volume that a later mount \
           hides: one mounted at the same folder over it, or at a folder above it, the root \
           folder included. umount given that path unmounts the mount over it, or fails. \
           {place} is where the hidden mount is; {cover} is where the mount over it is, the \
           same folder as {place} when the two are stacked there. \"It\" in \"mount it \
           again\" is the mount over it.",
    placeholders: &["place", "cover"],
    surface: Surface::Cli,
};

/// The last lines of the fix for [`CHECK_MOUNTED_TWICE`]: keep a desktop from
/// mounting the drive next time.
pub const CHECK_MOUNTED_TWICE_ADVICE: Message = Message {
    id: "check.mounted-twice-advice",
    text: "Long before the next use, turn off the automatic mounting of removable media.\n\
           Read \"Attaching the drive\" in the decoy requirements on another device.",
    note: "The last two lines of the fix shown below check.mounted-twice, after its unmount \
           lines. The first is about the desktop's setting that mounts a drive once it is \
           attached or unlocked (GNOME, KDE, udiskie); \"long before\" because a setting \
           changed just before a session dates it. The second names the section of the \
           documentation (docs/decoy-requirements.md) that says where those settings are; it \
           is read on another device, as opening it on this computer leaves traces.",
    placeholders: &[],
    surface: Surface::Cli,
};

/// Every catalogue entry, for the copy lint and any front end that walks them.
pub const CATALOG: &[Message] = &[
    REHEARSE_GUIDE_PLANT_ACTIVE,
    REHEARSE_GUIDE_PLANT_INACTIVE,
    REHEARSE_GUIDE_SCAN_NEXT_SESSION,
    REHEARSE_GUIDE_SCAN_NOW,
    REHEARSE_GUIDE_DONE,
    CANCEL_ACTIVATE,
    CANCEL_ACTIVATE_KEEPS_BUILD,
    CANCEL_ACTIVATE_WARNED_STORAGE,
    CANCEL_ACTIVATE_ALLOWED_STORAGE,
    CANCEL_DEACTIVATE,
    CANCEL_DISCARD,
    CANCEL_EMERGENCY,
    CANCEL_CONFIG,
    CANCEL_INTERRUPTED,
    CHECK_MOUNTED_TWICE,
    CHECK_MOUNTED_TWICE_FIX,
    CHECK_MOUNTED_TWICE_FIX_HOLDING_ROOT,
    CHECK_MOUNTED_TWICE_FIX_HOLDING_FOLDER,
    CHECK_MOUNTED_TWICE_FIX_HOLDING_SUBVOLUME,
    CHECK_MOUNTED_TWICE_HIDDEN,
    CHECK_MOUNTED_TWICE_ADVICE,
];
