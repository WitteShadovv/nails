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
/// one of the two below applies: the one cancel shape, as the human neutral
/// line and the `--json` error message.
pub const CANCEL_ACTIVATE: Message = Message {
    id: "activate.cancelled",
    text: "Activation cancelled. It wrote nothing to this computer's disk.",
    note: "Shown when the operator answers no at the activation prompt, or presses Ctrl+C \
           before the point of no return, while no hidden NixOS system was being built and \
           the hidden volume is a volume of its own. \"It\" is the activation; \"this \
           computer's disk\" is the computer's own storage, which an activation does not \
           write to before the point of no return. The same text is the --json error message.",
    placeholders: &[],
    surface: Surface::Cli,
};

/// The notice of an activation that builds a hidden NixOS system, cancelled
/// once its entry began: what the build finished stays on the hidden volume.
pub const CANCEL_ACTIVATE_KEEPS_BUILD: Message = Message {
    id: "activate.cancelled-keeps-build",
    text: "Activation cancelled. It wrote nothing to this computer's disk.\n\
           Anything already built stays on the hidden volume for the next activation.",
    note: "Shown instead of activate.cancelled when Ctrl+C stops an activation that builds a \
           hidden NixOS system after its entry began: what the build had finished stays on \
           the hidden volume, and the next activation uses it rather than building it again. \
           \"Anything\" because the cancel may come before the build wrote anything. Two \
           lines; the same text is the --json error message.",
    placeholders: &[],
    surface: Surface::Cli,
};

/// The notice of a cancelled activation whose hidden volume lies on storage
/// the operator allowed with `--allow-decoy-storage`.
pub const CANCEL_ACTIVATE_ALLOWED_STORAGE: Message = Message {
    id: "activate.cancelled-allowed-storage",
    text: "Activation cancelled. What it wrote to the storage you allowed stays there.",
    note: "Shown instead of the other two activation cancel notices when the operator allowed \
           a hidden volume on storage the decoy uses (--allow-decoy-storage), which may be \
           this computer's own disk: what the activation wrote there before the cancel stays. \
           The same text is the --json error message.",
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

/// Every catalogue entry, for the copy lint and any front end that walks them.
pub const CATALOG: &[Message] = &[
    REHEARSE_GUIDE_PLANT_ACTIVE,
    REHEARSE_GUIDE_PLANT_INACTIVE,
    REHEARSE_GUIDE_SCAN_NEXT_SESSION,
    REHEARSE_GUIDE_SCAN_NOW,
    REHEARSE_GUIDE_DONE,
    CANCEL_ACTIVATE,
    CANCEL_ACTIVATE_KEEPS_BUILD,
    CANCEL_ACTIVATE_ALLOWED_STORAGE,
    CANCEL_DEACTIVATE,
    CANCEL_DISCARD,
    CANCEL_EMERGENCY,
    CANCEL_CONFIG,
    CANCEL_INTERRUPTED,
];
