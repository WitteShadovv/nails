// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! What the window's Emergency control does: `window.emergency` as the
//! window read it, and the finish that follows from it.
//!
//! The control asks nothing when it is used, so how it ends a hidden session
//! is chosen in advance, on Settings. The window reads the setting with
//! `config show` once the first status of a hidden session came in, and
//! again from every read of the settings after it, its Settings page's
//! included: a change saved there holds from the read that follows the save.
//! Firing works out the finish from what the window knows then, and asks
//! nobody. Where the window cannot tell, or knows the session cannot end so,
//! the control powers off, the strongest ending, and says why:
//!
//! - once the window has no helper: it has no restart of its own
//!   ([`crate::emergency`]);
//! - while the helper runs a request of Verify or of Rehearsal: a verify or
//!   a step of the rehearsal can take minutes, and the read of where the
//!   rehearsal stands counts too. The helper reads the emergency only after
//!   the request, and the window does not wait that long before it powers
//!   off itself;
//! - until the window has read the setting;
//! - where the settings could not be read, or the setting holds a value the
//!   window does not know;
//! - for a restart while a deactivation powers the computer off: the
//!   emergency never turns that into a weaker ending.
//!
//! An older engine's `return`, the ending before every hidden session ended
//! in a power-off, reads as a power-off, as the engine reads it now.
//!
//! The page of a hidden session's status names what the control does as a
//! fact, and every other page names it where the control powers off for one
//! of these reasons, but for the page of a deactivation that ends once its
//! power-off has taken the helper with the session, as it does: that page
//! stays as it is until the power-off is overdue and names the control as a
//! way out.
//! The control's description says it on every page it shows on.

use serde_json::Value;

use super::{Model, Stage};
use crate::emergency::Finish;
use crate::envelope::{self, ConfigShowData};
use crate::text;
use crate::worker::Kind;

/// The key of the setting.
const KEY: &str = "window.emergency";

/// What the window knows of the setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Chosen {
    /// It has not been read.
    NotRead,
    /// It was read and asks for this finish.
    Read(Finish),
    /// The settings could not be read, or the setting holds a value the
    /// window does not know.
    Unreadable,
}

/// Why the control powers off instead of ending as the setting says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Instead {
    /// The window has no helper.
    NoHelper,
    /// The helper runs a request of Verify or of Rehearsal: a verify, a step
    /// of the rehearsal, or the read of where the rehearsal stands.
    Busy,
    /// The setting has not been read.
    NotRead,
    /// The setting could not be read.
    Unreadable,
    /// A deactivation powers the computer off.
    PoweringOff,
}

/// The setting as the answer `value` of `config show` gives it.
pub(super) fn read(value: &Value) -> Chosen {
    let Ok(envelope) = envelope::read::<ConfigShowData>(value, "config") else {
        return Chosen::Unreadable;
    };
    let spelling = envelope
        .data
        .as_ref()
        .and_then(|data| data.config.get("window"))
        .and_then(|window| window.get("emergency"))
        .and_then(Value::as_str);
    match spelling {
        Some("poweroff" | "return") => Chosen::Read(Finish::PowerOff),
        Some("reboot") => Chosen::Read(Finish::Reboot),
        _ => Chosen::Unreadable,
    }
}

/// The spelling of `finish` in `nails.toml`.
fn spelling(finish: Finish) -> &'static str {
    match finish {
        Finish::PowerOff => "poweroff",
        Finish::Reboot => "reboot",
    }
}

impl Model {
    /// The finish the Emergency control fires with now, and why it is a
    /// power-off where the setting does not ask for one.
    pub(super) fn emergency_finish(&self) -> (Finish, Option<Instead>) {
        let instead = if self.helper_gone || matches!(self.stage, Stage::Ended(_) | Stage::Over(_))
        {
            Instead::NoHelper
        } else if matches!(self.running, Some(Kind::Verify | Kind::Rehearse)) {
            Instead::Busy
        } else {
            match self.emergency_setting {
                Chosen::NotRead => Instead::NotRead,
                Chosen::Unreadable => Instead::Unreadable,
                Chosen::Read(Finish::PowerOff) => return (Finish::PowerOff, None),
                Chosen::Read(_) if self.deactivation.is_some() => Instead::PoweringOff,
                Chosen::Read(finish) => return (finish, None),
            }
        };
        (Finish::PowerOff, Some(instead))
    }

    /// The fact that says what the Emergency control does: for the page of
    /// a hidden session's status, and for any page where it powers off
    /// instead of ending as the setting says.
    pub(super) fn emergency_fact(&self) -> (String, String) {
        let (finish, instead) = self.emergency_finish();
        let name = text::choice(KEY, spelling(finish)).0;
        let value = match instead {
            None => name.to_string(),
            Some(why) => format!(
                "{name}, {}",
                match why {
                    Instead::NoHelper => text::EMERGENCY_NO_HELPER,
                    Instead::Busy => text::EMERGENCY_BUSY,
                    Instead::NotRead => text::EMERGENCY_NOT_READ,
                    Instead::Unreadable => text::EMERGENCY_UNREADABLE,
                    Instead::PoweringOff => text::EMERGENCY_POWERING_OFF,
                }
            ),
        };
        (text::FACT_EMERGENCY.to_string(), value)
    }
}
