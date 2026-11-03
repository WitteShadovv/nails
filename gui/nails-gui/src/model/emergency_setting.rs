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
//! nobody. Where the window cannot tell, the control powers off, the
//! strongest ending, and the page says why:
//!
//! - until the window has read the setting;
//! - where the settings could not be read, or the setting holds a value the
//!   window does not know;
//! - for a return in a hidden session without a way back, which the engine's
//!   emergency has nothing to return with;
//! - once the window has no helper: it has no way back to the decoy of its
//!   own ([`crate::emergency`]).
//!
//! Each page of a hidden session's status names what the control does as a
//! fact, and the control's description says it on every page it shows on.

use serde_json::Value;

use super::{Model, Stage};
use crate::emergency::Finish;
use crate::envelope::{self, Attention, ConfigShowData};
use crate::text;

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
    /// The setting has not been read.
    NotRead,
    /// The setting could not be read.
    Unreadable,
    /// The setting asks for a return in a session without a way back.
    NoWayBack,
    /// The window has no helper.
    NoHelper,
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
        Some("return") => Chosen::Read(Finish::Return),
        Some("poweroff") => Chosen::Read(Finish::PowerOff),
        Some("reboot") => Chosen::Read(Finish::Reboot),
        _ => Chosen::Unreadable,
    }
}

/// The spelling of `finish` in `nails.toml`.
fn spelling(finish: Finish) -> &'static str {
    match finish {
        Finish::Return => "return",
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
        } else {
            match self.emergency_setting {
                Chosen::NotRead => Instead::NotRead,
                Chosen::Unreadable => Instead::Unreadable,
                Chosen::Read(Finish::Return) if self.no_way_back() => Instead::NoWayBack,
                Chosen::Read(finish) => return (finish, None),
            }
        };
        (Finish::PowerOff, Some(instead))
    }

    /// Whether the status says the hidden session has no way back.
    fn no_way_back(&self) -> bool {
        self.status
            .as_ref()
            .is_some_and(|status| status.attention == Some(Attention::NoWayBack))
    }

    /// The fact that says what the Emergency control does, for the pages of
    /// a hidden session's status.
    pub(super) fn emergency_fact(&self) -> (String, String) {
        let (finish, instead) = self.emergency_finish();
        let name = text::choice(KEY, spelling(finish)).0;
        let value = match instead {
            None => name.to_string(),
            Some(why) => format!(
                "{name}, {}",
                match why {
                    Instead::NotRead => text::EMERGENCY_NOT_READ,
                    Instead::Unreadable => text::EMERGENCY_UNREADABLE,
                    Instead::NoWayBack => text::EMERGENCY_NO_WAY_BACK,
                    Instead::NoHelper => text::EMERGENCY_NO_HELPER,
                }
            ),
        };
        (text::FACT_EMERGENCY.to_string(), value)
    }
}
