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
//! - once the window has no helper: it has no way back to the decoy of its
//!   own ([`crate::emergency`]);
//! - while the helper runs a request of Verify or of Rehearsal: a verify or
//!   a step of the rehearsal can take minutes, and the read of where the
//!   rehearsal stands counts too. The helper reads the emergency only after
//!   the request, and the window does not wait that long before it powers
//!   off itself;
//! - until the window has read the setting;
//! - where the settings could not be read, or the setting holds a value the
//!   window does not know;
//! - for a return or a restart while a deactivation powers the computer off:
//!   the emergency never turns that into a weaker ending;
//! - for a restart while a deactivation returns to the decoy: the helper
//!   reads the emergency only once it has answered the deactivation's apply,
//!   and the switch that follows ends the window and the helper with the
//!   session, so the request may never be read. The window's own ending is a
//!   power-off, which it then asks for at once
//!   ([`Firing::POWER_OFF_AT_ONCE`]), as it does for every power-off fired
//!   then;
//! - for a return in a hidden session without a way back, which the engine's
//!   emergency has nothing to return with;
//! - for a return while the window holds the plan of one that powers off
//!   instead whatever happens before it runs: the emergency's return ends
//!   through the same way back.
//!
//! The page of a hidden session's status names what the control does as a
//! fact, and every other page names it where the control powers off for one
//! of these reasons, but for the page of a deactivation that ends once its
//! switch has taken the helper with the session, as it does: that page stays
//! as it is until the switch is overdue and names the control as a way out.
//! The control's description says it on every page it shows on.

use serde_json::Value;

use super::deactivation::{Deactivation, Ending};
use super::{Model, Stage};
use crate::emergency::{Finish, Firing};
use crate::envelope::{self, Attention, ConfigShowData};
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
    /// The setting asks for a restart while a deactivation returns to the
    /// decoy.
    Returning,
    /// The setting asks for a return in a session without a way back.
    NoWayBack,
    /// The setting asks for a return, and the plan the window holds says the
    /// way back powers off instead, whatever happens before it runs.
    WayBackPowersOff,
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
        } else if matches!(self.running, Some(Kind::Verify | Kind::Rehearse)) {
            Instead::Busy
        } else {
            match self.emergency_setting {
                Chosen::NotRead => Instead::NotRead,
                Chosen::Unreadable => Instead::Unreadable,
                Chosen::Read(Finish::PowerOff) => return (Finish::PowerOff, None),
                Chosen::Read(_) if self.powering_off() => Instead::PoweringOff,
                Chosen::Read(Finish::Reboot) if self.returning() => Instead::Returning,
                Chosen::Read(Finish::Return) if self.no_way_back() => Instead::NoWayBack,
                Chosen::Read(Finish::Return) if self.way_back_powers_off() => {
                    Instead::WayBackPowersOff
                }
                Chosen::Read(finish) => return (finish, None),
            }
        };
        (Finish::PowerOff, Some(instead))
    }

    /// How the control fires now: with [its finish](Self::emergency_finish),
    /// and a power-off at once while a deactivation returns to the decoy,
    /// where the window would not live through the grace it waits for the
    /// helper otherwise.
    pub(super) fn emergency_firing(&self) -> Firing {
        match self.emergency_finish().0 {
            Finish::PowerOff if self.returning() => Firing::POWER_OFF_AT_ONCE,
            finish => finish.into(),
        }
    }

    /// Whether the status says the hidden session has no way back.
    fn no_way_back(&self) -> bool {
        self.status
            .as_ref()
            .is_some_and(|status| status.attention == Some(Attention::NoWayBack))
    }

    /// Whether a deactivation powers the computer off: the person chose
    /// Power Off, and its plan is asked for or applied.
    fn powering_off(&self) -> bool {
        matches!(
            self.deactivation,
            Some(
                Deactivation::Replanning
                    | Deactivation::Ending {
                        ending: Ending::PowerOff,
                        ..
                    }
            )
        )
    }

    /// Whether a deactivation returns to the decoy: the person chose Return
    /// to Decoy, and its plan is applied.
    fn returning(&self) -> bool {
        matches!(
            self.deactivation,
            Some(Deactivation::Ending {
                ending: Ending::Return,
                ..
            })
        )
    }

    /// Whether the plan of a return the window holds says the way back
    /// powers off instead, whatever happens before it runs.
    fn way_back_powers_off(&self) -> bool {
        self.return_instead
            .as_ref()
            .is_some_and(|instead| instead.certain)
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
                    Instead::Returning => text::EMERGENCY_RETURNING,
                    Instead::NoWayBack => text::EMERGENCY_NO_WAY_BACK,
                    Instead::WayBackPowersOff => text::EMERGENCY_WAY_BACK_POWERS_OFF,
                }
            ),
        };
        (text::FACT_EMERGENCY.to_string(), value)
    }
}
