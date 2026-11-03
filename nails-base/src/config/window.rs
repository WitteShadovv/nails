// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `[window]` configuration: what the window does in a hidden session.
//!
//! The window's Emergency control ends a hidden session with one gesture and
//! asks nothing at that moment, so how it ends is chosen in advance, here.
//! Only the window reads it: the hot path of `nails emergency` acts before
//! any configuration is read, and takes `--poweroff` or `--reboot` on its
//! command line instead.

use serde::{Deserialize, Serialize};

/// How the window's Emergency control ends a hidden session: the ending of
/// `nails emergency`, `--poweroff` or `--reboot`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowEmergency {
    /// Back to the decoy's own login screen, as `nails emergency` without a
    /// flag. The default: to someone in the room a running decoy looks like
    /// a logout, where a machine that goes dark draws the eye.
    #[default]
    Return,
    /// Power off, as `nails emergency --poweroff`: RAM decays, the strongest
    /// answer to a seizure.
    Poweroff,
    /// Reboot fully, as `nails emergency --reboot`. A warm reboot does not
    /// clear RAM.
    Reboot,
}

/// `[window]` configuration table.
///
/// Every key is optional and unknown keys are rejected, like the other tables.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowConfig {
    /// How the window's Emergency control ends a hidden session. Defaults to
    /// [`WindowEmergency::Return`].
    #[serde(default)]
    pub emergency: WindowEmergency,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_returns_to_the_decoy() {
        assert_eq!(WindowConfig::default().emergency, WindowEmergency::Return);
        let config: WindowConfig = toml::from_str("").unwrap();
        assert_eq!(config, WindowConfig::default());
    }

    #[test]
    fn every_ending_parses_and_round_trips() {
        for (text, ending) in [
            ("emergency = \"return\"", WindowEmergency::Return),
            ("emergency = \"poweroff\"", WindowEmergency::Poweroff),
            ("emergency = \"reboot\"", WindowEmergency::Reboot),
        ] {
            let config: WindowConfig = toml::from_str(text).unwrap();
            assert_eq!(config.emergency, ending, "{text}");
            let written = toml::to_string(&config).unwrap();
            assert_eq!(written.trim(), text);
        }
    }

    #[test]
    fn an_unknown_ending_or_key_is_refused() {
        for text in [
            "emergency = \"power-off\"",
            "emergency = \"halt\"",
            "emergency = true",
            "emergancy = \"return\"",
        ] {
            assert!(toml::from_str::<WindowConfig>(text).is_err(), "{text}");
        }
    }
}
