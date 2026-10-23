// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The booted kernel's command line, read the way the kernel reads it.
//!
//! `/proc/cmdline` holds the parameters the kernel booted with. The kernel
//! applies each occurrence of a parameter in turn, so the last value it accepts
//! wins; a bare `--` ends its own parameters, and what follows goes to init; and
//! `-` and `_` are the same character in a parameter name. A boolean parameter
//! goes through the kernel's `kstrtobool`, whose spellings grew in Linux 6.16,
//! so which values count depends on the booted release. The memory-wipe and
//! DMA-protection checks share this reading.

/// The first Linux release, `(major, minor)`, whose `kstrtobool` also reads a
/// value starting with `e` (`enable`) as true and one starting with `d`
/// (`disable`) as false.
const ENABLE_DISABLE_SINCE: (u32, u32) = (6, 16);

/// Which values the booted kernel's `kstrtobool` accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoolSpellings {
    /// Linux 6.15 and earlier: a value starting with `y`, `t` or `1`, or with
    /// `on`, is true, and one starting with `n`, `f` or `0`, or with `of`, is
    /// false, in either case. Any other is rejected, `enable` and `disable`
    /// among them.
    Classic,
    /// Linux 6.16 and later also read a value starting with `e` (`enable`) as
    /// true and one starting with `d` (`disable`) as false.
    EnableDisable,
}

impl BoolSpellings {
    /// The spellings of the kernel whose release (`uname -r`, as
    /// `/proc/sys/kernel/osrelease` gives it) is `release`. A release that
    /// cannot be read or parsed is taken for a current kernel, Linux 6.16 or
    /// later: a running kernel always shows its release there.
    pub fn of_release(release: Option<&str>) -> Self {
        match release.and_then(major_minor) {
            Some(version) if version < ENABLE_DISABLE_SINCE => Self::Classic,
            _ => Self::EnableDisable,
        }
    }

    /// The kernel's `kstrtobool` of `value`: `None` for a value it rejects,
    /// which leaves the parameter as it was.
    pub fn parse(self, value: &str) -> Option<bool> {
        let mut chars = value.chars().map(|c| c.to_ascii_lowercase());
        match chars.next()? {
            'y' | 't' | '1' => Some(true),
            'n' | 'f' | '0' => Some(false),
            'e' if self == Self::EnableDisable => Some(true),
            'd' if self == Self::EnableDisable => Some(false),
            'o' => match chars.next()? {
                'n' => Some(true),
                'f' => Some(false),
                _ => None,
            },
            _ => None,
        }
    }
}

/// The `name=value` parameters of the kernel command line `cmdline` that the
/// kernel reads itself, in order: each name with `-` read as `_`, each value
/// without the double quotes around it. A parameter given without a value is
/// left out, as is everything after a bare `--`.
pub fn parameters(cmdline: &str) -> impl Iterator<Item = (String, &str)> {
    cmdline
        .split_whitespace()
        .take_while(|token| *token != "--")
        .filter_map(|token| {
            let (name, value) = token.split_once('=')?;
            Some((name.replace('-', "_"), value.trim_matches('"')))
        })
}

/// The last value of the boolean parameter `name` on `cmdline` that the kernel
/// accepts, or `None` when the command line sets no accepted value.
pub fn last_bool(cmdline: &str, name: &str, spellings: BoolSpellings) -> Option<bool> {
    parameters(cmdline)
        .filter(|(key, _)| key == name)
        .filter_map(|(_, value)| spellings.parse(value))
        .last()
}

/// The major and minor number of a kernel release such as `6.12.48-1-amd64`.
fn major_minor(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.trim().split('.');
    let major = leading_number(parts.next()?)?;
    let minor = leading_number(parts.next()?)?;
    Some((major, minor))
}

/// The leading run of ASCII digits of `part` as a number.
fn leading_number(part: &str) -> Option<u32> {
    let digits = part.bytes().take_while(u8::is_ascii_digit).count();
    part[..digits].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kstrtobool_reads_the_classic_spellings_on_every_release() {
        // Linux's lib/kstrtox.c: the first character decides, except for `o`,
        // where the second tells `on` from `off`; case is ignored.
        for spellings in [BoolSpellings::Classic, BoolSpellings::EnableDisable] {
            for truthy in ["y", "Y", "yes", "t", "true", "1", "on", "ON", "On"] {
                assert_eq!(spellings.parse(truthy), Some(true), "{truthy:?}");
            }
            for falsy in ["n", "N", "no", "f", "false", "0", "off", "OFF", "of"] {
                assert_eq!(spellings.parse(falsy), Some(false), "{falsy:?}");
            }
            // A leading `o` that is neither `on` nor `off`, a bare `o`, junk and
            // the empty value are rejected.
            for rejected in ["ouch", "o", "maybe", "2", "", " 1", "ö"] {
                assert_eq!(spellings.parse(rejected), None, "{rejected:?}");
            }
        }
    }

    #[test]
    fn enable_and_disable_count_from_linux_6_16() {
        // Linux 6.16 added `e`/`E` as true and `d`/`D` as false to kstrtobool.
        let current = BoolSpellings::EnableDisable;
        for truthy in ["e", "E", "enable", "enabled", "Enable"] {
            assert_eq!(current.parse(truthy), Some(true), "{truthy:?}");
        }
        for falsy in ["d", "D", "disable", "disabled", "Disable"] {
            assert_eq!(current.parse(falsy), Some(false), "{falsy:?}");
        }
        // An older kernel rejects them, leaving the parameter as it was.
        let classic = BoolSpellings::Classic;
        for rejected in ["e", "enable", "D", "disabled"] {
            assert_eq!(classic.parse(rejected), None, "{rejected:?}");
        }
    }

    #[test]
    fn the_spellings_follow_the_booted_release() {
        for (release, spellings) in [
            ("6.15.11-arch1-1", BoolSpellings::Classic),
            ("6.12.48+deb13-amd64", BoolSpellings::Classic),
            ("6.8.0-45-generic", BoolSpellings::Classic),
            ("5.15.0", BoolSpellings::Classic),
            ("6.16.0", BoolSpellings::EnableDisable),
            ("6.16", BoolSpellings::EnableDisable),
            ("6.17.2-200.fc42.x86_64\n", BoolSpellings::EnableDisable),
            ("7.0.0-14-generic", BoolSpellings::EnableDisable),
            ("10.1", BoolSpellings::EnableDisable),
        ] {
            assert_eq!(
                BoolSpellings::of_release(Some(release)),
                spellings,
                "{release:?}"
            );
        }
        // A release that cannot be read or parsed is taken for a current one.
        for unreadable in [None, Some(""), Some("linux"), Some("6"), Some("6.x")] {
            assert_eq!(
                BoolSpellings::of_release(unreadable),
                BoolSpellings::EnableDisable,
                "{unreadable:?}"
            );
        }
    }

    #[test]
    fn parameters_are_read_as_the_kernel_reads_them() {
        let read: Vec<(String, &str)> =
            parameters("BOOT_IMAGE=/vmlinuz quiet init-on-free=\"1\" iommu.passthrough=0 -- x=1")
                .collect();
        assert_eq!(
            read,
            vec![
                ("BOOT_IMAGE".to_string(), "/vmlinuz"),
                ("init_on_free".to_string(), "1"),
                ("iommu.passthrough".to_string(), "0"),
            ]
        );
    }

    #[test]
    fn the_last_accepted_value_wins() {
        let classic = BoolSpellings::Classic;
        let current = BoolSpellings::EnableDisable;
        assert_eq!(last_bool("x=1 x=0", "x", classic), Some(false));
        assert_eq!(last_bool("x=0 x=1", "x", classic), Some(true));
        // A rejected value leaves the earlier one in place.
        assert_eq!(last_bool("x=1 x=bogus", "x", classic), Some(true));
        assert_eq!(last_bool("x=1 x=disable", "x", classic), Some(true));
        assert_eq!(last_bool("x=1 x=disable", "x", current), Some(false));
        // Nothing accepted, or nothing set.
        assert_eq!(last_bool("x x= x=maybe", "x", current), None);
        assert_eq!(last_bool("quiet", "x", current), None);
        // A similar name does not count, and init's arguments are not read.
        assert_eq!(last_bool("xx=1 y_x=1", "x", current), None);
        assert_eq!(last_bool("quiet -- x=1", "x", current), None);
    }
}
