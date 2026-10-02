//! Dynamic overlay configuration

use std::path::{Path, PathBuf};

use super::overlay::OverlayMode;
use super::types::{Config, DEFAULT_OVERLAY_EXCLUSIONS};

/// Top-level directories a normal session writes to.
///
/// In Auto mode, everything the hidden session writes under an excluded
/// directory reaches the decoy disk. Excluding one of these would leak user
/// files, configuration changes, logs or installed software, so it is refused
/// unless the directory is also listed in `allow_leaky_exclusions`. `/media`
/// is deliberately absent: excluding it is how a hidden volume mounted there
/// is kept visible.
pub const LOAD_BEARING_DIRECTORIES: &[&str] =
    &["/home", "/root", "/etc", "/var", "/nix", "/srv", "/opt"];

/// Load-bearing only when it is not a tmpfs: writes to a RAM-backed `/tmp`
/// never reach a disk.
pub const TMP_DIRECTORY: &str = "/tmp";

impl Config {
    /// Compute effective exclusion list for dynamic overlay enumeration
    ///
    /// Combines default exclusions with user additions and removals:
    /// 1. Start with DEFAULT_OVERLAY_EXCLUSIONS
    /// 2. Add user-specified overlay_exclusions
    /// 3. Remove user-specified overlay_exclusions_remove
    /// 4. Deduplicate results
    ///
    /// # Returns
    ///
    /// Vec of PathBuf containing all effective exclusions (deduplicated)
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::config::Config;
    /// use std::path::PathBuf;
    ///
    /// let mut config = Config::default();
    /// config.overlay_exclusions = vec![PathBuf::from("/tmp")];
    /// config.overlay_exclusions_remove = vec![PathBuf::from("/mnt")];
    ///
    /// let exclusions = config.compute_effective_exclusions();
    /// assert!(exclusions.contains(&PathBuf::from("/proc")));  // default
    /// assert!(exclusions.contains(&PathBuf::from("/tmp")));   // user addition
    /// assert!(!exclusions.contains(&PathBuf::from("/mnt")));  // user removal
    /// ```
    pub fn compute_effective_exclusions(&self) -> Vec<PathBuf> {
        use std::collections::HashSet;

        // Start with defaults converted to PathBuf
        let mut exclusions: HashSet<PathBuf> = DEFAULT_OVERLAY_EXCLUSIONS
            .iter()
            .map(PathBuf::from)
            .collect();

        // Warn if user is removing dangerous exclusions (pseudo-filesystems that cannot be overlaid)
        let dangerous_exclusions = ["/proc", "/sys", "/dev", "/run"];
        for dangerous in &dangerous_exclusions {
            if self
                .overlay_exclusions_remove
                .contains(&PathBuf::from(dangerous))
            {
                tracing::warn!(
                    exclusion = %dangerous,
                    "Removing {} from exclusion list - mount will likely FAIL (pseudo-filesystem cannot be overlaid)",
                    dangerous
                );
            }
        }

        // Add user-specified additions
        for path in &self.overlay_exclusions {
            exclusions.insert(path.clone());
        }

        // Remove user-specified removals
        for path in &self.overlay_exclusions_remove {
            exclusions.remove(path);
        }

        // Convert to Vec and sort for deterministic output
        let mut result: Vec<PathBuf> = exclusions.into_iter().collect();
        result.sort();
        result
    }

    /// Effective exclusions that would send hidden-session writes to the
    /// decoy disk and are not accepted in `allow_leaky_exclusions`.
    ///
    /// Only Auto mode excludes anything, so Explicit mode always returns an
    /// empty list. Whether `/tmp` counts depends on its filesystem, which this
    /// lexical check cannot see: callers that can look pass `tmp_is_tmpfs`,
    /// and config validation passes `true` and leaves `/tmp` to the
    /// `overlay-targets` pre-flight check.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::config::Config;
    /// use std::path::PathBuf;
    ///
    /// let mut config = Config::default();
    /// config.overlay_exclusions = vec![PathBuf::from("/home"), PathBuf::from("/media")];
    /// assert_eq!(config.leaky_exclusions(true), vec![PathBuf::from("/home")]);
    ///
    /// config.allow_leaky_exclusions = vec![PathBuf::from("/home")];
    /// assert!(config.leaky_exclusions(true).is_empty());
    /// ```
    pub fn leaky_exclusions(&self, tmp_is_tmpfs: bool) -> Vec<PathBuf> {
        let mut excluded = self.excluded_load_bearing(tmp_is_tmpfs);
        excluded.retain(|path| !self.allow_leaky_exclusions.contains(path));
        excluded
    }

    /// Load-bearing directories that are excluded because
    /// `allow_leaky_exclusions` accepts the leak.
    ///
    /// Reported as a reminder: writes under them still reach the decoy disk.
    pub fn accepted_leaky_exclusions(&self, tmp_is_tmpfs: bool) -> Vec<PathBuf> {
        let mut excluded = self.excluded_load_bearing(tmp_is_tmpfs);
        excluded.retain(|path| self.allow_leaky_exclusions.contains(path));
        excluded
    }

    /// Effective exclusions that are load-bearing, sorted. Empty outside Auto
    /// mode.
    fn excluded_load_bearing(&self, tmp_is_tmpfs: bool) -> Vec<PathBuf> {
        if self.overlay_mode != OverlayMode::Auto {
            return Vec::new();
        }
        let tmp = (!tmp_is_tmpfs).then_some(TMP_DIRECTORY);
        let mut excluded = self.compute_effective_exclusions();
        excluded.retain(|path| {
            LOAD_BEARING_DIRECTORIES
                .iter()
                .chain(tmp.iter())
                .any(|dir| path == Path::new(dir))
        });
        excluded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auto_config(exclusions: &[&str], allowed: &[&str]) -> Config {
        Config {
            overlay_mode: OverlayMode::Auto,
            overlay_exclusions: exclusions.iter().map(PathBuf::from).collect(),
            allow_leaky_exclusions: allowed.iter().map(PathBuf::from).collect(),
            ..Config::default()
        }
    }

    #[test]
    fn default_exclusions_are_not_leaky() {
        let config = auto_config(&[], &[]);
        assert!(config.leaky_exclusions(false).is_empty());
        assert!(config.accepted_leaky_exclusions(false).is_empty());
    }

    #[test]
    fn each_load_bearing_exclusion_is_leaky() {
        for dir in LOAD_BEARING_DIRECTORIES {
            let config = auto_config(&[dir], &[]);
            assert_eq!(
                config.leaky_exclusions(true),
                vec![PathBuf::from(dir)],
                "excluding {dir} must be reported"
            );
        }
    }

    #[test]
    fn allowed_load_bearing_exclusion_is_accepted_not_leaky() {
        for dir in LOAD_BEARING_DIRECTORIES {
            let config = auto_config(&[dir], &[dir]);
            assert!(config.leaky_exclusions(true).is_empty(), "{dir}");
            assert_eq!(
                config.accepted_leaky_exclusions(true),
                vec![PathBuf::from(dir)]
            );
        }
    }

    #[test]
    fn allowing_one_directory_does_not_allow_another() {
        let config = auto_config(&["/home", "/nix"], &["/nix"]);
        assert_eq!(config.leaky_exclusions(true), vec![PathBuf::from("/home")]);
    }

    #[test]
    fn tmp_is_leaky_only_when_not_tmpfs() {
        let config = auto_config(&["/tmp"], &[]);
        assert!(config.leaky_exclusions(true).is_empty());
        assert_eq!(config.leaky_exclusions(false), vec![PathBuf::from("/tmp")]);

        let allowed = auto_config(&["/tmp"], &["/tmp"]);
        assert!(allowed.leaky_exclusions(false).is_empty());
        assert_eq!(
            allowed.accepted_leaky_exclusions(false),
            vec![PathBuf::from("/tmp")]
        );
    }

    #[test]
    fn media_and_other_directories_may_be_excluded() {
        let config = auto_config(&["/media", "/boot", "/data", "/home/user"], &[]);
        assert!(config.leaky_exclusions(false).is_empty());
    }

    #[test]
    fn trailing_slash_does_not_hide_a_leaky_exclusion() {
        let config = auto_config(&["/var/"], &[]);
        assert_eq!(config.leaky_exclusions(true), vec![PathBuf::from("/var")]);
    }

    #[test]
    fn exclusion_cancelled_by_remove_is_not_leaky() {
        let mut config = auto_config(&["/home"], &[]);
        config.overlay_exclusions_remove = vec![PathBuf::from("/home")];
        assert!(config.leaky_exclusions(false).is_empty());
    }

    #[test]
    fn explicit_mode_has_no_leaky_exclusions() {
        let mut config = auto_config(&["/home", "/tmp"], &[]);
        config.overlay_mode = OverlayMode::Explicit;
        assert!(config.leaky_exclusions(false).is_empty());
        assert!(config.accepted_leaky_exclusions(false).is_empty());
    }
}
