//! Dynamic overlay configuration

use std::path::PathBuf;

use super::types::{Config, DEFAULT_OVERLAY_EXCLUSIONS};

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
}
