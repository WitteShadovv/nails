// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Deep scan of user homes: shell histories, desktop recent-file lists and temp directories.

use super::*;

impl<F: Filesystem> Verifier<F> {
    /// Perform deep scan of temporary directories, user homes and shell history.
    pub(super) fn deep_scan(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // 1. Temporary and log directories: recursively scan for nails-named
        //    files, tolerating directories we cannot enter.
        let deep_scan_paths = ["/tmp", "/var/tmp", "/var/log"];
        for base_path in deep_scan_paths {
            let path_buf = self.rebase(Path::new(base_path));
            if self.filesystem.path_exists(&path_buf)? && self.filesystem.is_directory(&path_buf)? {
                let scan = self
                    .filesystem
                    .scan_files_with_pattern(&path_buf, "nails")?;
                for file in scan.matches {
                    findings.push(
                        Finding::new(
                            Severity::Warn,
                            "file",
                            format!("NAILS-related file found: {}", file.display()),
                        )
                        .with_fix_guidance(format!("Delete file: rm {}", file.display())),
                    );
                }
                for unreadable in scan.unreadable {
                    findings.push(Finding::new(
                        Severity::Info,
                        "file",
                        format!(
                            "Directory not checked (permission denied): {}",
                            unreadable.display()
                        ),
                    ));
                }
            }
        }

        // 2. Per-home history and desktop recency files.
        for home in self.user_homes() {
            findings.extend(self.scan_home(&home)?);
        }

        Ok(findings)
    }

    /// Scan one user's home for shell history containing nails commands and for
    /// desktop recency files that name the configured hidden root.
    fn scan_home(&self, home: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for history in HISTORY_FILES {
            let path = home.join(history);
            let probe = self.rebase(&path);
            if !self.filesystem.path_exists(&probe)? {
                continue;
            }
            match self.filesystem.read_file_content(&probe) {
                Ok(content) if content.to_lowercase().contains("nails") => {
                    findings.push(
                        Finding::new(
                            Severity::Warn,
                            "file",
                            format!("Shell history contains nails commands: {}", path.display()),
                        )
                        .with_fix_guidance(format!(
                            "Edit history to remove nails commands: nano {}",
                            path.display()
                        )),
                    );
                }
                Ok(_) => {}
                Err(_) => {
                    findings.push(
                        Finding::new(
                            Severity::Info,
                            "file",
                            format!(
                                "History file exists (cannot read contents): {}",
                                path.display()
                            ),
                        )
                        .with_fix_guidance("Review history manually if needed"),
                    );
                }
            }
        }

        // Desktop recency files only matter when they name the hidden root, so
        // there is nothing to look for without a configured hidden root.
        if let Some(hidden_root) = self.hidden_root() {
            let needle = hidden_root.to_string_lossy().to_string();
            for recent in DESKTOP_RECENT_FILES {
                let path = home.join(recent);
                let probe = self.rebase(&path);
                if !self.filesystem.path_exists(&probe)? {
                    continue;
                }
                if let Ok(content) = self.filesystem.read_file_content(&probe)
                    && content.contains(&needle)
                {
                    findings.push(
                        Finding::new(
                            Severity::Warn,
                            "file",
                            format!(
                                "Desktop recency file references the hidden volume root: {}",
                                path.display()
                            ),
                        )
                        .with_fix_guidance(format!(
                            "Remove the entry that names {} from {}",
                            needle,
                            path.display()
                        )),
                    );
                }
            }
        }

        Ok(findings)
    }

    /// The home directories to scan: root, every real login account from
    /// `/etc/passwd`, and `$SUDO_USER` when verify was run under sudo.
    ///
    /// Parsing `/etc/passwd` directly (rather than resolving a single user) is
    /// what makes the scan cover *every* user's history instead of the old
    /// hardcoded `/root` plus a bare `/home` history file that never exists. In an
    /// offline image scan the file is read from under the image root.
    fn user_homes(&self) -> Vec<PathBuf> {
        let mut homes: BTreeSet<PathBuf> = BTreeSet::new();
        // Root's home is always present and always worth scanning.
        homes.insert(PathBuf::from("/root"));

        let passwd_path = self.rebase(Path::new(PASSWD_FILE));
        if let Ok(content) = self.filesystem.read_file_content(&passwd_path) {
            for line in content.lines() {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() < 7 {
                    continue;
                }
                let uid: u32 = match fields[2].parse() {
                    Ok(uid) => uid,
                    Err(_) => continue,
                };
                let home = fields[5];
                let shell = fields[6];
                let has_login_shell =
                    !shell.is_empty() && !shell.ends_with("/nologin") && !shell.ends_with("/false");
                let is_real_user = uid == 0 || (uid >= FIRST_LOGIN_UID && has_login_shell);
                if is_real_user && !home.is_empty() {
                    homes.insert(PathBuf::from(home));
                }
            }
        }

        // Prefer the invoking user's real home when running under sudo on the
        // live host; an offline scan has no meaningful live environment.
        if !self.is_offline()
            && let Ok(sudo_user) = std::env::var("SUDO_USER")
            && !sudo_user.is_empty()
            && let Ok(content) = self.filesystem.read_file_content(Path::new(PASSWD_FILE))
        {
            for line in content.lines() {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 7 && fields[0] == sudo_user && !fields[5].is_empty() {
                    homes.insert(PathBuf::from(fields[5]));
                }
            }
        }

        homes.into_iter().collect()
    }
}
