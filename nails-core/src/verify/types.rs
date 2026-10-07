// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Data types for forensic verification

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Severity level for verification findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    /// Informational message (no action required)
    Info,
    /// Warning - potential issue that should be investigated
    Warn,
    /// Critical issue requiring immediate attention
    Critical,
}

/// A single forensic finding from the verification process
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Severity level of the finding
    pub severity: Severity,
    /// Category of the finding (mount, file, process, memory)
    pub category: String,
    /// Human-readable message describing the finding
    pub message: String,
    /// Optional guidance on how to fix the issue
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub fix_guidance: Option<String>,
}

impl Finding {
    /// Create a new finding
    pub fn new(
        severity: Severity,
        category: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            category: category.into(),
            message: message.into(),
            fix_guidance: None,
        }
    }

    /// Add fix guidance to the finding (builder pattern)
    pub fn with_fix_guidance(mut self, guidance: impl Into<String>) -> Self {
        self.fix_guidance = Some(guidance.into());
        self
    }
}

/// Overall verification status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum VerifyStatus {
    /// System is clean - no artifacts found
    Secure,
    /// Warnings found - investigate but not critical
    Warning,
    /// Critical artifacts found - requires immediate action
    Critical,
}

/// Depth of verification scan
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum ScanDepth {
    /// Standard scan (quick, common locations)
    Standard,
    /// Deep scan (comprehensive, slower)
    Deep,
}

/// Explicit state-file status captured during verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StateFileStatus {
    /// State file status was not checked
    NotChecked,
    /// No state file exists at the configured path
    Missing { path: PathBuf },
    /// State file exists and was loaded successfully
    Present { path: PathBuf, state: String },
    /// State file exists but could not be loaded safely
    Error { path: PathBuf, message: String },
}

/// Result of a verification scan
#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    /// Overall status of the system
    pub status: VerifyStatus,
    /// List of all findings
    pub findings: Vec<Finding>,
    /// Depth of scan performed
    pub scan_depth: ScanDepth,
    /// Whether the scan was config-aware (had access to Config)
    pub config_aware: bool,
    /// Number of config-specific paths that were checked
    pub config_paths_checked: usize,
    /// Explicit state-file status observed for this verify run
    pub state_file_status: StateFileStatus,
    /// Number of distinct check groups this run executed, surfaced in the honest
    /// headline so a clean result states how much was actually inspected.
    pub checks_run: usize,
    /// Areas this run did not inspect. A clean result is "no known artifacts
    /// found", not proof the system is untouched; this names what was skipped so
    /// the headline never overclaims.
    pub areas_not_checked: Vec<String>,
    /// The examiner audit of setup traces (`verify --offline --examiner`),
    /// reported apart from the session findings and never changing `status`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub examiner: Option<super::ExaminerReport>,
}

impl VerifyResult {
    /// Create a new verify result
    pub fn new(status: VerifyStatus, findings: Vec<Finding>, scan_depth: ScanDepth) -> Self {
        Self {
            status,
            findings,
            scan_depth,
            config_aware: false,
            config_paths_checked: 0,
            state_file_status: StateFileStatus::NotChecked,
            checks_run: 0,
            areas_not_checked: Vec::new(),
            examiner: None,
        }
    }

    /// Create a new config-aware verify result
    pub fn new_config_aware(
        status: VerifyStatus,
        findings: Vec<Finding>,
        scan_depth: ScanDepth,
        config_paths_checked: usize,
        state_file_status: StateFileStatus,
    ) -> Self {
        Self {
            status,
            findings,
            scan_depth,
            config_aware: true,
            config_paths_checked,
            state_file_status,
            checks_run: 0,
            areas_not_checked: Vec::new(),
            examiner: None,
        }
    }

    /// Create a secure result (no findings)
    pub fn secure(scan_depth: ScanDepth) -> Self {
        Self {
            status: VerifyStatus::Secure,
            findings: Vec::new(),
            scan_depth,
            config_aware: false,
            config_paths_checked: 0,
            state_file_status: StateFileStatus::NotChecked,
            checks_run: 0,
            areas_not_checked: Vec::new(),
            examiner: None,
        }
    }
}
