//! Data types for forensic verification

use serde::Serialize;

/// Severity level for verification findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Severity level of the finding
    pub severity: Severity,
    /// Category of the finding (mount, file, process, memory)
    pub category: String,
    /// Human-readable message describing the finding
    pub message: String,
    /// Optional guidance on how to fix the issue
    #[serde(skip_serializing_if = "Option::is_none")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

/// Result of a verification scan
#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    /// Overall status of the system
    pub status: VerifyStatus,
    /// List of all findings
    pub findings: Vec<Finding>,
    /// Depth of scan performed
    pub scan_depth: ScanDepth,
}

impl VerifyResult {
    /// Create a new verify result
    pub fn new(status: VerifyStatus, findings: Vec<Finding>, scan_depth: ScanDepth) -> Self {
        Self {
            status,
            findings,
            scan_depth,
        }
    }

    /// Create a secure result (no findings)
    pub fn secure(scan_depth: ScanDepth) -> Self {
        Self {
            status: VerifyStatus::Secure,
            findings: Vec::new(),
            scan_depth,
        }
    }
}
