// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Logging infrastructure with hidden volume validation
//!
//! Provides structured JSON logging that only writes to the hidden volume,
//! ensuring operational logs never contaminate the decoy system.
//!
//! # Security Constraints
//!
//! - Logs to hidden volume ONLY
//! - Refuse to log if hidden volume not mounted (fail-safe)
//! - Structured JSON logs (newline-delimited)
//! - Pre-flight validation of hidden volume path before any write
//!
//! # Usage Workflow
//!
//! ## 1. Initialize LoggingManager
//!
//! ```no_run
//! use nails_base::logging::LoggingManager;
//! use nails_base::{RealFilesystem, Verbosity};
//! use std::path::PathBuf;
//!
//! // Create manager with log path and hidden volume path
//! let log_path = PathBuf::from("/mnt/hidden-volume/logs");
//! let hidden_volume_root = PathBuf::from("/mnt/hidden-volume");
//! let manager = LoggingManager::new(log_path, hidden_volume_root);
//!
//! // Validate and initialize (fail-safe: refuses if outside hidden volume)
//! let fs = RealFilesystem;
//! let config = manager.init(&fs).expect("Failed to initialize logging")
//!     .expect("Hidden volume not available");
//! ```
//!
//! ## 2. Install Subscriber
//!
//! ```no_run
//! # use nails_base::logging::LoggingConfig;
//! # use nails_base::Verbosity;
//! # use std::path::PathBuf;
//! # let config = LoggingConfig {
//! #     log_file_path: PathBuf::from("/mnt/hidden-volume/logs/nails.log"),
//! # };
//! // Install with verbosity level
//! config.build_and_install_with_verbosity(Verbosity::Normal)
//!     .expect("Failed to install subscriber");
//! ```
//!
//! ## 3. Use Tracing Events
//!
//! ```no_run
//! // Now all tracing events are captured to the log file
//! tracing::info!(user = "alice", state = "active", "System activated");
//! tracing::error!(path = "/home", error = "busy", "Mount failed");
//! ```
//!
//! ## JSON Output Format
//!
//! Logs are written as newline-delimited JSON:
//!
//! ```json
//! {"timestamp":"2026-02-12T10:30:45.123Z","level":"INFO","message":"System activated","fields":{"user":"alice","state":"active"}}
//! {"timestamp":"2026-02-12T10:30:46.456Z","level":"ERROR","message":"Mount failed","fields":{"path":"/home","error":"busy"}}
//! ```

// Module declarations
mod config;
mod manager;
mod path;
mod rotation;

// Public re-exports
pub use config::LoggingConfig;
pub use manager::LoggingManager;
pub use rotation::{DEFAULT_MAX_LOG_SIZE_MB, DEFAULT_RETENTION_DAYS, LOG_FILE_NAME};
