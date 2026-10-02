//! Output formatting modules for CLI commands
//!
//! [`OutputSettings`] holds the rendering decisions resolved once per run; the
//! per-command modules render results with it. Machine-readable output goes
//! through one [`envelope::Envelope`] on stdout, and every handler returns an
//! [`exit::ExitStatus`] so `main` owns the process exit code.

pub mod activate;
pub mod check;
pub mod deactivate;
pub mod dto;
pub mod envelope;
pub mod exit;
pub mod settings;
pub mod status;
pub mod verify;

// Re-export commonly used formatters
pub use activate::{print_activate_human, print_activate_json_result, print_activate_progress};
pub use check::{print_check_human, print_check_json};
pub use deactivate::{deactivate_error_body, print_deactivate_json};
pub use envelope::{Envelope, ErrorBody, report_error};
pub use exit::ExitStatus;
pub use settings::{Environment, OutputMode, OutputSettings};
pub use status::{print_status_header, print_status_human, print_status_json};
pub use verify::print_verify_result;
