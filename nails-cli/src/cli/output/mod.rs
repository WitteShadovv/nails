//! Output formatting modules for CLI commands
//!
//! [`OutputSettings`] holds the rendering decisions resolved once per run; the
//! per-command modules render results with it.

pub mod activate;
pub mod deactivate;
pub mod settings;
pub mod status;
pub mod verify;

// Re-export commonly used formatters
pub use activate::{print_activate_human, print_activate_json};
pub use deactivate::{print_deactivate_human, print_deactivate_json};
pub use settings::{Environment, OutputMode, OutputSettings};
pub use status::{print_status_header, print_status_human, print_status_json};
pub use verify::print_verify_result;
