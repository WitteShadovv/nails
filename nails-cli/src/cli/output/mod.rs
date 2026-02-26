//! Output formatting modules for CLI commands
//!
//! This module contains formatters for different output types (JSON, human-readable, ASCII)
//! organized by command.

pub mod activate;
pub mod deactivate;
pub mod status;
pub mod verify;

// Re-export commonly used formatters
pub use activate::{print_activate_human, print_activate_json};
pub use deactivate::{print_deactivate_human, print_deactivate_json};
pub use status::{print_status_ascii, print_status_human, print_status_json};
pub use verify::print_verify_result;
