//! Command handler modules
//!
//! Each command handler is a standalone module that encapsulates the logic
//! for a specific CLI command. Handlers are called from the main command dispatcher
//! in the parent module.

pub mod activate;
pub mod deactivate;
pub mod emergency;
pub mod status;
pub mod verify;
