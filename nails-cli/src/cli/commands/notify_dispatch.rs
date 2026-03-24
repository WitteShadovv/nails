//! Notify-dispatch command handler
//!
//! Reads pending notification signal files from the hidden volume and
//! dispatches them as desktop notifications via `notify-send`.
//! Called by the XDG autostart entry after user login.

use std::path::PathBuf;

/// Execute the notify-dispatch command
///
/// Reads all pending notification files, sends them via `notify-send`,
/// and deletes successfully dispatched files.
///
/// # Arguments
///
/// * `config_override` - Optional config file path override
/// * `json` - Output results in JSON format
pub fn execute(config_override: Option<PathBuf>, json: bool) -> ! {
    use nails_core::Config;

    let config_path = nails_core::config::discover_config_path(config_override.as_deref());
    let config = Config::load_or_default(&config_path).unwrap_or_else(|_| Config::default());

    match nails_core::notification::dispatch_all(&config.hidden_volume_root) {
        Ok(initial_count) => {
            let mut total = initial_count;
            // If we dispatched any notifications, the system is activating.
            // Poll briefly for late-arriving notifications (e.g., NixOS rebuild result).
            // We use an idle-timeout strategy instead of breaking on the first late hit:
            // after dispatching a late notification, continue polling for 3 more empty
            // cycles (15s) in case more arrive. If nothing ever arrives after the initial
            // batch, give up after 6 empty cycles (30s).
            if initial_count > 0 {
                let mut idle_streak = 0u32;
                for _ in 0..60 {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    match nails_core::notification::dispatch_all(&config.hidden_volume_root) {
                        Ok(0) => {
                            idle_streak += 1;
                            // Exit after 3 consecutive empty polls following a late dispatch,
                            // or after 6 empty polls if we never got a late one.
                            if (total > initial_count && idle_streak >= 3) || idle_streak >= 6 {
                                break;
                            }
                        }
                        Ok(n) => {
                            total += n;
                            idle_streak = 0;
                        }
                        Err(_) => break,
                    }
                }
            }
            if json {
                println!(
                    "{}",
                    serde_json::json!({"dispatched": total, "status": "ok"})
                );
            } else if total > 0 {
                tracing::debug!(count = total, "Dispatched desktop notifications");
            }
            std::process::exit(0);
        }
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"dispatched": 0, "status": "error", "error": e.to_string()})
                );
            } else {
                tracing::warn!(error = %e, "Failed to dispatch notifications");
            }
            // Exit 0 even on error — this runs from autostart; we don't want
            // error dialogs bothering the user for a non-critical feature.
            std::process::exit(0);
        }
    }
}
