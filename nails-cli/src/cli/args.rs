//! CLI argument definitions
//!
//! This module contains the Clap-based CLI argument parser definitions
//! for the NAILS CLI application.

use clap::{Parser, Subcommand};

/// NixOS Anti-forensics Isolation & Layering System
#[derive(Parser)]
#[command(name = "nails")]
#[command(author = "NAILS Project")]
#[command(version)]
#[command(about = "NixOS Anti-forensics Isolation & Layering System", long_about = None)]
pub struct Cli {
    /// Path to configuration file (overrides binary-relative discovery)
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<std::path::PathBuf>,

    /// Verbose output (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, conflicts_with = "quiet")]
    pub verbose: u8,

    /// Quiet mode: only show errors and warnings
    #[arg(short = 'q', long, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Skip file logging (only log to stdout)
    #[arg(long)]
    pub no_logs: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Activate the hidden NixOS environment (mount overlayfs + switch profiles)
    Activate {
        /// Skip pre-flight checks (DANGEROUS - expert use only)
        #[arg(long)]
        no_preflight: bool,

        /// Quiet mode: only show final result
        #[arg(short = 'q', long, conflicts_with = "verbose")]
        quiet: bool,

        /// Verbose output (-v for detailed, -vv for debug)
        #[arg(short, long, action = clap::ArgAction::Count, conflicts_with = "quiet")]
        verbose: u8,

        /// Output results in JSON format
        #[arg(long)]
        json: bool,

        /// Disable colored output
        #[arg(long)]
        no_color: bool,

        /// ASCII-only output (no Unicode symbols)
        #[arg(long)]
        plain: bool,

        /// Skip clearing shell history on deactivation
        #[arg(long)]
        no_clear_history: bool,

        /// Kill graphical session before activation (enabled by default)
        #[arg(long)]
        kill_session: bool,

        /// Do not kill session (interactive mode)
        #[arg(long, conflicts_with = "kill_session")]
        no_kill_session: bool,

        /// Accept pivot mount fallback for any volume (degraded security)
        #[arg(long, conflicts_with = "no_pivot")]
        accept_pivot_risks: bool,

        /// Abort if any volume requires pivot mount (strict security, enabled by default)
        #[arg(long, conflicts_with = "accept_pivot_risks")]
        no_pivot: bool,

        /// Skip all confirmation prompts (enabled by default)
        #[arg(short = 'y', long)]
        yes: bool,

        /// Prompt for confirmations (interactive mode)
        #[arg(long, conflicts_with = "yes")]
        interactive: bool,
    },
    /// Deactivate and return to decoy state (unmount + cleanup)
    Deactivate {
        /// Skip shell history cleanup
        ///
        /// By default, deactivation removes all 'nails' commands from shell history.
        /// Use this flag to preserve history (not recommended for forensic safety).
        #[arg(long)]
        no_clear_history: bool,

        /// Suppress output except errors
        #[arg(short, long, conflicts_with = "verbose")]
        quiet: bool,

        /// Increase verbosity (-v for details, -vv for debug)
        #[arg(short, long, action = clap::ArgAction::Count, conflicts_with = "quiet")]
        verbose: u8,

        /// Output results in JSON format
        #[arg(long)]
        json: bool,

        /// Disable colored output
        #[arg(long)]
        no_color: bool,

        /// ASCII-only output (no Unicode symbols)
        #[arg(long)]
        plain: bool,
    },
    /// Emergency mode: rapid deactivation with countdown
    Emergency {
        /// Skip the 3-second countdown (proceed immediately)
        #[arg(long)]
        no_countdown: bool,

        /// Suppress output except final result
        #[arg(long, conflicts_with = "verbose")]
        quiet: bool,

        /// Increase verbosity (-v for details, -vv for debug)
        #[arg(short, long, action = clap::ArgAction::Count, conflicts_with = "quiet")]
        verbose: u8,

        /// Output results in JSON format
        #[arg(long)]
        json: bool,

        /// Disable colored output
        #[arg(long)]
        no_color: bool,

        /// ASCII-only output (no Unicode symbols)
        #[arg(long)]
        plain: bool,
    },
    /// Show current status and uptime
    Status {
        /// Output results in JSON format
        #[arg(long)]
        json: bool,

        /// Disable colored output
        #[arg(long)]
        no_color: bool,

        /// ASCII-only output (no Unicode box drawing or emoji)
        #[arg(long)]
        plain: bool,

        /// Display detailed overlay mount information
        #[arg(short, long)]
        verbose: bool,
    },
    /// Verify system is clean of NAILS artifacts
    Verify {
        /// Perform deep scan (slower, more thorough)
        #[arg(long)]
        deep: bool,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
}
