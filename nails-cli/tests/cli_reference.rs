// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! CLI reference staleness guard.
//!
//! The shipped man page (`nails.1`) and Markdown CLI reference (`docs/cli.md`)
//! are generated from the clap command tree, not written by hand, so they cannot
//! drift from the real flags. This test regenerates both into memory and fails
//! when a committed file differs. Regenerate and review the diff with:
//!
//!   REGENERATE_CLI_DOCS=1 cargo test -p nails-cli --test cli_reference
//!
//! The man page's date is pinned (see `render_man`) so the output depends only on
//! the command definition, never on the day the test runs.

use std::path::{Path, PathBuf};

use clap::CommandFactory;
use nails::cli::Cli;

/// The repository root (the workspace directory above `nails-cli`).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("nails-cli has a parent workspace directory")
        .to_path_buf()
}

/// Render the man page for the whole CLI with a pinned date, so the committed
/// `nails.1` changes only when the command definition changes.
fn render_man() -> String {
    let command = Cli::command();
    // Pin every volatile field: the release epoch's date, a fixed manual title
    // and the project name as the source. Without this clap_mangen stamps the
    // current date and the file would go stale every day.
    let man = clap_mangen::Man::new(command)
        .date("1980-01-01")
        .manual("NAILS Manual")
        .source("nails");
    let mut buffer: Vec<u8> = Vec::new();
    man.render(&mut buffer).expect("man page renders");
    String::from_utf8(buffer).expect("man page is UTF-8")
}

/// Render the Markdown CLI reference, with an exit-status table appended.
fn render_markdown() -> String {
    let mut markdown = clap_markdown::help_markdown::<Cli>();
    markdown.push_str(EXIT_STATUS_TABLE);
    markdown
}

/// The per-command exit-status reference appended to `docs/cli.md`. clap-markdown
/// does not know the process exit codes, so they are documented here and kept in
/// step with the `ExitStatus` enum and the `--help` EXIT STATUS section.
const EXIT_STATUS_TABLE: &str = "\
## Exit status

Every command shares one set of exit codes.

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | The operation failed |
| 2 | Command-line usage error |
| 3 | The configuration file or environment was unusable |
| 4 | A pre-flight check refused the operation |
| 5 | The operation needs privileges it did not have |
| 6 | The on-disk state could not be trusted |
| 7 | A degraded or interrupted session, or an incomplete cleanup; `nails status` names the fix (usually `nails recover`) |
| 8 | The host is not one NAILS can operate on |
| 9 | Completed, but with a warning the caller should act on |
| 10 | `verify` found warnings |
| 11 | `verify` found critical artifacts, or `rehearse scan` found its canary |
| 130 | Cancelled: a declined prompt, or a signal (SIGINT/SIGTERM) |

Notable per-command codes: `verify` returns 0/10/11 for secure/warning/critical;
`rehearse scan` returns 0 when the canary is not found, 11 when it is, and 9
when a device could not be scanned completely;
`status` returns 7 on a degraded posture and 6 on an untrusted state file; every
mutating command returns 5 when run without root.
";

/// Compare generated content against a committed file, or rewrite it when
/// `REGENERATE_CLI_DOCS=1` is set.
fn check_or_regenerate(relative: &str, generated: &str) {
    let path = repo_root().join(relative);
    if std::env::var_os("REGENERATE_CLI_DOCS").is_some() {
        std::fs::write(&path, generated)
            .unwrap_or_else(|e| panic!("could not write {}: {e}", path.display()));
        return;
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
    assert!(
        committed == generated,
        "{} is stale. Regenerate it with:\n  \
         REGENERATE_CLI_DOCS=1 cargo test -p nails-cli --test cli_reference",
        path.display()
    );
}

#[test]
fn man_page_is_current() {
    check_or_regenerate("nails.1", &render_man());
}

#[test]
fn cli_markdown_reference_is_current() {
    check_or_regenerate("docs/cli.md", &render_markdown());
}

/// The README's `nails -h` capture, `docs/assets/screenshots/help.txt`: its
/// body (below the `---` that ends the front matter) is the short help as
/// clap renders it. `render-terminal-svg.py --check` compares each SVG with
/// its capture only, so without this the capture would drift from the help.
/// `REGENERATE_CLI_DOCS=1` rewrites the body; render the SVG again after it.
#[test]
fn the_help_capture_is_current() {
    let relative = "docs/assets/screenshots/help.txt";
    let committed = std::fs::read_to_string(repo_root().join(relative))
        .unwrap_or_else(|e| panic!("could not read {relative}: {e}"));
    let (front, _) = committed
        .split_once("\n---\n")
        .unwrap_or_else(|| panic!("{relative} has no front matter"));
    let help = Cli::command().render_help().to_string();
    check_or_regenerate(relative, &format!("{front}\n---\n{help}"));
}
