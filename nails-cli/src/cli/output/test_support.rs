// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Helpers for the tests that run a handler in a child process (the test
//! binary run again for one case) to see its real stdout and exit code, and
//! judge the `--json` envelope it printed against the committed schema.

use serde_json::Value;

/// The lines a child test process printed on stdout, blank lines and the test
/// harness's own `running 1 test` header left out. Run the child with
/// `--quiet`, so the harness prints no test name before the child's lines.
pub(crate) fn stdout_lines(output: &std::process::Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with("running "))
        .map(str::to_string)
        .collect()
}

/// `line` as a JSON document, checked against the schema of `command` in
/// `docs/schemas/`.
pub(crate) fn envelope(command: &str, line: &str) -> Value {
    let value: Value =
        serde_json::from_str(line).unwrap_or_else(|e| panic!("not JSON ({e}): {line}"));
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../docs/schemas/{command}.schema.json"));
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let validator = jsonschema::validator_for(&schema).expect("compile the schema");
    let errors: Vec<String> = validator
        .iter_errors(&value)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}: {line}");
    value
}
