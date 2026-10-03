//! Host-tool availability pre-flight check.
//!
//! nails shells out to a fixed set of host tools during activation and teardown
//! (`systemctl`, `cp`, `swapoff`, …). On a host missing one of them the first
//! spawn fails late, after the user session may already be gone. This check
//! resolves every required tool for the detected platform through the same
//! [`HostCommands`] resolver the runner uses, and fails *before* any state is
//! written, naming each missing tool and the package that provides it.

use super::super::{CheckResult, PreFlightCheck};
use crate::platform::{HostCommands, PlatformKind};
use crate::{Filesystem, Result};
use std::path::PathBuf;

/// A host tool nails requires, with the package that provides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RequiredTool {
    tool: &'static str,
    package: &'static str,
}

/// Tools every supported platform must provide.
const COMMON_TOOLS: &[RequiredTool] = &[
    RequiredTool {
        tool: "systemctl",
        package: "systemd",
    },
    RequiredTool {
        tool: "loginctl",
        package: "systemd",
    },
    RequiredTool {
        tool: "systemd-run",
        package: "systemd",
    },
    RequiredTool {
        tool: "cp",
        package: "coreutils",
    },
    RequiredTool {
        tool: "chown",
        package: "coreutils",
    },
    RequiredTool {
        tool: "sync",
        package: "coreutils",
    },
    RequiredTool {
        tool: "swapoff",
        package: "util-linux",
    },
    RequiredTool {
        tool: "kill",
        package: "procps",
    },
];

/// Tools only a NixOS host needs on top of [`COMMON_TOOLS`].
const NIXOS_TOOLS: &[RequiredTool] = &[RequiredTool {
    tool: "nixos-rebuild",
    package: "nixos-rebuild",
}];

/// The tools required for a given platform.
fn required_tools(kind: PlatformKind) -> Vec<RequiredTool> {
    let mut tools = COMMON_TOOLS.to_vec();
    if kind == PlatformKind::NixOs {
        tools.extend_from_slice(NIXOS_TOOLS);
    }
    tools
}

/// Pre-flight check that every required host tool resolves on this platform.
#[derive(Debug, Default)]
pub struct HostToolsCheck {
    /// Test override: pin the search directories and the tool set, and resolve
    /// without the root-trust check (the sandbox runs unprivileged). Production
    /// leaves this `None` and detects the platform at run time.
    #[cfg(test)]
    probe: Option<(Vec<PathBuf>, Vec<RequiredTool>)>,
}

impl HostToolsCheck {
    /// Create a check that detects the platform and resolves its required tools.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve each tool through `resolver`, collecting those that do not.
    fn evaluate(resolver: &HostCommands, tools: &[RequiredTool]) -> CheckResult {
        let missing: Vec<RequiredTool> = tools
            .iter()
            .copied()
            .filter(|required| resolver.resolve(required.tool).is_err())
            .collect();

        if missing.is_empty() {
            return CheckResult::Pass(format!(
                "All {} required host tools are present",
                tools.len()
            ));
        }

        let mut message = String::from("Required host tools are missing. Install them and retry:");
        for item in &missing {
            message.push_str(&format!("\n  {} (package: {})", item.tool, item.package));
        }
        CheckResult::Fail(message)
    }
}

impl<F: Filesystem> PreFlightCheck<F> for HostToolsCheck {
    fn name(&self) -> &'static str {
        "host-tools"
    }

    fn description(&self) -> &'static str {
        "Validates the host tools nails spawns are present on this platform"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        #[cfg(test)]
        if let Some((dirs, tools)) = &self.probe {
            let resolver = HostCommands::new(dirs.iter()).with_trust_enforcement(false);
            return Ok(Self::evaluate(&resolver, tools));
        }

        // Resolving real host tools touches the running host, so skip in a test
        // or test-like context exactly as the rest of the host-interacting code
        // does; the dedicated unit tests exercise the resolution directly.
        if crate::runtime_safety::should_skip_host_interaction() {
            return Ok(CheckResult::Pass(
                "Host tool check skipped in test/test-like context".into(),
            ));
        }

        let profile = crate::platform::detect(fs)?;
        if profile.kind == PlatformKind::Unsupported {
            // A refused host is declined with a typed error elsewhere; there is
            // no platform search list to resolve against here.
            return Ok(CheckResult::Pass(
                "Host tool check skipped on an unsupported host".into(),
            ));
        }

        let dirs: Vec<PathBuf> = crate::platform::platform_for::<F>(&profile)
            .host_command_dirs()
            .iter()
            .map(PathBuf::from)
            .collect();
        let resolver = HostCommands::new(dirs.iter());
        Ok(Self::evaluate(&resolver, &required_tools(profile.kind)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    impl HostToolsCheck {
        fn with_probe(dirs: Vec<PathBuf>, tools: Vec<RequiredTool>) -> Self {
            Self {
                probe: Some((dirs, tools)),
            }
        }
    }

    fn write_executable(path: &std::path::Path) {
        fs::write(path, "#!/bin/sh\n").unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[test]
    fn passes_when_every_required_tool_resolves() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("bin");
        fs::create_dir_all(&dir).unwrap();
        write_executable(&dir.join("systemctl"));
        write_executable(&dir.join("cp"));

        let check = HostToolsCheck::with_probe(
            vec![dir],
            vec![
                RequiredTool {
                    tool: "systemctl",
                    package: "systemd",
                },
                RequiredTool {
                    tool: "cp",
                    package: "coreutils",
                },
            ],
        );
        let result = check.run(&MockFilesystem::new()).unwrap();
        assert!(result.is_pass(), "{result:?}");
    }

    #[test]
    fn fails_with_the_package_table_when_a_tool_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("bin");
        fs::create_dir_all(&dir).unwrap();
        write_executable(&dir.join("systemctl"));
        // `swapoff` is deliberately absent.

        let check = HostToolsCheck::with_probe(
            vec![dir],
            vec![
                RequiredTool {
                    tool: "systemctl",
                    package: "systemd",
                },
                RequiredTool {
                    tool: "swapoff",
                    package: "util-linux",
                },
            ],
        );
        let result = check.run(&MockFilesystem::new()).unwrap();

        assert!(result.is_fail(), "{result:?}");
        let message = result.message();
        assert!(message.contains("swapoff"), "{message}");
        assert!(message.contains("util-linux"), "{message}");
        // A present tool is not named in the remediation table.
        assert!(!message.contains("systemctl"), "{message}");
    }

    #[test]
    fn skips_in_test_context_without_a_probe() {
        // Without a probe override the check short-circuits to a skipped Pass in a
        // test runtime, so it never touches the real host from the shared registry.
        let check = HostToolsCheck::new();
        let result = check.run(&MockFilesystem::new()).unwrap();
        assert!(result.is_pass(), "{result:?}");
    }

    #[test]
    fn opaque_and_native_walks_drop_the_attr_du_and_find_requirements() {
        // Opaque handling is in-process and directory sizing/walking is native,
        // so nails no longer spawns getfattr/setfattr/du/find. Requiring them
        // here would fail pre-flight on a host without the `attr` package, which
        // Debian and Ubuntu do not install by default.
        let tools = required_tools(PlatformKind::Fhs);
        for absent in ["getfattr", "setfattr", "du", "find"] {
            assert!(
                !tools.iter().any(|t| t.tool == absent),
                "{absent} is no longer spawned and must not be required"
            );
        }
        // The resolver-routed `cp` fallback stays, so it is still required.
        assert!(tools.iter().any(|t| t.tool == "cp"));
    }

    #[test]
    fn nixos_requires_nixos_rebuild_on_top_of_the_common_set() {
        let nixos = required_tools(PlatformKind::NixOs);
        let fhs = required_tools(PlatformKind::Fhs);
        assert!(nixos.iter().any(|t| t.tool == "nixos-rebuild"));
        assert!(!fhs.iter().any(|t| t.tool == "nixos-rebuild"));
        assert!(fhs.iter().any(|t| t.tool == "systemctl"));
    }
}
