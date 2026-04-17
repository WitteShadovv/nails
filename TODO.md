# Repository Review

- **Review scope:** Full repository review of `/home/witteshadovv/git/nails`
- **Dimensions reviewed:** Code Quality & Correctness; Security Posture; Architecture & Design; User Experience & Usability; CI/CD & DevOps; Documentation & Governance
- **Verification status:** Complete, evidence-backed review across six parallel `repo-reviewer` passes; all backlog items below cite repository file:line references.

## Priority Definitions

- `P0`: Security bugs, correctness failures, broken contracts, or severe trust failures
- `P1`: Important reliability, maintainability, UX, architecture, or process issues
- `P2`: Long-term improvements and structural health work

## Repository Health Scorecard

| Dimension | Score | Key Finding |
|-----------|-------|-------------|
| Code Quality & Correctness | 5/10 | State-file integrity handling and session/process edge cases can produce false failures or silent misbehavior. |
| Security Posture | 5/10 | Hidden-volume artifacts and boundary checks fail too open for a security-sensitive tool. |
| Architecture & Design | 6/10 | Workspace layering is sound, but `nails-core` still owns terminal UX and oversized orchestration flows. |
| User Experience & Usability | 5/10 | Operator trust is weakened by silent config fallback, inconsistent log/status behavior, and missing recovery guidance. |
| CI/CD & DevOps | 5/10 | CI exists and is partially hardened, but PR validation, E2E gating, and benchmark/tool reproducibility have gaps. |
| Documentation & Governance | 6/10 | Core policies exist, but contributor workflow docs, security scope, and intake templates have drifted. |
| Overall | 5.3/10 | Security and correctness risks dominate; architecture, automation, and documentation are usable but materially drifted. |

## P0 - Critical

### P0-01: Repair state-file integrity handling

**Objective:** Make state-file verification upgrade-safe and make its integrity guarantees accurate.

**Why it matters:** Current checksum handling can reject legitimate compatible state files, and the stored plain SHA-256 digest is described more strongly than it really is.

**Verified:** `nails-core/src/state/file.rs:75-77`, `nails-core/src/state/file.rs:211-225`, `nails-core/src/state/file.rs:357-388`, `nails-core/src/state/tests.rs:1543-1588`

**File-by-file tasks:**
- `nails-core/src/state/file.rs`: verify the serialized on-disk payload before mutating `version`, or redesign the integrity input so compatible version migration does not change the verification payload.
- `nails-core/src/state/file.rs`: replace the unkeyed digest with authenticated integrity protection, or rename comments/errors everywhere to corruption detection if authenticated protection is out of scope.
- `nails-core/src/state/tests.rs`: add regressions for compatible-version load success, tampered compatible-version failure, and future-major-version rejection.

**Acceptance criteria:**
- [ ] Compatible older state files with valid integrity data load successfully.
- [ ] The repository either implements authenticated integrity checks or clearly downgrades the mechanism everywhere to corruption detection.
- [ ] Regression tests cover upgrade, corruption/tamper, and future-major-version cases.

**Effort:** `L`
**Dependencies:** `None`

### P0-02: Restrict hidden-volume artifact permissions

**Objective:** Ensure notification and log artifacts are readable only by the intended owner.

**Why it matters:** Current `0755`/`0644` defaults expose hidden-environment activity, failure messages, and TRACE-level operational details to other local users.

**Verified:** `nails-core/src/notification/mod.rs:64-66`, `nails-core/src/notification/mod.rs:124-126`, `nails-core/src/manager/activation/mod.rs:250-258`, `nails-core/src/manager/activation/mod.rs:371-399`, `nails-cli/src/cli/logging.rs:250-255`, `nails-cli/src/cli/logging.rs:276-285`

**File-by-file tasks:**
- `nails-core/src/notification/mod.rs`: change notification directory mode to `0700` and notification file mode to `0600`; keep ownership handoff compatible with dispatch/deletion.
- `nails-cli/src/cli/logging.rs`: create and reopen log files with `0600`, and normalize permissions before appending to existing files.
- `nails-core/src/notification/mod.rs`: add or extend tests to assert expected Unix modes for notification artifacts.
- `nails-cli/src/cli/logging.rs`: add or extend tests to assert expected Unix modes for log artifacts.

**Acceptance criteria:**
- [ ] Notification directories and files are owner-only.
- [ ] Log files are created and reopened with owner-only permissions.
- [ ] Tests assert the expected Unix modes for both artifact types.

**Effort:** `M`
**Dependencies:** `None`

### P0-03: Fail closed on symlinked or escaping hidden-volume paths

**Objective:** Ensure log and state writes can only occur inside the real hidden-volume mount.

**Why it matters:** Current validation relies too much on configured path strings and can approve writes through symlinked roots or escaping first-write paths.

**Verified:** `nails-core/src/logging/manager/mod.rs:75-89`, `nails-core/src/logging/manager/mod.rs:129-143`, `nails-core/src/filesystem/traits/mod.rs:118-122`, `nails-cli/src/cli/logging.rs:217-255`, `nails-core/src/state/mod.rs:76-117`, `nails-core/src/state/file.rs:196-206`

**File-by-file tasks:**
- `nails-core/src/logging/manager/mod.rs`: canonicalize and validate the configured hidden-volume root itself, and reject symlinked roots/log paths before initialization.
- `nails-core/src/state/mod.rs`: reject symlinked roots, symlinked parents, and non-existent first-write targets that only pass string-prefix checks.
- `nails-core/src/state/file.rs`: propagate hard failures when state-save validation detects a symlink or boundary escape.
- `nails-core/src/state/tests.rs`: add regressions for symlinked roots, symlinked parents, and traversal/escape attempts.

**Acceptance criteria:**
- [ ] A symlinked hidden-volume root is rejected before any state or log file is written.
- [ ] Non-existent targets cannot pass validation via string-prefix matching alone.
- [ ] Regression tests cover symlink, traversal, and escape attempts.

**Effort:** `L`
**Dependencies:** `None`

### P0-04: Fail closed on explicit `--config` path errors

**Objective:** Make explicit `--config` paths error out when missing or unreadable while preserving implicit discovery/default behavior.

**Why it matters:** Silent fallback breaks operator trust during setup and troubleshooting because an explicit operator choice is ignored without warning.

**Verified:** `nails-core/src/config/loading.rs:49-53`, `nails-core/src/config/loading.rs:285-293`, `nails-core/src/config/overrides.rs:87-93`, `nails-cli/src/cli/commands/mod.rs:36-38`, `nails-cli/tests/cli_integration.rs:1391-1413`

**File-by-file tasks:**
- `nails-cli/src/cli/commands/mod.rs`: split config loading so explicit override paths use strict loading instead of `load_or_default()`.
- `nails-core/src/config/overrides.rs`: add or use a strict loading path for explicit config overrides.
- `nails-cli/src/cli/commands/activate/mod.rs`: preserve fail-closed behavior for explicit `--config` in activate.
- `nails-cli/tests/cli_integration.rs`: replace the current success expectation for missing explicit config with an error expectation.

**Acceptance criteria:**
- [ ] `nails --config /missing status` exits non-zero and names the missing path.
- [ ] Running without `--config` still falls back to defaults when no discovered config file exists.

**Effort:** `M`
**Dependencies:** `None`

## P1 - Important

### P1-01: Make session detection and teardown deterministic

**Objective:** Enforce valid session-context invariants and surface real failure reasons during fallback process termination.

**Why it matters:** The current code can construct impossible `GraphicalUser` contexts and can silently drop TERM/KILL executor failures.

**Verified:** `nails-core/src/process/session/detection.rs:60-73`, `nails-core/src/process/session/detection.rs:392-407`, `nails-core/src/process/session/management/mod.rs:106-123`, `nails-core/src/process/session/management/mod.rs:293-305`, `nails-core/src/process/session/types.rs:91-95`

**File-by-file tasks:**
- `nails-core/src/process/session/detection.rs`: require a valid override UID before returning `GraphicalUser`, or return a deterministic alternate context/error when overrides are incomplete.
- `nails-core/src/process/session/management/mod.rs`: propagate TERM/KILL executor errors instead of `unwrap_or(false)`.
- `nails-core/src/process/session/management/tests.rs`: add regression tests for invalid override UID, TERM failure, KILL failure, and mixed partial-success behavior.

**Acceptance criteria:**
- [ ] `GraphicalUser` is never constructed with `target_uid: None`.
- [ ] TERM/KILL executor failures are visible to callers.
- [ ] Regression tests cover invalid override inputs and kill executor failure paths.

**Effort:** `M`
**Dependencies:** `None`

### P1-02: Make `/proc/*/maps` path detection boundary-aware

**Objective:** Replace raw string-prefix matching in mmap detection with real path-boundary checks.

**Why it matters:** False-positive process detection can trigger unnecessary warnings, prompts, or session/process handling decisions.

**Verified:** `nails-core/src/process/detection/mod.rs:200-219`, `nails-core/src/process/detection/mod.rs:234-243`, `nails-core/src/process/detection/tests.rs:191-219`

**File-by-file tasks:**
- `nails-core/src/process/detection/mod.rs`: replace raw string `starts_with` matching for mapped paths with boundary-aware path matching.
- `nails-core/src/process/detection/tests.rs`: add a sibling-prefix regression such as target `/home` versus mapping `/home2/lib.so`.

**Acceptance criteria:**
- [ ] `/home2/...` does not match target `/home`.
- [ ] Existing positive detection cases still pass.
- [ ] mmap detection semantics match cwd/fd path detection semantics.

**Effort:** `S`
**Dependencies:** `None`

### P1-03: Unify the log and status operator contract

**Objective:** Make logging, status, verify, and documentation agree on one canonical log path and one real state-loading/reporting contract.

**Why it matters:** Users cannot reliably find logs or trust status output when the logger, `status`, `verify`, and docs disagree about where logs live and which state-file errors are actually surfaced.

**Verified:** `README.md:307-312`, `nails-core/src/config/defaults.rs:241-243`, `nails-cli/src/cli/logging.rs:215-223`, `nails-core/src/verify/verifier.rs:333-349`, `nails-cli/src/cli/commands/status.rs:51-119`, `nails-cli/src/cli/commands/status.rs:123-140`, `nails-cli/src/cli/output/status/mod.rs:24-29`, `nails-cli/src/cli/output/status/mod.rs:157-185`, `nails-cli/src/cli/output/status/mod.rs:267-295`, `nails-core/src/status/mod.rs:156-159`, `nails-core/src/state/file.rs:278-323`, `nails-core/src/state/file.rs:401-407`

**File-by-file tasks:**
- `nails-cli/src/cli/logging.rs`: honor `config.log_path` when initializing the logger.
- `nails-cli/src/cli/commands/status.rs`: pass the configured log path and structured state-load outcomes into status rendering.
- `nails-cli/src/cli/output/status/mod.rs`: read recent logs from the canonical configured path, show resolved config/state/hidden-root paths while inactive, and remove or rewire dead error branches.
- `nails-core/src/state/file.rs`: split strict versus lenient loading, or return structured load outcomes instead of silently normalizing all read/parse failures.
- `nails-core/src/status/mod.rs`: use the intended loader behavior explicitly.
- `README.md`: align documented log location with runtime behavior.

**Acceptance criteria:**
- [ ] Logging, `status`, and `verify` inspect the same canonical log path.
- [ ] Status output for missing/corrupt/unreadable state matches the chosen loader contract.
- [ ] `nails status -v` shows resolved setup paths even when inactive.

**Effort:** `M`
**Dependencies:** `None`

### P1-04: Add post-operation recovery guidance to `deactivate` and `emergency`

**Objective:** Surface required next steps after successful `deactivate` and `emergency` runs in both human and machine-readable output.

**Why it matters:** The repository docs require manual dismount/reboot follow-up, but current success output does not tell operators what to do next.

**Verified:** `README.md:526-539`, `README.md:644-646`, `nails-cli/src/cli/commands/deactivate.rs:69-80`, `nails-cli/src/cli/commands/emergency.rs:81-90`

**File-by-file tasks:**
- `nails-cli/src/cli/commands/deactivate.rs`: add a reminder that hidden storage may still need manual dismount after reboot.
- `nails-cli/src/cli/commands/emergency.rs`: add guidance to dismount when safe or reboot immediately if cleanup certainty is low.
- `nails-cli/src/cli/commands/deactivate.rs`: include follow-up guidance in JSON output.
- `nails-cli/src/cli/commands/emergency.rs`: include follow-up guidance in JSON output.

**Acceptance criteria:**
- [ ] Successful `deactivate` output says reboot is not the final safe state until hidden storage is dismounted.
- [ ] Successful `emergency` output says to dismount when safe or reboot immediately if unsure.

**Effort:** `S`
**Dependencies:** `None`

### P1-05: Restore a clean core/CLI boundary and shrink workflow orchestrators

**Objective:** Make `nails-core` interface-neutral and reduce activation/deactivation workflow coordination to clear, testable owners.

**Why it matters:** `nails-core` claims “No direct user interaction” but still prints and reads from terminals, and the main activation/deactivation flows remain oversized hotspots.

**Verified:** `nails-core/src/lib.rs:19-23`, `nails-core/src/process/session/management/mod.rs:54-74`, `nails-core/src/overlay/strategy/mod.rs:148-167`, `nails-core/src/overlay/strategy/mod.rs:189-200`, `nails-core/src/overlay/strategy/mod.rs:206-283`, `nails-core/src/overlay/strategy/mod.rs:329-373`, `nails-core/src/manager/activation/mod.rs:80-457`, `nails-core/src/manager/deactivation.rs:1-4`, `nails-core/src/manager/deactivation.rs:46-69`, `nails-core/src/manager/deactivation.rs:71-125`, `nails-core/src/manager/deactivation.rs:161-284`, `nails-core/src/deactivation/orchestrator/mod.rs:140-364`

**File-by-file tasks:**
- `nails-core/src/process/session/management/mod.rs`: replace direct prompt/print behavior with structured decisions/events or an injected prompt/reporting interface.
- `nails-core/src/overlay/strategy/mod.rs`: replace direct terminal output with structured events/results.
- `nails-cli/src/cli/commands/activate/mod.rs`: render prompts/progress from the extracted core interfaces.
- `nails-core/src/manager/activation/mod.rs`: reduce activation to a thin sequence over focused workflow steps.
- `nails-core/src/manager/deactivation.rs` and `nails-core/src/deactivation/orchestrator/mod.rs`: make one component the obvious owner of deactivation sequencing.

**Acceptance criteria:**
- [ ] Production paths in `nails-core` do not read stdin or print user-facing terminal output directly.
- [ ] Activation and deactivation each have one obvious orchestration owner.
- [ ] Major workflow steps are independently testable.

**Effort:** `L`
**Dependencies:** `None`

### P1-06: Align local development workflow and contributor docs with real CI

**Objective:** Make local scripts, contributor docs, and coverage guidance describe the same toolchain and thresholds enforced by current hooks and CI.

**Why it matters:** The repository currently claims CI parity where it does not exist and still documents tarpaulin/Makefile-era commands instead of the checked-in llvm-cov/pre-commit/nextest flow.

**Verified:** `scripts/ci-local.sh:2-4`, `scripts/ci-local.sh:41-52`, `scripts/ci-local.sh:96-138`, `.github/workflows/ci.yml:53-105`, `.github/workflows/ci.yml:107-140`, `.github/workflows/ci.yml:179-205`, `.github/workflows/ci.yml:246-327`, `.github/workflows/ci.yml:354-363`, `docs/development-guide.md:16-44`, `docs/development-guide.md:91-104`, `docs/definition-of-done.md:147-159`, `docs/definition-of-done.md:414-434`, `.pre-commit-config.yaml:158-214`, `.tarpaulin.toml:1-29`

**File-by-file tasks:**
- `scripts/ci-local.sh`: either add the missing CI stages or relabel/document the script clearly as a reduced subset.
- `docs/development-guide.md`: replace tarpaulin/Makefile-era commands with the current supported toolchain.
- `docs/definition-of-done.md`: replace outdated coverage/workflow guidance with current llvm-cov-based enforcement.
- `CONTRIBUTING.md`: align terminology and local commands with the updated contributor docs.
- `.tarpaulin.toml`: remove it or clearly mark it deprecated if unsupported.

**Acceptance criteria:**
- [ ] Local script descriptions match what the script actually runs.
- [ ] Contributor docs consistently describe the supported local/CI workflow.
- [ ] Coverage tooling and thresholds are defined once and match CI/pre-commit.

**Effort:** `M`
**Dependencies:** `None`

### P1-07: Validate the canonical release artifact in PR CI

**Objective:** Make pull-request validation exercise the same release output that `release.yml` publishes.

**Why it matters:** Current PR validation can pass while the actual release bundle path is broken because it builds `.#nails` instead of `.#nails-release`.

**Verified:** `.github/workflows/nix-pr-verify.yml:41-47`, `.github/workflows/release.yml:125-127`, `.github/workflows/release.yml:177-184`, `flake.nix:143-147`

**File-by-file tasks:**
- `.github/workflows/nix-pr-verify.yml`: build `.#nails-release` instead of `.#nails`.
- `.github/workflows/nix-pr-verify.yml`: verify archive, checksum, and extracted bundle contents instead of only `result/bin/nails --version`.
- `flake.nix`: add helper attrs only if needed to share validation logic between PR and release workflows.

**Acceptance criteria:**
- [ ] PR verification fails if the canonical release archive or checksums are missing or malformed.
- [ ] PR verification exercises the same flake output used by `release.yml`.

**Effort:** `M`
**Dependencies:** `None`

### P1-08: Restore merge-relevant end-to-end coverage

**Objective:** Re-enable automated E2E validation for pushes/pull requests or route it into the main CI gate with explicit policy.

**Why it matters:** The repository defines NixOS VM E2E checks, but current automation runs them only manually and does not use them as a merge-relevant signal.

**Verified:** `.github/workflows/e2e-tests.yml:6-18`, `.github/workflows/e2e-tests.yml:43-45`, `flake.nix:167-177`

**File-by-file tasks:**
- `.github/workflows/e2e-tests.yml`: re-enable `push`/`pull_request` triggers or add path-filtered automation.
- `.github/workflows/ci.yml`: call or surface the E2E result in the main CI gate if that is the intended merge signal.
- `docs/ci.md`: document the final E2E trigger policy.

**Acceptance criteria:**
- [ ] Pull requests to protected branches automatically run the intended E2E validation policy.
- [ ] A failing E2E run is visible as a merge-relevant CI signal.

**Effort:** `L`
**Dependencies:** `None`

### P1-09: Make CI tooling reproducible and benchmark signals enforceable

**Objective:** Pin helper tool versions and turn benchmark jobs into real regression gates.

**Why it matters:** Unpinned helper tools can drift between runs, and the current benchmark job publishes artifacts without actually enforcing performance budgets.

**Verified:** `.github/workflows/ci.yml:74-78`, `.github/workflows/ci.yml:132-133`, `.github/workflows/ci.yml:179-180`, `.github/workflows/ci.yml:267-268`, `.github/workflows/ci.yml:311-312`, `.github/workflows/ci.yml:397-407`, `.github/workflows/release.yml:163-165`, `nails-cli/benches/startup.rs:5-10`, `nails-core/benches/performance.rs:263-294`, `docs/ci.md:120-127`, `docs/ci.md:289-293`

**File-by-file tasks:**
- `.github/workflows/ci.yml`: pin cargo-installed helper versions or provision them from a pinned Nix environment.
- `.github/workflows/release.yml`: pin `cargo-sbom` consistently with CI.
- `nails-cli/benches/startup.rs`: benchmark real binary startup or rename the current benchmark so it matches what is being measured.
- `.github/workflows/ci.yml`: parse benchmark output and fail on explicit budgets or regression thresholds.
- `docs/ci.md`: update benchmark claims so they match actual enforced behavior.

**Acceptance criteria:**
- [ ] Helper tool versions are controlled by repository state.
- [ ] CI fails on documented benchmark threshold breaches or regression budgets.
- [ ] Benchmark names accurately describe the measured behavior.

**Effort:** `M`
**Dependencies:** `None`

### P1-10: Fix security scope and public reporting guidance

**Objective:** Align security/governance docs and issue intake with the repository’s actual responsibilities.

**Why it matters:** `SECURITY.md` currently overstates repo-owned crypto/storage scope, and public issue templates are too generic for a security-sensitive NixOS project.

**Verified:** `SECURITY.md:25-33`, `README.md:123-136`, `README.md:248-265`, `CONTRIBUTING.md:227-230`, `SECURITY.md:73-75`, `.github/ISSUE_TEMPLATE/bug_report.md:10-35`, `.github/ISSUE_TEMPLATE/feature_request.md:10-20`, `nails-core/src/obfuscate/mod.rs:9-20`, `nails-core/Cargo.toml:19-34`

**File-by-file tasks:**
- `SECURITY.md`: narrow the in-scope/out-of-scope tables to repo-owned behavior only.
- `.github/ISSUE_TEMPLATE/bug_report.md`: replace generic browser/mobile prompts with NixOS/runtime context and a prominent “do not use for vulnerabilities” redirect.
- `.github/ISSUE_TEMPLATE/feature_request.md`: add repo-specific prompts tied to commands, workflows, and threat-model impact.
- `README.md`: expand governance/support links and align storage-backend responsibility wording with the security policy.
- `SUPPORT.md` and `CODE_OF_CONDUCT.md`: add explicit public support and conduct policies if the project intends to support those channels.

**Acceptance criteria:**
- [ ] The security policy no longer claims repo-owned encryption/KDF/secure erasure absent implementation.
- [ ] Public issue templates collect repo-relevant context and redirect vulnerabilities to private disclosure.
- [ ] Governance docs expose clear public support and conduct expectations.

**Effort:** `M`
**Dependencies:** `None`

## P2 - Improvement

### P2-01: Sync the README command reference with the current CLI surface

**Objective:** Bring README command documentation back into line with the clap-defined CLI.

**Why it matters:** The README is the primary user-facing reference, and stale options undermine trust and hide supported workflows such as `--dry-run` and `--overlay-only`.

**Verified:** `README.md:560-579`, `nails-cli/src/cli/args.rs:100-106`

**File-by-file tasks:**
- `README.md`: add missing `activate` flags (`--dry-run`, `--overlay-only`) and review other documented command option lists against clap.
- `docs/development-guide.md`: update any command examples that enumerate flags so they match the README/CLI wording.

**Acceptance criteria:**
- [ ] README option lists match the current public CLI.
- [ ] Advanced user-facing flags are documented or explicitly marked internal-only.

**Effort:** `S`
**Dependencies:** `None`

### P2-02: Centralize socket-aware service lifecycle control

**Objective:** Replace repeated service/socket start-stop logic with one shared abstraction.

**Why it matters:** Service lifecycle sequencing is sensitive operational logic, and duplicating it across activation, deactivation, overlay fallback, and process restart paths invites drift.

**Verified:** `nails-core/src/manager/helpers.rs:10-23`, `nails-core/src/overlay/strategy/mod.rs:38-57`, `nails-core/src/manager/activation/overlay_mount/auto_mount.rs:27-43`, `nails-core/src/manager/deactivation.rs:201-209`, `nails-core/src/process/restart/mod.rs:193-199`

**File-by-file tasks:**
- `nails-core/src/manager/helpers.rs`: replace the ad hoc helper with a shared service-control component.
- `nails-core/src/overlay/strategy/mod.rs`: route restart-after-failure behavior through the shared component.
- `nails-core/src/manager/activation/overlay_mount/auto_mount.rs`: route nix-daemon stop behavior through the shared component.
- `nails-core/src/manager/deactivation.rs`: route nix-daemon stop/start behavior through the shared component.
- `nails-core/src/process/restart/mod.rs`: align socket-aware stop behavior with the same shared implementation or policy.

**Acceptance criteria:**
- [ ] Socket-aware service lifecycle ordering is defined once.
- [ ] Activation, deactivation, and restart paths use the same implementation or policy.
- [ ] Future lifecycle changes require editing one shared abstraction.

**Effort:** `M`
**Dependencies:** `P1-05`

## Summary

- **Overall rating:** `5.3/10`
- **Primary risks:** fail-open filesystem/config behavior, incorrect state integrity semantics, operator-facing observability drift, and incomplete CI gating.
- **Most immediate wins:** lock down artifact permissions, fail closed on explicit config errors, harden hidden-volume boundary validation, and make status/log behavior consistent.
- **Relative strengths:** crate-level layering is fundamentally sound, overlay verification code is comparatively well covered, GitHub Actions are SHA-pinned, release workflows use concurrency controls, and the repo already has baseline security/contribution policy files plus local secret-scanning hooks.

## Recommended First Sprint

1. **P0-02 — Restrict hidden-volume artifact permissions** (`M`): fast security win with low architectural blast radius.
2. **P0-04 — Fail closed on explicit `--config` path errors** (`M`): restores operator trust during setup/debugging.
3. **P0-03 — Fail closed on symlinked or escaping hidden-volume paths** (`L`): closes the largest trust-boundary gap.
4. **P0-01 — Repair state-file integrity handling** (`L`): removes false upgrade failures and forces an honest integrity model.
5. **P1-03 — Unify the log and status operator contract** (`M`): makes troubleshooting predictable.
6. **P1-04 — Add post-operation recovery guidance** (`S`): cheap UX improvement on critical flows.
7. **P2-01 — Sync the README command reference with the current CLI surface** (`S`): cheap documentation cleanup that reduces support noise.

**Total estimated effort:** `~2L + 3M + 2S` (roughly `3-4 engineer-weeks` for one engineer).
