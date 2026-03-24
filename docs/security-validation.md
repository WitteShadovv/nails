# Security Validation Guide

**Project:** NAILS (NixOS Anti-forensics Isolation & Layering System)
**Audience:** Security Auditors, Developers, Release Managers
**Related:** [SECURITY.md](../SECURITY.md), [vulnerability-handling.md](vulnerability-handling.md), [ci.md](ci.md)

---

## Overview

NAILS is a security-critical application requiring rigorous supply chain validation. This guide provides comprehensive instructions for:

- Generating and validating Software Bills of Materials (SBOMs)
- Auditing dependencies for known vulnerabilities
- Verifying SLSA provenance for release artifacts
- Creating security reports for compliance and auditing
- Automating security validation workflows

**Key Principles:**
- **Defense in Depth:** Multiple layers of security validation
- **Automation First:** Security checks run on every commit
- **Supply Chain Transparency:** Full dependency disclosure via SBOMs
- **Cryptographic Verification:** SLSA provenance for tamper-proof builds

---

## Table of Contents

1. [SBOM Generation and Validation](#1-sbom-generation-and-validation)
2. [Dependency Auditing](#2-dependency-auditing)
3. [SLSA Provenance Verification](#3-slsa-provenance-verification)
4. [Security Reports](#4-security-reports)
5. [Pre-commit Validation](#5-pre-commit-validation)
6. [Regular Security Workflow](#6-regular-security-workflow)
7. [Incident Response](#7-incident-response)

---

## 1. SBOM Generation and Validation

### 1.1 What is an SBOM?

A **Software Bill of Materials (SBOM)** is a complete inventory of all dependencies in the NAILS project. It enables:

- **Vulnerability Tracking:** Quickly identify affected components when CVEs are disclosed
- **License Compliance:** Verify all dependencies are GPL-3.0 compatible
- **Supply Chain Transparency:** Prove what's included in release artifacts
- **Audit Readiness:** Provide evidence for security certifications

NAILS uses the **CycloneDX 1.6** format (JSON), an industry-standard SBOM specification.

---

### 1.2 Local SBOM Generation

#### Prerequisites

```bash
# Install cargo-sbom (one-time setup)
cargo install cargo-sbom --locked

# Install CycloneDX CLI for validation (optional)
wget -q https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.27.1/cyclonedx-linux-x64 -O cyclonedx
chmod +x cyclonedx
sudo mv cyclonedx /usr/local/bin/
```

#### Generate SBOM

```bash
# Generate SBOM in CycloneDX 1.6 JSON format
cargo sbom --output-format cyclonedx_json_1_6 > sbom.cdx.json

# Verify SBOM was created
ls -lh sbom.cdx.json
```

**Output:** `sbom.cdx.json` - A JSON file containing the complete dependency tree with:
- Component names and versions
- Licenses (SPDX identifiers)
- Dependency relationships (direct vs. transitive)
- Package URLs (purls) for vulnerability lookups

#### Validate SBOM Format

```bash
# Validate against CycloneDX 1.6 schema
cyclonedx validate --input-file sbom.cdx.json --input-format json

# Expected output:
# Validating sbom.cdx.json...
# Valid CycloneDX BOM
```

**Common Validation Errors:**

| Error | Cause | Solution |
|-------|-------|----------|
| Invalid JSON | Corrupted file | Regenerate SBOM |
| Schema violation | Unsupported `cargo-sbom` version | Update: `cargo install cargo-sbom --locked` |
| Missing required fields | Incomplete dependency metadata | Check `Cargo.toml` has all required fields |

---

### 1.3 SBOM Analysis

#### Count Dependencies

```bash
# Total components (direct + transitive)
jq '.components | length' sbom.cdx.json

# Example output: 142
```

#### List All Licenses

```bash
# Extract unique licenses
jq -r '.components[].licenses[]?.license.id // .components[].licenses[]?.license.name // "UNKNOWN"' sbom.cdx.json | sort -u

# Example output:
# Apache-2.0
# MIT
# GPL-3.0-or-later
# LGPL-2.1
```

**Action if Unknown License Found:**
1. Identify the crate: `jq '.components[] | select(.licenses == null or .licenses == []) | .name' sbom.cdx.json`
2. Manually check the crate's license on crates.io or GitHub
3. If incompatible with GPL-3.0, file an issue or replace the dependency

#### List Direct Dependencies Only

```bash
# Filter to direct dependencies (referenced in our Cargo.toml)
jq -r '.components[] | select(.scope == "required") | "\(.name) \(.version)"' sbom.cdx.json | head -20
```

#### Find Components with Known Vulnerabilities

```bash
# Cross-reference with RustSec advisory database
# (Use cargo-audit or cargo-deny for automated checking - see Section 2)
jq -r '.components[] | "\(.name)@\(.version)"' sbom.cdx.json | while read dep; do
  echo "Checking $dep..."
  cargo audit --db ~/.cargo/advisory-db --json | jq -r --arg dep "$dep" '.vulnerabilities.list[] | select(.package.name == $dep) | .advisory.id'
done
```

---

### 1.4 CI SBOM Access

SBOMs are automatically generated in the CI/CD pipeline for every release.

#### Download from CI Artifacts

**Location:** GitHub Actions → Workflow Runs → `Release` workflow

```bash
# List artifacts for a specific workflow run
gh run view <run-id> --repo WitteShadovv/nails

# Download the canonical release artifact (includes SBOM)
gh run download <run-id> --name canonical-release-<commit-sha> --repo WitteShadovv/nails

# SBOM is in: dist/sbom.cdx.json
cat canonical-release-*/sbom.cdx.json | jq '.metadata'
```

**Retention:** CI artifacts are retained for **14 days** (configurable in `.github/workflows/release.yml`).

#### Download from GitHub Releases

**Location:** GitHub Releases → Tags → Select release → Assets

```bash
# Download SBOM from a specific release
wget https://github.com/WitteShadovv/nails/releases/download/v0.1.0-git.abc1234/sbom.cdx.json

# Or using gh CLI
gh release download v0.1.0-git.abc1234 --pattern "sbom.cdx.json" --repo WitteShadovv/nails
```

**Retention:** Release artifacts are **permanent** (until manually deleted).

---

### 1.5 SBOM Analysis Tools

#### Dependency Track

[Dependency Track](https://dependencytrack.org/) is an open-source platform for continuous SBOM analysis.

**Setup:**

```bash
# Run Dependency Track with Docker
docker run -d -p 8080:8080 --name dependency-track dependencytrack/bundled

# Access UI: http://localhost:8080
# Default credentials: admin / admin
```

**Upload SBOM:**

1. Log in to Dependency Track
2. Create a new project: `NAILS`
3. Upload `sbom.cdx.json` (CycloneDX format)
4. View vulnerabilities, outdated components, license risks

**Automation:**

```bash
# Upload SBOM via API
curl -X PUT "http://localhost:8080/api/v1/bom" \
  -H "X-Api-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d @sbom.cdx.json
```

#### Grype (Vulnerability Scanner)

```bash
# Install Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Scan SBOM for vulnerabilities
grype sbom:./sbom.cdx.json

# Output JSON report
grype sbom:./sbom.cdx.json -o json > grype-report.json
```

**Interpret Results:**

| Severity | Action |
|----------|--------|
| **Critical** | Immediate update required (emergency release) |
| **High** | Update within 7 days (see [vulnerability-handling.md](vulnerability-handling.md)) |
| **Medium** | Update in next release (30 days) |
| **Low** | Update at convenience (90 days) |

#### Manual Inspection with jq

**Find all dependencies from a specific author:**

```bash
jq -r '.components[] | select(.author == "tokio-rs") | "\(.name) \(.version)"' sbom.cdx.json
```

**Find dependencies with GPL licenses:**

```bash
jq -r '.components[] | select(.licenses[]?.license.id | startswith("GPL")) | "\(.name) \(.licenses[0].license.id)"' sbom.cdx.json
```

**Export dependency graph (DOT format for Graphviz):**

```bash
# Extract relationships
jq -r '.dependencies[] | "  \"\(.ref)\" -> \"\(.dependsOn[])\""' sbom.cdx.json > deps.dot

# Add graph wrapper
echo "digraph G {" > graph.dot
cat deps.dot >> graph.dot
echo "}" >> graph.dot

# Render to PNG
dot -Tpng graph.dot -o dependency-graph.png
```

---

## 2. Dependency Auditing

### 2.1 cargo-audit

**Purpose:** Check for known security vulnerabilities in Rust dependencies using the [RustSec Advisory Database](https://rustsec.org/).

#### Installation

```bash
cargo install cargo-audit --locked
```

#### Basic Usage

```bash
# Check for known vulnerabilities
cargo audit

# Example output:
#    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
#       Loaded 900 security advisories (from rustsec-advisories-db)
#       Scanning Cargo.lock for vulnerabilities (142 crate dependencies)
# Crate:     time
# Version:   0.1.45
# Warning:   potential segfault in `time` crate
# ID:        RUSTSEC-2020-0071
# ...
```

#### Advanced Usage

```bash
# Check specific advisory database path
cargo audit --db /path/to/advisory-db

# Output JSON (for CI/automation)
cargo audit --json > audit-report.json

# Ignore specific advisories (use sparingly)
cargo audit --ignore RUSTSEC-2020-0001

# Deny warnings (fail on any advisory)
cargo audit --deny warnings
```

#### Interpreting Results

**Advisory Structure:**

```
Crate:     <crate-name>
Version:   <installed-version>
Warning:   <vulnerability-description>
ID:        RUSTSEC-YYYY-NNNN
Solution:  upgrade to >= <fixed-version>
```

**Response Actions:**

1. **Check Reachability:** Is the vulnerable code path used by NAILS?
   ```bash
   # Find where the vulnerable crate is used
   cargo tree -i <vulnerable-crate>

   # Search codebase for usage
   rg "<vulnerable-function>" --type rust
   ```

2. **Assess Severity:** Apply NAILS-specific context (see [vulnerability-handling.md](vulnerability-handling.md) Section 6.2)

3. **Update Dependency:**
   ```bash
   # Update specific crate
   cargo update -p <vulnerable-crate>

   # Verify fix
   cargo audit
   ```

4. **Document Decision:** If not updating immediately, document why in `deny.toml`:
   ```toml
   [advisories]
   ignore = [
       { id = "RUSTSEC-2020-0001", reason = "Vulnerable code path not used in NAILS" }
   ]
   ```

---

### 2.2 cargo-deny

**Purpose:** Comprehensive dependency policy enforcement beyond vulnerability scanning. Checks:
- **Advisories:** Security vulnerabilities (overlaps with `cargo-audit`)
- **Licenses:** GPL-3.0 compatibility
- **Bans:** Blocked dependencies (e.g., prefer `rustls` over `openssl`)
- **Sources:** Registry restrictions (only crates.io)

#### Installation

```bash
cargo install cargo-deny --locked
```

#### Configuration

NAILS uses `deny.toml` in the project root (see [deny.toml](../deny.toml) for full configuration).

**Key Policies:**

```toml
[advisories]
vulnerability = "deny"    # Fail on any known vulnerability
yanked = "deny"           # Fail on yanked crates

[licenses]
allow = ["MIT", "Apache-2.0", "GPL-3.0-or-later", ...]  # GPL-compatible only

[sources]
unknown-registry = "deny" # Only crates.io allowed
unknown-git = "deny"      # No git dependencies in production
```

#### Run All Checks

```bash
# Run all checks at once
cargo deny check

# Expected output if all pass:
# advisories ok
# licenses ok
# bans ok
# sources ok
```

#### Run Specific Checks

```bash
# Security vulnerabilities only
cargo deny check advisories

# License compliance only
cargo deny check licenses

# Banned dependencies only
cargo deny check bans

# Source restrictions only
cargo deny check sources
```

#### Output JSON (for CI)

```bash
# Generate JSON report
cargo deny check --format json > deny-report.json

# Parse with jq
jq '.advisories.errors' deny-report.json
jq '.licenses.errors' deny-report.json
```

#### Common Scenarios

**Scenario 1: Incompatible License Detected**

```
licenses FAILED: crate 'problematic-crate' has license 'GPL-2.0-only' which is not allowed
```

**Action:**
1. Verify the license: `cargo tree -i problematic-crate`
2. Check if there's an alternative crate with compatible license
3. If no alternative, consider forking or requesting license change upstream
4. Document exception in `deny.toml` (with maintainer approval)

**Scenario 2: Multiple Versions of Same Crate**

```
bans WARN: multiple versions for dependency 'serde':
  serde 1.0.200 (used by foo)
  serde 1.0.199 (used by bar)
```

**Action:**
1. Update dependencies to use the same version:
   ```bash
   cargo update -p serde
   ```
2. If caused by incompatible semver requirements, file issues upstream
3. If unavoidable, add to `deny.toml` skip list:
   ```toml
   [[bans.skip]]
   name = "serde"
   version = "*"
   ```

**Scenario 3: Banned Dependency Used**

```
bans FAILED: crate 'openssl' is explicitly denied
```

**Action:**
1. Replace with allowed alternative (e.g., `openssl` → `rustls`)
2. Update `Cargo.toml` dependencies
3. Verify: `cargo deny check bans`

---

### 2.3 CI Automation

Both `cargo-audit` and `cargo-deny` run automatically in CI on every PR and push.

**Workflow:** `.github/workflows/ci.yml` (Audit job)

```yaml
- name: Run security audit (cargo-audit)
  run: cargo audit

- name: Run dependency policy check (cargo-deny)
  run: |
    cargo deny check advisories
    cargo deny check licenses
    cargo deny check bans
    cargo deny check sources
```

**Behavior:**
- **Blocks PR merge** if high/critical vulnerabilities found (AR51)
- **Uploads audit reports** as artifacts (30-day retention)
- **Runs daily** via cron schedule (weekly for `cargo-deny`)

**Access Reports:**

```bash
# Download audit report from CI
gh run download <run-id> --name audit-report --repo WitteShadovv/nails
cat audit-report.json | jq '.vulnerabilities.list'
```

---

## 3. SLSA Provenance Verification

### 3.1 What is SLSA Provenance?

**SLSA (Supply-chain Levels for Software Artifacts)** is a framework for ensuring software supply chain integrity. NAILS achieves **SLSA Level 3** through:

1. **Isolated Builds:** Builds run on ephemeral GitHub Actions runners (no persistence)
2. **Signed Provenance:** Cryptographically signed attestation of build metadata
3. **Non-falsifiable:** Provenance cannot be tampered with after build

**Provenance File:** `nails.intoto.jsonl` (in-toto format, JSON Lines)

**What Provenance Guarantees:**

| Property | Description |
|----------|-------------|
| **Source Integrity** | Artifact was built from `github.com/WitteShadovv/nails` at a specific commit |
| **Builder Identity** | Build ran on GitHub Actions (trusted builder) |
| **Build Isolation** | No tampering possible during build process |
| **Tamper Resistance** | Signature verification proves artifact matches provenance |

---

### 3.2 Download Provenance from GitHub Release

#### Prerequisites

```bash
# Install slsa-verifier (requires Go)
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Verify installation
slsa-verifier version
```

#### Download Release Artifacts

```bash
# Example: Download v0.1.0-git.abc1234 release
VERSION="v0.1.0-git.abc1234"

# Download release archive
wget "https://github.com/WitteShadovv/nails/releases/download/${VERSION}/nails-${VERSION}.tar.gz"

# Download SLSA provenance
wget "https://github.com/WitteShadovv/nails/releases/download/${VERSION}/nails.intoto.jsonl"

# Or use gh CLI (recommended)
gh release download "$VERSION" \
  --pattern "nails-*.tar.gz" \
  --pattern "nails.intoto.jsonl" \
  --repo WitteShadovv/nails
```

---

### 3.3 Verify Release Artifacts

> **Important:** This repository is private at `github.com/WitteShadovv/nails`. You **must** use `--source-uri github.com/WitteShadovv/nails` (not the public URL format).

#### Verify the Release Archive

```bash
# Verify the tarball
slsa-verifier verify-artifact nails-v0.1.0-git.abc1234.tar.gz \
  --provenance-path nails.intoto.jsonl \
  --source-uri github.com/WitteShadovv/nails

# Expected output:
# Verified signature against tlog entry index 123456 at URL: https://rekor.sigstore.dev/...
# Verified build using builder https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0
# PASSED: Verified SLSA provenance
```

#### Verify the Binary (After Extraction)

```bash
# Extract the archive
tar -xzf nails-v0.1.0-git.abc1234.tar.gz

# Verify the binary
slsa-verifier verify-artifact nails-v0.1.0-git.abc1234/nails \
  --provenance-path nails.intoto.jsonl \
  --source-uri github.com/WitteShadovv/nails

# Expected output: PASSED: Verified SLSA provenance
```

#### Verify Against Specific Git Commit

```bash
# Verify artifact was built from a specific commit SHA
slsa-verifier verify-artifact nails-v0.1.0-git.abc1234.tar.gz \
  --provenance-path nails.intoto.jsonl \
  --source-uri github.com/WitteShadovv/nails \
  --source-tag "v0.1.0"  # Or use --source-versioned-tag for tagged releases
```

---

### 3.4 What SLSA Verification Proves

✅ **Artifact Authenticity:**
- The artifact's SHA256 hash matches the hash in the signed provenance
- The provenance signature is valid and trusted (Sigstore transparency log)

✅ **Source Code Integrity:**
- The artifact was built from the exact source code at the specified commit
- No modifications were made to the source after the commit

✅ **Build Environment Isolation:**
- The build ran on an ephemeral GitHub Actions runner
- No persistent state or external tampering possible during build

✅ **Builder Identity:**
- The build used the official SLSA generic generator workflow
- GitHub Actions workflow identity is cryptographically verified

❌ **What SLSA Does NOT Prove:**
- **Code Quality:** SLSA doesn't verify the source code is secure (use audits/tests)
- **Dependency Security:** SLSA doesn't validate dependencies (use SBOMs + `cargo-audit`)
- **Runtime Behavior:** SLSA doesn't guarantee the binary behaves as expected (use E2E tests)

---

### 3.5 Inspecting Provenance Metadata

```bash
# View provenance contents (JSON Lines format)
cat nails.intoto.jsonl | jq .

# Extract subject (artifact being attested)
cat nails.intoto.jsonl | jq '.subject'

# Extract builder information
cat nails.intoto.jsonl | jq '.predicate.builder.id'

# Extract build invocation details
cat nails.intoto.jsonl | jq '.predicate.buildDefinition'

# Verify signature transparency log
cat nails.intoto.jsonl | jq '.dsseEnvelope.signatures'
```

**Example Output (Builder ID):**

```json
{
  "builder": {
    "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0"
  }
}
```

---

## 4. Security Reports

### 4.1 Generating Security Reports

#### Vulnerability Report

```bash
# Generate comprehensive vulnerability report (JSON)
cargo audit --json > vulnerability-report.json

# Generate cargo-deny advisory report
cargo deny check advisories --format json > advisory-report.json

# Merge reports with jq
jq -s '.[0].vulnerabilities.list + .[1].advisories.errors' \
  vulnerability-report.json advisory-report.json > combined-vulnerabilities.json
```

**Report Contents:**
- CVE IDs and RUSTSEC advisory IDs
- Affected crate names and versions
- Severity levels (Critical, High, Medium, Low)
- Fixed versions (if available)
- CVSS scores

#### License Compliance Report

```bash
# Generate license compliance report
cargo deny check licenses --format json > license-report.json

# Extract allowed licenses
jq -r '.licenses.allowed[] | "\(.name): \(.license)"' license-report.json

# Find crates with non-standard licenses
jq -r '.licenses.errors[] | "\(.name): \(.reason)"' license-report.json
```

**Use Cases:**
- Legal compliance audits
- Open-source license verification
- GPL-3.0 compatibility checks

#### Dependency Policy Report

```bash
# Full cargo-deny report (all checks)
cargo deny check --format json > full-deny-report.json

# Extract summary
jq '{
  advisories: .advisories.errors | length,
  licenses: .licenses.errors | length,
  bans: .bans.errors | length,
  sources: .sources.errors | length
}' full-deny-report.json
```

---

### 4.2 Report Analysis

#### Reading Vulnerability Reports

**Example `cargo audit` Output:**

```json
{
  "vulnerabilities": {
    "list": [
      {
        "advisory": {
          "id": "RUSTSEC-2020-0071",
          "title": "Potential segfault in time::Duration::checked_add",
          "description": "...",
          "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
        },
        "package": {
          "name": "time",
          "version": "0.1.45"
        },
        "versions": {
          "patched": [">= 0.2.23"],
          "unaffected": []
        }
      }
    ],
    "count": 1
  }
}
```

**Key Fields:**

| Field | Description |
|-------|-------------|
| `advisory.id` | RUSTSEC advisory identifier |
| `advisory.cvss` | CVSS 3.1 severity score (if available) |
| `package.name` | Affected crate name |
| `package.version` | Installed vulnerable version |
| `versions.patched` | Fixed versions (upgrade target) |

#### Interpreting Severity Levels

**CVSS 3.1 Score Mapping:**

| Score Range | Severity | NAILS Response SLA |
|-------------|----------|-------------------|
| 9.0 - 10.0 | **Critical** | 24-72 hours (emergency release) |
| 7.0 - 8.9 | **High** | 7 days (expedited release) |
| 4.0 - 6.9 | **Medium** | 30 days (next scheduled release) |
| 0.1 - 3.9 | **Low** | 90 days (opportunistic fix) |

**Severity Adjustment Factors:**

1. **Reachability:** Is the vulnerable code path used by NAILS?
   - ✅ Used → Keep original severity
   - ❌ Not used → Downgrade by one level (document in `deny.toml`)

2. **Exploitability:** Is there a known exploit or PoC?
   - ✅ Exploit exists → Upgrade by one level
   - ❌ Theoretical only → Keep original severity

3. **Impact on Deniability:** Does this compromise NAILS' core security guarantees?
   - ✅ Compromises deniability → **Critical** (regardless of CVSS)
   - ❌ No deniability impact → Use CVSS severity

#### Checking Reachability

```bash
# Step 1: Find where the vulnerable crate is used
cargo tree -i <vulnerable-crate>

# Example output:
# time v0.1.45
# └── chrono v0.4.19
#     └── nails-core v0.1.0 (/path/to/nails/nails-core)

# Step 2: Search codebase for usage of vulnerable function
rg "Duration::checked_add" --type rust

# Step 3: Review code context - is this path reachable in production?
```

**Decision Matrix:**

| Reachability | Severity (CVSS) | Action | Timeline |
|--------------|----------------|--------|----------|
| Used | Critical/High | Immediate update | 24-72 hours |
| Used | Medium/Low | Scheduled update | Next release |
| Not used | Critical/High | Document, defer update | 90 days |
| Not used | Medium/Low | Monitor, update with batch | As convenient |

#### Deciding Update Priority

**Immediate Update Required:**

```bash
# High severity + reachable code path
cargo update -p <vulnerable-crate>
cargo test  # Verify no regressions
git commit -m "fix(deps): update <crate> to fix RUSTSEC-YYYY-NNNN"
```

**Scheduled Update:**

```bash
# Add to milestone/sprint backlog
gh issue create --title "Update <crate> for RUSTSEC-YYYY-NNNN" \
  --body "Medium severity, update in next release" \
  --milestone "v0.2.0" \
  --label "security,dependencies"
```

**Deferred Update (Document Exception):**

```toml
# deny.toml
[advisories]
ignore = [
    { id = "RUSTSEC-2020-0071", reason = "time::Duration::checked_add not used in NAILS code paths" }
]
```

---

### 4.3 Automated Reporting

#### CI-Generated Reports

**Location:** GitHub Actions Artifacts (Audit job)

```bash
# List recent workflow runs
gh run list --workflow ci.yml --repo WitteShadovv/nails

# Download audit report from specific run
gh run download <run-id> --name audit-report --repo WitteShadovv/nails

# View vulnerabilities
jq '.vulnerabilities.list[] | {id: .advisory.id, crate: .package.name, severity: .advisory.cvss}' audit-report.json
```

**Retention:** 30 days

#### Setting Up Notifications

**GitHub Actions Workflow Notifications:**

```yaml
# .github/workflows/ci.yml (add to audit job)
- name: Notify on security failures
  if: failure()
  uses: 8398a7/action-slack@v3
  with:
    status: ${{ job.status }}
    text: 'Security audit failed! Check artifacts for details.'
    webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

**Email Notifications (GitHub):**

1. Go to repository → **Settings** → **Notifications**
2. Enable **Actions** notifications
3. Select **Send notifications for failed workflows only**

**Dependabot Alerts:**

1. Go to repository → **Settings** → **Security & analysis**
2. Enable **Dependabot alerts**
3. Enable **Dependabot security updates** (auto-PR for vulnerabilities)

---

## 5. Pre-commit Validation

NAILS enforces security checks **before every commit** using pre-commit hooks.

### 5.1 Installation

```bash
# Install pre-commit (if not already installed)
pip install pre-commit

# Install hooks from .pre-commit-config.yaml
pre-commit install
pre-commit install --hook-type commit-msg
```

### 5.2 Security Hooks

**Configuration:** `.pre-commit-config.yaml`

| Hook | Command | Purpose |
|------|---------|---------|
| `cargo-audit` | `cargo audit` | Block commits with high/critical vulnerabilities |
| `cargo-deny` | `cargo deny check` | Enforce license/source/ban policies |
| `detect-secrets` | `detect-secrets scan` | Prevent accidental secret commits |
| `rust-coverage` | `cargo llvm-cov` | Enforce 85% test coverage |

### 5.3 Run All Pre-commit Hooks

```bash
# Run all hooks on staged files
pre-commit run

# Run all hooks on all files (comprehensive check)
pre-commit run --all-files

# Run specific hook only
pre-commit run cargo-audit --all-files
pre-commit run cargo-deny --all-files
pre-commit run detect-secrets --all-files
```

### 5.4 Hook Behavior

**Commit Blocked Example:**

```
$ git commit -m "feat: add new feature"

Cargo Security Audit.......................................Failed
- hook id: cargo-audit
- exit code: 1

    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
       Loaded 900 security advisories
    Scanning Cargo.lock for vulnerabilities (142 crate dependencies)
Crate:     time
Version:   0.1.45
Warning:   potential segfault in time::Duration::checked_add
ID:        RUSTSEC-2020-0071
Solution:  upgrade to >= 0.2.23

❌ Security audit failed - commit blocked
```

**Action:**

1. Fix the issue:
   ```bash
   cargo update -p time
   cargo test
   ```

2. Retry commit:
   ```bash
   git add Cargo.lock
   git commit -m "feat: add new feature (fix: update time crate)"
   ```

### 5.5 Bypassing Hooks (Emergency Only)

```bash
# Skip all hooks (NOT RECOMMENDED - use only in emergencies)
git commit --no-verify -m "emergency: bypass hooks"

# Or set SKIP environment variable to skip specific hooks
SKIP=cargo-audit git commit -m "fix: urgent hotfix"
```

**Warning:** Bypassing hooks may violate security policies. Document the reason in the commit message and file a follow-up issue.

---

## 6. Regular Security Workflow

### 6.1 Weekly Security Review (30 minutes)

**Recommended Schedule:** Every Monday morning

#### Checklist

```bash
# 1. Review Dependabot PRs
gh pr list --label dependencies --repo WitteShadovv/nails

# 2. Run cargo audit
cargo audit

# 3. Check for new CVEs in dependencies
cargo audit --json | jq -r '.vulnerabilities.list[] | "\(.advisory.id): \(.package.name)@\(.package.version)"'

# 4. Update SBOM
cargo sbom --output-format cyclonedx_json_1_6 > sbom.cdx.json
git add sbom.cdx.json
git commit -m "chore(sbom): update dependency inventory"

# 5. Review RustSec advisories
# Visit: https://rustsec.org/advisories/
# Filter by: last 7 days

# 6. Run full cargo deny check
cargo deny check
```

#### Action Items

| Finding | Action |
|---------|--------|
| New Critical/High vulnerability | Create emergency release (see [vulnerability-handling.md](vulnerability-handling.md) Section 8) |
| New Medium vulnerability | Add to sprint backlog, target next release |
| Dependabot PR ready | Review, test, merge |
| License violation | Investigate, replace dependency or add exception |

---

### 6.2 Monthly Security Audit (2 hours)

**Recommended Schedule:** First Monday of each month

#### Extended Checklist

1. **Dependency Health:**
   ```bash
   # Check for outdated dependencies
   cargo outdated

   # Review dependency tree complexity
   cargo tree --depth 3
   ```

2. **SBOM Comparison:**
   ```bash
   # Compare with last month's SBOM
   diff sbom-2026-02.cdx.json sbom-2026-03.cdx.json | grep '"name"'
   ```

3. **Security Advisory Review:**
   - Review all RustSec advisories from the past month
   - Check NAILS GitHub Security Advisories (if any)
   - Review NAILS-related CVEs (search NVD: `site:nvd.nist.gov nails`)

4. **Update Documentation:**
   - Verify SECURITY.md is current
   - Update vulnerability-handling.md if process changed
   - Document any new security exceptions in deny.toml

5. **Tooling Updates:**
   ```bash
   cargo install cargo-audit --locked
   cargo install cargo-deny --locked
   cargo install cargo-sbom --locked
   pre-commit autoupdate
   ```

---

### 6.3 Automation (GitHub Actions)

**Scheduled Security Scans:** `.github/workflows/ci.yml`

```yaml
on:
  schedule:
    - cron: "0 2 * * 0"  # Weekly on Sundays at 2am UTC
```

**What Runs:**
- `cargo audit` (full scan)
- `cargo deny check` (all policies)
- SBOM generation and validation
- Burn-in test loop (flaky test detection)

**Notification on Failure:**
- GitHub Actions email (if enabled)
- Workflow run status visible in Actions tab

---

## 7. Incident Response

When a vulnerability is discovered (by you, a reporter, or automated scan):

### 7.1 Immediate Actions (Hour 0)

```bash
# 1. Verify the vulnerability
cargo audit
cargo tree -i <vulnerable-crate>

# 2. Assess reachability (is the code path used?)
rg "<vulnerable-function>" --type rust

# 3. Check SBOM to identify affected releases
jq -r '.components[] | select(.name == "<vulnerable-crate>") | .version' sbom.cdx.json
```

### 7.2 Severity Assessment (Hours 1-4)

Follow [SECURITY.md](../SECURITY.md) classification criteria:

| Question | Yes → | No → |
|----------|-------|------|
| Remote code execution? | **Critical** | Continue |
| Compromises cryptographic keys? | **Critical** | Continue |
| Defeats plausible deniability? | **Critical** | Continue |
| Local privilege escalation? | **High** | Continue |
| Partial deniability compromise? | **High** | Continue |
| Conditional information disclosure? | **Medium** | Continue |
| Minimal practical impact? | **Low** | Continue |

### 7.3 Generate Updated SBOM After Fix (Hours 4-24)

```bash
# 1. Update vulnerable dependency
cargo update -p <vulnerable-crate>

# 2. Verify fix
cargo audit  # Should show no vulnerabilities

# 3. Test thoroughly
cargo test --all-features
./scripts/ci-local.sh

# 4. Generate new SBOM
cargo sbom --output-format cyclonedx_json_1_6 > sbom.cdx.json

# 5. Commit fix
git add Cargo.lock sbom.cdx.json
git commit -m "fix(security): update <crate> to fix RUSTSEC-YYYY-NNNN"
```

### 7.4 Document in CHANGELOG (Post-Fix)

```markdown
## [0.1.1] - 2026-03-25

### Security

- **fix(security)**: Update `time` crate to 0.2.23 to fix RUSTSEC-2020-0071
  - Severity: Medium
  - Impact: Potential segfault in `Duration::checked_add` (not reachable in NAILS code paths)
  - Advisory: https://rustsec.org/advisories/RUSTSEC-2020-0071
  - SBOM updated to reflect new dependency versions
```

### 7.5 Follow Vulnerability Handling Process

See [vulnerability-handling.md](vulnerability-handling.md) for complete incident response process, including:

- **Section 3:** Fix Development Process
- **Section 4:** Disclosure Process
- **Section 5:** Postmortem Process (Critical/High only)
- **Section 8:** Emergency Release Process (Critical only)

---

## Appendix A: Quick Reference

### Command Cheat Sheet

```bash
# SBOM Generation
cargo sbom --output-format cyclonedx_json_1_6 > sbom.cdx.json
cyclonedx validate --input-file sbom.cdx.json

# Dependency Auditing
cargo audit
cargo audit --json > audit-report.json
cargo deny check
cargo deny check advisories --format json

# SLSA Verification
slsa-verifier verify-artifact <artifact> \
  --provenance-path nails.intoto.jsonl \
  --source-uri github.com/WitteShadovv/nails

# Pre-commit Hooks
pre-commit run --all-files
pre-commit run cargo-audit
pre-commit run cargo-deny

# CI Artifact Download
gh run download <run-id> --name audit-report
gh release download <tag> --pattern "sbom.cdx.json"
```

---

## Appendix B: Tool Installation

### One-Time Setup Script

```bash
#!/usr/bin/env bash
# setup-security-tools.sh - Install all security validation tools

set -euo pipefail

echo "Installing Rust security tools..."
cargo install cargo-audit --locked
cargo install cargo-deny --locked
cargo install cargo-sbom --locked
cargo install cargo-nextest --locked
cargo install cargo-llvm-cov --locked

echo "Installing CycloneDX CLI..."
curl -sSfL https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.27.1/cyclonedx-linux-x64 -o /tmp/cyclonedx-cli
chmod +x /tmp/cyclonedx-cli
sudo mv /tmp/cyclonedx-cli /usr/local/bin/cyclonedx

echo "Installing slsa-verifier (requires Go)..."
if command -v go &> /dev/null; then
    go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
else
    echo "Warning: Go not found, skipping slsa-verifier installation"
fi

echo "Installing pre-commit..."
pip install --user pre-commit

echo "Setting up pre-commit hooks..."
pre-commit install
pre-commit install --hook-type commit-msg

echo "✅ All security tools installed successfully!"
echo "Run 'pre-commit run --all-files' to verify setup."
```

**Usage:**

```bash
chmod +x scripts/setup-security-tools.sh
./scripts/setup-security-tools.sh
```

---

## Appendix C: Troubleshooting

### Issue: cargo-audit Fails with Database Error

**Symptoms:**

```
error: couldn't fetch advisory database
```

**Solution:**

```bash
# Manually update advisory database
rm -rf ~/.cargo/advisory-db
cargo audit

# Or specify a different database path
cargo audit --db /tmp/advisory-db
```

---

### Issue: SLSA Verification Fails with "source mismatch"

**Symptoms:**

```
FAILED: SLSA verification failed: source does not match
```

**Solution:**

Ensure you're using the correct `--source-uri` for the private repository:

```bash
# ❌ WRONG (public URL format)
slsa-verifier verify-artifact nails.tar.gz \
  --provenance-path nails.intoto.jsonl \
  --source-uri https://github.com/WitteShadovv/nails

# ✅ CORRECT (repository path only)
slsa-verifier verify-artifact nails.tar.gz \
  --provenance-path nails.intoto.jsonl \
  --source-uri github.com/WitteShadovv/nails
```

---

### Issue: Pre-commit Hook Timeout

**Symptoms:**

```
cargo-audit.............................................Timed out
```

**Solution:**

```bash
# Increase timeout in .pre-commit-config.yaml
- id: cargo-audit
  name: Cargo Security Audit
  entry: cargo audit
  language: system
  pass_filenames: false
  timeout: 120  # Increase from default 60 seconds
```

---

## References

- **SECURITY.md** - Security policy and vulnerability reporting
- **vulnerability-handling.md** - Internal vulnerability handling process
- **ci.md** - CI/CD pipeline documentation (SBOM generation)
- **deny.toml** - cargo-deny configuration
- [RustSec Advisory Database](https://rustsec.org/)
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [SLSA Framework](https://slsa.dev/)
- [cargo-audit Documentation](https://github.com/rustsec/rustsec/tree/main/cargo-audit)
- [cargo-deny Documentation](https://embarkstudios.github.io/cargo-deny/)

---

## Document History

| Date | Change | Author |
|------|--------|--------|
| 2026-03-24 | Initial version | WitteShadovv |

---

**Questions or feedback?** Open an issue or discussion in the NAILS repository, or contact the maintainers via the channels listed in [SECURITY.md](../SECURITY.md).
