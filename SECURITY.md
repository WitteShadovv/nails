# Security Policy

NAILS (NixOS Anti-forensics Integrated Livesystem) is a security-critical application designed to provide plausible deniability through hidden computing environments. Given the sensitive nature of this tool and its potential use in high-risk scenarios, we take security vulnerabilities extremely seriously.

This document outlines our security policy, vulnerability reporting process, and response procedures.

---

## Table of Contents

- [Security Scope](#security-scope)
- [Supported Versions](#supported-versions)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Severity Classification](#severity-classification)
- [Response Process](#response-process)
- [Security Measures](#security-measures)
- [Security Advisories](#security-advisories)

---

## Security Scope

### In Scope

The following components are covered by this security policy:

| Component | Description |
|-----------|-------------|
| `nails` binary | The main command-line interface and all subcommands |
| Core library (`libnails`) | All Rust library code in `src/` |
| Cryptographic operations | Key derivation, encryption, secure erasure |
| Hidden environment management | Creation, activation, and concealment mechanisms |
| Build and release artifacts | Official releases and Nix flake outputs |

### Out of Scope

The following are **not** covered by this security policy:

| Component | Reason | Where to Report |
|-----------|--------|-----------------|
| Upstream Nix packages | Maintained by Nixpkgs | [Nixpkgs Security](https://github.com/NixOS/nixpkgs/security) |
| NixOS kernel/system | Maintained by NixOS | [NixOS Security](https://nixos.org/community/teams/security.html) |
| User misconfiguration | User responsibility | Open a Discussion for guidance |
| Third-party integrations | Not maintained by us | Report to respective maintainers |
| Physical security threats | Outside software scope | N/A |
| Social engineering attacks | Outside software scope | N/A |

> **Note:** If you are unsure whether an issue falls within scope, please report it anyway. We would rather receive reports that turn out to be out of scope than miss a genuine vulnerability.

---

## Supported Versions

NAILS is currently in alpha development. Security updates are provided for the following versions:

| Version | Status | Security Updates |
|---------|--------|------------------|
| 0.1.x   | Alpha (current) | :white_check_mark: Supported |
| < 0.1.0 | Pre-release | :x: Not supported |

> **Important:** As an alpha project, we strongly recommend always using the latest release. Older versions may contain known vulnerabilities and will not receive backported fixes.

Once NAILS reaches stable release (1.0.0), we will maintain security updates for:
- The current major version
- The previous major version (for 6 months after a new major release)

---

## Reporting a Vulnerability

### Contact Information

**Email:** security@nails.run

> **Do not** report security vulnerabilities through public GitHub issues, discussions, or pull requests.

### What to Include

Please provide as much of the following information as possible to help us triage and respond effectively:

1. **Vulnerability Description**
   - Clear, concise description of the vulnerability
   - Affected component(s) and version(s)
   - Type of vulnerability (e.g., data leakage, cryptographic weakness, privilege escalation)

2. **Reproduction Steps**
   - Step-by-step instructions to reproduce the issue
   - Proof-of-concept code or commands (if applicable)
   - Environment details (OS, Nix version, hardware if relevant)

3. **Impact Assessment**
   - Your assessment of the severity and potential impact
   - Attack scenarios and prerequisites
   - Affected user population (all users, specific configurations, etc.)

4. **Additional Context**
   - Any patches or mitigations you have identified
   - Related CVEs or public disclosures
   - Your preferred attribution (name, handle, or anonymous)

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Initial acknowledgment | Within **48 hours** |
| Preliminary assessment | Within **7 days** |
| Severity classification | Within **14 days** |
| Fix timeline communication | Within **14 days** |

### Responsible Disclosure

We request that you:

- **Do not** publicly disclose the vulnerability until we have released a fix or mutually agreed on a disclosure date
- **Do not** exploit the vulnerability beyond what is necessary for demonstration
- **Do not** access, modify, or delete data belonging to others
- **Do** provide us reasonable time to address the issue before public disclosure

We commit to:

- Working with you in good faith to understand and resolve the issue
- Keeping you informed of our progress
- Crediting you in our security advisory (unless you prefer anonymity)
- A standard coordinated disclosure period of **90 days**, unless the severity requires faster action or mutual agreement extends this period

---

## Severity Classification

We classify vulnerabilities using a four-tier system adapted for security-critical anti-forensics software. The primary concern is maintaining plausible deniability and preventing data exposure.

### Critical

**Definition:** Vulnerabilities that can be exploited remotely without unusual user interaction, or that fundamentally compromise the core security guarantees of the system.

**Examples specific to NAILS:**
- Remote code execution in the nails binary
- Complete bypass of hidden environment concealment
- Cryptographic key extraction without physical access
- Silent data exfiltration from hidden environments

**Response:** Emergency release within **24-72 hours**. All users will be notified immediately.

---

### High

**Definition:** Vulnerabilities that compromise plausible deniability, enable persistent code execution, or allow privilege escalation from the primary attack surface.

**Examples specific to NAILS:**
- Partial data leakage revealing hidden environment existence
- Persistent code execution in hidden environments
- Weak or predictable key derivation
- Forensic artifacts that survive secure erasure
- Local privilege escalation from the nails binary

**Response:** Urgent fix within **7 days**. Emergency release if necessary.

---

### Medium

**Definition:** Vulnerabilities requiring specific conditions to exploit, or that enable local attacks not from the primary attack surface.

**Examples specific to NAILS:**
- Information disclosure requiring local access and specific configuration
- Timing side-channels in cryptographic operations
- Denial of service against nails operations
- Local privilege escalation from non-primary vectors

**Response:** Prioritized fix in the next scheduled release, or within **30 days** for actively exploited issues.

---

### Low

**Definition:** Vulnerabilities with limited impact, requiring unusual conditions, or with effective mitigations available.

**Examples specific to NAILS:**
- Information disclosure requiring physical access and rare configurations
- Minor cryptographic implementation issues with theoretical impact
- UI/UX issues that could lead to user error
- Verbose error messages leaking non-sensitive information

**Response:** Fix included in next regular release.

---

### Severity Decision Matrix

| Factor | Increases Severity | Decreases Severity |
|--------|-------------------|-------------------|
| Attack vector | Remote, network-based | Local, physical access required |
| User interaction | None required | Complex actions required |
| Privileges required | None | Root/admin required |
| Impact on deniability | Direct compromise | Indirect/theoretical |
| Exploitability | Known exploit exists | Theoretical only |

---

## Response Process

### 1. Receipt and Acknowledgment (0-48 hours)

- Acknowledge receipt of the report
- Assign a tracking identifier
- Designate a response coordinator

### 2. Triage and Assessment (48 hours - 7 days)

- Reproduce the vulnerability
- Assess scope and impact
- Assign preliminary severity classification
- Communicate initial findings to reporter

### 3. Fix Development (Timeline varies by severity)

| Severity | Fix Timeline | Release Type |
|----------|--------------|--------------|
| Critical | 24-72 hours | Emergency release |
| High | 7 days | Emergency or expedited release |
| Medium | 30 days | Next scheduled release |
| Low | 90 days | Next scheduled release |

### 4. Fix Verification

- Internal testing of the fix
- Verification that the fix addresses the root cause
- Regression testing to ensure no new issues introduced
- Optional: Request reporter to verify the fix

### 5. Release and Disclosure

- Coordinate disclosure timeline with reporter
- Prepare security advisory
- Release fixed version
- Publish security advisory (see [Security Advisories](#security-advisories))
- Update CHANGELOG with security fix notation

### 6. Post-Mortem (Critical and High only)

- Conduct internal review
- Document lessons learned
- Implement process improvements if needed

### Credit and Recognition

We believe in recognizing the valuable contributions of security researchers. Unless you prefer to remain anonymous, we will credit you in:

- The GitHub Security Advisory
- The CHANGELOG entry
- Any public announcements

Please indicate your preference when submitting your report.

---

## Security Measures

NAILS implements multiple layers of security controls throughout development and deployment.

### Dependency Security

| Measure | Implementation | Frequency |
|---------|----------------|-----------|
| `cargo-audit` | Pre-commit hook | Every commit |
| `cargo-audit` | CI pipeline | Every PR and push to main |
| Dependency review | Manual review of new dependencies | As needed |

### Build Security

| Measure | Description |
|---------|-------------|
| Static linking | Reduces runtime attack surface and dependency on system libraries |
| Reproducible builds | Nix flake ensures bit-for-bit reproducible builds |
| Minimal dependencies | Conscious effort to minimize dependency tree |

### Code Quality

| Measure | Implementation |
|---------|----------------|
| Clippy lints | Enforced in CI with security-relevant lints enabled |
| Pre-commit hooks | Automated checks before every commit |
| Secret detection | Pre-commit hooks scan for accidental secret commits |

### Cryptographic Security

| Measure | Description |
|---------|-------------|
| Audited libraries | Use of well-established cryptographic libraries |
| No custom crypto | Avoid implementing custom cryptographic primitives |
| Secure defaults | Cryptographic operations use secure defaults |

### Future Enhancements

The following security measures are planned for future releases:

- [ ] Fuzzing infrastructure for input parsing
- [ ] Memory safety verification with Miri
- [ ] Third-party security audit
- [ ] Formal verification of critical components
- [ ] Security-focused documentation review

---

## Security Advisories

### Communication Channels

Security issues will be communicated through the following channels:

| Channel | Purpose | Link |
|---------|---------|------|
| GitHub Security Advisories | Primary disclosure mechanism | [Security Advisories](../../security/advisories) |
| CHANGELOG.md | Documented in release notes | [CHANGELOG](./CHANGELOG.md) |
| GitHub Releases | Release notes for fixed versions | [Releases](../../releases) |

> **Note:** This repository is private. Security advisories created here will only be visible to repository collaborators unless explicitly published. For broader security notifications, fixes will be documented in CHANGELOG.md and release notes.

### Advisory Format

Each security advisory will include:

- **Advisory ID:** Unique identifier (format: `NAILS-YYYY-NNNN`)
- **CVE ID:** If assigned
- **Severity:** Critical, High, Medium, or Low
- **Affected Versions:** Version range affected
- **Fixed Versions:** Versions containing the fix
- **Description:** Non-technical summary
- **Technical Details:** Detailed technical description
- **Impact:** What an attacker could achieve
- **Mitigation:** Workarounds if immediate upgrade is not possible
- **Credit:** Attribution to reporter (if desired)

### Subscribing to Updates

To receive security notifications:

1. **Watch this repository** with "Security alerts" enabled
2. **Check GitHub Security Advisories** periodically
3. **Monitor releases** for security-related updates

> **Future:** We plan to establish a security mailing list for advance notification of critical issues. This section will be updated when available.

---

## Questions and Concerns

For general security questions that are **not** vulnerability reports, please:

1. Check existing [GitHub Discussions](../../discussions) for answers
2. Open a new Discussion with the "Security" category (for non-sensitive questions)
3. Email security@nails.run for sensitive questions

---

## Acknowledgments

This security policy is inspired by:
- [Tails Security](https://tails.net/security/)
- [Rust Security Policy](https://www.rust-lang.org/policies/security)
- [GitHub Security Best Practices](https://docs.github.com/en/code-security)

---

## Policy Updates

This security policy may be updated periodically. Significant changes will be announced through:
- Commit messages referencing this file
- GitHub release notes (for major policy changes)

**Last updated:** 2024-01-15
**Policy version:** 1.0.0
