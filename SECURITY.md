# Security Policy

NAILS (NixOS Anti-forensics Isolation & Layering System) is security-sensitive software. This policy explains what qualifies as a security issue, how to report one privately, and how the project handles coordinated disclosure.

## Scope

This policy applies to security issues in the NAILS repository and its officially published release artifacts, including:

- the `nails` CLI and workspace crates
- NAILS-specific state handling, cleanup, and isolation logic
- NixOS integration that is implemented in this repository
- official GitHub prerelease bundles published from this repository

This policy does **not** cover:

- vulnerabilities in upstream projects such as NixOS, Nixpkgs, VeraCrypt, LUKS, or the Linux kernel
- local deployment mistakes or unsupported operating environments
- general hardening advice that does not describe a specific vulnerability in this repository
- physical access, coercion, or other threats outside the software boundary

If you are unsure whether something is in scope, report it anyway. We would rather review a borderline report than miss a real issue.

## Supported Versions

NAILS is currently released as **alpha** software. Security fixes are applied to the latest supported release line first.

| Version | Status | Security support |
| --- | --- | --- |
| Latest GitHub prerelease from `main` | Current alpha verification bundle | Security fixes are applied here first |
| Earlier GitHub prereleases in the current alpha series | Superseded | Not supported |

There is no separate stable release line yet. Because the project is pre-1.0, we recommend upgrading to the latest published prerelease bundle instead of relying on backported fixes.

## Reporting a Vulnerability

### Private reporting channel

Report vulnerabilities by email to **security@nails.run**.

Please **do not** open public GitHub issues, discussions, or pull requests for suspected vulnerabilities.

If you accidentally disclose something sensitive in a public issue, edit the report if possible and contact us at `security@nails.run`.

### What to include

Please include as much of the following as you can:

- affected version or commit
- environment details relevant to reproduction
- clear reproduction steps or proof of concept
- expected security boundary and observed failure
- impact assessment and any suggested mitigations
- whether and how you would like to be credited

### What to expect from us

We normally:

- acknowledge receipt within **72 hours**
- communicate an initial triage assessment within **7 days**
- keep you informed if remediation will take longer

These are response targets rather than guaranteed SLAs, but we use them to keep reports moving and reporters informed.

## Coordinated Disclosure

We ask reporters to avoid public disclosure until:

- a fix is available, or
- we agree on a disclosure date together

In return, we will:

- investigate reports in good faith
- work toward a fix or mitigation appropriate to the severity
- coordinate publication when a fix is ready
- credit the reporter unless anonymity is requested

Our default goal is coordinated disclosure within **90 days**, but we may shorten or extend that window depending on severity, active exploitation, fix complexity, or mutual agreement with the reporter.

## Severity Guidelines

We prioritize issues based on impact to user safety, data exposure, isolation failure, and the reliability of NAILS cleanup and state guarantees.

| Severity | Typical impact |
| --- | --- |
| Critical | Remote compromise, complete isolation failure, or direct exposure of protected data/workflows |
| High | Significant local compromise, persistent artifacts, privilege escalation, or bypass of important safety guarantees |
| Medium | Limited information disclosure, denial of service, or issues requiring narrow conditions |
| Low | Defense-in-depth gaps, low-impact leaks, or issues with practical mitigations |

Examples of potentially high-priority reports include:

- exposure of hidden-environment artifacts after documented cleanup
- bypasses of isolation or rollback guarantees
- privilege escalation through NAILS-managed operations
- release artifact integrity problems

## Security Advisories and Fix Publication

When we publish a security fix, we communicate it through the repository's public release channels, which can include:

- GitHub Security Advisories
- GitHub Releases
- `CHANGELOG.md`

Publication format and timing depend on severity, remediation, and disclosure coordination. During the current alpha phase, some fixes may appear first in GitHub prerelease notes before a formal advisory is published.

## Non-sensitive Security Questions

For non-sensitive questions about hardening, threat model, or secure use:

- review the existing documentation first
- use the repository's public collaboration channels if appropriate and available
- use `security@nails.run` only when the discussion itself would be sensitive

## Policy Updates

This policy is maintained with the repository. Material updates will be reflected in this file.

**Last updated:** 2026-04-20
