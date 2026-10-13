# Security Policy

NAILS, a tool that runs a hidden session on a decoy system, is security-sensitive software. This policy explains what qualifies as a security issue, how to report one privately, and how the project handles coordinated disclosure.

## Scope

This policy applies to security issues in the NAILS repository and its officially published release artifacts, including:

- the `nails` CLI and workspace crates
- NAILS-specific state handling, cleanup, and isolation logic
- NixOS integration that is implemented in this repository
- official GitHub release bundles published from this repository

What NAILS is and is not designed to defend against (the adversary, assumptions and out-of-scope threats) is defined in [docs/threat-model.md](docs/threat-model.md). A report shows a vulnerability when NAILS fails to uphold that model, for example a hidden-session trace that survives teardown on a decoy that meets its assumptions. Vulnerabilities in upstream projects such as NixOS, Nixpkgs, VeraCrypt, LUKS or the Linux kernel belong with those projects.

If you are unsure whether something is in scope, report it anyway. We would rather review a borderline report than miss a real issue.

## Supported Versions

NAILS is currently released as **alpha** software. Only the most recent `0.2.x` release carries security fixes; there are no backports to earlier lines.

| Version | Status | Security support |
| --- | --- | --- |
| `0.2.x` | Current release line | Supported |
| `0.1.x` and earlier alpha builds | Superseded | Not supported |

Run the latest release and verify its artifacts before use; how releases are produced and numbered is described in [RELEASING.md](RELEASING.md).

## Reporting a Vulnerability

> [!NOTE]
> NAILS is currently maintained by a solo developer. Response targets below are best-effort goals, not guaranteed SLAs.

### Private reporting channels

Use one of these two channels, in this order:

1. **GitHub private vulnerability reporting (primary).** Open a report at <https://github.com/WitteShadovv/nails/security/advisories/new>, or use **Report a vulnerability** on the repository's Security tab. Only you and the maintainer can see the report, and the fix and the eventual advisory are coordinated in the same private thread.
2. **Email to `security@nails.run` (fallback).** Use it if you cannot or do not want to use a GitHub account, or if you do not want GitHub to be able to read the report. No PGP key is published yet (see below), so send only a short request for a private channel first, without any details of the issue.

Please **do not** open public GitHub issues or pull requests for suspected vulnerabilities.

If you accidentally post something sensitive in a public issue, tell us through one of the channels above so we can delete the issue. Editing it is not enough: the original text stays in the issue's edit history and in notification emails that were already sent.

### PGP key

No OpenPGP key for `security@nails.run` is published yet. It will be published through Web Key Directory (WKD) on nails.run, and its fingerprint will appear below. Once both are there, fetch it with:

```sh
gpg --auto-key-locate clear,nodefault,wkd --locate-external-keys security@nails.run
```

Compare the fingerprint gpg prints with the one below before encrypting, and do not use a key for this address whose fingerprint differs, wherever it came from.

<!-- Replace the next line with the full 40-hex-digit fingerprint of the key served by WKD on
     nails.run, grouped in blocks of four, once that key is published. -->
**Fingerprint:** not yet published. Until it appears here, prefer private vulnerability reporting. If you must use email, first send only a short request for a private channel, without any details of the issue.

### OPSEC for reporters

- A pseudonymous or throwaway GitHub account or email address is fine. We do not need your real name.
- Real paths, hostnames, usernames, volume labels, and unredacted `nails status` or `nails verify` output are not needed. Replace them with placeholders such as `/mnt/usb` or `host1`, or describe the layout in words.
- Strip metadata from attachments such as screenshots and log files.
- Say if you do not want to be credited. We then leave your name and account out of the published advisory.

### What to include

Please include as much of the following as you can:

- affected version or commit
- environment details relevant to reproduction (OS or distribution, storage backend), with placeholders for anything that identifies your setup
- clear reproduction steps or proof of concept
- expected security boundary and observed failure
- impact assessment and any suggested mitigations
- whether and how you would like to be credited

### What to expect from us

We normally:

- acknowledge receipt within **72 hours**
- communicate an initial triage assessment within **7 days**
- keep you informed if remediation will take longer

These are best-effort response targets rather than guaranteed SLAs, but we use them to keep reports moving and reporters informed.

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
- bypasses of the session's isolation, the way back or the rollback of an interrupted entry
- privilege escalation through NAILS-managed operations
- release artifact integrity problems

## Security Advisories and Fix Publication

When we publish a security fix, we communicate it through the repository's public release channels, which can include:

- GitHub Security Advisories
- GitHub Releases
- `CHANGELOG.md`

Publication format and timing depend on severity, remediation, and disclosure coordination. During the current alpha phase, some fixes may appear first in GitHub release notes before a formal advisory is published.

## Maintainer Handling Process

This section describes how maintainers triage, fix, and disclose vulnerabilities.
It is public on purpose: reporters should be able to see the standards we aim to
follow. It describes intended practice, not a legal guarantee, and it will evolve
with the project's release process and tooling.

### Principles

- Protect users first.
- Validate reports carefully and respectfully.
- Prefer coordinated disclosure over surprise public discussion.
- Document fixes clearly once a remedy is available.
- Avoid overstating process maturity while the project is in alpha.

A report that arrives through private vulnerability reporting opens a draft
advisory, so triage, the fix, and the published advisory stay in one private
thread. If a report appears in public, move the conversation to a private channel
and delete the public issue as quickly as practical: editing is not enough,
because the original text stays in the edit history and in notification emails
that were already sent.

### Triage

1. Acknowledge receipt.
2. Confirm whether the report appears credible and in scope.
3. Reproduce the issue when possible.
4. Assess impact, affected versions, and likely mitigations.
5. Assign a severity (see the table above) and decide whether the fix needs
   restricted coordination. When in doubt, classify conservatively at first and
   refine after reproduction.

### Developing and shipping a fix

For higher-severity issues, use the least-public coordination path available
until users have a fix or mitigation. Depending on repository capabilities, that
may include GitHub Security Advisories, restricted branches or private forks, and
limited distribution of proof-of-concept details until release.

Every security fix should aim to include:

- a clear root-cause fix
- regression coverage where feasible
- review of adjacent failure paths and cleanup behaviour
- release notes or advisory text appropriate to the issue

Once a fix is ready, prepare the release or patch, coordinate timing with the
reporter when practical, publish an advisory and/or release note, and credit the
reporter unless anonymity was requested.

### Post-incident follow-up

For significant issues, record what failed, how the issue was introduced, why
earlier review or testing did not catch it, and what preventive action should
follow. That follow-up may live in a public postmortem, a tracked issue, or a
smaller maintainer note, depending on sensitivity.

### Dependency vulnerabilities

When an upstream dependency issue affects NAILS:

1. confirm whether the vulnerable path is reachable in this project
2. assess NAILS-specific impact rather than copying upstream severity blindly
3. update, patch, pin, or mitigate based on urgency and feasibility
4. document user-facing impact if the issue materially affects released builds

### Maintainer review checklist

- [ ] Report is in scope or routed appropriately
- [ ] Sensitive details are not exposed publicly
- [ ] Severity and affected versions are recorded
- [ ] Fix includes tests or a documented reason why it cannot
- [ ] Release/advisory text is prepared
- [ ] Reporter credit preference is respected

## Non-sensitive Security Questions

For non-sensitive questions about hardening, threat model, or secure use:

- review the existing documentation first
- if the documentation leaves a gap, open a public issue about it, following the OPSEC note above
- use the private channels above only when the question itself would be sensitive

## Policy Updates

This policy is maintained with the repository. Material updates will be reflected in this file.

**Last updated:** 2026-10-02
