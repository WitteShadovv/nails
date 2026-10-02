# Support

NAILS is maintained through this repository. Use GitHub issues for actionable bug reports, focused feature proposals, and documentation improvements. The fastest way to get useful help is to provide a concise, reproducible report that stays within the project's documented scope.

If your issue is about NAILS OS, the installable distribution, open it in the separate [nails-os](https://github.com/WitteShadovv/nails-os) repository instead.

NAILS is currently alpha-stage software and support is best-effort. The latest published stable release, when present, is the primary supported public release line; otherwise use the latest relevant prerelease.

## Where to Get Help

| Need | Best channel |
| --- | --- |
| Reproducible bug in NAILS | [GitHub Issues](https://github.com/WitteShadovv/nails/issues) using the bug report template |
| Feature request or documentation improvement | [GitHub Issues](https://github.com/WitteShadovv/nails/issues) using the appropriate template |
| Security vulnerability | [Private vulnerability reporting](https://github.com/WitteShadovv/nails/security/advisories/new), or `security@nails.run` as the fallback — see [SECURITY.md](SECURITY.md) |
| Usage or setup question | Review the README, command help, and existing issues first; if you find a concrete product or documentation gap, open an issue with specifics |

## Before You Open an Issue

Please:

1. Search existing issues for duplicates.
2. Confirm that the behavior is in scope for this repository.
3. Check the latest published release or prerelease bundle, or note the exact commit if you are testing unreleased code.
4. Gather what the bug report form asks for:
   - `nails --version`
   - your distribution and its release
   - the steps that reproduce the problem, with real paths and hostnames replaced by placeholders

Issues are public and link your GitHub account to NAILS. Consider a throwaway account, and do not post `nails status` or `nails verify` output, real paths, hostnames, usernames, volume labels, secrets, private keys, recovery material, or any other sensitive operational data.

## Security Reports

Do **not** report suspected vulnerabilities in public issues or pull requests.

Use [GitHub private vulnerability reporting](https://github.com/WitteShadovv/nails/security/advisories/new), or email `security@nails.run` if you cannot use GitHub. [SECURITY.md](SECURITY.md) has the PGP key details and an OPSEC note for reporters. If you are unsure whether an issue is security-sensitive, err on the side of private reporting.

## Support Scope

- Reports are triaged based on reproducibility, user impact, and the information provided.
- We may ask for clarification before triage is complete, but never for real paths, hostnames, or unredacted output in a public issue.
- The latest published stable release, when present, is the primary target for fixes and documentation updates; otherwise use the latest relevant prerelease.
- We do not provide private consulting or troubleshooting for custom deployments, forks, unsupported environments, or third-party integrations.

Do **not** use the security contact for general troubleshooting or feature requests.

Concise, reproducible reports are the fastest way to get useful help.
