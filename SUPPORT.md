# Support

NAILS is maintained through this repository. Use GitHub issues for actionable bug reports, focused feature proposals, and documentation improvements. The fastest way to get useful help is to provide a concise, reproducible report that stays within the project's documented scope.

If your issue is about NAILS OS, the installable distribution, open it in the separate [nails-os](https://github.com/WitteShadovv/nails-os) repository instead.

NAILS is currently alpha-stage software and support is best-effort. The latest published GitHub prerelease bundle from `main` is the primary supported public release line.

## Where to Get Help

| Need | Best channel |
| --- | --- |
| Reproducible bug in NAILS | [GitHub Issues](https://github.com/WitteShadovv/nails/issues) using the bug report template |
| Feature request or documentation improvement | [GitHub Issues](https://github.com/WitteShadovv/nails/issues) using the appropriate template |
| Security vulnerability | `security@nails.run` — see [SECURITY.md](SECURITY.md) |
| Usage or setup question | Review the README, command help, and existing issues first; if you find a concrete product or documentation gap, open an issue with specifics |

## Before You Open an Issue

Please:

1. Search existing issues for duplicates.
2. Confirm that the behavior is in scope for this repository.
3. Check the latest published prerelease bundle, or note the exact commit if you are testing unreleased code.
4. Gather useful diagnostics such as:
   - `nails --version`
   - `nails status -v`
   - relevant NixOS version details
   - configuration details needed to reproduce the problem

When reporting problems, avoid posting secrets, private keys, recovery material, or any sensitive operational data.

## Security Reports

Do **not** report suspected vulnerabilities in public issues or discussions.

Use the private reporting path in [SECURITY.md](SECURITY.md). If you are unsure whether an issue is security-sensitive, err on the side of private reporting.

## Support Scope

- Reports are triaged based on reproducibility, user impact, and the information provided.
- We may ask for clarification or sanitized diagnostics before triage is complete.
- The latest published GitHub prerelease bundle from `main` is the primary target for fixes and documentation updates.
- We do not provide private consulting or troubleshooting for custom deployments, forks, unsupported environments, or third-party integrations.

Do **not** use the security contact for general troubleshooting or feature requests.

Concise, reproducible reports are the fastest way to get useful help.
