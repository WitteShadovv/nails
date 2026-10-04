#!/usr/bin/env bash
# Documentation gate: check that the Markdown docs link to things that exist and
# that no retired name has crept back in.
#
# Two independent checks run over the git-tracked Markdown:
#
#   1. Link check. `lychee --offline` resolves every relative link and anchor
#      without touching the network, so a renamed or deleted doc is caught the
#      moment something still points at it.
#
#   2. Retired-name guard. Old paths, keys and file names that the project has
#      moved away from must not reappear in the user-facing docs. CHANGELOG.md
#      and TODO.md are exempt: the changelog records the removals by name and the
#      backlog describes the problems they came from, so both legitimately
#      mention the old names.
#
# Exit status is non-zero if either check fails.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

status=0

# Names the project has retired. Each must be gone from the user-facing docs.
retired_pattern='nails\.yaml|~/\.nails|USER-SECURITY-GUIDE|/mnt/hidden-volume|/mnt/hidden|veracrypt-hidden|hidden_volume_path'

# Collect the Markdown, NUL-separated so paths with spaces survive. Prefer the
# git index (the authoritative set, no build artefacts), and fall back to a
# filesystem walk when run outside a work tree, for example inside the Nix build
# sandbox that has no `.git`.
all_docs=()
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  mapfile -d '' -t all_docs < <(git ls-files -z '*.md')
fi
if [ "${#all_docs[@]}" -eq 0 ]; then
  mapfile -d '' -t all_docs < <(find . -type f -name '*.md' -print0)
fi

if [ "${#all_docs[@]}" -eq 0 ]; then
  echo "docs-check: no Markdown files found" >&2
  exit 1
fi

# The retired-name guard skips the changelog and the backlog, matched by base
# name so a `./` prefix from the filesystem walk does not slip past it.
guard_docs=()
for doc in "${all_docs[@]}"; do
  case "${doc##*/}" in
    CHANGELOG.md | TODO.md) ;;
    *) guard_docs+=("$doc") ;;
  esac
done

echo "docs-check: scanning ${#guard_docs[@]} doc(s) for retired names"
if grep -nHE "$retired_pattern" "${guard_docs[@]}"; then
  echo "docs-check: a retired name appears above; replace it with the current one" >&2
  status=1
fi

echo "docs-check: link-checking ${#all_docs[@]} Markdown file(s) with lychee"
if ! command -v lychee >/dev/null 2>&1; then
  echo "docs-check: lychee is not installed; enter the dev shell or install it" >&2
  exit 1
fi

if ! lychee --offline --no-progress "${all_docs[@]}"; then
  echo "docs-check: lychee found a broken link above" >&2
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "docs-check: OK"
fi
exit "$status"
