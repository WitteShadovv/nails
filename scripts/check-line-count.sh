#!/usr/bin/env bash
# Rust file size check, run unchanged by the pre-commit hook, `just check` and
# CI. It counts code lines (neither blank nor a `//` comment) in every .rs file
# of the crate directories (nails-*/) of the repository, or of the directory
# given as the only argument. Production files warn above 500 and fail above
# 850. Test files (tests.rs, tests_*.rs, *_tests.rs and anything below tests/ or
# benches/) only warn, above 1500. The limits flag a file that has grown several
# responsibilities: split it by responsibility, never just to fit a number.
set -euo pipefail
cd "${1:-$(dirname "$0")/..}"
find nails-* -name target -prune -o -name '*.rs' -print0 | LC_ALL=C sort -z |
  xargs -0 -r awk -v warn=500 -v fail=850 -v test_warn=1500 '
    FNR == 1 { files[++count] = FILENAME }
    !/^[ \t]*(\/\/.*)?$/ { lines[FILENAME]++ }
    END {
      for (i = 1; i <= count; i++) {
        f = files[i]; n = lines[f] + 0
        test = f ~ "/(tests|benches)/" || f ~ "/(tests|tests_[^/]*|[^/]*_tests)\\.rs$"
        if (!test && n > fail) { printf "error: %s: %d code lines (limit %d)\n", f, n, fail; failed = 1 }
        else if (n > (test ? test_warn : warn)) printf "warning: %s: %d code lines (over %d)\n", f, n, test ? test_warn : warn
      }
      exit failed
    }' || exit 1
