# Fail `nix flake check` when an E2E test contains an assertion that cannot
# fail. The suite's only value is that a regression turns a test red, so a
# branch that reports a problem and then lets the test pass is worse than no
# test at all: it hides the regression behind a green run.
#
# The banned idiom is the soft "Note:" branch -- `print("Note: ...")` or
# `print(f"Note: ...")` written where a hard `assert` or `machine.fail(...)`
# belongs. See the "no softened assertions" invariant in README.md for the
# wider rule, including the `|| echo 'CLEAN'` keyword filter that only a
# complete allowlist diff (not a grep lint) can judge.
#
# `tests` is the tests tree; `scenarios` holds the bodies of the batched tests
# (lib/batch.nix), which are test code just the same.
{
  pkgs,
  tests,
  scenarios,
}:
pkgs.runCommandLocal "lint-e2e-soft-assertions" { } ''
  if grep -rEn 'print\(f?"Note:' ${tests} ${scenarios}; then
    echo >&2
    echo "E2E lint: the lines above report a problem with print('Note: ...')" >&2
    echo "and then let the test pass. Replace each with a hard assertion" >&2
    echo "(assert ... or machine.fail(...)). See the 'no softened assertions'" >&2
    echo "invariant in nix/e2e-tests/README.md." >&2
    exit 1
  fi
  touch "$out"
''
