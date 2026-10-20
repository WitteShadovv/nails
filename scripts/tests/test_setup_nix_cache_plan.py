"""Tests for .github/actions/setup-nix/cache_plan.py."""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / ".github" / "actions" / "setup-nix" / "cache_plan.py"

_spec = importlib.util.spec_from_file_location("cache_plan", SCRIPT)
assert _spec is not None and _spec.loader is not None
cache_plan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cache_plan)

NAME = "nails-ci"
# Low entropy on purpose: realistic keys and hashes trip the secret scanner.
KEY = f"{NAME}.cachix.org-1:{'A' * 43}="
HASH = "0" * 32

# The post-build hook that cachix-action v17 writes (registerPostBuildHook in
# its src/main.ts), with `cachix daemon push` replaced by printing the paths
# it would push. The action pastes pushFilter into the script as text, and
# the shebang is not on the first line, so Nix runs the hook with /bin/sh.
HOOK = """
    #!/usr/bin/env bash

    set -eu
    set -f # disable globbing

    PUSH_FILTER="@PUSH_FILTER@"

    filterPaths() {
      local regex=$1
      local paths=$2

      for path in $paths; do
        echo $path | grep -vEe $regex
      done | xargs
    }

    if [ -n "$PUSH_FILTER" ]; then
      OUT_PATHS=$(filterPaths $PUSH_FILTER "$OUT_PATHS")
    fi

    printf '%s\\n' $OUT_PATHS
    exit 0
"""

SHELLS = sorted(
    {path for name in ("sh", "bash", "dash") if (path := shutil.which(name))}
)


@unittest.skipUnless(SHELLS and shutil.which("grep"), "needs a shell and grep")
class PushFilterTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.hook = Path(tmp.name) / "post-build-hook.sh"
        hook = HOOK.replace("@PUSH_FILTER@", cache_plan.push_filter())
        self.hook.write_text(hook, encoding="utf-8")

    def pushed(self, shell: str, name: str) -> bool:
        # One output per run, like the hook of a single-output derivation.
        path = f"/nix/store/{HASH}-{name}"
        result = subprocess.run(
            [shell, str(self.hook)],
            env={**os.environ, "OUT_PATHS": path},
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(result.stderr, "")
        pushed = result.stdout.split()
        self.assertIn(pushed, ([], [path]))
        return pushed == [path]

    def test_pushes_only_allowed_names(self) -> None:
        cases = {
            "nails-0.2.0": True,
            "nails-nix-daemon-overlay-lifecycle-test": True,
            "vm-test-run-basic-workflow": True,
            "rust-default-1.93.0": True,
            "nails-release-0.2.0-git.abc1234": False,
            "nails": False,
            "nail": False,
            "nailsx-1.0": False,
            "vm-test-run": False,
            "vm-test-runner": False,
            "rust-default": False,
            "rust-std-1.93.0-x86_64-unknown-linux-musl": False,
            "cargo-vendor-dir": False,
            "source": False,
            "nixos-system-machine-25.11": False,
        }
        for shell in SHELLS:
            for name, expected in cases.items():
                with self.subTest(shell=shell, name=name):
                    self.assertEqual(self.pushed(shell, name), expected)

    def test_filter_is_literal_in_the_hook_script(self) -> None:
        pattern = cache_plan.push_filter()
        # No quote, backslash, backquote or whitespace, and every "$" is
        # followed by "|", which no shell expands.
        self.assertRegex(pattern, r"^[a-z0-9^/\[\]{}()|$-]+$")
        self.assertEqual(re.findall(r"\$.", pattern), ["$|"] * pattern.count("$"))

    def test_rejects_prefixes_that_would_need_quoting(self) -> None:
        for prefix in ("", "a.b", "Nails-", "a b", 'a"', "a$"):
            with self.subTest(prefix=prefix):
                with self.assertRaises(ValueError):
                    cache_plan.push_filter(allow=(prefix,))
                with self.assertRaises(ValueError):
                    cache_plan.push_filter(deny=(prefix,))

    def test_rejects_an_empty_allowlist(self) -> None:
        with self.assertRaises(ValueError):
            cache_plan.push_filter(allow=())


class TrustTest(unittest.TestCase):
    def test_only_trusted_events_push(self) -> None:
        repo = "owner/nails"
        cases = [
            ("push", "refs/heads/main", "", True),
            ("push", "refs/heads/next", "", True),
            ("push", "refs/heads/feature", "", False),
            ("push", "refs/heads/next-feature", "", False),
            ("push", "refs/tags/next", "", False),
            ("push", "refs/tags/v1.0.0", "", False),
            ("schedule", "refs/heads/main", "", True),
            ("workflow_dispatch", "refs/heads/feature", "", True),
            ("pull_request", "refs/pull/1/merge", repo, True),
            ("pull_request", "refs/pull/1/merge", "fork/nails", False),
            ("pull_request", "refs/pull/1/merge", "", False),
            ("pull_request_target", "refs/heads/main", repo, False),
            ("merge_group", "refs/heads/gh-readonly-queue/main/x", "", False),
        ]
        for event, ref, head, expected in cases:
            with self.subTest(event=event, ref=ref, head=head):
                self.assertEqual(cache_plan.may_push(event, ref, head, repo), expected)


def env(**overrides: str) -> dict[str, str]:
    values = {
        "CACHE": "true",
        "CACHIX_NAME": NAME,
        "CACHIX_PUBLIC_KEY": KEY,
        "HAS_TOKEN": "true",
        "EVENT_NAME": "push",
        "GIT_REF": "refs/heads/main",
        "HEAD_REPOSITORY": "",
        "REPOSITORY": "owner/nails",
    }
    values.update(overrides)
    return values


class PlanTest(unittest.TestCase):
    def test_trusted_event_with_token_pushes(self) -> None:
        result = cache_plan.plan(env())
        self.assertTrue(result.push)
        self.assertEqual(result.cache_name, NAME)
        self.assertEqual(
            result.nix_config.splitlines(),
            [
                f"extra-substituters = https://{NAME}.cachix.org",
                f"extra-trusted-public-keys = {KEY}",
            ],
        )

    def test_reads_without_a_token_or_a_trusted_event(self) -> None:
        cases = {
            "read-only: no Cachix auth token": {"HAS_TOKEN": "false"},
            "read-only: pull request from fork/nails": {
                "EVENT_NAME": "pull_request",
                "HEAD_REPOSITORY": "fork/nails",
            },
            "read-only: push on refs/heads/dev does not push": {
                "GIT_REF": "refs/heads/dev"
            },
        }
        for reason, overrides in cases.items():
            with self.subTest(reason=reason):
                result = cache_plan.plan(env(**overrides))
                self.assertEqual((result.push, result.cache_name), (False, ""))
                self.assertEqual(result.reason, reason)
                self.assertIn(f"https://{NAME}.cachix.org", result.nix_config)

    def test_disabled_or_unconfigured_cache_adds_nothing(self) -> None:
        for overrides in (
            {"CACHE": "false"},
            {"CACHE": "false", "CACHIX_NAME": "Not Valid"},
            {"CACHIX_NAME": "", "CACHIX_PUBLIC_KEY": ""},
        ):
            with self.subTest(**overrides):
                result = cache_plan.plan(env(**overrides))
                self.assertEqual(
                    (result.nix_config, result.cache_name, result.push), ("", "", False)
                )

    def test_rejects_bad_configuration(self) -> None:
        for overrides in (
            {"CACHE": "yes"},
            {"CACHE": ""},
            {"CACHIX_PUBLIC_KEY": ""},
            {"CACHIX_NAME": ""},
            {"CACHIX_NAME": "Nails"},
            {"CACHIX_PUBLIC_KEY": f"other.cachix.org-1:{'A' * 43}="},
            {"CACHIX_PUBLIC_KEY": f"{NAME}.cachix.org:{'A' * 43}="},
            {"CACHIX_NAME": f"{NAME}\npost-build-hook = /tmp/x"},
            {"CACHIX_PUBLIC_KEY": f"{KEY}\npost-build-hook = /tmp/x"},
        ):
            with self.subTest(**overrides), self.assertRaises(ValueError):
                cache_plan.plan(env(**overrides))


class MainTest(unittest.TestCase):
    def run_script(
        self, **overrides: str
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            output.touch()
            result = subprocess.run(
                [sys.executable, str(SCRIPT)],
                env={**os.environ, **env(**overrides), "GITHUB_OUTPUT": str(output)},
                capture_output=True,
                text=True,
                check=False,
            )
            return result, output.read_text(encoding="utf-8")

    def test_writes_step_outputs(self) -> None:
        result, output = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            output,
            "nix-config<<NIX_CONFIG_END\n"
            f"extra-substituters = https://{NAME}.cachix.org\n"
            f"extra-trusted-public-keys = {KEY}\n"
            "NIX_CONFIG_END\n"
            "push=true\n"
            f"cachix-name={NAME}\n"
            f"push-filter={cache_plan.push_filter()}\n",
        )
        self.assertIn(
            f"pushing nails-*, rust-default-*, vm-test-run-* to {NAME}", result.stdout
        )

    def test_read_only_job_gets_no_push_settings(self) -> None:
        result, output = self.run_script(HAS_TOKEN="false")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(output.endswith("push=false\ncachix-name=\npush-filter=\n"))

    def test_unconfigured_cache_writes_an_empty_config(self) -> None:
        result, output = self.run_script(CACHIX_NAME="", CACHIX_PUBLIC_KEY="")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(
            output.startswith("nix-config<<NIX_CONFIG_END\n\nNIX_CONFIG_END\n")
        )
        self.assertIn("no project cache is configured", result.stdout)

    def test_bad_input_fails_the_step(self) -> None:
        result, output = self.run_script(CACHE="maybe")
        self.assertEqual(result.returncode, 1)
        self.assertIn("::error title=setup-nix::cache must be", result.stdout)
        self.assertEqual(output, "")


if __name__ == "__main__":
    unittest.main()
