"""Decide how a CI job uses the project's Nix binary cache.

action.yml runs this before Nix is installed. It reads the cache settings and
the triggering event from the environment and writes these step outputs:

nix-config
    nix.conf lines that add the project cache as a substituter, with its
    pinned signing key. Empty when the cache is disabled or not configured.
push
    "true" when this job may push build results to the cache.
cachix-name
    The cache to push to, set only when pushing.
push-filter
    The cachix-action pushFilter that limits pushes to PUSH_ALLOW, set only
    when pushing.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping
from typing import NamedTuple

# Name prefixes of the store paths worth pushing. cachix uploads each path
# with its closure, minus what cache.nixos.org already serves.
PUSH_ALLOW = (
    # The binary that every VM test embeds.
    "nails-",
    # The rust-overlay toolchain aggregate; its closure holds the components.
    "rust-default-",
    # A passed VM test: substituting it skips booting the test again.
    "vm-test-run-",
)
# Release bundles are always built by the job that publishes them.
PUSH_DENY = ("nails-release-",)

STORE_PATH = "^/nix/store/[0-9a-z]{32}-"
# Prefixes are limited to characters that are literal in an ERE and need no
# quoting in the shell script cachix-action pastes the filter into.
NAME_PREFIX = re.compile(r"[a-z0-9-]+")
CACHE_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
PUBLIC_KEY = re.compile(r"(?P<host>[a-z0-9.-]+)-[0-9]+:[A-Za-z0-9+/]+={0,2}")
OUTPUT_DELIMITER = "NIX_CONFIG_END"


class Plan(NamedTuple):
    nix_config: str
    cache_name: str
    push: bool
    reason: str


def _check_prefixes(prefixes: tuple[str, ...]) -> None:
    for prefix in prefixes:
        if not NAME_PREFIX.fullmatch(prefix):
            raise ValueError(f"unsupported store path name prefix {prefix!r}")


def _none_of(chars: set[str]) -> str:
    # A "-" is literal only at the end of a bracket expression.
    body = "".join(sorted(chars - {"-"}))
    return f"[^{body}{'-' if '-' in chars else ''}]"


def _not_starting_with(prefixes: tuple[str, ...]) -> str:
    """ERE for the names that start with none of `prefixes`.

    ERE has no negative lookahead, so the complement is spelled out over the
    trie of the prefixes: at each node a matching name either ends, continues
    with a character no prefix continues with, or follows a branch that does
    not complete a prefix.
    """
    if not prefixes:
        raise ValueError("no store path name prefix to allow")
    _check_prefixes(prefixes)
    trie: dict[str, dict] = {}
    for prefix in prefixes:
        node = trie
        for char in prefix:
            node = node.setdefault(char, {})
        node[""] = {}

    def walk(node: dict[str, dict]) -> str | None:
        if "" in node:
            return None
        branches = ["$", _none_of(set(node))]
        for char in sorted(node):
            rest = walk(node[char])
            if rest is not None:
                branches.append(char + rest)
        return "(" + "|".join(branches) + ")"

    pattern = walk(trie)
    assert pattern is not None  # every prefix is non-empty
    return pattern


def push_filter(
    allow: tuple[str, ...] = PUSH_ALLOW, deny: tuple[str, ...] = PUSH_DENY
) -> str:
    """cachix-action pushFilter that pushes only `allow` minus `deny`.

    cachix drops every path that `grep -vEe <pushFilter>` filters out, so the
    filter matches the paths that must not be pushed.
    """
    _check_prefixes(deny)
    excluded = [_not_starting_with(allow), *deny]
    return STORE_PATH + "(" + "|".join(excluded) + ")"


def may_push(event: str, ref: str, head_repository: str, repository: str) -> bool:
    """Whether a job triggered by `event` may write to the shared cache.

    Only people with write access can push to main, schedule or dispatch a
    workflow, or open a pull request from a branch of this repository. A
    fork's pull request runs code nobody vetted; pull_request_target and
    events added later stay read-only until someone decides otherwise.
    """
    if event == "push":
        return ref == "refs/heads/main"
    if event in ("schedule", "workflow_dispatch"):
        return True
    if event == "pull_request":
        return head_repository == repository
    return False


def plan(env: Mapping[str, str]) -> Plan:
    """Work out one job's cache settings; ValueError means misconfiguration."""
    cache = env.get("CACHE", "")
    if cache not in ("true", "false"):
        raise ValueError(f"cache must be 'true' or 'false', got {cache!r}")
    if cache == "false":
        return Plan("", "", False, "project cache disabled for this job")

    name = env.get("CACHIX_NAME", "")
    key = env.get("CACHIX_PUBLIC_KEY", "")
    if not name and not key:
        return Plan("", "", False, "no project cache is configured")
    if not CACHE_NAME.fullmatch(name):
        raise ValueError(f"invalid Cachix cache name {name!r}")
    match = PUBLIC_KEY.fullmatch(key)
    if match is None or match["host"] != f"{name}.cachix.org":
        raise ValueError(f"the public key is not a signing key of {name}.cachix.org")

    nix_config = (
        f"extra-substituters = https://{name}.cachix.org\n"
        f"extra-trusted-public-keys = {key}"
    )
    event = env.get("EVENT_NAME", "")
    ref = env.get("GIT_REF", "")
    head = env.get("HEAD_REPOSITORY", "")
    if not may_push(event, ref, head, env.get("REPOSITORY", "")):
        if event == "pull_request":
            reason = f"read-only: pull request from {head or 'a deleted fork'}"
        else:
            reason = f"read-only: {event} on {ref} does not push"
        return Plan(nix_config, "", False, reason)
    if env.get("HAS_TOKEN") != "true":
        return Plan(nix_config, "", False, "read-only: no Cachix auth token")
    pushed = ", ".join(f"{prefix}*" for prefix in PUSH_ALLOW)
    return Plan(nix_config, name, True, f"pushing {pushed} to {name}.cachix.org")


def main() -> int:
    try:
        result = plan(os.environ)
    except ValueError as error:
        print(f"::error title=setup-nix::{error}")
        return 1
    filter_value = push_filter() if result.push else ""
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(
            f"nix-config<<{OUTPUT_DELIMITER}\n"
            f"{result.nix_config}\n"
            f"{OUTPUT_DELIMITER}\n"
            f"push={'true' if result.push else 'false'}\n"
            f"cachix-name={result.cache_name}\n"
            f"push-filter={filter_value}\n"
        )
    print(f"Binary cache: {result.reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
