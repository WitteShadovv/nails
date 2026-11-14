#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Add the positive controls the producer of a set of real images planted itself
# to a copy of the scan's controls, for run-scan.sh's ORACLE_EXTRA_CONTROLS:
#
#   merge-controls.sh <controls.json> <extra.json> > <merged.json>
#
# <extra.json> holds a `positive_controls` list and nothing else, with at least
# one control. Each control is one of the restore channel (`btrfs_restore`): an
# absolute path and the SHA-256 of the file the producer read back there
# (`sha256:` and 64 lowercase hex digits), a name no other control has, and an
# optional note. Anything else fails the merge (exit 1) and writes nothing, so
# an extra file can only add exact controls of files: never widen, replace or
# drop one, and never add a canary. Exits 2 on a usage error.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: merge-controls.sh <controls.json> <extra.json>" >&2
  exit 2
fi
base=$1
extra=$2
for file in "$base" "$extra"; do
  if [ ! -f "$file" ]; then
    echo "merge-controls: not a file: $file" >&2
    exit 2
  fi
done

# The names a control may not take: those of the committed controls.
# shellcheck disable=SC2016  # $base, $taken, $names and $n are jq's
valid='
  def control_ok:
    type == "object"
    and ((keys - ["note"]) == ["field", "name", "path", "tool"])
    and (.name | type == "string" and length > 0)
    and .tool == "btrfs_restore"
    and (.path | type == "string" and startswith("/") and length > 1
      and (endswith("/") | not))
    and (.field | type == "string" and test("^sha256:[0-9a-f]{64}$"))
    and ((.note // "") | type == "string");
  ($base[0].positive_controls | map(.name)) as $taken
  | type == "object"
  and keys == ["positive_controls"]
  and (.positive_controls | type == "array" and length > 0)
  and all(.positive_controls[]; control_ok)
  and ([.positive_controls[].name] as $names
    | ($names | length) == ($names | unique | length)
    and all($names[]; . as $n | $taken | any(. == $n) | not))
'
if ! jq -e --slurpfile base "$base" "$valid" "$extra" >/dev/null; then
  echo "merge-controls: $extra is not a list of exact restore-channel controls with new names; nothing merged" >&2
  exit 1
fi
jq --slurpfile extra "$extra" '.positive_controls += $extra[0].positive_controls' "$base"
