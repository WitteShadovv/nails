#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Tell whether a plaso timeline has an event for one on-image file, which proves
# plaso read the file system that holds it. run-scan.sh asks about the canary's
# file, which every image carries: plaso reads an image whose file system it
# cannot open as one opaque file and still dates that file, so a timeline that
# is merely not empty proves nothing.
#
#   timeline-has-file.sh <timeline.jsonl> <on-image-path>
#
# The timeline is psort's json_line export, one JSON object per event. An event
# read from a file system names its file in "filename", as an absolute path
# within that file system (/var/lib/x, never the path of the image itself), so a
# literal match on that key and its value needs no JSON parser. A path that JSON
# escapes (a quote, a backslash, a control or non-ASCII character) never
# matches. Exits 0 when the timeline has such an event, 1 when it has none, and
# 2 when the timeline cannot be read or the path is not absolute.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: timeline-has-file.sh <timeline.jsonl> <on-image-path>" >&2
  exit 2
fi
timeline=$1
path=$2
case $path in
  /*) ;;
  *)
    echo "timeline-has-file: not an absolute on-image path: '$path'" >&2
    exit 2
    ;;
esac

# psort writes ": " between a key and its value; the compact form counts too.
grep -qF -e "\"filename\": \"$path\"" -e "\"filename\":\"$path\"" -- "$timeline"
