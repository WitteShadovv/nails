# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Admit one base row of the family table (nails-platform/src/platform/family.rs)
# for the test-only build of lib/admitted.nix, and change nothing else:
#
#   awk -v id=<os-release ID> -f admit-row.awk family.rs > family.rs.new
#
# A row of the table runs from its `    FamilyRow {` line to its `    },` line;
# the braces of an edition inside it are indented deeper, so neither line
# matches them. The row whose id line names `id` gets its one
# `admitted: false,` line made `admitted: true,`. The script exits 1, and its
# output must not be used, unless the table holds exactly one row with that id,
# the row is a base row (`kind: Kind::Base,`) and it holds exactly one
# `admitted: false,` line: a row already admitted, a derivative's row, an id
# the table lacks and a row that never closes each fail it.

BEGIN {
  want = "        id: \"" id "\","
  if (id == "") failed = 1
}

$0 == "    FamilyRow {" {
  if (inrow) failed = 1
  inrow = 1
  n = 0
}

inrow {
  row[++n] = $0
  if ($0 != "    },") next
  inrow = 0
  named = 0
  base = 0
  refused = 0
  at = 0
  for (i = 1; i <= n; i++) {
    if (row[i] == want) named++
    if (row[i] == "        kind: Kind::Base,") base = 1
    if (row[i] == "        admitted: false,") {
      refused++
      at = i
    }
  }
  if (named) {
    rows++
    if (named == 1 && base && refused == 1) {
      sub(/false/, "true", row[at])
      flipped++
    }
  }
  for (i = 1; i <= n; i++) print row[i]
  next
}

{ print }

END {
  if (inrow || failed || rows != 1 || flipped != 1) exit 1
}
