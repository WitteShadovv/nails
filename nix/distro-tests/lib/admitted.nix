# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# A test-only build of the release binary in which one base row of the family
# table (nails-platform/src/platform/family.rs) is admitted, and nothing else
# changes: the scenarios a family's admission needs run on its images before
# the commit that admits it. The build fails unless exactly that one row
# changes. It is never released, and what a scenario shows with it says what
# NAILS does on that family's image, not that NAILS supports the family.
#
# `id` is the row's os-release ID ("fedora", "arch"). A derivative of the
# family keeps its row as it is.
{ self }:
id:
self.packages.x86_64-linux.nails.overrideAttrs (old: {
  pname = "nails-test-${id}-admitted";
  postPatch = (old.postPatch or "") + ''
    table=nails-platform/src/platform/family.rs
    awk -v id='        id: "${id}",' '
      $0 == id { row = 1 }
      row && /^        admitted: false,$/ { sub(/false/, "true"); row = 0; flipped++ }
      { print }
      END { if (flipped != 1) exit 1 }
    ' "$table" > "$table.new" || {
      echo "the ${id} row of $table did not change exactly once" >&2
      exit 1
    }
    mv "$table.new" "$table"
  '';
  meta = old.meta // {
    description = "nails with the ${id} row of the family table admitted, for the scenarios of its admission only; never released";
  };
})
