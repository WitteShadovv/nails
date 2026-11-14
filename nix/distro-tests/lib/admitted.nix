# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# A test-only build of the release binary in which one base row of the family
# table (nails-platform/src/platform/family.rs) is admitted, and nothing else
# changes: the scenarios a family's admission needs run on its images before
# the commit that admits it. admit-row.awk makes the change, and the build
# fails unless the row is a base row the table refuses and exactly its
# `admitted` line changes: a row already admitted, a derivative's row and an
# id the table lacks each fail it (ci/tests/test_admit_row.py runs the
# script on the table). It is never released, and what a scenario shows with
# it says what NAILS does on that family's image, not that NAILS supports the
# family.
#
# `id` is the row's os-release ID ("fedora", "arch"). A derivative of the
# family keeps its row as it is.
{ self }:
id:
assert builtins.match "[a-z0-9._-]+" id != null;
self.packages.x86_64-linux.nails.overrideAttrs (old: {
  pname = "nails-test-${id}-admitted";
  postPatch = (old.postPatch or "") + ''
    table=nails-platform/src/platform/family.rs
    if ! awk -v id='${id}' -f ${./admit-row.awk} "$table" > "$table.new"; then
      echo "the ${id} row of $table is not one refused base row of the table" >&2
      exit 1
    fi
    changed=$(diff "$table" "$table.new" | grep -c '^[<>]' || true)
    if [ "$changed" != 2 ]; then
      echo "admitting the ${id} row changed $changed lines of $table, not one" >&2
      exit 1
    fi
    mv "$table.new" "$table"
  '';
  meta = old.meta // {
    description = "nails with the ${id} row of the family table admitted, for the scenarios of its admission only; never released";
  };
})
