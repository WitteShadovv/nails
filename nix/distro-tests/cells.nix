# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Research only (a branch that is never merged): the SELinux cells of an
# enforcing Fedora image, keyed "<cell>-cell".
#
# A cell runs NAILS on a Fedora Cloud image booted with SELinux enforcing,
# with one way of starting the RAM copy of the binary in the units that run
# it (the research build reads it from /run/dsx/dsxcell):
#
#   none     the start command names the copy, as the shipped units do;
#   env      the copy starts through /usr/bin/env, which PID 1 makes a domain
#            transition on;
#   context  the unit sets SELinuxContext= to the unconfined service domain.
#
# Each mechanism also runs with the policy's dontaudit rules removed
# (semodule -DB, which rebuilds the policy store of the test VM only), so a
# denial a dontaudit rule hides is counted too: "<image>-enforcing-<mechanism>"
# keeps the rules, "...-noda" removes them.
#
# py/cells_driver.py runs the flows (a plain soft-reboot as the control, an
# entry with a command in the session and deactivate, an entry ended by the
# emergency), marks every step in the kernel log, reads it whole after each,
# and writes <cell>.json, <cell>.raw.json and <cell>.kmsg.txt into the
# directory NAILS_CELL_OUT names.
#
# Fedora is not admitted: like the oracle images, the cells run a test-only
# build of the binary with the one Fedora row of the family table admitted.
{
  self,
  pkgs,
  nix-vm-test,
}:
let
  inherit (pkgs) lib;

  images = import ./images.nix { inherit pkgs; };
  distroVm = import ./lib/distro-vm.nix { inherit pkgs nix-vm-test; };
  hiddenRoot = import ./lib/hidden-root.nix;

  # The research build with the Fedora base row admitted, for the cells only.
  # The build fails unless exactly that one row changes.
  nailsFedoraAdmitted = self.packages.x86_64-linux.nails.overrideAttrs (old: {
    pname = "nails-research-fedora-admitted";
    postPatch = (old.postPatch or "") + ''
      table=nails-platform/src/platform/family.rs
      awk '
        /^        id: "fedora",$/ { row = 1 }
        row && /^        admitted: false,$/ { sub(/false/, "true"); row = 0; flipped++ }
        { print }
        END { if (flipped != 1) exit 1 }
      ' "$table" > "$table.new" || {
        echo "the Fedora row of $table did not change exactly once" >&2
        exit 1
      }
      mv "$table.new" "$table"
    '';
    meta = old.meta // {
      description = "nails research build with the Fedora row admitted, for the SELinux cells only; never released";
    };
  });

  # The helpers alone, so a change elsewhere in py/ does not rebuild a cell.
  cellsPy = lib.fileset.toSource {
    root = ./py;
    fileset = lib.fileset.unions [
      ./py/selinux_cells.py
      ./py/cells_driver.py
    ];
  };

  fedoraImages = lib.filterAttrs (
    _: entry: entry.osId == "fedora" && distroVm.imageAvailable entry
  ) images;

  mechanisms = [
    "none"
    "env"
    "context"
  ];

  # Cell name -> { image, entry, mechanism, dontaudit }.
  cells = lib.listToAttrs (
    lib.concatMap (
      image:
      lib.concatMap (
        mechanism:
        map
          (
            dontaudit:
            lib.nameValuePair
              "${image}-enforcing-${mechanism}${lib.optionalString (dontaudit == "off") "-noda"}"
              {
                inherit image mechanism dontaudit;
                entry = fedoraImages.${image} // {
                  enforcing = true;
                };
              }
          )
          [
            "on"
            "off"
          ]
      ) mechanisms
    ) (builtins.attrNames fedoraImages)
  );

  # A run: three switches and two sessions, a policy rebuild in the -noda
  # cells, the kernel log read whole at every step.
  timeout = 3000;

  cellFor =
    name: cell:
    let
      settings = {
        inherit name;
        inherit (cell) image mechanism dontaudit;
        inherit (cell.entry) osId release;
      };
      scripts = {
        amnesic = hiddenRoot.makeDecoyAmnesic;
        setup_hidden_root = hiddenRoot.setupHiddenRoot;
      };
    in
    distroVm.buildVmTest {
      inherit (cell) entry;
      target = "driver";
      sharedDirs.tools = {
        source = "${nailsFedoraAdmitted}/bin";
        target = "/run/tools";
      };
      memorySize = cell.entry.memory;
      testScript = ''
        import json
        import sys

        sys.path.insert(0, "${../e2e-tests/py}")
        sys.path.insert(0, "${cellsPy}")
        from nails_e2e import session  # noqa: E402
        import cells_driver  # noqa: E402

        cells_driver.run(
            vm,
            session,
            json.loads(${builtins.toJSON (builtins.toJSON settings)}),
            json.loads(${builtins.toJSON (builtins.toJSON scripts)}),
        )
      '';
    };
in
{
  # The binary every cell shares, for a run to build once before the cells.
  nails = nailsFedoraAdmitted;
  # Cell name -> its host driver.
  drivers = lib.mapAttrs cellFor cells;
  # Every cell can boot: only pinned images make cells.
  runnable = builtins.attrNames cells;
  inherit timeout;
}
