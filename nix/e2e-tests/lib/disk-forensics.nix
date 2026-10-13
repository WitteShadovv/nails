# Driver-side wiring for the host disk-image forensic helpers.
#
# `disk_forensics.py` is plain Python (its parsers are unit-tested without Nix).
# This wrapper hands the driver a snippet that points the module at the host
# forensic tools in the Nix store and imports it, plus the store path of the
# artifact-indicators fixture the scans read. Each forensic test pastes
# `pythonSetup` near the top of its testScript.
{ pkgs }:
let
  module = pkgs.writeTextDir "disk_forensics.py" (builtins.readFile ./disk_forensics.py);
in
{
  # Store path of the committed artifact-indicators registry (the single source
  # of what the disk scans must not find).
  indicatorsJson = ../fixtures/indicators.json;

  pythonSetup = ''
    import os as _nails_os
    import sys as _nails_sys

    _nails_os.environ["NAILS_QEMU_IMG"] = "${pkgs.qemu-utils}/bin/qemu-img"
    _nails_os.environ["NAILS_FLS"] = "${pkgs.sleuthkit}/bin/fls"
    _nails_os.environ["NAILS_MMLS"] = "${pkgs.sleuthkit}/bin/mmls"
    _nails_os.environ["NAILS_ICAT"] = "${pkgs.sleuthkit}/bin/icat"
    _nails_os.environ["NAILS_DEBUGFS"] = "${pkgs.e2fsprogs}/bin/debugfs"
    _nails_os.environ["NAILS_JOURNALCTL"] = "${pkgs.systemd}/bin/journalctl"

    # Import after the tool paths are set: the module reads them at import time.
    # The path is only resolvable at runtime via the insert above, so the driver's
    # static type check (ty) cannot find the module; silence its import error.
    _nails_sys.path.insert(0, "${module}")
    import disk_forensics  # ty: ignore[unresolved-import]


    def load_registry_tokens():
        import json

        with open("${../fixtures/indicators.json}", encoding="utf-8") as _fh:
            _data = json.load(_fh)
        return [artifact["image_token"] for artifact in _data["artifacts"]]
  '';
}
