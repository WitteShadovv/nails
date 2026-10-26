# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# A probe boots the stock cloud image of a distribution the smoke suite does not
# admit yet (Fedora, Arch), without nails, runs the queries of
# py/probe_facts.py in it, soft-reboots it once and runs the queries that follow
# the soft-reboot. It writes the facts as <probe>.json, the record the matching
# probe/<probe>.json fixture holds (see probe/README.md), and the raw output of
# every query beside it. A probe is a host driver: a maintainer runs it on a
# KVM-capable host, or dispatches distro-e2e.yml with the probe suite, which
# runs it on a hosted KVM runner and uploads the JSON. Nothing runs a probe
# unasked.
{ pkgs, nix-vm-test }:
let
  inherit (pkgs) lib;

  images = import ./images.nix { inherit pkgs; };
  distroVm = import ./lib/distro-vm.nix { inherit pkgs nix-vm-test; };

  # The families the smoke suite does not run yet, so their facts are unknown.
  probeOsIds = [
    "fedora"
    "arch"
  ];
  probeImages = lib.filterAttrs (_: entry: builtins.elem entry.osId probeOsIds) images;

  # Fedora boots SELinux permissive as images.json pins it, which hides what
  # only an enforcing boot shows (denials, whether the 9p share still mounts,
  # what the policy load after a soft-reboot does). Each Fedora image therefore
  # also gets a "<name>-enforcing" variant. A probe is its image key and the
  # entry it boots.
  probes =
    lib.mapAttrs (image: entry: { inherit image entry; }) probeImages
    // lib.mapAttrs' (
      image: entry:
      lib.nameValuePair "${image}-enforcing" {
        inherit image;
        entry = entry // {
          enforcing = true;
        };
      }
    ) (lib.filterAttrs (_: entry: entry.osId == "fedora") probeImages);

  # The queries and their reading, alone, so that a change to the smoke
  # helpers beside them does not rebuild every probe driver.
  probeFacts = lib.fileset.toSource {
    root = ./py;
    fileset = ./py/probe_facts.py;
  };

  # The seconds a probe run gets, from the boot to the JSON, soft-reboot
  # included; a hosted run stops the driver after them.
  timeout = 1200;

  # Boot the stock image (no nails share, no activation), run the queries and
  # write the record. Every query runs in a subshell with its status discarded
  # (`( ... ) 2>&1 || true`): the host driver does not return a guest command's
  # real exit code, so a probe never trusts one; it reads stdout. The record
  # goes into the directory NAILS_PROBE_OUT names, or the one the driver runs
  # in.
  probeScript =
    name: probe:
    let
      settings = {
        inherit name;
        inherit (probe) image;
        inherit (probe.entry) osId enforcing;
        # The pinned file the facts come from, so a fixture names its pin.
        imageFile = probe.entry.source.name or probe.entry.source.asset or null;
      };
    in
    ''
      import json
      import os
      import sys

      sys.path.insert(0, "${../e2e-tests/py}")
      sys.path.insert(0, "${probeFacts}")
      from nails_e2e import session  # noqa: E402
      import probe_facts  # noqa: E402

      probe = json.loads(${builtins.toJSON (builtins.toJSON settings)})
      blocks = {}

      def dump(label, cmd):
          blocks[label] = vm.succeed("( " + cmd + " ) 2>&1 || true")
          print("=== " + label + " ===")
          print(blocks[label])

      vm.wait_for_unit("multi-user.target")
      for label, cmd in probe_facts.cold_boot_queries(probe["osId"]):
          dump(label, cmd)

      # Last, a plain soft-reboot with no NAILS involved: what fails or is
      # denied after it is what the way back meets on this image, since every
      # way back is a soft-reboot, and a cold boot cannot show it.
      vm.succeed(probe_facts.BEFORE_SOFT_REBOOT)
      session.follow_soft_reboot(vm, "systemctl soft-reboot", "probe-soft-reboot")
      vm.wait_for_unit("multi-user.target")
      for label, cmd in probe_facts.soft_reboot_queries():
          dump(label, cmd)

      record = probe_facts.record(
          blocks,
          image=probe["image"],
          os_id=probe["osId"],
          enforcing=probe["enforcing"],
          image_file=probe["imageFile"],
      )
      out_dir = os.environ.get("NAILS_PROBE_OUT") or os.getcwd()
      os.makedirs(out_dir, exist_ok=True)
      path = os.path.join(out_dir, probe["name"] + ".json")
      with open(path, "w", encoding="utf-8") as handle:
          handle.write(probe_facts.dumps(record))
      raw = os.path.join(out_dir, probe["name"] + ".raw.json")
      with open(raw, "w", encoding="utf-8") as handle:
          handle.write(probe_facts.dumps(blocks))
      print("probe facts written to " + path)
    '';

  probeFor =
    name: probe:
    distroVm.buildVmTest {
      inherit (probe) entry;
      testScript = probeScript name probe;
      memorySize = probe.entry.memory;
      target = "driver";
    };
in
{
  # Probe name -> its host driver.
  drivers = lib.mapAttrs probeFor probes;
  # The probes whose image is pinned or hosted, so that a run can boot them.
  runnable = builtins.attrNames (
    lib.filterAttrs (_: probe: distroVm.imageAvailable probe.entry) probes
  );
  inherit timeout;
}
