# The portable distribution suites.
#
# Maps the smoke scenario over the enabled entries of the image table
# (images.nix), so every enabled entry becomes one buildable VM test plus one
# metadata record. An entry with `enabled = false` is still a full entry the
# `distro-images` check evaluates and the next package can boot, but it stays
# out of the smoke set and the CI matrix, so staging a distribution changes
# nothing that runs today; enabling it is a single flip in images.json. Debian
# 13 runs the Nix scenario among its smokes, and Debian 13 and both Ubuntu
# images the unattended-upgrades scenario. Beside the smokes are the host
# drivers: the records scenarios, the refusals of the families the family table
# does not admit, the probes and the oracle images.
{
  self,
  pkgs,
  nix-vm-test,
}:
let
  inherit (pkgs) lib;

  images = import ./images.nix { inherit pkgs; };
  enabledImages = lib.filterAttrs (_: entry: entry.enabled) images;

  distroVm = import ./lib/distro-vm.nix { inherit pkgs nix-vm-test; };
  makeSmoke = import ./tests/smoke.nix { inherit self pkgs nix-vm-test; };
  makeNixTrace = import ./tests/nix-trace.nix { inherit self pkgs nix-vm-test; };
  makeAptShutdown = import ./tests/apt-shutdown.nix { inherit self pkgs nix-vm-test; };

  # Distribution boot plus repeated disk-image conversions make a distro VM
  # slower than a single-boot NixOS test; this leaves margin on a shared runner.
  smokeTimeout = 2400;

  # distro name -> its smoke test derivation, keyed "<distro>-smoke".
  scenarioName = name: "${name}-smoke";

  tests = lib.mapAttrs' (
    name: entry: lib.nameValuePair (scenarioName name) (makeSmoke name entry)
  ) enabledImages;

  # The Nix scenario, keyed "<distro>-nix-trace": Nix installed inside a
  # hidden session leaves no trace on the decoy, and Nix installed on the decoy
  # is named by the check and found on its disk (tests/nix-trace.nix). One
  # Debian image runs it, beside its smoke, in the same CI matrix.
  nixTraceDistros = lib.filter (name: enabledImages ? ${name}) [ "debian-13" ];
  nixTraceName = name: "${name}-nix-trace";
  # Three images of the decoy and two installs of Nix next to one session.
  nixTraceTimeout = 2700;
  nixTraces = lib.listToAttrs (
    map (
      name: lib.nameValuePair (nixTraceName name) (makeNixTrace name enabledImages.${name})
    ) nixTraceDistros
  );

  # The unattended-upgrades scenario, keyed "<distro>-apt-shutdown"
  # (tests/apt-shutdown.nix): check and activate refuse during a held daily
  # unattended-upgrade run and while apt-daily.service runs before its
  # download takes the lock, each with a plain soft-reboot as the control;
  # they refuse with InstallOnShutdown on, with the line deleted after the
  # helper read it, and with a file apt refuses, each with an activation
  # under the override as the control; and they only warn of a helper stopped
  # but enabled, and of one without python3-gi. The images with
  # unattended-upgrades run it, beside their smokes, in the same CI matrix.
  aptShutdownDistros = lib.filter (name: enabledImages ? ${name}) [
    "debian-13"
    "ubuntu-24.04"
    "ubuntu-26.04"
  ];
  aptShutdownName = name: "${name}-apt-shutdown";
  # One boot, ten switches (a plain soft-reboot during each held run, then
  # four sessions in and out), and waits of up to ten minutes for each daily
  # run to reach its hold and five for it to end.
  aptShutdownTimeout = 2400;
  aptShutdowns = lib.listToAttrs (
    map (
      name: lib.nameValuePair (aptShutdownName name) (makeAptShutdown name enabledImages.${name})
    ) aptShutdownDistros
  );

  # The login- and boot-record regression scenarios, keyed "<distro>-records".
  # They are host drivers (nix-vm-test `driver`), which a CI job builds and
  # runs on its runner, so the metadata lists them apart from the smokes, for
  # the records suite of distro-e2e.yml.
  recordsSet = import ./records.nix { inherit self pkgs nix-vm-test; };
  recordsName = name: "${name}-records";
  records = lib.mapAttrs' (name: drv: lib.nameValuePair (recordsName name) drv) recordsSet.drivers;

  # Fact-capture probes for the families not admitted yet, keyed "<name>-probe".
  # Like the records scenarios they are host drivers. The metadata lists the
  # ones whose image is pinned, for a dispatch of distro-e2e.yml that runs the
  # probes.
  probeSet = import ./probe.nix { inherit pkgs nix-vm-test; };
  probeName = name: "${name}-probe";
  probes = lib.mapAttrs' (name: drv: lib.nameValuePair (probeName name) drv) probeSet.drivers;

  # The refusal of those same families, keyed "<name>-refusal": host drivers
  # too. The metadata lists the ones whose image is pinned, for the refusal
  # suite of distro-e2e.yml.
  refusalSet = import ./refusal.nix { inherit self pkgs nix-vm-test; };
  refusalName = name: "${name}-refusal";
  refusals = lib.mapAttrs' (name: drv: lib.nameValuePair (refusalName name) drv) refusalSet.drivers;

  # The real btrfs decoy images of the forensic oracle, keyed
  # "<name>-oracle-images": a host driver too, run by the oracle real-image
  # nightly and kept out of the metadata.
  oracleImages = import ./oracle-images.nix { inherit self pkgs nix-vm-test; };

  distros = builtins.attrNames enabledImages;

  # The timeout of every driver of one driver suite that a run can boot, keyed
  # by the driver's attribute.
  driverTimeouts =
    set: name: lib.listToAttrs (map (driver: lib.nameValuePair (name driver) set.timeout) set.runnable);

  metadata = {
    inherit distros;
    scenarios = lib.listToAttrs (
      map (
        name:
        lib.nameValuePair name (
          [ (scenarioName name) ]
          ++ lib.optional (builtins.elem name nixTraceDistros) (nixTraceName name)
          ++ lib.optional (builtins.elem name aptShutdownDistros) (aptShutdownName name)
        )
      ) distros
    );
    timeouts =
      lib.listToAttrs (map (name: lib.nameValuePair (scenarioName name) smokeTimeout) distros)
      // lib.listToAttrs (
        map (name: lib.nameValuePair (nixTraceName name) nixTraceTimeout) nixTraceDistros
      )
      // lib.listToAttrs (
        map (name: lib.nameValuePair (aptShutdownName name) aptShutdownTimeout) aptShutdownDistros
      )
      // driverTimeouts probeSet probeName
      // driverTimeouts recordsSet recordsName
      // driverTimeouts refusalSet refusalName;
    # Probe name -> its attribute, for every probe a run can boot.
    probes = lib.genAttrs probeSet.runnable probeName;
    # Distribution -> its records scenario's attribute.
    records = lib.genAttrs recordsSet.runnable recordsName;
    # Image name -> its refusal's attribute, for every refusal a run can boot.
    refusals = lib.genAttrs refusalSet.runnable refusalName;
  };

  # Every entry reduced to the derivation path of a minimal VM test, so the
  # `distro-images` check can force the whole table -- fetch, prepare and build,
  # for the disabled entries too -- through evaluation without building a VM.
  # A pinned Debian or Ubuntu entry resolves straight to its nix-vm-test
  # derivation; a Fedora or Arch entry resolves through the fetchurl-and-prepare
  # seam; an unpinned entry resolves to the "unavailable" placeholder.
  probeScript = "vm.wait_for_unit('multi-user.target')\n";
  imageProbes = lib.mapAttrs (
    _: entry:
    # The drvPath forces the whole seam (fetch, prepare, build) through
    # evaluation, which is the proof; discarding its string context keeps the
    # VM test from becoming a build dependency, so the check stays eval-only and
    # never tries to build a VM (or fetch a not-yet-pinned image).
    builtins.unsafeDiscardStringContext
      (distroVm.buildVmTest {
        inherit entry;
        testScript = probeScript;
        memorySize = entry.memory;
      }).drvPath
  ) images;
in
tests
// nixTraces
// aptShutdowns
// records
// probes
// refusals
// oracleImages
// {
  _metadata = metadata;
  # Plain data the `distro-images` check serialises to force evaluation of the
  # whole table and of every entry's image seam. Not read by the CI planner.
  _images = {
    table = images;
    probes = imageProbes;
  };
}
