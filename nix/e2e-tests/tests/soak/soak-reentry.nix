# The soft-reboot re-entry soak: one VM through many activate/deactivate cycles
# in a single boot, beside neighbour VMs that cycle on their own, so the host
# runs several soft-reboots at once. The re-entry hang was found only by paired,
# repeated activations under that kind of host load, never by a one-shot test,
# so this lane exists to keep it closed: it asserts that every re-entry reaches
# the hidden root's backdoor within the deadline and that the decoy never sees
# the hidden canary, over hundreds of cycles.
#
# It is heavy (a cycle is ~10-15 s, so the soaker alone runs well over an hour)
# and is not a gate: the `soak` tag keeps it out of `all`, the tag groups, the
# CI shards and `--affected` (see default.nix), and its own workflow runs it on
# a hosted runner weekly and before a release. Build or run it by name:
#
#   just e2e-tests run soak-reentry
#
# The stall diagnosis (a job-queue report on Alt+ArrowUp and the SysRq dumps) is
# already on every node through vm-config.nix, so a switch that never settles
# leaves its cause on the serial console before the deadline fails the test.
{
  self,
  pkgs,
  ...
}:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;

  # The soaker's cycle count: at least 500 cycles in one boot fit a single
  # hosted job (a cycle is 10 to 15 s, so about 1.4 to 2.1 hours).
  cycles = 500;

  # A re-entry that takes longer than this is the hang, not a slow host: the
  # lifecycle's generous backdoor deadline, which the stall report fires before.
  deadlineSeconds = 600;

  # How many neighbour VMs cycle beside the soaker (one or two). Each
  # self-drives a plain activate/deactivate churn so the host carries several
  # soft-reboots at once, the condition under which the hang appeared.
  neighbours = [
    "neighbourOne"
    "neighbourTwo"
  ];

  nailsPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.nails;

  # A plain decoy node: the standard VM with the nails binary, as the lifecycle
  # test's node.
  decoyNode = {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ nailsPackage ];
  };

  # A neighbour node: a decoy that, once the test arms it, performs one
  # transition on every boot. The soft-reboot that a transition enqueues ends
  # this oneshot with userspace, and the next boot runs it again, so the
  # neighbour churns on its own without the driver steering it. It is a
  # best-effort load source: every step ignores its own failure, and the test
  # asserts nothing about the neighbours, so a neighbour that falls behind only
  # lightens the host load and never fails the run.
  neighbourNode = {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ nailsPackage ];
    systemd.services.nails-soak = {
      description = "Activate/deactivate churn beside the soak, for host contention";
      # Runs on every boot, including after each soft-reboot, so one transition
      # follows another once the test arms it.
      wantedBy = [ "multi-user.target" ];
      after = [ "multi-user.target" ];
      serviceConfig.Type = "oneshot";
      path = [
        nailsPackage
        pkgs.cryptsetup
        pkgs.util-linux
        pkgs.coreutils
        pkgs.gnugrep
      ];
      script = ''
        set +e
        # Disarmed until the test has formatted the hidden volume and written
        # the marker on the decoy root (visible through the overlay in the
        # hidden session too), so the first boot before setup does nothing.
        [ -e /var/lib/nails-soak-armed ] || exit 0
        config=/mnt/data/config/nails.toml
        if findmnt -no FSTYPE / | grep -qx overlay; then
          # In the hidden root: go back to the decoy.
          nails --config "$config" deactivate -y
        else
          # On the decoy: reopen the hidden volume and enter.
          if [ ! -e /dev/mapper/data ]; then
            echo -n 'test-passphrase' \
              | cryptsetup luksOpen --key-file - /dev/disk/by-id/virtio-data data
          fi
          mkdir -p /mnt/data
          mountpoint -q /mnt/data || mount /dev/mapper/data /mnt/data
          nails --config "$config" activate -y --overlay-only
        fi
      '';
    };
  };

  nodes = {
    soaker = _: decoyNode;
  }
  // builtins.listToAttrs (
    map (name: {
      inherit name;
      value = _: neighbourNode;
    }) neighbours
  );

  neighbourList = pkgs.lib.concatMapStringsSep ", " (name: "\"${name}\"") neighbours;
in
{
  name = "soak-reentry";
  meta.tags = [ "soak" ];
  # The soaker's 500 cycles run well over an hour, and host contention slows
  # them, so the box is generous; the stall report, not this timeout, is what
  # catches a hang.
  globalTimeout = 14400;

  inherit nodes;

  testScript = _: ''
    import secrets

    from nails_e2e import session

    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    UPPER = "/mnt/data/root/upper"
    PEEK = "/run/decoy-peek"
    CYCLES = ${toString cycles}
    DEADLINE_S = ${toString deadlineSeconds}.0
    # The decoy-clean check remounts the decoy root read-only, which is too slow
    # to do every cycle; run it this often, and always on the last cycle.
    DEEP_CHECK_EVERY = 25

    neighbours = [${neighbourList}]


    def setup(node):
        """Format the hidden volume and write the headless config a cycle uses."""
        node.succeed("""${hiddenVolume.setupHiddenVolume}""")
        node.succeed("nails init /mnt/data")
        # Name the root (the binary runs from the store) and lower the space
        # floor for the test disk, as the lifecycle test does.
        node.succeed(
            f"cat > {CONFIG} <<'EOF'\n"
            'hidden_volume_root = "/mnt/data"\n'
            "minimum_space_mb = 100\n"
            "EOF"
        )


    def decoy_is_clean(node, canaries):
        """Fail if any hidden canary reached the decoy root filesystem.

        The decoy superblock is the overlay's lower and stays mounted
        read-write, so a plain read-only mount would fail with EBUSY: mount it,
        then make this mount read-only, exactly as the lifecycle test peeks."""
        decoy_dev = node.succeed("findmnt -no SOURCE /").strip()
        node.succeed(
            f"mkdir -p {PEEK} && mount {decoy_dev} {PEEK} && mount -o remount,bind,ro {PEEK}"
        )
        try:
            for canary in canaries:
                node.fail(f"test -e {PEEK}/root/{canary}")
        finally:
            node.succeed(f"umount {PEEK} && rmdir {PEEK}")


    # The driver injects each node under its name (soaker, neighbourOne, ...).
    start_all()
    for node in [soaker] + [globals()[name] for name in neighbours]:
        node.wait_for_unit("multi-user.target")

    # Arm the neighbours: format their hidden volumes, then let their boot
    # service churn on its own. --no-block so the activation it triggers (and
    # the soft-reboot with it) does not hang the driver here.
    for name in neighbours:
        neighbour = globals()[name]
        setup(neighbour)
        neighbour.succeed("touch /var/lib/nails-soak-armed")
        neighbour.execute("systemctl start --no-block nails-soak.service")

    setup(soaker)

    reached = 0
    with subtest(f"the soaker re-enters the hidden root {CYCLES} times"):
        for cycle in range(CYCLES):
            if cycle > 0:
                soaker.succeed("""${hiddenVolume.reopenHiddenVolume}""")
            # A re-entry that does not reach the backdoor within the deadline
            # fails here; the stall report has already printed the job queue.
            canonical_activate(
                CONFIG, "--overlay-only", f"soak-{cycle}", deadline_s=DEADLINE_S
            )
            session.assert_hidden_root(soaker, UPPER)
            reached += 1
            # A canary written in the hidden session must land in the upper and
            # never on the decoy disk.
            canary = "soak-" + secrets.token_hex(6)
            soaker.succeed(f"echo {canary} > /root/{canary} && sync")
            canonical_deactivate(CONFIG, f"soak-{cycle}-back")
            deep = (cycle + 1) % DEEP_CHECK_EVERY == 0 or cycle + 1 == CYCLES
            if deep:
                soaker.succeed("""${hiddenVolume.reopenHiddenVolume}""")
                assert canary in soaker.succeed(f"cat {UPPER}/{canary}"), (
                    "the hidden canary did not persist in the upper"
                )
                decoy_is_clean(soaker, [canary])
                soaker.log(f"soak cycle {cycle + 1}/{CYCLES}: re-entry and decoy clean")

    assert reached == CYCLES, f"only {reached} of {CYCLES} re-entries reached the backdoor"
    soaker.log(f"soak complete: {reached} re-entries, decoy clean")
  '';
}
