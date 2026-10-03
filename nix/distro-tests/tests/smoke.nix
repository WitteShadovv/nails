# The portable smoke scenario, generated once per distribution.
#
# nix/distro-tests/default.nix maps this function over the image table, so every
# distribution runs the same lifecycle on the NixOS test driver through
# nix-vm-test. The scenario proves the overlay-only backend end to end on a
# non-NixOS host and -- the point of a VM tier over a container one -- that a
# hidden-session write cannot reach the decoy's read-only system trees.
#
# The host-side disk-image forensic scanners are shared verbatim with the NixOS
# suite (nix/e2e-tests/lib/disk_forensics.py): they run on the NixOS test driver,
# not in the guest, so they are distribution-agnostic.
{
  self,
  pkgs,
  nix-vm-test,
}:
let
  distroVm = import ../lib/distro-vm.nix { inherit pkgs nix-vm-test; };
  hiddenRoot = import ../lib/hidden-root.nix;
  diskForensics = import ../../e2e-tests/lib/disk-forensics.nix { inherit pkgs; };

  # The canonical static musl binary, the exact artifact a user installs.
  inherit (self.packages.x86_64-linux) nails;
in
# `entry` is one value from images.nix.
entry:
distroVm.buildVmTest {
  inherit entry;

  # The binary is exposed read-only under /mnt and invoked by absolute path, so
  # it is never one of the trees the overlay freezes -- the /usr write assertion
  # below stays about the decoy system, not about reaching our own binary.
  sharedDirs."nails-bin" = {
    source = "${nails}/bin";
    target = "/mnt/nails-bin";
  };

  testScript = ''
    import shlex

    ${diskForensics.pythonSetup}

    nails = "/mnt/nails-bin/nails"
    config = "/run/nails-smoke.toml"


    def write_config():
        # Overlay every base-OS tree that must be isolated on an FHS host. /usr,
        # /bin and /lib are core binary roots the writable-trees preflight refuses
        # to leave writable, so they are overlaid just as auto mode would.
        machine.succeed("mkdir -p /run")
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "skip"

    [[overlays]]
    name = "home"
    lower = "/home"
    upper = "/mnt/data/home"
    work = "/mnt/data/.work/home"
    target = "/home"

    [[overlays]]
    name = "etc"
    lower = "/etc"
    upper = "/mnt/data/etc"
    work = "/mnt/data/.work/etc"
    target = "/etc"

    [[overlays]]
    name = "srv"
    lower = "/srv"
    upper = "/mnt/data/srv"
    work = "/mnt/data/.work/srv"
    target = "/srv"

    [[overlays]]
    name = "opt"
    lower = "/opt"
    upper = "/mnt/data/opt"
    work = "/mnt/data/.work/opt"
    target = "/opt"

    [[overlays]]
    name = "var"
    lower = "/var"
    upper = "/mnt/data/var"
    work = "/mnt/data/.work/var"
    target = "/var"

    [[overlays]]
    name = "tmp"
    lower = "/tmp"
    upper = "/mnt/data/tmp"
    work = "/mnt/data/.work/tmp"
    target = "/tmp"

    [[overlays]]
    name = "usr"
    lower = "/usr"
    upper = "/mnt/data/usr"
    work = "/mnt/data/.work/usr"
    target = "/usr"
    EOF""" % shlex.quote(config)
        )


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed(f"test -x {nails}")

    with subtest("platform detection selects the overlay-only Debian-family backend"):
        # `nails init` reports the detected host. A supported FHS host (Debian or
        # Ubuntu) has no NixOS config layer, so init prints the overlay-only skip
        # note naming the host id -- proof the Debian-family backend was chosen
        # and not NixOS or the unsupported refusal path.
        init_out = machine.succeed(f"{nails} init /root/nails-base 2>&1")
        assert "overlay-only" in init_out, (
            f"expected the overlay-only backend to be selected, got: {init_out}"
        )

    with subtest("decoy-persistence preflight refuses a persistent journal"):
        # A stock cloud image keeps a persistent journal, which the preflight
        # refuses by design. The check is read-only, so a refusal is a non-zero
        # exit, not a side effect.
        refusal = machine.fail(f"{nails} --config {config} check --overlay-only 2>&1")
        assert "journal" in refusal.lower() or "persist" in refusal.lower(), (
            f"expected a decoy-persistence refusal, got: {refusal}"
        )
        # Accepting the risk explicitly, or switching journald to volatile, both
        # make the check pass; the suite exercises the real fix.
        machine.succeed("""${hiddenRoot.makeJournalVolatile}""")
        machine.succeed(f"{nails} --config {config} check --overlay-only")

    with subtest("overlay-only activation isolates the writable trees"):
        machine.succeed("""${hiddenRoot.setupHiddenRoot}""")
        write_config()
        machine.succeed(f"{nails} --config {config} activate --overlay-only --session keep -y")

        for tree in ("home", "etc", "srv", "opt", "var", "tmp", "usr"):
            mounts = machine.succeed("mount")
            assert f"overlay on /{tree}" in mounts, f"/{tree} is not overlaid"

        # Canaries written through the overlay land on the hidden root, never the
        # decoy disk; the forensic scan below proves they do not leak.
        for tree in ("home", "etc", "srv", "opt", "var", "tmp"):
            machine.succeed(f"echo NAILS_CANARY_{tree} > /{tree}/nails-canary-{tree}")

    with subtest("writes under /usr and /usr/local fail on the read-only system"):
        # The core binary roots are isolated: a hidden-session write there must
        # fail, or it would reach the decoy disk. EROFS is the expected errno.
        usr_err = machine.fail("touch /usr/nails-should-fail 2>&1")
        local_err = machine.fail("touch /usr/local/nails-should-fail 2>&1")
        for err in (usr_err, local_err):
            assert "read-only" in err.lower() or "erofs" in err.lower(), (
                f"expected a read-only-filesystem error, got: {err}"
            )

    with subtest("status, verify and emergency operate on the active session"):
        machine.succeed(f"{nails} status")
        machine.succeed(f"{nails} verify")
        # Emergency starts immediately; a countdown is opt-in.
        machine.succeed(f"{nails} emergency")

    with subtest("deactivation with a reboot restores the decoy"):
        # Re-activate so deactivate has a session to restore, then deactivate and
        # let it reboot. After the reboot no overlay is mounted.
        machine.succeed("""${hiddenRoot.setupHiddenRoot}""")
        machine.succeed(f"{nails} --config {config} activate --overlay-only --session keep -y")
        machine.succeed(f"{nails} deactivate -y || true")
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        assert "overlay on /home" not in machine.succeed("mount"), (
            "an overlay survived the reboot"
        )

    with subtest("negative control: a writable /usr is caught"):
        # Proves the /usr assertion above is real: with no overlay on /usr a
        # write succeeds, so the assertion would have failed had isolation failed.
        machine.succeed("touch /usr/nails-negative-control && rm -f /usr/nails-negative-control")

    with subtest("decoy disk-image leak check: no hidden canaries, positive control caught"):
        registry_tokens = load_registry_tokens()
        canary_tokens = [f"NAILS_CANARY_{tree}" for tree in
                         ("home", "etc", "srv", "opt", "var", "tmp")]

        # Null control: image the decoy root and prove no canary or registry
        # token leaked onto it. snapshot() power-cycles the machine.
        clean = disk_forensics.snapshot(machine, "clean", restart=False)
        leaked = disk_forensics.run_strings_scan(clean, canary_tokens + registry_tokens)
        assert not leaked, f"decoy disk leaked hidden tokens: {sorted(leaked)}"

        # Positive control: a token written straight onto the decoy root (no
        # overlay) must be found, so a scanner that silently finds nothing fails.
        machine.start()
        machine.wait_for_unit("multi-user.target")
        poison = "NAILS_POSCTL_distro"
        machine.succeed(f"printf '%s\\n' {poison} > /var/tmp/{poison} || true")
        # /var/tmp is outside any overlay once deactivated, so this is a real
        # decoy-disk write.
        machine.succeed("sync")
        positive = disk_forensics.snapshot(machine, "positive", restart=False)
        found = disk_forensics.run_strings_scan(positive, [poison])
        assert found == {poison}, (
            f"positive control failed: the scanner did not see the planted token ({found})"
        )
  '';
}
