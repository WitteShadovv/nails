# Test 77: Fresh-home mode keeps the hidden session off the decoy's sync remote
#
# The mitigation for the pull-back in test 76. In fresh-home mode the hidden
# session runs from a clean home on the hidden volume, and the recommended
# posture (see the "Remote state and sync clients" limitation in the security
# guide) is that the decoy's account-bound clients do not run in the hidden
# session. Modelled here by not carrying the decoy Syncthing into the hidden
# session: the canary the hidden session writes into its fresh synced folder
# therefore never reaches the peer, and because the fresh upper is discarded on
# deactivation there is nothing for the decoy client to pull back when it resumes.
#
# Hard assertions: the peer never receives the canary, and the decoy disk image
# stays clean. Test 76 is the positive control that proves this plumbing can leak.
#
# Two nodes and disk imaging across a reboot: it must run on the Nix VM driver.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  persona = import ./../../lib/persona-helpers.nix { inherit self pkgs; };
  diskForensics = import ./../../lib/disk-forensics.nix { inherit pkgs; };
in
{
  name = "persona-fresh-home-no-sync";
  meta.tags = [ "forensic" ];

  globalTimeout = 2400;

  nodes = {
    client = persona.clientNode;
    peer = persona.peerNode;
  };

  testScript = _: ''
    ${persona.writePersonaConfigFn}
    ${persona.syncClientHelpersFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertOverlayMountedFn}
    ${diskForensics.pythonSetup}

    CLIENT_CFG = "${persona.clientConfigDir}"
    PEER_CFG = "${persona.peerConfigDir}"
    FOLDER = "${persona.syncFolderId}"
    CLIENT_SYNC = "${persona.clientSyncPath}"
    PEER_SYNC = "${persona.peerSyncPath}"
    CANARY = "fresh-home-canary.txt"
    CANARY_TOKEN = "NAILS_PERSONA_FRESHHOME_2026a"

    machine = client

    start_all()
    client.wait_for_unit("multi-user.target")
    peer.wait_for_unit("multi-user.target")

    with subtest("pair the decoy client with the peer and prove connectivity"):
        st_wait_ready(client, CLIENT_CFG)
        st_wait_ready(peer, PEER_CFG)
        client_id = st_device_id(client, CLIENT_CFG)
        peer_id = st_device_id(peer, PEER_CFG)
        st_add_device(client, CLIENT_CFG, peer_id, "peer", "tcp://peer:22000")
        st_add_folder(client, CLIENT_CFG, FOLDER, CLIENT_SYNC, peer_id)
        st_add_device(peer, PEER_CFG, client_id, "client", "tcp://client:22000")
        st_add_folder(peer, PEER_CFG, FOLDER, PEER_SYNC, client_id)
        for _ in range(60):
            if st_connected(client, CLIENT_CFG, peer_id):
                break
            time.sleep(2)
        else:
            raise Exception("client and peer never connected")
        # A baseline file syncs, so a later absence is meaningful and not just a
        # broken pairing.
        client.succeed(
            f"su - testuser -c 'echo baseline > {CLIENT_SYNC}/baseline.txt'"
        )
        st_rescan(client, CLIENT_CFG, FOLDER)
        peer.wait_until_succeeds(f"test -f {PEER_SYNC}/baseline.txt", timeout=120)

    with subtest("capture the decoy baseline image (canary absent)"):
        baseline = disk_forensics.snapshot(client, "baseline")
        assert disk_forensics.run_strings_scan(baseline, [CANARY_TOKEN]) == set(), (
            "canary token already present on the baseline image"
        )

    with subtest("the decoy sync client is not carried into the hidden session"):
        # Fresh-home's recommended posture: the account-bound client does not run
        # in the hidden session. Masking it models a user-level client that a
        # fresh home would not autostart.
        client.succeed("systemctl mask --now syncthing.service")
        client.wait_until_fails("systemctl is-active syncthing.service")

    with subtest("activate the hidden session in fresh-home mode"):
        client.succeed("""${hiddenVolume.setupHiddenVolume}""")
        config_path = "/tmp/nails-persona.toml"
        write_persona_config(config_path, mode="fresh-home")
        client.succeed(
            f"NAILS_TARGET_USER=testuser nails --config {config_path} "
            "activate --overlay-only --session keep -y"
        )
        assert_overlay_mounted("/home")
        # The fresh persona home shadows the decoy home; the decoy's synced file
        # is not visible and the fresh synced folder starts empty.
        client.fail(f"test -e {CLIENT_SYNC}/baseline.txt")

    with subtest("the hidden session writes a canary into its fresh synced folder"):
        client.succeed(f"mkdir -p {CLIENT_SYNC}")
        client.succeed(
            f"printf %s {CANARY_TOKEN} > {CLIENT_SYNC}/{CANARY}"
        )
        # It lands on the hidden volume (the persona home upper), never the decoy.
        client.succeed(f"test -f /mnt/data/persona/home/Sync/{CANARY}")

    with subtest("hard assertion: the peer never receives the canary"):
        # Give any stray push ample time to arrive, then require its absence.
        time.sleep(30)
        peer.fail(f"test -e {PEER_SYNC}/{CANARY}")

    with subtest("deactivate and let the decoy client resume"):
        canonical_deactivate(
            config_path, unit_name="nails-deactivate-persona-fresh-home"
        )
        client.fail("mount | grep 'overlay on /home'")
        client.succeed("systemctl unmask syncthing.service")
        client.succeed("systemctl start syncthing.service")
        st_wait_ready(client, CLIENT_CFG)
        st_rescan(client, CLIENT_CFG, FOLDER)
        # Nothing to pull back: the canary never reached the peer and the fresh
        # upper is gone.
        time.sleep(30)
        client.fail(f"test -e {CLIENT_SYNC}/{CANARY}")

    with subtest("hard assertion: the decoy disk image stays clean"):
        post = disk_forensics.snapshot(client, "post-deactivation", restart=False)
        hits = disk_forensics.run_strings_scan(post, [CANARY_TOKEN])
        assert hits == set(), (
            f"fresh-home must leave no canary on the decoy image, found: {hits}"
        )
  '';
}
