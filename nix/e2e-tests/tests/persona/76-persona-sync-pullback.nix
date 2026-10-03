# Test 76: Remote-state pull-back through a decoy sync client (known limitation)
#
# Deactivation only discards the overlay upper dirs; it never rolls back state a
# remote already holds. In shared-home mode the decoy's Syncthing is live in the
# hidden session, so a canary written into the synced folder is pushed to the
# peer. After deactivation the decoy Syncthing resumes from its pre-activation
# local state, reconciles with the peer and pulls the canary back onto the decoy
# disk, where a post-use examiner can find it.
#
# This is asserted as the documented known limitation and doubles as a positive
# control for the fresh-home test (77): it proves the canary really does traverse
# the peer and return, so 77's clean result is meaningful. See the "Remote state
# and sync clients" limitation in docs/USER-SECURITY-GUIDE.md.
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
  name = "persona-sync-pullback";
  meta.tags = [ "forensic" ];

  # Two Syncthing nodes, a full activation cycle, a deactivation reboot and a
  # disk image of the decoy root afterwards.
  globalTimeout = 2400;

  nodes = {
    client = persona.clientNode;
    peer = persona.peerNode;
  };

  testScript = _: ''
    ${persona.writePersonaConfigFn}
    ${persona.syncClientHelpersFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertOverlayMountedFn}
    ${diskForensics.pythonSetup}

    CLIENT_CFG = "${persona.clientConfigDir}"
    PEER_CFG = "${persona.peerConfigDir}"
    FOLDER = "${persona.syncFolderId}"
    CLIENT_SYNC = "${persona.clientSyncPath}"
    PEER_SYNC = "${persona.peerSyncPath}"
    CANARY = "pullback-canary.txt"
    CANARY_TOKEN = "NAILS_PERSONA_PULLBACK_2026a"

    # The persona tests drive a `client` and a `peer`; the shared helpers and the
    # canonical-deactivate helper operate on a `machine` global, so point it at
    # the decoy client.
    machine = client

    start_all()
    client.wait_for_unit("multi-user.target")
    peer.wait_for_unit("multi-user.target")

    with subtest("pair the decoy client with the peer"):
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

    with subtest("sanity: a pre-activation file syncs to the peer"):
        client.succeed(
            f"su - testuser -c 'echo baseline > {CLIENT_SYNC}/baseline.txt'"
        )
        st_rescan(client, CLIENT_CFG, FOLDER)
        peer.wait_until_succeeds(
            f"test -f {PEER_SYNC}/baseline.txt", timeout=120
        )

    with subtest("capture the decoy baseline image (canary absent)"):
        baseline = disk_forensics.snapshot(client, "baseline")
        assert disk_forensics.run_strings_scan(baseline, [CANARY_TOKEN]) == set(), (
            "canary token already present on the baseline image"
        )
        st_wait_ready(client, CLIENT_CFG)

    with subtest("activate the hidden session in shared-home mode"):
        client.succeed("""${hiddenVolume.setupHiddenVolume}""")
        config_path = "/tmp/nails-persona.toml"
        write_persona_config(config_path, mode="shared-home")
        client.succeed(
            f"NAILS_TARGET_USER=testuser nails --config {config_path} "
            "activate --overlay-only --session keep -y"
        )
        assert_overlay_mounted("/home")

    with subtest("the hidden session writes a canary into the synced folder"):
        # The new file lands on the overlay upper (the hidden volume), not the
        # decoy lower; the decoy Syncthing still pushes it to the peer.
        client.succeed(
            f"su - testuser -c 'printf %s {CANARY_TOKEN} > {CLIENT_SYNC}/{CANARY}'"
        )
        client.succeed(f"test -f /mnt/data/home/testuser/Sync/{CANARY}")
        st_rescan(client, CLIENT_CFG, FOLDER)

    with subtest("the canary reaches the peer"):
        peer.wait_until_succeeds(
            f"grep -q {CANARY_TOKEN} {PEER_SYNC}/{CANARY}", timeout=180
        )

    with subtest("deactivate: the overlay upper is discarded"):
        canonical_deactivate(config_path, unit_name="nails-deactivate-persona-pullback")
        client.fail("mount | grep 'overlay on /home'")
        # The hidden upper is detached; the decoy home has no canary yet.
        client.fail(f"test -e {CLIENT_SYNC}/{CANARY}")

    with subtest("known limitation: the decoy client pulls the canary back"):
        st_wait_ready(client, CLIENT_CFG)
        st_rescan(client, CLIENT_CFG, FOLDER)
        client.wait_until_succeeds(
            f"grep -q {CANARY_TOKEN} {CLIENT_SYNC}/{CANARY}", timeout=240
        )
        print(
            "KNOWN LIMITATION: hidden-session data pushed through the decoy sync "
            "client was pulled back onto the decoy disk after deactivation."
        )

    with subtest("the pulled-back canary is visible on the decoy disk image"):
        post = disk_forensics.snapshot(client, "post-deactivation", restart=False)
        hits = disk_forensics.run_strings_scan(post, [CANARY_TOKEN])
        assert CANARY_TOKEN in hits, (
            "expected the pulled-back canary on the decoy image; this is the "
            "documented remote-state limitation and the control for test 77"
        )
  '';
}
