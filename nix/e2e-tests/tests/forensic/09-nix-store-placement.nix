# Test 09: Hidden-session Nix store writes land on the hidden volume, not the decoy
#
# The forensic profile gives the decoy an on-disk, imageable Nix store (a store
# image plus an on-disk writable layer) and a persistent journal. In the
# whole-root session the decoy store is a separate filesystem, so the fstab
# policy overlays it with an upper on the hidden volume at
# /mnt/data/root/mounts/nix-store/upper (on a VM whose store is part of the
# root filesystem it is the root upper, /mnt/data/root/upper/nix/store).
#
# In the hidden session the test realises two run-unique store paths through
# the hidden nix-daemon: `nix store add` of a nonce file and a
# `builtins.toFile` evaluation. Both must exist in the hidden session and
# live in a store upper on the hidden volume. After `nails deactivate` the
# paths must not resolve on the decoy, and the powered-off decoy image must
# carry no trace of the nonce: not in the fls listing (deleted entries
# included), not in the raw image bytes, and not among the paths registered in
# the decoy store's db.sqlite.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  diskForensics = import ./../../lib/disk-forensics.nix { inherit pkgs; };
in
{
  name = "nix-store-placement";
  meta.tags = [ "forensic" ];

  # Two soft-reboots, store writes through the daemon, then a power-off and an
  # image of the decoy root; the imaging dominates the runtime.
  globalTimeout = 1800;

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/forensic-vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      };
  };

  testScript = _: ''
    import secrets

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${diskForensics.pythonSetup}

    from nails_e2e import session

    NIX = "nix --extra-experimental-features nix-command"
    # Where a hidden store write can land on the hidden volume: the overlay
    # over a separate decoy store filesystem, or the root upper when the store
    # is part of the root filesystem.
    STORE_UPPERS = [
        "/mnt/data/root/mounts/nix-store/upper",
        "/mnt/data/root/upper/nix/store",
    ]

    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("prepare the hidden volume and enter the hidden session"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        # The configuration lives on the hidden volume: nothing of it may reach
        # the decoy image this test inspects.
        config_path = "/mnt/data/config/nails.toml"
        write_headless_config(config_path)
        canonical_activate(
            config_path, "--overlay-only --accept-persistent-decoy", "activate"
        )
        session.assert_hidden_root(machine)

    nonce_id = secrets.token_hex(16)
    nonce_token = f"NAILS_STORE_NONCE_{nonce_id}"

    def landed_in(store_path):
        base = store_path.rsplit("/", 1)[-1]
        for upper in STORE_UPPERS:
            if machine.execute(f"test -e {upper}/{base}")[0] == 0:
                return upper
        return None

    with subtest("hidden store writes through the daemon land on the hidden volume"):
        machine.succeed("systemctl start nix-daemon.socket")
        # (1) nix store add of a nonce file. The source file is on the hidden
        # volume, so only a store-write leak can bring the nonce to the decoy.
        probe_file = f"/mnt/data/nonce-{nonce_id}"
        machine.succeed(
            f"printf '%s hidden-session store write\\n' {nonce_token} > {probe_file}"
        )
        added = machine.succeed(f"{NIX} store add --store daemon {probe_file}").strip()
        # (2) a builtins.toFile evaluation, realised by the daemon.
        expr = (
            f'builtins.toFile "nonce-{nonce_id}-decl" "{nonce_token} declarative body"'
        )
        decl = machine.succeed(
            f"{NIX} eval --store daemon --raw --expr '{expr}'"
        ).strip()
        for path in (added, decl):
            assert path.startswith("/nix/store/"), path
            machine.succeed(f"grep -q {nonce_token} {path}")
            upper = landed_in(path)
            assert upper is not None, (
                f"{path} is not in a store upper on the hidden volume; uppers: "
                + machine.succeed("ls -d /mnt/data/root/upper/nix /mnt/data/root/mounts/* 2>&1 || true")
            )
            machine.log(f"{path} landed in {upper}")
        machine.succeed("sync")

        # The run-unique tokens that must never reach the decoy root disk: the
        # content nonce and the hash-and-name of each store path.
        nonce_tokens = [
            nonce_id,
            nonce_token,
            added.rsplit("/", 1)[-1],
            decl.rsplit("/", 1)[-1],
        ]

    with subtest("deactivate: the paths are absent from the decoy store"):
        canonical_deactivate(config_path, "deactivate")
        for path in (added, decl):
            machine.fail(f"test -e {path}")
            machine.fail(f"nix-store --check-validity {path}")

    with subtest("the powered-off decoy image carries no trace of the nonce"):
        post = disk_forensics.snapshot(machine, "post-nix-store-placement", restart=False)
        offset = disk_forensics.partition_offset(post)

        post_fls = disk_forensics.fls_paths(disk_forensics.run_fls(post, offset))
        fls_hits = sorted(
            name for name in post_fls if any(tok in name for tok in nonce_tokens)
        )
        assert not fls_hits, f"fls found nonce-named entries on the decoy image: {fls_hits}"

        string_hits = disk_forensics.run_strings_scan(post, nonce_tokens)
        assert not string_hits, f"strings found nonce content on the decoy image: {sorted(string_hits)}"

        store_hits = disk_forensics.run_store_scan(post, nonce_tokens, offset=offset)
        assert not store_hits, (
            f"the decoy store DB registered a hidden-session path: {sorted(store_hits)}"
        )
        print("decoy image clean of the hidden-session store paths")
  '';
}
