# Backend refusal: NFS cannot host an overlayfs upper layer
#
# A network filesystem exports no trusted xattrs and no reliable readdir d_type,
# so the kernel cannot use it as the upper of the root overlay. An unusable
# backend found while building /run/nextroot, or after the soft-reboot, is found
# too late, so the upper-fs-capability pre-flight check must refuse activation
# up front, naming the cause, and leave the machine on the plain decoy with no
# next root and no overlay.
#
# Two nodes: `server` exports a share, `client` mounts it at the hidden root and
# attempts to activate. Companion to the preflight upper-fs-capability scenario,
# which proves the same probe on a single node.

{ self, pkgs, ... }:
let
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "backend-nfs-unsuitable";
  meta.tags = [
    "preflight"
    "lifecycle"
  ];

  # A second node plus NFSv4 bring-up is slower than a single-node preflight test.
  globalTimeout = 1200;

  nodes = {
    server =
      { ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];
        # Export a share over NFSv4 (fsid=0 roots the pseudo-filesystem here, so
        # the client mounts `server:/`). `insecure` allows the client's high
        # source port; the test network is trusted, so the wide host match is
        # acceptable for a fixture.
        services.nfs.server.enable = true;
        services.nfs.server.exports = ''
          /export *(rw,no_root_squash,no_subtree_check,insecure,fsid=0)
        '';
        systemd.tmpfiles.rules = [ "d /export 0777 root root -" ];
      };

    client =
      { ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];
        environment.systemPackages = [
          self.packages.x86_64-linux.nails
          pkgs.nfs-utils
        ];
      };
  };

  testScript = _: ''
    from nails_e2e import session

    ${preflightHelpers.writeTextFileFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    start_all()
    server.wait_for_unit("nfs-server.service")
    server.wait_for_open_port(2049)
    client.wait_for_unit("multi-user.target")

    # The preflight helpers operate on a `machine` global; point it at the client.
    machine = client

    with subtest("mount the NFS share at the hidden root"):
        client.succeed("mkdir -p /mnt/data")
        client.wait_until_succeeds("mount -t nfs4 server:/ /mnt/data", timeout=60)
        # Confirm the hidden root really is NFS, so the refusal below is about the
        # backend and not an unrelated setup failure.
        fstype = client.succeed("findmnt -n -o FSTYPE /mnt/data").strip()
        assert fstype.startswith("nfs"), f"hidden root is {fstype!r}, expected nfs"
        client.succeed("mkdir -p /mnt/data/root/work /mnt/data/config")

    with subtest("activation is refused with the upper-fs capability error"):
        write_text_file(
            "/run/backend-nfs-unsuitable.toml",
            'hidden_volume_root = "/mnt/data"\nminimum_space_mb = 100\n',
        )
        result = run_command_capture(
            "backend-nfs-unsuitable",
            "nails --config /run/backend-nfs-unsuitable.toml activate -y --overlay-only",
        )
        assert_command_failed(result)
        assert_result_contains(
            result,
            ["cannot host an overlayfs upper layer", "NFS"],
            stream="stderr",
        )

    with subtest("the refusal built no next root and left the plain decoy"):
        # Pre-flight runs before /run/nextroot is built; the backdoor answering
        # here already shows no soft-reboot was started.
        session.assert_decoy_root(client)
        client.fail("grep -q 'upperdir=/mnt/data' /proc/mounts")
        client.fail("test -e /run/overlay-runtime")
        client.succeed("umount /mnt/data")
  '';
}
