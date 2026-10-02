# Backend refusal: NFS cannot host an overlayfs upper layer
#
# A network filesystem exports no trusted xattrs and no reliable readdir d_type,
# so the kernel cannot use it as an overlayfs upper. The real overlays mount only
# after the decoy session is killed, so an unusable backend discovered then is
# discovered too late. The upper-fs-capability preflight check must therefore
# refuse activation up front, before anything is mounted, naming the backend.
#
# Two nodes: `server` exports a share, `client` mounts it at the hidden root and
# attempts to activate. The activation must fail with the capability error.
# Companion to tests/preflight/24, which proves the same probe against a FAT
# upper on a single node.

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
    ${preflightHelpers.writeTextFileFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    start_all()
    server.wait_for_unit("nfs-server.service")
    server.wait_for_open_port(2049)
    client.wait_for_unit("multi-user.target")

    # The preflight helpers operate on a `machine` global; point it at the client.
    machine = client

    def write_nfs_hidden_config(path):
        write_text_file(path, """
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"

    [[overlays]]
    name = "home"
    lower = "/home"
    upper = "/mnt/data/home"
    work = "/mnt/data/.work/home"
    target = "/home"
    """.strip() + "\n")

    with subtest("mount the NFS share at the hidden root"):
        client.succeed("mkdir -p /mnt/data")
        client.wait_until_succeeds("mount -t nfs4 server:/ /mnt/data", timeout=60)
        # Confirm the hidden root really is NFS, so the refusal below is about the
        # backend and not an unrelated setup failure.
        fstype = client.succeed("findmnt -n -o FSTYPE /mnt/data").strip()
        assert fstype.startswith("nfs"), f"hidden root is {fstype!r}, expected nfs"
        client.succeed("mkdir -p /mnt/data/home /mnt/data/.work/home")

    with subtest("activation is refused with the upper-fs capability error"):
        write_nfs_hidden_config("/tmp/backend-nfs-unsuitable.toml")
        result = run_command_capture(
            "backend-nfs-unsuitable",
            "nails --config /tmp/backend-nfs-unsuitable.toml activate --overlay-only --session keep -y",
        )
        assert_command_failed(result)
        assert_result_contains(
            result,
            ["cannot host an overlayfs upper layer", "NFS"],
            stream="stderr",
        )

    with subtest("the refusal mounted no overlay"):
        # Preflight runs before any mount, so no overlay backed by the hidden root
        # may exist. Match on the upperdir to avoid a false positive if the VM's
        # own root is itself an overlay.
        client.fail("grep -q 'upperdir=/mnt/data' /proc/mounts")
        client.succeed("umount /mnt/data")
  '';
}
