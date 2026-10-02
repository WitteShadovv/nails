# Test 23: Preflight Mount Namespace

{ self, pkgs, ... }:
let
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-mount-namespace";
  meta.tags = [
    "preflight"
    "smoke"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.e2fsprogs
        pkgs.util-linux
      ];
    };

  testScript = _: ''
    ${preflightHelpers.writeTextFileFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    def write_hidden_config(path):
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

    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("activation in a private mount namespace is refused before mounting"):
        # A real ext4 hidden volume so the namespace check is the decisive
        # failure rather than an unrelated storage check.
        machine.succeed(
                "bash -lc 'truncate -s 128M /tmp/hidden.img && mkfs.ext4 -q /tmp/hidden.img && mkdir -p /mnt/data && mount -o loop /tmp/hidden.img /mnt/data'"
            )
        write_hidden_config("/tmp/preflight-mount-namespace.toml")

        result = run_command_capture(
            "preflight-mount-namespace",
            "unshare -m nails --config /tmp/preflight-mount-namespace.toml activate --overlay-only --session keep -y",
        )
        assert_command_failed(result)
        assert_result_contains(
            result,
            ["private mount namespace", "unshare -m"],
            stream="stderr",
        )

        # Preflight failed, so no overlay was stacked on the decoy /home.
        machine.fail("findmnt --noheadings --types overlay /home")

        machine.succeed("umount /mnt/data")
  '';
}
