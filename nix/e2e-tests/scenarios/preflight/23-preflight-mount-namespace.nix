# Scenario `preflight-mount-namespace` of the `preflight-hidden-root` batch:
#   tests/preflight/13-preflight-hidden-root.nix
# Formerly the stand-alone test
#   tests/preflight/23-preflight-mount-namespace.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix);
# its subtests and assertions are unchanged.
#
# Test 23: Preflight Mount Namespace

_:
let
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
  baseOs = import ./../../lib/base-os-overlays.nix;
in
{
  name = "preflight-mount-namespace";
  tags = [
    "preflight"
    "smoke"
  ];

  helpers = [
    preflightHelpers.writeTextFileFn
    preflightHelpers.runCommandCaptureFn
    preflightHelpers.commandAssertionsFn
  ];

  script = ''
    def scenario_preflight_mount_namespace() -> None:
        def write_hidden_config(path):
            write_text_file(path, """
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"

    ${baseOs.toml}
    [[overlays]]
    name = "home"
    lower = "/home"
    upper = "/mnt/data/home"
    work = "/mnt/data/.work/home"
    target = "/home"
    """.strip() + "\n")

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
