# Contract: the help and version surface never leaks internal commands.
#
# cli_contract.rs already snapshots every command's --help without a VM, so this
# test does not re-pin the wording. It guards the one property those snapshots
# cannot assert as a whole: that nothing a user can reach from `--help`, `-h` or
# `--version` ever names an internal-only command. The watcher and the
# notification dispatcher are started by the tool itself and must stay hidden; if
# a future refactor drops a `hide = true` they would surface in public help, and
# only an end-to-end sweep over every public command catches that. The run also
# confirms the workflow preamble, the EXIT STATUS table and the per-command
# EXAMPLES sections actually render in a real install.

_:
let
  # Internal commands that are runnable but marked `hide = true`. None of these
  # tokens may appear in any help or version output a user can reach.
  hiddenTokens = [
    "notify-dispatch"
    "watch"
  ];

  # Every command the public help promises. Each one's long help must render an
  # EXAMPLES section.
  publicCommands = [
    "init"
    "check"
    "activate"
    "deactivate"
    "emergency"
    "recover"
    "status"
    "verify"
    "reapply"
    "reset-upper"
    "config"
  ];
in
{
  name = "help-version-no-leak";
  meta.tags = [
    "smoke"
    "contract"
  ];

  testScript = _: ''
    hidden_tokens = ${builtins.toJSON hiddenTokens}
    public_commands = ${builtins.toJSON publicCommands}


    def capture(label, command):
        # Help and version exit 0; capture stdout and stderr together so a token
        # that slipped onto either stream is caught.
        output = machine.succeed(f"nails {command} 2>&1")
        for token in hidden_tokens:
            assert token not in output, (
                f"{label}: internal command token {token!r} leaked into public "
                f"output:\n{output}"
            )
        return output


    with subtest("boot the plain install"):
        machine.start()
        machine.wait_for_unit("multi-user.target")

    with subtest("root help omits internal commands and renders its sections"):
        for flag in ("--help", "-h"):
            root = capture(f"root {flag}", flag)
            # The command list names every public command and nothing hidden.
            for command in public_commands:
                assert command in root, (command, root)
        long_help = capture("root --help", "--help")
        assert "full path from the mounted volume" in long_help, long_help
        assert "The workflow has four steps" in long_help, long_help
        assert "EXIT STATUS:" in long_help, long_help

    with subtest("version prints only the name and semver, no paths or host"):
        version = capture("--version", "--version").strip()
        assert version.startswith("nails "), version
        # A leaked install path or hostname would carry a separator; the version
        # line is just "nails X.Y.Z".
        assert "/" not in version, version
        assert "\n" not in version, version
        host = machine.succeed("hostname").strip()
        assert host not in version, (host, version)

    with subtest("every public command's long help renders EXAMPLES, none leak"):
        for command in public_commands:
            help_text = capture(f"{command} --help", f"{command} --help")
            assert "EXAMPLES:" in help_text, (command, help_text)

    with subtest("hidden commands still run, they are only absent from help"):
        # Being hidden is a help-surface property, not a removal: the dispatcher
        # must still be invokable (its own --help resolves).
        for token in hidden_tokens:
            machine.succeed(f"nails {token} --help >/dev/null 2>&1")

    print("\n=== help/version no-leak contract passed ===")
  '';
}
