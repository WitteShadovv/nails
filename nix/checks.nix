# Lint gates for `nix flake check`. Each check reads only source files, so the
# whole gate takes seconds on a warm store. The VM tests are deliberately not
# here (they live under legacyPackages.x86_64-linux.e2e), and the Rust gate
# stays cargo-native in CI.
{ pkgs, e2eMetadata }:
let
  inherit (pkgs) lib;
  fs = lib.fileset;
  root = ../.;

  nixFiles = fs.fileFilter (file: file.hasExt "nix") root;
  shellScripts = fs.fileFilter (file: file.hasExt "sh") root;
  githubDir = root + "/.github";

  # Each linter sees a writable copy of just the files it reads, so editing
  # Rust code does not rerun the Nix lint and vice versa.
  lint =
    name:
    {
      files,
      tools,
      script,
    }:
    let
      src = fs.toSource {
        inherit root;
        fileset = files;
      };
    in
    pkgs.runCommandLocal "lint-${name}" { nativeBuildInputs = tools; } ''
      cp -r --no-preserve=mode ${src} source
      cd source
      ${script}
      touch "$out"
    '';

  e2eMetadataJson = pkgs.writeText "e2e-metadata.json" (builtins.toJSON e2eMetadata);
in
{
  nixfmt = lint "nixfmt" {
    files = nixFiles;
    tools = [ pkgs.nixfmt ];
    script = "find . -type f -name '*.nix' -print0 | xargs -0 nixfmt --check";
  };

  statix = lint "statix" {
    files = nixFiles;
    tools = [ pkgs.statix ];
    script = "statix check .";
  };

  deadnix = lint "deadnix" {
    files = nixFiles;
    tools = [ pkgs.deadnix ];
    script = "deadnix --fail .";
  };

  # Same exclusions as the pre-commit hook, so both gates agree.
  shellcheck = lint "shellcheck" {
    files = shellScripts;
    tools = [ pkgs.shellcheck ];
    script = "find . -type f -name '*.sh' -print0 | xargs -0 shellcheck -e SC1091 -e SC2034";
  };

  # With shellcheck on PATH, actionlint also lints every `run:` script.
  # actionlint only resolves local actions and reusable workflows inside a
  # repository, which it recognises by a .git directory.
  actionlint = lint "actionlint" {
    files = githubDir;
    tools = [
      pkgs.actionlint
      pkgs.shellcheck
    ];
    script = ''
      mkdir .git
      actionlint
    '';
  };

  # Offline: the build sandbox has no network, and online audits would make
  # the result depend on the GitHub API. The audit policy and the findings
  # that predate this check live in .github/zizmor.yml.
  zizmor = lint "zizmor" {
    files = githubDir;
    tools = [ pkgs.zizmor ];
    script = "zizmor --offline --no-progress --color never .github";
  };

  # Validates the checked-in shard weights against the timeouts the test
  # derivations really use. Evaluating the metadata also runs the assertions
  # in nix/e2e-tests/default.nix without building any VM test.
  e2e-shard-weights = lint "e2e-shard-weights" {
    files = fs.unions [
      ../scripts/e2e_shard_weights.py
      ./e2e-tests/shard-durations.json
    ];
    tools = [ pkgs.python3 ];
    script = ''
      python3 scripts/e2e_shard_weights.py check \
        --weights nix/e2e-tests/shard-durations.json \
        --metadata ${e2eMetadataJson}
    '';
  };
}
