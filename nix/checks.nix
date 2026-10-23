# Lint gates for `nix flake check`. Each check reads only source files, so the
# whole gate takes seconds on a warm store. The VM tests are deliberately not
# here (they live under legacyPackages.x86_64-linux.e2e), and the Rust gate
# stays cargo-native in CI.
{
  pkgs,
  nails,
  e2eMetadata,
  distroImages,
}:
let
  inherit (pkgs) lib;
  fs = lib.fileset;
  root = ../.;

  # The Python that pyproject.toml targets, the same as the dev shell's.
  python = pkgs.python314;

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

  # The whole distribution table, and the derivation path of a minimal VM test
  # for every entry, serialised to one file. Writing it forces evaluation of
  # each entry (the schema assertions in images.nix) and of each entry's image
  # seam -- the hash-pinned fetch and nix-vm-test prepare for Fedora and Arch
  # among them -- so a malformed entry or a broken seam fails here, at eval,
  # with no VM built. The Debian and Ubuntu derivations are evaluated but not
  # rebuilt, which is what keeps them byte-identical across this change.
  distroImagesJson = pkgs.writeText "distro-images.json" (builtins.toJSON distroImages);
in
{
  distro-images = pkgs.runCommandLocal "distro-images" { } ''
    cp ${distroImagesJson} "$out"
  '';

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

  # Link-check the Markdown docs and reject retired names. A link can point at
  # any file in the tree, so the whole source is the input rather than a minimal
  # fileset; the check is offline and takes seconds. The script walks the files
  # with `find` here because the build sandbox has no `.git`. lychee builds its
  # HTTP client even with `--offline`, and that needs a CA bundle; the sandbox
  # has none.
  docs-check = lint "docs-check" {
    files = root;
    tools = [
      pkgs.lychee
      pkgs.bash
    ];
    script = "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt bash scripts/docs-check.sh";
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

  # The binary's source must hold only what cargo reads (sourceFiles in
  # flake.nix): any other file would rebuild it, and rerun every VM test, on
  # unrelated edits.
  nails-source = pkgs.runCommandLocal "nails-source" { } ''
    actual=$(cd ${nails.src} && LC_ALL=C ls -A)
    expected=$(printf '%s\n' .cargo Cargo.lock Cargo.toml nails-api nails-base nails-cli nails-core nails-forensics nails-oracle nails-platform nails-session nails-teardown rust-toolchain.toml)
    if [ "$actual" != "$expected" ]; then
      printf 'nails source holds:\n%s\nexpected exactly:\n%s\n' "$actual" "$expected" >&2
      exit 1
    fi
    touch "$out"
  '';

  # The released binary must carry none of the test-only hook strings: the
  # test-detection env vars, the reboot/systemctl path overrides, the
  # unsafe-ops opt-in, the build-directory heuristic or the backdoor
  # exemption. They compile only under the non-default `test-hooks` feature,
  # which the release build never enables; this asserts it over the shipped
  # artifact (the `nails-e2e` package carries them on purpose and is not
  # checked here).
  nails-release-hygiene = pkgs.runCommandLocal "nails-release-hygiene" { } ''
    forbidden='NAILS_TEST_|NAILS_SYSTEMCTL_PATH|NAILS_REBOOT_PATH|NAILS_SYSTEMD_RUN_PATH|NAILS_UNSAFE_REAL_OPS|/target/debug|/target/release|llvm-cov-target|backdoor'
    if LC_ALL=C grep -a -E -q "$forbidden" ${nails}/bin/nails; then
      echo "release binary contains test-only hook strings:" >&2
      LC_ALL=C grep -a -E -o "$forbidden" ${nails}/bin/nails | sort -u >&2 || true
      exit 1
    fi
    touch "$out"
  '';

  # The cheap Python gate: the ci/ package's unittest suite, ruff and a
  # non-strict mypy, exactly what `just ci-python` runs locally. It is seconds,
  # not the VM tests. The stand-alone scripts/ are not covered yet; they join
  # once the forensics runners that still fail ruff are removed.
  #
  # The suite also reads the repository data its tooling validates, so the
  # fileset carries those inputs: deny.toml (the advisory-ignore config),
  # docs/ci.md plus .github/workflows (the workflow-documentation check), the
  # root Cargo.toml (the workspace members the path filters must cover), and
  # the E2E metadata sources the shard planner's tests scan (default.nix, the
  # tests tree and the checked-in weights) and the helper library and batched
  # scenarios the E2E synchronisation lint scans. git is a tool because
  # changes.py shells out to it and its tests build throwaway repositories, and
  # e2fsprogs because the oracle's free-space planting is tested on ext4
  # images it makes and checks.
  ci-python = lint "ci-python" {
    files = fs.unions [
      ../ci
      ../pyproject.toml
      ../deny.toml
      ../Cargo.toml
      ../docs/ci.md
      ../.github/workflows
      ./distro-tests/images.json
      ./e2e-tests/default.nix
      ./e2e-tests/lib
      ./e2e-tests/tests
      ./e2e-tests/scenarios
      ./e2e-tests/shard-durations.json
    ];
    tools = [
      python
      pkgs.ruff
      pkgs.mypy
      pkgs.git
      pkgs.e2fsprogs
    ];
    script = ''
      # ruff and mypy write their caches under HOME; the copied source is the
      # only writable tree in the build sandbox.
      export HOME="$PWD"
      python3 -m unittest discover -s ci/tests -t .
      ruff check ci
      mypy ci
    '';
  };

  # The host-side disk-image forensics parser module and its unit tests. These
  # run in the fast lane (no VM, no root) against tool output captured once under
  # fixtures/forensics, so the parsers the VM forensic tests depend on cannot
  # drift unnoticed.
  e2e-disk-forensics = lint "e2e-disk-forensics" {
    files = fs.unions [
      ./e2e-tests/lib/disk_forensics.py
      ./e2e-tests/lib/records.py
      ./e2e-tests/lib/tests
      ./e2e-tests/fixtures/forensics
      ./e2e-tests/fixtures/indicators.json
      ../pyproject.toml
    ];
    tools = [
      python
      pkgs.ruff
      pkgs.mypy
    ];
    script = ''
      export HOME="$PWD"
      python3 -m unittest discover -s nix/e2e-tests/lib/tests -t nix/e2e-tests/lib
      ruff check nix/e2e-tests/lib
      mypy nix/e2e-tests/lib/disk_forensics.py nix/e2e-tests/lib/records.py \
        nix/e2e-tests/lib/tests/test_disk_forensics.py nix/e2e-tests/lib/tests/test_records.py
    '';
  };

  # The in-VM helper package nails_e2e (nix/e2e-tests/py), lint and unit-tested
  # host-side without a VM, the same fast lane as e2e-disk-forensics. The VM
  # tests import the package through the driver's extraPythonPackages; this
  # proves the helpers themselves stay correct, linted and typed on every
  # `nix flake check`, not only when a VM test is assembled.
  e2e-helpers = lint "e2e-helpers" {
    files = fs.unions [
      ./e2e-tests/py
      ../pyproject.toml
    ];
    tools = [
      python
      pkgs.ruff
      pkgs.mypy
      pkgs.bash
    ];
    script = ''
      export HOME="$PWD"
      python3 -m unittest discover -s nix/e2e-tests/py/tests -t nix/e2e-tests/py
      ruff check nix/e2e-tests/py
      MYPYPATH=nix/e2e-tests/py mypy nix/e2e-tests/py/nails_e2e nix/e2e-tests/py/tests
    '';
  };

  # The portable smoke suite's host-side helpers (nix/distro-tests/py), lint
  # and unit-tested without a VM, the same fast lane as e2e-helpers. The smoke
  # scenario loads distro_checks on the driver; this proves the pure layout
  # rules it depends on -- the mount-aware canary uppers, the boot-filesystem
  # read-back and the overlay feature-option check -- stay correct, linted and
  # typed on every `nix flake check`, not only when a distro VM test runs.
  distro-checks = lint "distro-checks" {
    files = fs.unions [
      ./distro-tests/py
      ../pyproject.toml
    ];
    tools = [
      python
      pkgs.ruff
      pkgs.mypy
    ];
    script = ''
      export HOME="$PWD"
      python3 -m unittest discover -s nix/distro-tests/py/tests -t nix/distro-tests/py
      ruff check nix/distro-tests/py
      MYPYPATH=nix/distro-tests/py mypy \
        nix/distro-tests/py/distro_checks.py \
        nix/distro-tests/py/tests/test_distro_checks.py
    '';
  };

  # Guards the E2E suite against assertions that can never fail (the soft
  # "Note:" branch). It reads only the test files, so it runs in seconds and
  # never builds a VM. The rule it enforces lives in nix/e2e-tests/README.md.
  e2e-soft-assertions = import ./e2e-tests/lint.nix {
    inherit pkgs;
    tests = ./e2e-tests/tests;
    scenarios = ./e2e-tests/scenarios;
  };

  # Validates the checked-in shard weights against the timeouts the test
  # derivations really use. Evaluating the metadata also runs the assertions
  # in nix/e2e-tests/default.nix without building any VM test.
  e2e-shard-weights = lint "e2e-shard-weights" {
    files = fs.unions [
      ../ci
      ./e2e-tests/shard-durations.json
    ];
    tools = [ python ];
    script = ''
      python3 -m ci.e2e check \
        --weights nix/e2e-tests/shard-durations.json \
        --metadata ${e2eMetadataJson}
    '';
  };
}
