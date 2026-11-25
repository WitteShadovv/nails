# The hidden NixOS system survives a decoy garbage collection and rebuild
# between two sessions, and the hidden sessions leave the decoy store
# unchanged.
#
# The hidden store is an overlay over the decoy's: a path the hidden closure
# shares with the decoy is read from the lower, and the hidden store database
# (copied up at the first build) keeps listing it. Activation therefore copies
# the hidden toplevel's closure up into the store upper on the hidden volume
# before it activates it.
#
# The hidden system here is the VM's own configuration plus
# fixtures/hidden-config/module.nix, built on the host like the
# `session-nixos-hidden-system` specialisation, but registered in the guest
# store without any GC root (`virtualisation.additionalPaths`), so the decoy's
# garbage collection deletes its own paths (the toplevel, its /etc, its units).
#
#   1. Session 1 builds (realises) the hidden toplevel, keeps its closure on
#      the hidden volume and enters it. Deactivate powers the machine off; on
#      the cold-booted decoy the decoy store is unchanged: its database (as
#      content), its profiles and roots are as before, and every path of the
#      decoy and hidden systems still hashes as the database recorded it.
#   2. The decoy rebuilds (a new rooted build) and garbage-collects: the hidden
#      toplevel is gone from the decoy store.
#   3. Session 2 enters the same hidden toplevel again: it still starts, from
#      the copy on the hidden volume, and copies nothing new. After its
#      power-off the decoy's profiles and roots are as before it, and the
#      database lists every path it listed, and no other path than the VM's
#      own boot registers again.
#
# The VM's writable store layer is a tmpfs (/nix/.rw-store), which every boot
# starts empty, and the VM registers its own closure (the hidden toplevel
# among it) at every boot (register-nix-paths). So a cold boot puts the
# collected toplevel back from the VM's read-only store and loses the decoy
# rebuild's output: neither is the session's doing, and neither is compared.
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  fixtureDir = ./../../fixtures/hidden-config;
in
{
  name = "session-nixos-store-gc";
  meta.tags = [
    "nixos"
    "session"
    "slow"
  ];
  # Two hidden builds, a copy of the whole system closure onto the hidden
  # volume, a decoy garbage collection and two sessions (a soft-reboot in, a
  # power-off and a cold boot out).
  globalTimeout = 4800;

  nodes.machine =
    {
      lib,
      extendModules,
      ...
    }:
    let
      hidden = extendModules { modules = [ ./../../fixtures/hidden-config/module.nix ]; };
    in
    {
      imports = [ ./../../lib/vm-config.nix ];

      options.nailsTest.hiddenSystem = lib.mkOption {
        type = lib.types.package;
        description = "The hidden toplevel, in the guest store without a GC root.";
      };

      config = {
        nailsTest.hiddenSystem = hidden.config.system.build.toplevel;
        virtualisation = {
          additionalPaths = [ hidden.config.system.build.toplevel ];
          # The whole hidden closure is copied onto the hidden volume.
          emptyDiskImages = lib.mkForce [
            {
              size = 8192;
              driveConfig.deviceExtraOpts.serial = "data";
            }
          ];
        };
        environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.nails ];
        nix.settings = {
          experimental-features = [
            "nix-command"
            "flakes"
          ];
          substituters = lib.mkForce [ ];
          # The decoy rebuild below runs /bin/sh as its builder.
          sandbox = false;
        };
      };
    };

  testScript =
    { nodes, ... }:
    ''
      import difflib
      import secrets
      import shlex

      ${testHelpers.canonicalActivateFn}
      ${testHelpers.canonicalDeactivateFn}

      CONFIG = "/mnt/data/config/nails.toml"
      FLAKE = "/mnt/data/nixos#nails-e2e"
      MARKER = "/etc/nails-hidden-marker"
      HIDDEN_SYSTEM = "${nodes.machine.nailsTest.hiddenSystem}"
      HIDDEN_BASE = HIDDEN_SYSTEM.rsplit("/", 1)[-1]
      RECORD = "/mnt/data/root/store-kept"
      # Where a kept path lives on the hidden volume: the overlay over a
      # separate decoy store (this VM's store share), or the root upper.
      STORE_UPPERS = [
          "/mnt/data/root/mounts/nix-store/upper",
          "/mnt/data/root/upper/nix/store",
      ]


      def decoy_store_state():
          # What the hidden session could change in the decoy store: its
          # database (as content: the sqlite file changes when a reader
          # checkpoints it) and its profiles and roots. The store contents
          # are checked against the database's hashes by verify_contents().
          return {
              "database": machine.succeed("nix-store --dump-db"),
              "roots": machine.succeed(
                  "find /nix/var/nix/profiles /nix/var/nix/gcroots -xdev -printf '%y %p %l\\n' "
                  "| LC_ALL=C sort"
              ),
          }


      def ram_layer():
          # The VM's writable store layer is a tmpfs, which every boot starts
          # empty: it is only logged, never compared.
          return machine.succeed(
              "findmnt -no SOURCE,FSTYPE,OPTIONS /nix/.rw-store; "
              "findmnt -no OPTIONS /nix/store; "
              "cd /nix/.rw-store && find . -xdev -printf '%y %m %s %p %l\\n' | LC_ALL=C sort"
          )


      def assert_store_unchanged(before, label):
          after = decoy_store_state()
          changed = []
          for key, text in before.items():
              if after[key] != text:
                  changed.append(key)
                  diff = difflib.unified_diff(
                      text.splitlines(), after[key].splitlines(), lineterm="", n=0
                  )
                  machine.log(f"{label}: the decoy store's {key} changed:\n" + "\n".join(list(diff)[:200]))
          assert not changed, f"{label} changed the decoy store: {changed}"


      def verify_contents(*roots):
          # Every registered path these roots reach still hashes as the decoy
          # database recorded it: the store contents are byte for byte intact.
          paths = " ".join(roots)
          machine.succeed(f"nix-store --verify-path $(nix-store --query --requisites {paths})")


      def valid_paths():
          return set(machine.succeed("nix path-info --all").split())


      def registered_at_boot():
          # The VM's own closure, which register-nix-paths registers at every
          # boot, from the regInfo= file on the kernel command line.
          words = machine.succeed("cat /proc/cmdline").split()
          files = [word.split("=", 1)[1] for word in words if word.startswith("regInfo=")]
          assert files, words
          return {
              line
              for line in machine.succeed(f"cat {files[0]}").splitlines()
              if line.startswith("/nix/store/")
          }


      def kept_in():
          for upper in STORE_UPPERS:
              if machine.execute(f"test -d {upper}/{HIDDEN_BASE}")[0] == 0:
                  return upper
          return None


      def assert_hidden_system():
          current = machine.succeed("readlink -f /run/current-system").strip()
          assert current == HIDDEN_SYSTEM, f"current-system is {current}, not {HIDDEN_SYSTEM}"
          machine.succeed(f"grep -Fx hidden-rebuild-active {MARKER}")
          machine.wait_for_unit("nails-hidden-canary.service")
          machine.succeed("getent passwd hiddencanary")


      machine.start()
      machine.wait_for_unit("multi-user.target")
      decoy_system = machine.succeed("readlink -f /run/current-system").strip()
      machine.succeed(f"nix-store --check-validity {HIDDEN_SYSTEM}")
      machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
      machine.succeed("nails init /mnt/data")
      machine.succeed(
          f"cat > {CONFIG} <<'EOF'\n"
          "hidden_volume_root = \"/mnt/data\"\n"
          "minimum_space_mb = 100\n"
          "rebuild_space_mb = 64\n"
          "EOF"
      )
      machine.succeed("mkdir -p /mnt/data/nixos && cp -rT ${fixtureDir} /mnt/data/nixos")
      machine.succeed("chmod -R u+w /mnt/data/nixos")
      machine.succeed(
          "sed -i " + shlex.quote(f"s|@toplevel@|{HIDDEN_SYSTEM}|") + " /mnt/data/nixos/flake.nix"
      )

      with subtest("session 1 keeps the hidden closure on the hidden volume"):
          store_before = decoy_store_state()
          ram_before = ram_layer()
          # The first entry copies the whole hidden system onto the hidden volume.
          canonical_activate(CONFIG, f"--nixos-flake {FLAKE}", "activate-1", deadline_s=1200.0)
          assert_hidden_system()
          upper = kept_in()
          assert upper is not None, (
              "the hidden toplevel was not copied onto the hidden volume: "
              + machine.succeed("ls -d /mnt/data/root/upper/nix/store /mnt/data/root/mounts/* 2>&1 || true")
          )
          machine.log(f"the hidden closure is kept in {upper}")
          machine.succeed(f"grep -Fx {HIDDEN_BASE} {RECORD}")
          # Every path of the closure is in the record.
          closure = machine.succeed(f"nix-store --query --requisites {HIDDEN_SYSTEM}").split()
          kept = set(machine.succeed(f"cat {RECORD}").split())
          missing = [p for p in closure if p.rsplit("/", 1)[-1] not in kept]
          assert not missing, f"closure paths not kept: {missing[:10]}"

      with subtest("after the power-off the decoy store is unchanged"):
          canonical_deactivate(CONFIG, "deactivate-1")
          current = machine.succeed("readlink -f /run/current-system").strip()
          assert current == decoy_system, current
          machine.log("the RAM store layer before and after:\n" + ram_before + "\n---\n" + ram_layer())
          assert_store_unchanged(store_before, "session 1")
          verify_contents("/run/current-system", HIDDEN_SYSTEM)

      with subtest("the decoy rebuilds and garbage-collects its store"):
          nonce = secrets.token_hex(8)
          expr = (
              f'derivation {{ name = "decoy-rebuild-{nonce}"; system = "${pkgs.stdenv.hostPlatform.system}"; '
              f'builder = "/bin/sh"; args = [ "-c" "echo {nonce} > $out" ]; }}'
          )
          rebuilt = machine.succeed(
              f"nix-build -o /root/decoy-rebuild -E {shlex.quote(expr)}"
          ).strip()
          machine.succeed(f"grep -Fx {nonce} {rebuilt}")
          machine.succeed("nix-collect-garbage >&2")
          machine.fail(f"test -e {HIDDEN_SYSTEM}")
          machine.fail(f"nix-store --check-validity {HIDDEN_SYSTEM}")
          machine.succeed(f"test -e {rebuilt}")
          store_before = decoy_store_state()
          valid_before = valid_paths()
          assert rebuilt in valid_before and HIDDEN_SYSTEM not in valid_before

      with subtest("session 2 still starts the hidden toplevel"):
          machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
          canonical_activate(CONFIG, f"--nixos-flake {FLAKE}", "activate-2")
          assert_hidden_system()
          machine.succeed("modprobe dummy && rmmod dummy")
          machine.succeed(f"test -x {HIDDEN_SYSTEM}/activate")

      with subtest("session 2 leaves the decoy store unchanged"):
          canonical_deactivate(CONFIG, "deactivate-2")
          assert_store_unchanged({"roots": store_before["roots"]}, "session 2")
          after = valid_paths()
          lost = sorted(valid_before - after)
          assert not lost, f"paths the decoy's database no longer lists: {lost[:20]}"
          gained = sorted(after - valid_before - registered_at_boot())
          assert not gained, f"paths the session added to the decoy's database: {gained[:20]}"
          verify_contents("/run/current-system")
    '';
}
