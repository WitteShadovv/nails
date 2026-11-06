# The Nix scenario: Nix installed inside a hidden session leaves no trace on
# the decoy, and Nix installed on the decoy is named by the `decoy-nix-trace`
# check and found on the decoy's disk.
#
# The distribution tier's counterpart of the NixOS suite's nix-store-placement
# test. On every distribution but NixOS, Nix belongs inside the hidden
# session, where everything the installer and Nix write lands on the hidden
# volume. The scenario installs it the way a person does, with the multi-user
# installer of Nix's release tarball (built here from this flake's Nix with
# Nix's own recipe), run as root with `--daemon`, and:
#
#   - images the decoy as booted, the baseline;
#   - runs `check`, whose decoy-nix-trace row names `/nix` alone: the
#     directories the test driver keeps there (below);
#   - activates, and in the hidden session installs Nix and uses the daemon
#     the installer starts: it adds a file holding a run-unique nonce to the
#     store, evaluates a `builtins.toFile` of it and builds a derivation that
#     writes it, as a build user in the build sandbox. These must lie in the
#     root overlay's upper on the hidden volume: the store paths the installer
#     copies and the three the session writes, each path the check looks for
#     that the install made, the shell startup files it adds its hook to, the
#     32 build users in `/etc/passwd` and `/etc/shadow`, the group in
#     `/etc/group`, and the copies shadow-utils keeps of the account files,
#     each naming them. `check` skips the row there;
#   - deactivates. On the decoy none of the paths the check looks for is left
#     but the test driver's `/nix`, no account file or copy of one names a
#     build user or the group, no system shell startup file holds a hook, no
#     daemon unit is known, and the row names `/nix` alone again;
#   - images the decoy and looks for the marks of the install: its `/nix`
#     holds what the baseline's held, and the image lists none of the
#     installer's files beyond the baseline's, deleted entries included. Its
#     bytes hold neither the nonce nor the name of a store path the session
#     wrote and, beyond what the baseline holds, neither the name of a store
#     path the installer copies nor three of the lines it writes (a build
#     user's line in `/etc/passwd`, its `build-users-group` setting and its
#     shell hook);
#   - as the positive control, boots the decoy again, installs and uses Nix on
#     the decoy itself, and asserts that the row names every path the check
#     looks for that the install left, and the group and the build users in
#     the account files and in their copies, and that the decoy's image lists
#     the store paths and holds the nonce, the installed Nix's name and those
#     three lines: so the scans that find nothing above can see a trace.
#
# The test driver needs the host's Nix store in the guest: the shell it runs
# commands in starts from a script there. nix-vm-test's mount-store.service
# mounts that store below `/nix` at every boot (`/nix/.ro-store`,
# `/nix/.rw-store`, `/nix/store`), so the decoy disk holds those three empty
# directories, and the stock decoy's row names `/nix`. Before each install
# the scenario unmounts them and removes `/nix`, so the installer starts on a
# system without one, as on a real decoy; the shell, the guest's own bash by
# then, does not need them. The decoy's next boot mounts them again.
#
# The guest has no network in the build sandbox, so the installer runs without
# a channel (`--no-channel-add`) and with no substituter.
{
  self,
  pkgs,
  nix-vm-test,
}:
let
  distroVm = import ../lib/distro-vm.nix { inherit pkgs nix-vm-test; };
  hiddenRoot = import ../lib/hidden-root.nix;
  diskForensics = import ../../e2e-tests/lib/disk-forensics.nix { inherit pkgs; };

  # The canonical static musl binary, the exact artifact a user installs.
  inherit (self.packages.x86_64-linux) nails;

  inherit (pkgs) lib nix cacert;

  # The components this flake's Nix is built from, from which the release
  # tarball takes what it installs, as Nix's own packaging does: the command
  # line (`nix-cli`, whose unit files are files where those of `nix` are links
  # to them, which `systemctl link` refuses), and the man pages of the manual,
  # a package of their own (the man output of `nix` carries the name of
  # `nix`, so `nix-env -i` would put it in the place of Nix).
  components =
    pkgs.nixVersions."nixComponents_${
      lib.replaceStrings [ "." ] [ "_" ] (lib.versions.majorMinor nix.version)
    }";
  installedNix =
    assert lib.assertMsg (
      components.nix-everything.outPath == nix.outPath
    ) "nix-trace: pkgs.nix is not the nix-everything of ${components.version}";
    components.nix-cli;
  manual = components.nix-manual.man;

  # What the release tarball installs: Nix, its manual and the CA bundle,
  # with every store path they need.
  installed = pkgs.closureInfo {
    rootPaths = [
      installedNix
      manual
      cacert
    ];
  };

  # The release tarball of this Nix, unpacked, as Nix's own
  # packaging/binary-tarball.nix lays it out: the install scripts with their
  # store paths filled in, the registration of the paths the installer copies,
  # and a copy of each of them below store/.
  installer = pkgs.runCommand "nix-${installedNix.version}-installer" { } ''
    mkdir -p $out/store
    cp ${installed}/registration $out/.reginfo
    substitute ${nix.src}/scripts/install-nix-from-tarball.sh $out/install \
      --subst-var-by nix ${installedNix} \
      --subst-var-by cacert ${cacert}
    substitute ${nix.src}/scripts/install-multi-user.sh $out/install-multi-user \
      --subst-var-by nix ${installedNix} \
      --subst-var-by nix-manual ${manual} \
      --subst-var-by cacert ${cacert}
    substitute ${nix.src}/scripts/install-systemd-multi-user.sh \
      $out/install-systemd-multi-user.sh \
      --subst-var-by nix ${installedNix} \
      --subst-var-by cacert ${cacert}
    chmod +x $out/install $out/install-multi-user $out/install-systemd-multi-user.sh
    while read -r path; do
      cp -a "$path" $out/store/
    done < ${installed}/store-paths
  '';

  # Both shares sit on the /run tmpfs, never on the decoy disk the scenario
  # images. The tags and paths are neutral: they show in the mount table.
  binShare = {
    tag = "tools";
    target = "/run/tools";
  };
  installerShare = {
    tag = "pkgs";
    target = "/run/pkgs";
  };
in
# `name` and `entry` are one name and value of images.nix.
_name: entry:
distroVm.buildVmTest {
  inherit entry;

  sharedDirs = {
    ${binShare.tag} = {
      source = "${nails}/bin";
      inherit (binShare) target;
    };
    ${installerShare.tag} = {
      source = "${installer}";
      inherit (installerShare) target;
    };
  };

  # Room for the installed store on the RAM-backed hidden root, next to a
  # full cloud-image boot.
  memorySize = entry.memory + 1024;

  testScript = ''
    import json
    import os
    import secrets
    import shlex
    import subprocess
    import sys
    import time
    from typing import Any

    # The NixOS suite's in-VM helper package, for following a soft-reboot.
    sys.path.insert(0, "${../../e2e-tests/py}")
    from nails_e2e import session  # noqa: E402

    ${diskForensics.pythonSetup}

    nails = "${binShare.target}/nails"
    installer = "${installerShare.target}"
    # On the /run tmpfs: never on the decoy disk; carried across soft-reboots.
    config = "/run/nails-nix-trace.toml"
    nails_cmd = f"{nails} --config {shlex.quote(config)}"
    nix = "/nix/var/nix/profiles/default/bin/nix --extra-experimental-features nix-command"

    # The store paths the installer copies, by name, and the installed Nix's.
    with open("${installed}/store-paths") as handle:
        installed_names = [os.path.basename(line.strip()) for line in handle if line.strip()]
    nix_name = os.path.basename("${installedNix}")
    assert nix_name in installed_names, installed_names

    # Lines the installer writes into the decoy's own files: a build user in
    # /etc/passwd, its setting in /etc/nix/nix.conf, its shell hook.
    INSTALLER_LINES = [
        "Nix build user 1:/var/empty",
        "build-users-group = nixbld",
        "/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh",
    ]

    # The paths the check looks for, as the decoy names them, but the
    # links in the dependency directories of /etc/systemd/system, which
    # candidates() lists, and the homes other than /root.
    CHECKED = [
        "/nix",
        "/etc/systemd/system/nix-daemon.service",
        "/etc/systemd/system/nix-daemon.socket",
        "/usr/local/lib/systemd/system/nix-daemon.service",
        "/usr/local/lib/systemd/system/nix-daemon.socket",
        "/usr/lib/systemd/system/nix-daemon.service",
        "/usr/lib/systemd/system/nix-daemon.socket",
        "/etc/systemd/system/nix-daemon.service.d",
        "/etc/systemd/system/nix-daemon.socket.d",
        "/etc/tmpfiles.d/nix-daemon.conf",
        "/etc/nix",
        "/usr/bin/nix",
        "/usr/local/bin/nix",
        "/etc/profile.d/nix.sh",
        "/etc/profile.d/nix-daemon.sh",
        "/etc/fish/conf.d/nix.fish",
        "/usr/local/etc/fish/conf.d/nix.fish",
        "/opt/homebrew/etc/fish/conf.d/nix.fish",
        "/opt/local/etc/fish/conf.d/nix.fish",
        "/etc/bashrc.backup-before-nix",
        "/etc/profile.d/nix.sh.backup-before-nix",
        "/etc/zshrc.backup-before-nix",
        "/etc/bash.bashrc.backup-before-nix",
        "/etc/zsh/zshrc.backup-before-nix",
        "/root/.nix-profile",
        "/root/.nix-defexpr",
        "/root/.nix-channels",
        "/root/.local/state/nix",
        "/root/.local/share/nix",
        "/root/.cache/nix",
        "/root/.config/nix",
        "/root/.config/fish/conf.d/nix.fish",
    ]

    # The account files the installer's groupadd and useradd change, and the
    # copy of each that shadow-utils keeps as it was before its last change.
    ACCOUNT_FILES = [
        f"/etc/{name}{copy}"
        for copy in ("", "-")
        for name in ("passwd", "shadow", "group", "gshadow")
    ]

    # The shell startup files the installer adds its hook to on this decoy,
    # where it makes /etc/bashrc and /etc/zshrc, and /etc/profile, which the
    # check reads as well.
    STARTUP_FILES = ["/etc/bashrc", "/etc/bash.bashrc", "/etc/zshrc", "/etc/profile"]

    # The files the installer writes on this decoy, as fls names them on its
    # image, the stubs it makes for the shell startup files included.
    INSTALLER_FILES = [path.lstrip("/") for path in CHECKED if path != "/nix"] + [
        "etc/systemd/system/sockets.target.wants/nix-daemon.socket",
        "etc/bashrc",
        "etc/zshrc",
    ]

    # What the row says on this decoy before any install: the test driver's
    # own /nix.
    HARNESS_ROW = "Nix is installed on the decoy, or was: it holds /nix."


    def write_config():
        vm.succeed(
            "printf '%s\\n' 'hidden_volume_root = \"/mnt/data\"' "
            + "'minimum_space_mb = 100' > "
            + shlex.quote(config)
        )


    def prepare_boot():
        # Everything a fresh boot loses: the 9p shares (nix-vm-test mounts
        # them only once, before this script) and the /run config. The apt
        # timers are stopped, so that no daily run refuses an activation.
        vm.wait_for_unit("multi-user.target")
        for tag, target in (
            ("${binShare.tag}", "${binShare.target}"),
            ("${installerShare.tag}", "${installerShare.target}"),
        ):
            vm.succeed(
                f"mkdir -p {target} && {{ mountpoint -q {target} || "
                + "mount -t 9p -o defaults,trans=virtio,version=9p2000.L,cache=loose,"
                + f"msize=268435456 {tag} {target}; }}"
            )
        vm.succeed(f"test -x {nails} && test -x {installer}/install")
        write_config()
        vm.succeed("""${hiddenRoot.stopAptTimers}""")
        vm.wait_until_succeeds("""${hiddenRoot.aptRunsEnded}""", timeout=900)


    def qmp(command: str, arguments: dict[str, Any] | None = None) -> Any:
        client = vm.qmp_client
        assert client is not None, "the QMP socket is not connected"
        reply: Any = client.send(command, arguments or {})
        return reply["return"]


    def persist_root_disk():
        # Mirror the running root disk, the image plus the -snapshot layer
        # that holds every guest write, into a standalone qcow2 where
        # disk_forensics.root_image() looks, and pivot QEMU onto it, so that
        # disk_forensics.snapshot shuts the guest down into that file instead
        # of discarding its writes (as tests/smoke.nix does).
        target = os.path.join(str(vm.state_dir), f"{vm.name}.qcow2")
        if os.path.exists(target):
            os.remove(target)
        blocks = qmp("query-block")
        roots = [
            block
            for block in blocks
            if block.get("inserted") and not block.get("removable", False)
        ]
        assert len(roots) == 1, f"cannot identify the root drive: {blocks}"
        device = roots[0]["device"]
        size = roots[0]["inserted"]["image"]["virtual-size"]
        subprocess.run(
            [disk_forensics.QEMU_IMG, "create", "-q", "-f", "qcow2", target, str(size)],
            check=True,
        )
        # Unique per call: a node name stays taken for the life of QEMU.
        job = f"persist-root-{time.monotonic_ns()}"
        qmp(
            "blockdev-add",
            {
                "driver": "qcow2",
                "node-name": job,
                "file": {"driver": "file", "filename": target},
            },
        )
        qmp("blockdev-mirror", {"job-id": job, "device": device, "target": job, "sync": "full"})
        deadline = time.monotonic() + 900
        while True:
            jobs = [entry for entry in qmp("query-block-jobs") if entry["device"] == job]
            assert jobs, f"the mirror of {device} ended before it was ready"
            if jobs[0].get("ready"):
                break
            assert time.monotonic() < deadline, f"the mirror of {device} never became ready"
            time.sleep(1)
        qmp("block-job-complete", {"device": job})
        while any(entry["device"] == job for entry in qmp("query-block-jobs")):
            assert time.monotonic() < deadline, f"the mirror of {device} never completed"
            time.sleep(1)
        active = [block for block in qmp("query-block") if block["device"] == device]
        assert active and active[0]["inserted"]["file"] == target, (
            f"QEMU did not pivot {device} onto {target}: {active}"
        )


    def image_decoy(label):
        # Ends this QEMU process; the next vm.start() boots the image afresh.
        persist_root_disk()
        return disk_forensics.snapshot(vm, label, restart=False)


    def listed(image):
        # Every name fls lists on the image's root filesystem, deleted ones
        # included, and the offset it found that filesystem at.
        offset = disk_forensics.partition_offset(image)
        return disk_forensics.fls_paths(disk_forensics.run_fls(image, offset)), offset


    def below_nix(names):
        return {name for name in names if name == "nix" or name.startswith("nix/")}


    def installer_files(names):
        # The names among `names` of the installer's files and what they hold.
        return {
            name
            for name in names
            if any(name == path or name.startswith(path + "/") for path in INSTALLER_FILES)
        }


    def follow(trigger, label):
        timings = session.follow_soft_reboot(vm, trigger, label)
        print(f"{label}: {timings}")
        prepare_boot()


    def nix_trace_row(where):
        # The decoy-nix-trace row of `check`. Its JSON is read off the
        # command's output, never written to the decoy disk.
        _, out = vm.execute(f"{nails_cmd} check --overlay-only --json 2>/dev/null")
        rows = json.loads(out)["data"]["checks"]
        row = next(row for row in rows if row["name"] == "decoy-nix-trace")
        print(f"decoy-nix-trace {where}: {json.dumps(row, indent=2)}")
        return row


    def candidates():
        # The paths the check looks for that are there now, as the decoy
        # names them.
        out = vm.succeed(
            "find /etc/systemd/system -mindepth 2 -maxdepth 2 "
            + "\\( -path '*.wants/*' -o -path '*.requires/*' -o -path '*.upholds/*' \\) "
            + "\\( -name nix-daemon.service -o -name nix-daemon.socket \\)"
        )
        paths = CHECKED + sorted(out.split())
        return [
            path
            for path in paths
            if vm.execute(f"test -e {path} || test -L {path}")[0] == 0
        ]


    def nix_mounts():
        # The mounts below /nix, the deepest first. The shell shares PID 1's
        # mount namespace, so this is what the daemon will see too.
        return sorted(
            (
                target
                for target in vm.succeed("findmnt -rn -o TARGET").split()
                if target == "/nix" or target.startswith("/nix/")
            ),
            reverse=True,
        )


    def clear_harness_store():
        # Take the host's store away from /nix (see the top of this file):
        # unmount what mount-store.service mounted there, the deepest first,
        # then remove /nix, never crossing into another filesystem.
        vm.succeed("test \"$(readlink /proc/self/ns/mnt)\" = \"$(readlink /proc/1/ns/mnt)\"")
        mounts = nix_mounts()
        print(f"the test driver's mounts below /nix: {mounts}")
        for target in mounts:
            vm.succeed(f"umount -l {shlex.quote(target)}")
        assert not nix_mounts(), nix_mounts()
        vm.succeed("rm -rf --one-file-system /nix")


    def nix_view():
        # The default profile and the generations of root's, for a failure.
        print(
            vm.succeed(
                "{ ls -la /nix/var/nix/profiles /nix/var/nix/profiles/per-user/root; "
                + "ls -la /nix/var/nix/profiles/default/ /nix/var/nix/profiles/default/lib/systemd/system; "
                + "} 2>&1 || true"
            )
        )


    def install_nix(where):
        # Nix's multi-user installer, run as root, headless (--yes), as from
        # the unpacked release tarball. Its log stays in /run.
        log = f"/run/nix-install-{where}.log"
        vm.succeed("printf 'substituters =\\n' > /run/nix-extra.conf")
        rc, _ = vm.execute(
            "cd / && env USER=root HOME=/root NIX_CONFIG='substituters =' "
            + f"{installer}/install --daemon --yes --no-channel-add "
            + f"--nix-extra-conf-file /run/nix-extra.conf > {log} 2>&1",
            timeout=1200,
        )
        print(vm.succeed(f"tail -n 80 {log}"))
        if rc != 0:
            nix_view()
        assert rc == 0, f"the installer failed {where} (exit {rc})"
        vm.succeed("systemctl is-active nix-daemon.socket")


    def use_nix(nonce_id, source_dir):
        # Store writes through the daemon: a file added, a builtins.toFile
        # evaluated, a derivation built by a build user in the sandbox. Each
        # holds the nonce.
        token = f"NAILS_NIX_NONCE_{nonce_id}"
        source = f"{source_dir}/nonce-{nonce_id}"
        vm.succeed(f"printf '%s store write\\n' {token} > {source}")
        added = vm.succeed(f"{nix} store add --store daemon {source}").strip()
        declared = vm.succeed(
            f"{nix} eval --store daemon --raw --expr "
            + shlex.quote(f'builtins.toFile "nonce-{nonce_id}-declared" "{token} declared"')
        ).strip()
        built = vm.succeed(
            f"{nix} build --store daemon --no-link --print-out-paths --expr "
            + shlex.quote(
                f'derivation {{ name = "nonce-{nonce_id}-built"; system = "x86_64-linux"; '
                + 'builder = "/bin/sh"; '
                + f'args = [ "-c" "echo {token} built > $out" ]; }}'
            )
        ).strip()
        paths = [added, declared, built]
        for path in paths:
            assert path.startswith("/nix/store/"), path
            vm.succeed(f"grep -q {token} {path}")
        print(f"store paths written: {paths}")
        return token, paths


    vm.wait_for_unit("multi-user.target")
    prepare_boot()

    with subtest("capture the decoy baseline image"):
        # The decoy as booted. The scans below compare the installer's lines
        # and the installed store paths' names with it, and its /nix is the
        # test driver's.
        baseline = image_decoy("baseline")
        baseline_names, _ = listed(baseline)
        baseline_nix = below_nix(baseline_names)
        baseline_files = installer_files(baseline_names)
        print(f"the installer's files on the baseline image: {sorted(baseline_files)}")
        print(f"/nix on the baseline image: {sorted(baseline_nix)}")
        assert baseline_nix == {"nix", "nix/.ro-store", "nix/.rw-store", "nix/store"}, baseline_nix
        baseline_hits = disk_forensics.run_strings_scan(
            baseline, INSTALLER_LINES + installed_names
        )
        print(f"the baseline holds: {sorted(baseline_hits)}")
        os.remove(baseline)
        vm.start()
        prepare_boot()

    with subtest("check names the test driver's /nix alone on the stock decoy"):
        vm.succeed("""${hiddenRoot.setupHiddenRoot}""")
        vm.succeed("""${hiddenRoot.makeDecoyAmnesic}""")
        row = nix_trace_row("on the stock decoy")
        assert row["status"] == "warn", row
        assert row["message"].splitlines()[0] == HARNESS_ROW, row
        assert candidates() == ["/nix"], candidates()

    nonce_id = secrets.token_hex(16)

    with subtest("Nix installed inside the hidden session writes to the hidden volume"):
        follow(f"{nails_cmd} activate -y > /mnt/data/activate.log 2>&1", "activate")
        print(vm.succeed("cat /mnt/data/activate.log || true"))
        session.assert_hidden_root(vm)
        row = nix_trace_row("in the hidden session")
        assert row["status"] == "skipped", row
        clear_harness_store()
        install_nix("session")
        token, paths = use_nix(nonce_id, "/mnt/data")
        upper = "/mnt/data/root/upper"
        # The store paths the session wrote and those the installer copied.
        for path in paths + [f"/nix/store/{name}" for name in installed_names]:
            vm.succeed(f"test -e {upper}{path}")
        # Each path the check looks for that the install made, the links that
        # enable the daemon among them, and the startup files it changed.
        made = candidates()
        print(f"the paths the check looks for in the session: {made}")
        for path in (
            "/nix",
            "/etc/nix",
            "/etc/systemd/system/nix-daemon.service",
            "/etc/systemd/system/nix-daemon.socket",
            "/etc/systemd/system/sockets.target.wants/nix-daemon.socket",
            "/etc/tmpfiles.d/nix-daemon.conf",
            "/etc/profile.d/nix.sh",
            "/etc/bash.bashrc.backup-before-nix",
        ):
            assert path in made, f"the install made no {path}: {made}"
        for path in made:
            vm.succeed(f"test -e {upper}{path} || test -L {upper}{path}")
        for path in ("/etc/bashrc", "/etc/bash.bashrc", "/etc/zshrc"):
            vm.succeed(f"grep -q /nix/var/nix/profiles/ {upper}{path}")
        # The 32 build users and the group, in the account files and their
        # copies.
        vm.succeed(
            "for n in $(seq 1 32); do "
            + f"grep -q \"^nixbld$n:\" {upper}/etc/passwd && "
            + f"grep -q \"^nixbld$n:\" {upper}/etc/shadow || exit 1; done"
        )
        for path in ACCOUNT_FILES:
            vm.succeed(f"grep -q '^nixbld' {upper}{path}")
        vm.succeed(f"grep -q '^nixbld:x:30000:' {upper}/etc/group")
        vm.succeed("sync")

    with subtest("deactivate: no trace of the installer is left on the decoy"):
        follow(f"{nails_cmd} deactivate -y", "deactivate")
        session.assert_decoy_root(vm)
        vm.fail("mountpoint -q /mnt/data")
        assert candidates() == ["/nix"], candidates()
        on_decoy = sorted(vm.succeed("find /nix -xdev -mindepth 1").split())
        assert on_decoy == ["/nix/.ro-store", "/nix/.rw-store", "/nix/store"], on_decoy
        vm.fail("getent group nixbld")
        vm.fail("getent passwd nixbld1")
        # grep -q exits 0 on a match even where another file is missing.
        vm.fail(
            "grep -q -e nixbld -e /nix/var/nix/profiles/ "
            + " ".join(ACCOUNT_FILES + STARTUP_FILES)
        )
        for unit in ("nix-daemon.service", "nix-daemon.socket"):
            state = vm.succeed(f"systemctl show -P LoadState {unit}").strip()
            assert state == "not-found", f"{unit} on the decoy: {state}"
        row = nix_trace_row("on the decoy after the session")
        assert row["status"] == "warn", row
        assert row["message"].splitlines()[0] == HARNESS_ROW, row

    with subtest("the decoy image holds no trace of the Nix the session installed"):
        session_tokens = [nonce_id, token] + [os.path.basename(path) for path in paths]
        clean = image_decoy("clean")
        names, offset = listed(clean)
        assert below_nix(names) == baseline_nix, sorted(below_nix(names) - baseline_nix)
        left = sorted(installer_files(names) - baseline_files)
        assert not left, f"fls lists the installer's files on the decoy image: {left}"
        nonce_named = sorted(name for name in names if nonce_id in name)
        assert not nonce_named, f"fls lists the session's store paths: {nonce_named}"
        hits = disk_forensics.run_strings_scan(
            clean, session_tokens + INSTALLER_LINES + installed_names
        )
        leaked = sorted(hits & set(session_tokens))
        assert not leaked, f"the decoy image holds the session's store writes: {leaked}"
        new = sorted(hits - baseline_hits - set(session_tokens))
        assert not new, f"the decoy image holds what the installer wrote: {new}"
        store_hits = disk_forensics.run_store_scan(clean, session_tokens, offset=offset)
        assert not store_hits, f"the decoy store registers a session path: {sorted(store_hits)}"
        os.remove(clean)
        print("decoy image clean of the Nix installed in the session")

    with subtest("positive control: Nix installed on the decoy is named and found"):
        vm.start()
        prepare_boot()
        clear_harness_store()
        install_nix("decoy")
        decoy_nonce = secrets.token_hex(16)
        decoy_token, decoy_paths = use_nix(decoy_nonce, "/run")
        row = nix_trace_row("after an install on the decoy")
        assert row["status"] == "warn", row
        named = row["message"].splitlines()[0]
        present = candidates()
        unnamed = [path for path in present if path not in named]
        assert not unnamed, f"the row does not name {unnamed}: {named}"
        for trace in (
            "/nix,",
            "/etc/nix,",
            "/etc/systemd/system/nix-daemon.socket",
            "/etc/systemd/system/sockets.target.wants/nix-daemon.socket",
            "/etc/tmpfiles.d/nix-daemon.conf",
            # The group and the build users in each account file and in its
            # copy: shadow-utils keeps each as it was before the last useradd,
            # which held the group and 31 of the build users.
            "the nixbld group (in /etc/group, /etc/gshadow, /etc/group- and /etc/gshadow-)",
            "32 Nix build users (nixbld1, nixbld2 and 30 more, in /etc/passwd, /etc/shadow, "
            + "/etc/passwd- and /etc/shadow-)",
            "/etc/profile.d/nix.sh",
            "the Nix lines in /etc/bash.bashrc",
            "/etc/bash.bashrc.backup-before-nix",
        ):
            assert trace in named, f"the row does not name {trace}: {named}"
        # The store's database keeps its last writes in its write-ahead log
        # until the last connection to it closes, and the store scan reads the
        # database alone: stop the daemon, then let a query of root's on the
        # store itself fold the log into the database.
        vm.succeed("systemctl stop nix-daemon.socket nix-daemon.service")
        vm.succeed(f"/nix/var/nix/profiles/default/bin/nix-store --query --hash {decoy_paths[0]}")
        print(vm.succeed("ls -la /nix/var/nix/db"))
        vm.succeed("sync")
        positive = image_decoy("positive")
        names, offset = listed(positive)
        for path in decoy_paths:
            assert path.lstrip("/") in names, f"fls does not list {path}"
        assert "etc/nix/nix.conf" in names, sorted(below_nix(names))[:20]
        wanted = {decoy_token, nix_name, *INSTALLER_LINES}
        found = disk_forensics.run_strings_scan(positive, sorted(wanted))
        assert found == wanted, f"the scan missed {sorted(wanted - found)}"
        store_hits = disk_forensics.run_store_scan(positive, [decoy_nonce], offset=offset)
        assert store_hits == {decoy_nonce}, f"the store scan missed the decoy's path: {store_hits}"
        print("the scans find the Nix installed on the decoy")
  '';
}
