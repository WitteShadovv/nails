# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The refusal scenario: NAILS refuses the families it has not admitted yet
# (Fedora, Arch) and changes nothing while it does. Admitting a family is a data
# change in the family table (nails-platform/src/platform/family.rs); until it
# is made, this runs the refusal on the family's own stock cloud image. The
# binary is shared in and a hidden root is set up as the smoke suite does it,
# and the scenario proves that:
#
#   - `check` fails its platform row with the family table's reason, and the
#     hidden root still holds what it held;
#   - `activate` exits with the unsupported-platform status (8) before it
#     writes anything to the hidden root or /run, and starts no session;
#   - neither the decoy's disk filesystems nor its journal hold anything of the
#     refused run, and a planted trace is found (the positive control).
#
# The decoy stays as the image ships it, its journal persistent, so anything the
# refused run logged would land on the decoy disk. The decoy disk is judged from
# inside the guest, through its filesystems and its journal: both images keep
# their root on btrfs compressed with zstd, where the suite's disk-image
# helpers cannot look (they read ext4, or the raw bytes a compressed extent
# hides). Like the probes it is a host driver, run by hand on a KVM-capable
# host (the build server has none), so it is not part of CI.
{
  self,
  pkgs,
  nix-vm-test,
}:
let
  inherit (pkgs) lib;

  images = import ./images.nix { inherit pkgs; };
  distroVm = import ./lib/distro-vm.nix { inherit pkgs nix-vm-test; };
  hiddenRoot = import ./lib/hidden-root.nix;
  diskForensics = import ../e2e-tests/lib/disk-forensics.nix { inherit pkgs; };

  # The canonical static musl binary, the exact artifact a user installs.
  inherit (self.packages.x86_64-linux) nails;

  # As in the smoke suite: the binary is shared read-only over 9p onto the /run
  # tmpfs, so neither it nor its mount point lands on the decoy disk.
  binShare = {
    tag = "tools";
    target = "/run/tools";
  };

  # The families the table refuses, by os-release ID, with the name each
  # refusal gives the family. Once a family is admitted its scenario fails, as
  # it must, so the commit that admits it takes the family out of this list.
  refusedFamilies = {
    fedora = "Fedora";
    arch = "Arch";
  };
  refusedImages = lib.filterAttrs (_: entry: refusedFamilies ? ${entry.osId}) images;

  refusalFor =
    entry:
    distroVm.buildVmTest {
      inherit entry;
      target = "driver";

      sharedDirs.${binShare.tag} = {
        source = "${nails}/bin";
        inherit (binShare) target;
      };

      memorySize = entry.memory;

      testScript = ''
        import json
        import shlex
        import sys

        # The NixOS suite's in-VM helper package: the decoy-root assertion and
        # the listing of /run.
        sys.path.insert(0, "${../e2e-tests/py}")
        from nails_e2e import session  # noqa: E402

        # The distribution-generic helpers (nix/distro-tests/py), locked by the
        # `distro-checks` flake check: the listings and what changed between two.
        sys.path.insert(0, "${./py}")
        import distro_checks  # noqa: E402

        ${diskForensics.pythonSetup}

        os_id = "${entry.osId}"
        family = "${refusedFamilies.${entry.osId}}"
        hidden_root = "/mnt/data"
        nails = "${binShare.target}/nails"
        # The harness keeps the configuration and every capture on a tmpfs of
        # its own: nothing it writes lands on the decoy disk, and the listing of
        # /run, which keeps to the /run filesystem, never sees it change.
        work = "/run/refusal"
        config = f"{work}/config.toml"
        nails_cmd = f"{nails} --config {shlex.quote(config)}"

        # The family table's refusal of a family it has not admitted, as far as
        # the list of supported platforms it ends with, which the table
        # generates.
        reason = (
            f"{family} is not yet a validated platform. NAILS refuses it until its "
            "support has been verified. NAILS supports NixOS and the Debian family ("
        )

        # What would name the refused run on the decoy disk, in a journal entry
        # or in what a file gained: NAILS by name (its binary is called nails,
        # and its messages name NAILS), the hidden root's path and the escaped
        # form a mount unit carries, and the configuration.
        trace_tokens = (
            "nails",
            hidden_root,
            distro_checks.escape_path(hidden_root),
            config,
        )
        trace_patterns = " ".join(f"-e {shlex.quote(token)}" for token in trace_tokens)
        # The names the artifact registry gives NAILS's files, and the state lock.
        nails_names = (*load_registry_tokens(), ".lock")
        # What a plain boot changes on its own, as the forensic suite allowlists
        # it for this family.
        boot_noise = disk_forensics.image_volatile(os_id)


        def run_nails(args, name):
            # stdout, stderr and the exit status go to files on the harness's
            # tmpfs: the driver hands back a command's stdout alone.
            out, err, status = (f"{work}/{name}.{kind}" for kind in ("out", "err", "status"))
            vm.succeed(
                "bash -c "
                + shlex.quote(
                    f"set +e; {nails_cmd} {args} > {out} 2> {err};"
                    f" printf '%s' $? > {status}"
                )
            )
            return (
                int(vm.succeed(f"cat {status}")),
                vm.succeed(f"cat {out}"),
                vm.succeed(f"cat {err}"),
            )


        def hidden_tree():
            return distro_checks.parse_listing(
                vm.succeed(distro_checks.listing_command(hidden_root, hashes=True))
            )


        def decoy_snapshot(mounts, label):
            # The listing stays in the guest, sorted, and two are compared there:
            # an output of megabytes does not always cross the driver's console
            # intact.
            snapshot = f"{work}/{label}.lst"
            for mount in mounts:
                listed = vm.succeed(
                    f"{distro_checks.listing_command(mount, live=True)}"
                    f" | tee -a {snapshot} | wc -l"
                )
                # A walk that failed outright lists nothing, and nothing would
                # compare as unchanged.
                assert int(listed) > 0, f"the listing of {mount} is empty"
            vm.succeed(f"LC_ALL=C sort -o {snapshot} {snapshot}")
            return snapshot


        def journal_cursor():
            vm.succeed("journalctl --sync")
            last = vm.succeed("journalctl -n 1 -o json --no-pager").strip()
            return json.loads(last)["__CURSOR"]


        def journal_since(cursor):
            # The harness closes the window with an entry of its own, so a read
            # that missed the window fails instead of finding nothing.
            vm.succeed("echo end of the window | systemd-cat -t refusal-harness")
            vm.succeed("journalctl --sync")
            entries = vm.succeed(
                f"journalctl --after-cursor={shlex.quote(cursor)} -o json --no-pager"
            )
            assert "end of the window" in entries, "the journal read missed the window"
            return entries


        def gained(path, offset, command):
            # What a changed file holds from offset on, through command; a file
            # that went away since the listing holds nothing.
            return vm.succeed(
                f"tail -c +{offset + 1} {shlex.quote(path)} 2> /dev/null | {command} || true"
            )


        def decoy_traces(mounts, before_snapshot, cursor, label):
            after_snapshot = decoy_snapshot(mounts, label)
            old, new = distro_checks.split_comm(
                vm.succeed(f"LC_ALL=C comm -3 {before_snapshot} {after_snapshot}")
            )
            before = distro_checks.parse_listing(old)
            after = distro_checks.parse_listing(new)
            changes = distro_checks.listing_changes(
                before, after, distro_checks.CHANGE_FIELDS
            )
            journal = journal_since(cursor)
            # What each changed file gained: past its old end when it only grew,
            # as a log does, else all of it. The journal's own files hold the
            # whole boot; its entries are read one by one instead.
            written = {}
            holding = []
            for path in changes:
                if after.get(path, {}).get("type") != "f":
                    continue
                if path.startswith("/var/log/journal/"):
                    continue
                offset = distro_checks.scan_offset(before, after, path)
                written[path] = gained(path, offset, "head -c 4000")
                hits = gained(path, offset, f"grep -a -c -i -F {trace_patterns}")
                if int(hits.strip() or "0") > 0:
                    holding.append(path)
            traces = {
                "changed outside the boot noise": distro_checks.outside_boot_noise(
                    changes, boot_noise
                ),
                "named like a NAILS file": distro_checks.named_like_nails(
                    changes, nails_names
                ),
                "holding what names NAILS": sorted(holding),
                "journal entries naming NAILS": distro_checks.journal_traces(
                    journal, trace_tokens
                ),
            }
            return changes, written, journal, traces


        vm.wait_for_unit("multi-user.target")
        vm.succeed(f"test -x {nails}")

        with subtest(f"the decoy is the stock {family} image"):
            os_release = dict(
                line.split("=", 1)
                for line in vm.succeed("cat /etc/os-release").splitlines()
                if "=" in line
            )
            print(
                "decoy os-release: "
                + " ".join(
                    f"{key}={os_release.get(key, '-')}"
                    for key in ("ID", "VERSION_ID", "VARIANT_ID", "PRETTY_NAME")
                )
            )
            assert os_release.get("ID", "").strip('"') == os_id, os_release

        with subtest("a hidden root is ready on the decoy as the image ships it"):
            vm.succeed(
                f"mkdir -p {work} && mount -t tmpfs -o size=128m,mode=0700 refusal {work}"
            )
            vm.succeed(
                """cat > %s <<'EOF'
        hidden_volume_root = "/mnt/data"
        minimum_space_mb = 100
        EOF"""
                % shlex.quote(config)
            )
            vm.succeed("""${hiddenRoot.setupHiddenRoot}""")
            # The decoy is not made amnesic: the platform gate comes before any
            # check of the decoy's posture, and the persistent journal is where a
            # trace of the refused run would land.

        with subtest("check and activate run between listings of what they could change"):
            mounts = distro_checks.decoy_disk_mounts(
                distro_checks.parse_findmnt_pairs(
                    vm.succeed("findmnt -rn -o TARGET,FSTYPE")
                ),
                hidden_root,
            )
            # The cursor first: journald's own work for the harness's request
            # lands before the window, not in it.
            cursor = journal_cursor()
            decoy_before = decoy_snapshot(mounts, "decoy-before")
            entries = vm.succeed(f"wc -l < {decoy_before}").strip()
            print(f"decoy disk filesystems {mounts}: {entries} entries")
            run_before = session.run_entries(vm)
            boot = "cat /proc/sys/kernel/random/boot_id; systemctl show -p SoftRebootsCount --value"
            boot_before = vm.succeed(boot)
            tree_before = hidden_tree()

            check = run_nails("check --json", "check")
            tree_checked = hidden_tree()
            activate = run_nails("activate -y", "activate")
            activate_json = run_nails("activate -y --json", "activate-json")
            tree_after = hidden_tree()

            run_after = session.run_entries(vm)
            boot_after = vm.succeed(boot)
            # What the decoy disk and its journal gained while the commands ran,
            # judged last, once the positive control below has shown that the
            # same checks find a trace.
            refused_run = decoy_traces(mounts, decoy_before, cursor, "decoy-after")

        with subtest("activate refuses before it writes anything to the hidden root"):
            # Not a byte and not a timestamp: no state lock, no log, no report.
            changes = distro_checks.listing_changes(tree_checked, tree_after)
            assert not changes, (
                "the refused activations changed the hidden root:\n"
                + distro_checks.format_changes(changes)
            )

        with subtest("check leaves the hidden root holding what it held"):
            # Its writability test and its upper-fs probe each create a scratch
            # entry on the hidden root and remove it again, which moves the times
            # of the directories they used.
            moved = distro_checks.listing_changes(tree_before, tree_checked)
            print(
                "check moved on the hidden root: "
                + (distro_checks.format_changes(moved) or "nothing")
            )
            changes = distro_checks.listing_changes(
                tree_before, tree_checked, distro_checks.CONTENT_FIELDS
            )
            assert not changes, (
                "check changed what the hidden root holds:\n"
                + distro_checks.format_changes(changes)
            )

        with subtest("activate exits 8 with the family table's reason"):
            status, out, err = activate
            print(f"activate -y exited {status}:\n{err}")
            assert status == 8, (status, out, err)
            assert f"Unsupported host: {reason}" in err, err
            assert "Nothing was changed" in err, err
            status, out, err = activate_json
            print(f"activate -y --json exited {status}: {out.strip()}")
            assert status == 8, (status, out, err)
            envelope = json.loads(out.strip().splitlines()[-1])
            assert envelope["ok"] is False, envelope
            assert envelope["error"]["code"] == "unsupported", envelope
            assert envelope["error"]["message"].startswith(
                f"Unsupported host: {reason}"
            ), envelope

        with subtest("activate starts no session"):
            assert run_after == run_before, (
                f"/run gained {sorted(run_after - run_before)} "
                f"and lost {sorted(run_before - run_after)}"
            )
            session.assert_decoy_root(vm)
            vm.fail("test -e /run/overlay-runtime")
            vm.fail("test -e /run/systemd/system/systemd-soft-reboot.service.d")
            jobs = vm.succeed("systemctl list-jobs --no-legend --no-pager")
            assert "soft-reboot" not in jobs, jobs
            assert boot_after == boot_before, (boot_before, boot_after)

        with subtest("check fails the platform row with the family table's reason"):
            status, out, err = check
            report = json.loads(out.strip().splitlines()[-1])
            rows = {row["name"]: row for row in report["data"]["checks"]}
            print(
                f"check exited {status}; its rows: "
                + ", ".join(f"{name} {row['status']}" for name, row in rows.items())
            )
            print(f"platform row: {rows.get('platform')}")
            row = rows["platform"]
            assert row["status"] == "fail", row
            assert row["message"].startswith(reason), row
            assert report["ok"] is False and report["data"]["ready"] is False, report
            # A failed row is a pre-flight refusal.
            assert status == 4, (status, err)

        with subtest("the decoy checks find a planted trace (positive control)"):
            cursor = journal_cursor()
            before = decoy_snapshot(mounts, "control-before")
            vm.succeed(f"printf '%s\\n' {hidden_root} > /root/nails.log")
            vm.succeed(f"printf '%s\\n' {hidden_root} > /var/tmp/refusal-control")
            vm.succeed(f"echo {hidden_root} | systemd-cat -t refusal-control")
            _, _, _, traces = decoy_traces(mounts, before, cursor, "control-after")
            assert traces == {
                "changed outside the boot noise": ["/root", "/root/nails.log"],
                "named like a NAILS file": ["/root/nails.log"],
                "holding what names NAILS": [
                    "/root/nails.log",
                    "/var/tmp/refusal-control",
                ],
                "journal entries naming NAILS": [f"refusal-control: {hidden_root}"],
            }, traces

        with subtest("the decoy disk holds nothing of the refused run"):
            changes, written, journal, traces = refused_run
            print(
                "changed on the decoy disk while the commands ran:\n"
                + (distro_checks.format_changes(changes) or "nothing")
            )
            for path, text in written.items():
                shown = "".join(ch if ch.isprintable() or ch in "\n\t" else "." for ch in text)
                print(f"--- what {path} gained meanwhile (at most 4000 bytes):\n{shown}")
            print(
                "journal entries written meanwhile:\n"
                + "\n".join(distro_checks.journal_messages(journal))
            )
            found = {kind: hits for kind, hits in traces.items() if hits}
            assert not found, f"the refused run left a trace on the decoy disk: {found}"
      '';
    };
in
lib.mapAttrs' (name: entry: lib.nameValuePair "${name}-refusal" (refusalFor entry)) refusedImages
