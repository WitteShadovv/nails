# Test 11: the examiner's view of setup traces on a decoy image
#
# `verify --offline --examiner` reports the traces of the setup an
# examiner looks for, grouped by what they suggest. The secondary test disk
# stands in for a seized decoy disk: a GPT with an ext4 "decoy root" partition
# and a second partition. The clean run builds it with nothing an examiner
# would flag and expects no setup traces; the seeded run adds one instance of
# every setup trace in the residue catalog (a LUKS2 header on the second
# partition, random data in a partition gap, a container file, crypttab and
# fstab entries, an LVM archive, udisks2 state, VeraCrypt installed, recent
# files, VeraCrypt history and a shell line naming the unlock) plus the session
# channels the catalog probes by path, and expects every one to be reported.
# The audit reads the disk raw and the root read-only: a SHA-256 of the whole
# disk before and after proves it wrote nothing.

{ pkgs, ... }:
let
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "examiner-audit";
  meta.tags = [ "forensic" ];

  baseNode = {
    extraPackages = [ pkgs.e2fsprogs ];
  };

  testScript = _: ''
    import json
    import shlex

    ${testHelpers.writeHeadlessConfigFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/examiner-headless.toml"
    write_headless_config(headless_config)
    disk = machine.succeed("readlink -f /dev/disk/by-id/virtio-data").strip()
    image = "/mnt/image"

    def build_disk():
        # GPT: p1 (decoy root, ext4) 1 MiB..257 MiB, p2 300 MiB..364 MiB,
        # leaving a gap between them and unpartitioned space after p2.
        machine.succeed(
            f"wipefs -a {disk} >/dev/null 2>&1 || true",
            f"dd if=/dev/zero of={disk} bs=1M count=400 conv=fsync status=none",
            f"printf 'label: gpt\\nstart=2048, size=524288, type=linux\\n"
            f"start=614400, size=131072, type=linux\\n' | sfdisk -q {disk}",
            "udevadm settle",
            f"mkfs.ext4 -q -F -L decoy {disk}1",
            f"mkfs.ext4 -q -F {disk}2",
            f"mkdir -p {image}",
            f"mount {disk}1 {image}",
            f"mkdir -p {image}/etc {image}/home/alice {image}/root",
            f"printf 'root:x:0:0::/root:/bin/sh\\nalice:x:1000:100::/home/alice:/bin/bash\\n'"
            f" > {image}/etc/passwd",
            f"printf 'LABEL=decoy / ext4 defaults 0 1\\n' > {image}/etc/fstab",
            f"printf 'ls\\nvim notes.txt\\n' > {image}/home/alice/.bash_history",
        )

    def audit():
        # Capture under /run (tmpfs) so nothing lands on a disk under test.
        command = (
            f"nails --no-log-file --config {shlex.quote(headless_config)} verify --json"
            f" --offline --root {image} --examiner --disk {disk}"
        )
        machine.succeed(
            "bash -c "
            + shlex.quote(
                f"set +e; {command} > /run/audit.json 2>/run/audit.err;"
                " printf '%s' $? > /run/audit.rc"
            )
        )
        rc = int(machine.succeed("cat /run/audit.rc"))
        payload = json.loads(machine.succeed("cat /run/audit.json"))["data"]
        return rc, payload

    def reported_ids(payload):
        return {
            finding["catalog_id"]
            for group in payload["examiner"]["groups"]
            for finding in group["findings"]
        }

    with subtest("a clean decoy disk reports no setup traces"):
        build_disk()
        machine.succeed(f"umount {image}", f"mount -o ro {disk}1 {image}")
        rc, payload = audit()
        assert payload["examiner"]["groups"] == [], payload["examiner"]
        assert rc == 0, (rc, payload)
        # The raw disk was read, so its classes are not listed as unchecked.
        assert not any("--disk" in area for area in payload["areas_not_checked"]), payload

    with subtest("seed every setup trace and the path-probed session channels"):
        machine.succeed(f"umount {image}")
        build_disk()
        machine.succeed(
            # Setup traces on the decoy root.
            f"printf 'secret /home/alice/vault.hc none tcrypt,veracrypt\\n' > {image}/etc/crypttab",
            f"printf '/home/alice/disk.img /mnt/x ext4 loop 0 0\\n' >> {image}/etc/fstab",
            f"mkdir -p {image}/etc/lvm/archive",
            f"printf 'description = \"Created *before* executing vgcreate hvg /dev/mapper/data\"\\n"
            f"creation_host = \"decoy\"\\ncreation_time = 1790000000\\n\\nhvg {{\\n}}\\n'"
            f" > {image}/etc/lvm/archive/hvg_00000-1.vg",
            f"mkdir -p {image}/var/lib/udisks2 && echo '[Drive]' > {image}/var/lib/udisks2/drive.conf",
            f"mkdir -p {image}/usr/bin && printf '#!/bin/sh\\n' > {image}/usr/bin/veracrypt",
            f"dd if=/dev/urandom of={image}/home/alice/vault.hc bs=1M count=4 status=none",
            f"mkdir -p {image}/home/alice/.local/share {image}/home/alice/.config/VeraCrypt",
            f"printf '<xbel>\\n<bookmark href=\"file:///home/alice/vault.hc\"/>\\n</xbel>\\n'"
            f" > {image}/home/alice/.local/share/recently-used.xbel",
            f"printf '<history><volume>/home/alice/vault.hc</volume></history>\\n'"
            f" > {image}/home/alice/.config/VeraCrypt/History.xml",
            f"printf 'sudo cryptsetup open /dev/sdb2 data\\n' >> {image}/home/alice/.bash_history",
            # Session channels the catalog probes by path.
            f"mkdir -p {image}/var/log/sudo-io/00/00/01 {image}/var/crash",
            f"echo 'alice : COMMAND=/mnt/usb/nails' > {image}/var/log/sudo.log",
            f"echo log > {image}/var/log/sudo-io/00/00/01/log",
            f"echo core > {image}/var/crash/core.1",
            f"mkdir -p {image}/var/lib/systemd/timesync {image}/var/lib/systemd/timers",
            f"touch {image}/var/lib/systemd/timesync/clock",
            f"touch {image}/var/lib/systemd/timers/stamp-fstrim.timer",
            f"umount {image}",
            # Raw-disk traces: a LUKS2 header on p2, random data filling the gap.
            f"printf 'passphrase' | cryptsetup luksFormat --type luks2 -q --key-file=- {disk}2",
            f"dd if=/dev/urandom of={disk} bs=1M seek=257 count=43 conv=notrunc,fsync status=none",
            f"mount -o ro {disk}1 {image}",
        )

    with subtest("the audit reports every seeded trace and changes nothing"):
        before = machine.succeed(f"sha256sum {disk}").split()[0]
        rc, payload = audit()
        after = machine.succeed(f"sha256sum {disk}").split()[0]
        assert before == after, "the audit wrote to the disk it inspected"

        setup_ids = reported_ids(payload)
        for expected in [
            "luks-headers",
            "high-entropy-space",
            "container-candidates",
            "crypttab-fstab",
            "lvm-metadata-archive",
            "udisks2-state",
            "backend-tooling",
            "container-history",
        ]:
            assert expected in setup_ids, (expected, payload["examiner"])

        session = " ".join(
            finding["message"]
            for finding in payload["findings"]
            if finding["category"] == "catalog"
        )
        for expected in [
            "sudo-logfile",
            "sudo-io-log",
            "crash-dumps",
            "timesync-clock",
            "timer-stamps",
        ]:
            assert f"[{expected}]" in session, (expected, payload["findings"])

        # The sudo log and I/O log are warnings, so verify exits 10; the setup
        # traces alone never change the status.
        assert rc == 10, (rc, payload["status"])
        conclusions = [group["conclusion"] for group in payload["examiner"]["groups"]]
        assert len(conclusions) == len(set(conclusions)), conclusions
        print(json.dumps(payload["examiner"], indent=2))
  '';
}
