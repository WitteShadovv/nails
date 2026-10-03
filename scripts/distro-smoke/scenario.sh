#!/usr/bin/env bash
#
# The container smoke scenario, run inside a privileged systemd container as
# root. It is the Debian/Ubuntu counterpart of the NixOS VM smoke test
# (nix/distro-tests/tests/smoke.nix): it drives the overlay-only backend through
# the full lifecycle on an FHS host and proves a hidden-session write cannot
# reach the decoy's read-only system trees, nor the decoy disk after teardown.
#
# What the container tier keeps from the VM tier: platform detection, the
# decoy-persistence preflight, overlay-only activation, the read-only /usr guard
# (EROFS), the emergency and deactivate teardowns, and a before/after
# decoy-unchanged check with canary-absence.
#
# What it cannot do, so the VM tier still owns it (see docs/ci.md):
#   * A real reboot. A container cannot reboot, so the reboot targets are masked
#     and deactivate's reboot dispatch is expected to fail after the teardown has
#     already completed -- the decoy restore and unmounts run regardless.
#   * The host-side disk-image forensic scan (`strings` over the raw decoy
#     image). This tier can only compare the decoy files in place, a weaker leak
#     check than the VM tier's image scan; it does not claim parity.
#
# Usage: scenario.sh [NAILS_BIN]
#   NAILS_BIN defaults to /mnt/nails-bin/nails, where run.sh copies the static
#   musl binary. The binary is invoked by absolute path from a read-only mount,
#   so it is never one of the trees the overlay freezes.

set -euo pipefail

nails="${1:-/mnt/nails-bin/nails}"
config="/run/nails-smoke.toml"
hidden_root="/mnt/data"
backing="/var/tmp/data.img"

# The trees the FHS backend overlays. The stable set (never auto-cleaned) is
# used for the byte-for-byte decoy-unchanged check; var and tmp are overlaid and
# asserted mounted, but the system writes to them constantly, so they are left
# out of the before/after comparison to avoid false positives.
overlay_trees=(home etc srv opt var tmp usr)
stable_trees=(home etc srv opt)

log() { printf '=== %s\n' "$*"; }

fail() {
	printf '!!! %s\n' "$*" >&2
	exit 1
}

# A privileged container drives systemd as PID 1; `systemctl reboot` would stop
# that systemd and kill the container. Mask the power targets up front so no
# lifecycle step can tear the container down mid-scenario: `systemctl reboot`
# then fails fast, which is exactly how deactivate's reboot dispatch behaves on a
# host that cannot reboot -- the teardown before it still runs.
mask_reboot() {
	log "masking the reboot/poweroff targets (a container cannot reboot)"
	systemctl mask reboot.target poweroff.target halt.target kexec.target >/dev/null 2>&1 || true
}

# Port of nix/distro-tests/lib/hidden-root.nix (makeJournalVolatile): switch
# journald to volatile so the decoy-persistence preflight passes.
make_journal_volatile() {
	log "switching journald to volatile storage"
	mkdir -p /etc/systemd/journald.conf.d
	printf '[Journal]\nStorage=volatile\n' \
		>/etc/systemd/journald.conf.d/00-nails-volatile.conf
	systemctl restart systemd-journald
}

# Port of nix/distro-tests/lib/hidden-root.nix (setupHiddenRoot): a 1 GiB
# loop-mounted ext4 image (LUKS when cryptsetup is present) with the overlay
# upper/work layout NAILS expects. Every on-disk name is neutral ("data").
setup_hidden_root() {
	log "creating the hidden root at ${hidden_root}"
	truncate -s 1G "$backing"

	if command -v cryptsetup >/dev/null 2>&1; then
		log "cryptsetup present: backing the hidden root with LUKS"
		echo -n 'test-passphrase' | cryptsetup luksFormat -q --iter-time 1 "$backing" -
		echo -n 'test-passphrase' | cryptsetup luksOpen --key-file - "$backing" data
		mkfs.ext4 -q -L data /dev/mapper/data
		mkdir -p "$hidden_root"
		mount /dev/mapper/data "$hidden_root"
	else
		log "cryptsetup absent: backing the hidden root with plain ext4 on loop"
		loop="$(losetup --show -f "$backing")"
		mkfs.ext4 -q -L data "$loop"
		mkdir -p "$hidden_root"
		mount "$loop" "$hidden_root"
	fi

	local tree
	for tree in "${overlay_trees[@]}"; do
		mkdir -p "$hidden_root/$tree" "$hidden_root/.work/$tree"
	done
	log "hidden root ready at ${hidden_root}"
}

# Tear the hidden root back down between the two activation rounds so each round
# starts from a clean loop/ext4 image.
teardown_hidden_root() {
	umount "$hidden_root" 2>/dev/null || true
	if [ -e /dev/mapper/data ]; then
		cryptsetup luksClose data 2>/dev/null || true
	fi
	losetup -j "$backing" 2>/dev/null | cut -d: -f1 | while read -r dev; do
		[ -n "$dev" ] && losetup -d "$dev" 2>/dev/null || true
	done
	rm -f "$backing"
}

# The 7-overlay config, mirroring nix/distro-tests/tests/smoke.nix. Every base-OS
# tree that must be isolated on an FHS host is overlaid; /usr is the core binary
# root the writable-trees preflight refuses to leave writable.
write_config() {
	log "writing the overlay config to ${config}"
	mkdir -p /run
	{
		printf 'hidden_volume_root = "%s"\n' "$hidden_root"
		printf 'overlay_mode = "explicit"\n'
		printf 'risky_services = "skip"\n'
		local tree
		for tree in "${overlay_trees[@]}"; do
			printf '\n[[overlays]]\n'
			printf 'name = "%s"\n' "$tree"
			printf 'lower = "/%s"\n' "$tree"
			printf 'upper = "%s/%s"\n' "$hidden_root" "$tree"
			printf 'work = "%s/.work/%s"\n' "$hidden_root" "$tree"
			printf 'target = "/%s"\n' "$tree"
		done
	} >"$config"
}

# Plant a decoy marker in each stable tree and record its digest. These files
# live on the decoy (the overlay lower); after teardown they must be
# byte-identical, proving the hidden session never wrote through to the decoy.
decoy_manifest="/run/nails-decoy-manifest.sha256"

plant_decoy_markers() {
	log "planting decoy markers and recording their digests"
	local tree
	for tree in "${stable_trees[@]}"; do
		printf 'decoy-content-%s\n' "$tree" >"/$tree/nails-decoy-marker"
	done
	: >"$decoy_manifest"
	for tree in "${stable_trees[@]}"; do
		sha256sum "/$tree/nails-decoy-marker" >>"$decoy_manifest"
	done
}

assert_overlays_mounted() {
	local mounts tree
	mounts="$(mount)"
	for tree in "${overlay_trees[@]}"; do
		grep -q "overlay on /$tree " <<<"$mounts" ||
			fail "/$tree is not overlaid"
	done
	log "all ${#overlay_trees[@]} trees are overlaid"
}

assert_no_overlays() {
	local mounts tree
	mounts="$(mount)"
	for tree in "${overlay_trees[@]}"; do
		if grep -q "overlay on /$tree " <<<"$mounts"; then
			fail "an overlay survived teardown on /$tree"
		fi
	done
	log "no overlay survived teardown"
}

write_hidden_canaries() {
	log "writing hidden canaries through the overlays"
	local tree
	for tree in "${overlay_trees[@]}"; do
		# /usr is read-only by design, so skip it; the EROFS assertion covers it.
		[ "$tree" = "usr" ] && continue
		printf 'NAILS_CANARY_%s\n' "$tree" >"/$tree/nails-canary-$tree"
	done
}

assert_decoy_unchanged() {
	log "verifying the decoy is byte-identical and carries no hidden canary"
	sha256sum --check --strict "$decoy_manifest" ||
		fail "a decoy marker changed after the hidden session"
	local tree
	for tree in "${overlay_trees[@]}"; do
		[ "$tree" = "usr" ] && continue
		if [ -e "/$tree/nails-canary-$tree" ]; then
			fail "hidden canary leaked onto the decoy at /$tree/nails-canary-$tree"
		fi
	done
	log "decoy unchanged and no canary leaked"
}

main() {
	test -x "$nails" || fail "nails binary not executable at $nails"

	mask_reboot
	make_journal_volatile

	log "platform detection selects the overlay-only Debian-family backend"
	init_out="$("$nails" init /root/nails-base 2>&1)" || {
		printf '%s\n' "$init_out"
		fail "nails init failed"
	}
	grep -q "overlay-only" <<<"$init_out" ||
		fail "expected the overlay-only backend, got: $init_out"

	setup_hidden_root
	write_config
	plant_decoy_markers

	# The decoy-persistence preflight is satisfied by the volatile journal above;
	# the VM tier exercises the refusal branch, which a stock cloud image with a
	# persistent journal triggers but a container often does not.
	log "decoy-persistence preflight passes with a volatile journal"
	"$nails" --config "$config" check --overlay-only ||
		fail "overlay-only check failed"

	# Negative control, part one: /usr is writable on the decoy before activation,
	# so the EROFS assertion below is real, not a pre-existing read-only /usr.
	log "negative control: /usr is writable before activation"
	if ! touch /usr/nails-pre-activation; then
		fail "/usr was not writable before activation; the EROFS check would be vacuous"
	fi
	rm -f /usr/nails-pre-activation

	log "overlay-only activation (round 1, emergency teardown)"
	"$nails" --config "$config" activate --overlay-only --session keep -y ||
		fail "activation failed"
	assert_overlays_mounted
	write_hidden_canaries

	log "writes under /usr and /usr/local fail with EROFS"
	usr_err="$(touch /usr/nails-should-fail 2>&1)" &&
		fail "a write under /usr unexpectedly succeeded"
	grep -qiE "read-only|erofs" <<<"$usr_err" ||
		fail "expected a read-only error under /usr, got: $usr_err"
	local_err="$(touch /usr/local/nails-should-fail 2>&1)" &&
		fail "a write under /usr/local unexpectedly succeeded"
	grep -qiE "read-only|erofs" <<<"$local_err" ||
		fail "expected a read-only error under /usr/local, got: $local_err"

	log "status and verify operate on the active session"
	"$nails" status || fail "status failed"
	"$nails" verify || fail "verify failed"

	log "emergency teardown (fast, no reboot)"
	"$nails" emergency --no-countdown || fail "emergency failed"
	assert_no_overlays

	log "overlay-only activation (round 2, deactivate teardown)"
	teardown_hidden_root
	setup_hidden_root
	plant_decoy_markers
	"$nails" --config "$config" activate --overlay-only --session keep -y ||
		fail "re-activation failed"
	assert_overlays_mounted
	write_hidden_canaries

	# deactivate ends with a reboot into the decoy. The reboot targets are masked,
	# so the reboot dispatch fails after the unmount + decoy restore have already
	# run; tolerate the non-zero exit and assert the teardown effects instead.
	log "deactivate teardown (reboot dispatch expected to fail in a container)"
	"$nails" deactivate -y || log "deactivate returned non-zero (reboot could not be dispatched; teardown already done)"
	assert_no_overlays
	assert_decoy_unchanged

	log "container smoke scenario passed"
}

main "$@"
