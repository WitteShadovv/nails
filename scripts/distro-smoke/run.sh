#!/usr/bin/env bash
#
# The per-PR container smoke driver for the Debian/Ubuntu overlay-only backend.
#
# It is the cheap, KVM-free counterpart of the NixOS-driver VM suite
# (nix/distro-tests/): a privileged systemd container is the test host, so it
# runs on an ordinary GitHub-hosted runner where booting a KVM guest would not.
# See docs/ci.md ("The portable distribution lanes") for how the two tiers
# divide the work.
#
# Usage: scripts/distro-smoke/run.sh <image>
#   <image>  a base image, e.g. debian:12, debian:13 or ubuntu:24.04
#
# Environment:
#   NAILS_BIN     path to a prebuilt static binary; skips the cargo build.
#   KEEP_CONTAINER=1   leave the container running for inspection on failure.
#
# Requires: docker (with a reachable daemon), run as root or a docker-group user.
# Stock debian/ubuntu images ship no init, and NAILS refuses a non-systemd host,
# so the driver first bootstraps systemd into the image and commits a local tag.

set -euo pipefail

usage() {
	printf 'usage: %s <image>   (e.g. %s debian:12)\n' "$0" "$0" >&2
	exit 2
}

[ "$#" -eq 1 ] || usage
image="$1"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
repo_root="$(cd -- "$script_dir/../.." >/dev/null && pwd)"

# A unique, neutral suffix per run so parallel matrix jobs on one host do not
# collide on container or image names.
slug="$(printf '%s' "$image" | tr -c 'a-zA-Z0-9' '-')"
run_id="${slug}-$$-${RANDOM}"
container="nails-smoke-${run_id}"
boot_container="nails-smoke-bootstrap-${run_id}"
systemd_tag="nails-smoke-systemd:${run_id}"

log() { printf '### %s\n' "$*"; }
die() {
	printf '### ERROR: %s\n' "$*" >&2
	exit 1
}

command -v docker >/dev/null 2>&1 || die "docker is required but not on PATH"
docker info >/dev/null 2>&1 || die "the docker daemon is not reachable"

cleanup() {
	local status=$?
	docker rm -f "$boot_container" >/dev/null 2>&1 || true
	if [ "${KEEP_CONTAINER:-0}" = "1" ] && [ "$status" -ne 0 ]; then
		log "KEEP_CONTAINER=1 and the run failed: leaving $container for inspection"
	else
		docker rm -f "$container" >/dev/null 2>&1 || true
	fi
	docker image rm -f "$systemd_tag" >/dev/null 2>&1 || true
	return "$status"
}
trap cleanup EXIT

# Resolve the static binary: an explicit NAILS_BIN, otherwise a release musl
# build. musl + crt-static yields a fully static binary that runs unchanged in
# any base image, which is the exact artifact a user installs.
resolve_binary() {
	if [ -n "${NAILS_BIN:-}" ]; then
		[ -x "$NAILS_BIN" ] || die "NAILS_BIN=$NAILS_BIN is not executable"
		printf '%s' "$NAILS_BIN"
		return
	fi

	local target="x86_64-unknown-linux-musl"
	log "building the static musl binary ($target)" >&2
	(
		cd "$repo_root"
		RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+crt-static" \
			cargo build --release --locked --target "$target" -p nails-cli >&2
	)
	local target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
	local bin="$target_dir/$target/release/nails"
	[ -x "$bin" ] || die "expected a built binary at $bin"
	printf '%s' "$bin"
}

# Bootstrap systemd into the base image and commit it to a local tag. Base
# debian/ubuntu images ship no init; these packages give systemd as PID 1 plus
# the loop/ext4/module tools the hidden-root setup needs. cryptsetup is optional:
# the scenario falls back to plain ext4 when it is absent.
bootstrap_systemd_image() {
	log "bootstrapping systemd into $image" >&2
	docker rm -f "$boot_container" >/dev/null 2>&1 || true
	docker run -d --name "$boot_container" "$image" sleep infinity >/dev/null

	docker exec "$boot_container" sh -c '
		set -eu
		export DEBIAN_FRONTEND=noninteractive
		apt-get update -qq
		apt-get install -y --no-install-recommends \
			systemd systemd-sysv util-linux e2fsprogs kmod mount cryptsetup
		apt-get clean
		rm -rf /var/lib/apt/lists/*
	' >&2

	docker commit \
		--change 'ENTRYPOINT ["/sbin/init"]' \
		"$boot_container" "$systemd_tag" >/dev/null
	docker rm -f "$boot_container" >/dev/null 2>&1 || true
}

# Boot the committed image as a privileged systemd container and wait for the
# manager to come up (degraded is fine: a cloud image has units that do not apply
# in a container). --cgroupns=host plus the cgroup2 bind let systemd manage its
# own cgroups; the tmpfs mounts give it a writable /run.
start_container() {
	log "starting the privileged systemd container" >&2
	docker run -d --name "$container" \
		--privileged \
		--cgroupns=host \
		--tmpfs /run \
		--tmpfs /run/lock \
		-v /sys/fs/cgroup:/sys/fs/cgroup:rw \
		"$systemd_tag" >/dev/null

	local state
	for _ in $(seq 1 60); do
		state="$(docker exec "$container" systemctl is-system-running 2>/dev/null || true)"
		case "$state" in
		running | degraded)
			log "systemd is up ($state)" >&2
			return 0
			;;
		esac
		sleep 1
	done
	docker logs "$container" >&2 || true
	die "systemd did not come up in the container"
}

main() {
	local bin
	bin="$(resolve_binary)"
	log "using binary: $bin"

	bootstrap_systemd_image
	start_container

	log "copying the binary and scenario into the container"
	docker exec "$container" mkdir -p /mnt/nails-bin
	docker cp "$bin" "$container:/mnt/nails-bin/nails"
	docker exec "$container" chmod +x /mnt/nails-bin/nails
	docker cp "$script_dir/scenario.sh" "$container:/root/scenario.sh"
	docker exec "$container" chmod +x /root/scenario.sh

	log "running the smoke scenario for $image"
	docker exec "$container" /root/scenario.sh /mnt/nails-bin/nails

	log "container smoke passed for $image"
}

main "$@"
