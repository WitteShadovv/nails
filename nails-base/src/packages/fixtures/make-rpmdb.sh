#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Write the rpm database fixtures of nails-base/src/packages/rpm_tests.rs with
# rpm itself: `nix shell nixpkgs#rpm -c ./make-rpmdb.sh <out dir>`.
#
# A database the decoy and hidden sessions share is copied, as a hidden
# session's first change copies it into the upper, and each side changes its
# own copy afterwards:
#
#   shared:  alpha 1.0-1, beta 2.0-1, gamma 1.0-1, kernel-core 6.17.1 (x86_64)
#   decoy:   beta updated to 2.1-1, delta 1:3.0-1 installed, gamma removed,
#            kernel-core 6.17.2 installed beside 6.17.1
#   hidden:  alpha updated to 1.1-1, epsilon 0.5-1 installed
#
# Each package has a file in /usr/share/<name> and a program in /usr/bin,
# both named after its version, a configuration file in /etc, a ghost log in
# /var/log and its own directory.
set -euo pipefail

out=$(realpath "$1")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export HOME=$work

package() { # name version release epoch arch
  local name=$1 version=$2 release=$3 epoch=$4 arch=$5
  cat > "$work/$name-$version.spec" <<SPEC
Name: $name
Version: $version
Release: $release
${epoch:+Epoch: $epoch}
Summary: A package of the NAILS fixtures
License: GPL-3.0-or-later
BuildArch: $arch
%global debug_package %{nil}
%global __os_install_post %{nil}
%description
A package of the NAILS fixtures.
%install
mkdir -p %{buildroot}/usr/share/$name %{buildroot}/usr/bin %{buildroot}/etc
echo $name-$version > %{buildroot}/usr/share/$name/$version
printf '#!/bin/sh\n' > %{buildroot}/usr/bin/$name-$version
echo setting > %{buildroot}/etc/$name.conf
%files
%dir /usr/share/$name
/usr/share/$name/$version
/usr/bin/$name-$version
%config(noreplace) /etc/$name.conf
%ghost /var/log/$name.log
SPEC
  rpmbuild --quiet --define "_topdir $work/top" --define "_dbpath $work/build-db" --define "_buildhost fixtures" \
    --define "source_date_epoch_from_changelog 0" -bb "$work/$name-$version.spec" >/dev/null
  find "$work/top/RPMS" -name "$name-$version-$release.*.rpm"
}

export SOURCE_DATE_EPOCH=1767225600
rpmdb() { rpm --define "_db_backend sqlite" --dbpath "$1" "${@:2}" --justdb --nodeps \
  --noscripts --notriggers; }

alpha10=$(package alpha 1.0 1 "" noarch)
alpha11=$(package alpha 1.1 1 "" noarch)
beta20=$(package beta 2.0 1 "" noarch)
beta21=$(package beta 2.1 1 "" noarch)
gamma=$(package gamma 1.0 1 "" noarch)
delta=$(package delta 3.0 1 1 noarch)
epsilon=$(package epsilon 0.5 1 "" noarch)
kernel1=$(package kernel-core 6.17.1 200.fc44 "" x86_64)
kernel2=$(package kernel-core 6.17.2 200.fc44 "" x86_64)

shared=$work/shared
rpm --define "_db_backend sqlite" --dbpath "$shared" --initdb
rpmdb "$shared" -i --ignorearch --ignoreos "$alpha10" "$beta20" "$gamma" "$kernel1"

cp -a "$shared" "$work/decoy"
rpmdb "$work/decoy" -U --ignorearch --ignoreos "$beta21"
rpmdb "$work/decoy" -i --ignorearch --ignoreos "$delta" "$kernel2"
rpmdb "$work/decoy" -e gamma

cp -a "$shared" "$work/hidden"
rpmdb "$work/hidden" -U --ignorearch --ignoreos "$alpha11"
rpmdb "$work/hidden" -i --ignorearch --ignoreos "$epsilon"

mkdir -p "$out"
for side in shared decoy hidden; do
  wal=$work/$side/rpmdb.sqlite-wal
  if [ -s "$wal" ]; then echo "the log of $side is not empty" >&2; exit 1; fi
  cp "$work/$side/rpmdb.sqlite" "$out/rpmdb-$side.sqlite"
done
for p in "$alpha11" "$delta" "$kernel1"; do cp "$p" "$out/"; done
