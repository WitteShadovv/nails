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
#
# The links fixtures record files through a directory link, as Fedora does:
# its filesystem package installs /lib as a link to usr/lib (and /bin, /sbin,
# /lib64 and /var/run as links too), and its kernel packages record their
# modules below /lib/modules, which rpm installs into /usr/lib/modules:
#
#   decoy:   filesystem 3.18-1, kernel-modules 6.17.1-200.fc44 (both x86_64)
#   hidden:  kernel-modules 6.18.0-200.fc44 installed, 6.17.1 removed
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

# Build the package of the spec file $1, named $2-$3-$4.$5.
build() {
  rpmbuild --quiet --define "_topdir $work/top" --define "_dbpath $work/build-db" --define "_buildhost fixtures" \
    --define "source_date_epoch_from_changelog 0" -bb "$1" >/dev/null
  find "$work/top/RPMS" -name "$2-$3-$4.$5.rpm"
}

filesystem() {
  cat > "$work/filesystem.spec" <<'SPEC'
Name: filesystem
Version: 3.18
Release: 1
Summary: A package of the NAILS fixtures
License: GPL-3.0-or-later
BuildArch: x86_64
%global debug_package %{nil}
%global __os_install_post %{nil}
%description
The directory layout of a Fedora system, its links in /usr merged.
%install
mkdir -p %{buildroot}/usr/bin %{buildroot}/usr/lib %{buildroot}/usr/lib64 %{buildroot}/usr/sbin
mkdir -p %{buildroot}/run %{buildroot}/var
ln -snf usr/bin %{buildroot}/bin
ln -snf usr/sbin %{buildroot}/sbin
ln -snf usr/lib %{buildroot}/lib
ln -snf usr/lib64 %{buildroot}/lib64
ln -snf ../run %{buildroot}/var/run
%files
/bin
/lib
/lib64
/sbin
%dir /run
%dir /usr
%dir /usr/bin
%dir /usr/lib
%dir /usr/lib64
%dir /usr/sbin
%dir /var
/var/run
SPEC
  build "$work/filesystem.spec" filesystem 3.18 1 x86_64
}

kernel_modules() { # version
  local version=$1 kver=$1-200.fc44.x86_64
  cat > "$work/kernel-modules-$version.spec" <<SPEC
Name: kernel-modules
Version: $version
Release: 200.fc44
Summary: A package of the NAILS fixtures
License: GPL-3.0-or-later
BuildArch: x86_64
%global debug_package %{nil}
%global __os_install_post %{nil}
%description
A kernel's modules, recorded below /lib/modules as Fedora records them.
%install
mkdir -p %{buildroot}/lib/modules/$kver/kernel/drivers/nails
echo nails > %{buildroot}/lib/modules/$kver/kernel/drivers/nails/nails.ko.xz
%files
%dir /lib/modules/$kver
%dir /lib/modules/$kver/kernel
%dir /lib/modules/$kver/kernel/drivers
%dir /lib/modules/$kver/kernel/drivers/nails
/lib/modules/$kver/kernel/drivers/nails/nails.ko.xz
SPEC
  build "$work/kernel-modules-$version.spec" kernel-modules "$version" 200.fc44 x86_64
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

layout=$(filesystem)
modules1=$(kernel_modules 6.17.1)
modules2=$(kernel_modules 6.18.0)
rpm --define "_db_backend sqlite" --dbpath "$work/links-decoy" --initdb
rpmdb "$work/links-decoy" -i --ignorearch --ignoreos "$layout" "$modules1"
cp -a "$work/links-decoy" "$work/links-hidden"
rpmdb "$work/links-hidden" -i --ignorearch --ignoreos "$modules2"
rpmdb "$work/links-hidden" -e kernel-modules-6.17.1-200.fc44.x86_64

mkdir -p "$out"
for side in shared decoy hidden links-decoy links-hidden; do
  wal=$work/$side/rpmdb.sqlite-wal
  if [ -s "$wal" ]; then echo "the log of $side is not empty" >&2; exit 1; fi
  cp "$work/$side/rpmdb.sqlite" "$out/rpmdb-$side.sqlite"
done
for p in "$alpha11" "$delta" "$kernel1"; do cp "$p" "$out/"; done
