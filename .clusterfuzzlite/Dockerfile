# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The image ClusterFuzzLite builds the fuzz targets in: OSS-Fuzz's Rust
# builder (clang, libFuzzer and cargo-fuzz), pinned by digest, with the
# toolchain rust-toolchain.toml pins and this repository's source. The
# builder's own nightly is older than the workspace's Rust version.
FROM gcr.io/oss-fuzz-base/base-builder-rust:v1@sha256:3428d0a90b1e7efbe2ba947bd1d0c9a70594986b4b6553804547f1fb24cfc92f
COPY . $SRC/nails
WORKDIR $SRC/nails
RUN rustup toolchain install "$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)" --profile minimal
COPY .clusterfuzzlite/build.sh $SRC/
