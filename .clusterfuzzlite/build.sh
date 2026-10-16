#!/bin/bash -eu
# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Builds the fuzz targets for ClusterFuzzLite, run by OSS-Fuzz's `compile`
# in the image of the Dockerfile here once it has put the sanitizer flags in
# RUSTFLAGS. Every cargo-fuzz target in fuzz/ goes to $OUT with its seed
# corpus, dictionary and libFuzzer options, where ClusterFuzzLite and
# OSS-Fuzz's helper look for them.

cd "$SRC/nails"

# The toolchain rust-toolchain.toml pins (the Dockerfile installs it), not
# the image's nightly. RUSTC_BOOTSTRAP lets this stable compiler accept the
# unstable sanitizer flag, as `just shuffle` does for an unstable libtest
# flag, so the fuzz build follows the toolchain pin without a nightly.
RUSTUP_TOOLCHAIN=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
export RUSTUP_TOOLCHAIN
export RUSTC_BOOTSTRAP=1

# Release builds with debug assertions and overflow checks: an arithmetic
# overflow on some input is a bug the fuzzers report.
cargo fuzz build --release --debug-assertions

built=fuzz/target/x86_64-unknown-linux-gnu/release
for source in fuzz/fuzz_targets/*.rs; do
  target=$(basename "$source" .rs)
  cp "$built/$target" "$OUT/"
  (cd "fuzz/seeds/$target" && zip -q -r "$OUT/${target}_seed_corpus.zip" .)
  for extra in "fuzz/dicts/$target.dict" "fuzz/options/$target.options"; do
    if [ -f "$extra" ]; then
      cp "$extra" "$OUT/"
    fi
  done
done
