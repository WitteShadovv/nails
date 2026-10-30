// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Compiles the window's Slint markup into Rust.
//!
//! The `testing` feature also compiles in the element tree's names and types,
//! which the headless UI tests need to find elements; a release build carries
//! none of it.

fn main() {
    // The widgets are the window's own (ui/adw/); the style only decides the
    // `Palette` global the window reads to follow the desktop's light or dark
    // setting.
    let config = slint_build::CompilerConfiguration::new()
        .with_style("fluent".into())
        .with_debug_info(std::env::var_os("CARGO_FEATURE_TESTING").is_some());
    slint_build::compile_with_config("ui/window.slint", config)
        .expect("the window's markup compiles");
}
