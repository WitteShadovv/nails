// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for shell module

use super::*;
use crate::MockFilesystem;
use crate::target_user::TargetUser;

fn create_test_shell() -> ShellInstrumentation<MockFilesystem> {
    let fs = MockFilesystem::new();
    let config = Config::default();
    ShellInstrumentation::new(fs, config)
}

fn set_mock_home(fs: &MockFilesystem, home: &str) {
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists(home, true);
}

fn gate_config() -> Config {
    Config {
        hidden_volume_root: "/mnt/data".into(),
        ..Default::default()
    }
}

const HOME_ON_HIDDEN_OVERLAY: &str = "36 1 0:40 / /home rw,relatime - overlay overlay \
     rw,lowerdir=/home,upperdir=/mnt/data/home,workdir=/mnt/data/.work/home";

const HOME_ON_DECOY_DISK: &str = "36 1 8:2 / /home rw,relatime - ext4 /dev/sda2 rw";

mod alias_scripts;
mod colors;
mod detection;
mod overlay_gate;
mod persona_masks;
mod prompt_scripts;
mod rc_files;
mod setup_cleanup;
mod xdg_autostart;
