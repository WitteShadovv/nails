use super::*;
use std::path::PathBuf;

fn make_test_process(name: &str, pid: u32, has_cwd: bool) -> ProcessInfo {
    ProcessInfo {
        pid,
        name: name.to_string(),
        cmdline: format!("/usr/bin/{}", name),
        cwd: PathBuf::from("/"),
        has_cwd_in_target: has_cwd,
        has_open_fds_in_target: false,
        has_mmap_in_target: false,
        service_name: None,
    }
}

// Tests for /var classification
#[test]
fn test_var_systemd_journald_safe() {
    let proc = make_test_process("systemd-journald", 234, false);
    let strategy = classify_process(&proc, Path::new("/var"));
    assert_eq!(strategy, RestartStrategy::Safe);
}

#[test]
fn test_var_rsyslogd_safe() {
    let proc = make_test_process("rsyslogd", 345, false);
    let strategy = classify_process(&proc, Path::new("/var"));
    assert_eq!(strategy, RestartStrategy::Safe);
}

#[test]
fn test_var_systemd_resolved_safe() {
    let proc = make_test_process("systemd-resolved", 456, false);
    let strategy = classify_process(&proc, Path::new("/var"));
    assert_eq!(strategy, RestartStrategy::Safe);
}

#[test]
fn test_var_networkmanager_risky() {
    let proc = make_test_process("NetworkManager", 567, false);
    let strategy = classify_process(&proc, Path::new("/var"));
    assert_eq!(strategy, RestartStrategy::Risky);
}

#[test]
fn test_var_unknown_process_safe() {
    let proc = make_test_process("unknown-daemon", 678, false);
    let strategy = classify_process(&proc, Path::new("/var"));
    assert_eq!(strategy, RestartStrategy::Safe);
}

// Tests for /etc classification
#[test]
fn test_etc_systemd_pid1_no_restart() {
    let proc = make_test_process("systemd", 1, false);
    let strategy = classify_process(&proc, Path::new("/etc"));
    assert_eq!(strategy, RestartStrategy::NoRestart);
}

#[test]
fn test_etc_systemd_not_pid1_safe() {
    let proc = make_test_process("systemd", 1234, false);
    let strategy = classify_process(&proc, Path::new("/etc"));
    assert_eq!(strategy, RestartStrategy::Safe);
}

#[test]
fn test_etc_dbus_daemon_risky() {
    let proc = make_test_process("dbus-daemon", 345, false);
    let strategy = classify_process(&proc, Path::new("/etc"));
    assert_eq!(strategy, RestartStrategy::Risky);
}

#[test]
fn test_etc_networkmanager_safe() {
    let proc = make_test_process("NetworkManager", 456, false);
    let strategy = classify_process(&proc, Path::new("/etc"));
    assert_eq!(strategy, RestartStrategy::Safe);
}

#[test]
fn test_etc_systemd_resolved_safe() {
    let proc = make_test_process("systemd-resolved", 567, false);
    let strategy = classify_process(&proc, Path::new("/etc"));
    assert_eq!(strategy, RestartStrategy::Safe);
}

#[test]
fn test_etc_unknown_process_safe() {
    let proc = make_test_process("some-config-reader", 678, false);
    let strategy = classify_process(&proc, Path::new("/etc"));
    assert_eq!(strategy, RestartStrategy::Safe);
}

// Tests for /home classification
#[test]
fn test_home_sway_no_restart() {
    let proc = make_test_process("sway", 1234, true);
    let strategy = classify_process(&proc, Path::new("/home"));
    assert_eq!(strategy, RestartStrategy::NoRestart);
}

#[test]
fn test_home_hyprland_no_restart() {
    let proc = make_test_process("Hyprland", 1235, true);
    let strategy = classify_process(&proc, Path::new("/home"));
    assert_eq!(strategy, RestartStrategy::NoRestart);
}

#[test]
fn test_home_gnome_shell_no_restart() {
    let proc = make_test_process("gnome-shell", 1236, true);
    let strategy = classify_process(&proc, Path::new("/home"));
    assert_eq!(strategy, RestartStrategy::NoRestart);
}

#[test]
fn test_home_xorg_no_restart() {
    let proc = make_test_process("Xorg", 1237, true);
    let strategy = classify_process(&proc, Path::new("/home"));
    assert_eq!(strategy, RestartStrategy::NoRestart);
}

#[test]
fn test_home_firefox_no_restart() {
    let proc = make_test_process("firefox", 5678, true);
    let strategy = classify_process(&proc, Path::new("/home"));
    assert_eq!(strategy, RestartStrategy::NoRestart);
}

#[test]
fn test_home_chrome_no_restart() {
    let proc = make_test_process("chrome", 5679, true);
    let strategy = classify_process(&proc, Path::new("/home"));
    assert_eq!(strategy, RestartStrategy::NoRestart);
}

#[test]
fn test_home_code_no_restart() {
    let proc = make_test_process("code", 5680, true);
    let strategy = classify_process(&proc, Path::new("/home"));
    assert_eq!(strategy, RestartStrategy::NoRestart);
}

#[test]
fn test_home_vim_no_restart() {
    let proc = make_test_process("vim", 5681, true);
    let strategy = classify_process(&proc, Path::new("/home"));
    assert_eq!(strategy, RestartStrategy::NoRestart);
}

#[test]
fn test_home_pulseaudio_risky() {
    let proc = make_test_process("pulseaudio", 6789, false);
    let strategy = classify_process(&proc, Path::new("/home"));
    assert_eq!(strategy, RestartStrategy::Risky);
}

#[test]
fn test_home_pipewire_risky() {
    let proc = make_test_process("pipewire", 6790, false);
    let strategy = classify_process(&proc, Path::new("/home"));
    assert_eq!(strategy, RestartStrategy::Risky);
}

#[test]
fn test_home_unknown_process_no_restart() {
    let proc = make_test_process("unknown-gui-app", 7890, true);
    let strategy = classify_process(&proc, Path::new("/home"));
    assert_eq!(strategy, RestartStrategy::NoRestart);
}

// Tests for /nix/store classification
#[test]
fn test_nix_store_nix_daemon_safe() {
    let proc = make_test_process("nix-daemon", 234, false);
    let strategy = classify_process(&proc, Path::new("/nix/store"));
    assert_eq!(strategy, RestartStrategy::Safe);
}

#[test]
fn test_nix_store_cwd_in_target_risky() {
    let proc = make_test_process("build-process", 345, true);
    let strategy = classify_process(&proc, Path::new("/nix/store"));
    assert_eq!(strategy, RestartStrategy::Risky);
}

#[test]
fn test_nix_store_only_open_files_skip() {
    let mut proc = make_test_process("any-binary", 456, false);
    proc.has_open_fds_in_target = true;
    let strategy = classify_process(&proc, Path::new("/nix/store"));
    assert_eq!(strategy, RestartStrategy::Skip);
}

#[test]
fn test_nix_store_only_mmaps_skip() {
    let mut proc = make_test_process("any-binary", 789, false);
    proc.has_mmap_in_target = true;
    let strategy = classify_process(&proc, Path::new("/nix/store"));
    assert_eq!(strategy, RestartStrategy::Skip);
}

// Tests for /nix classification (routing to nix-specific classifier)
#[test]
fn test_nix_routes_to_nix_classifier() {
    // /nix should NOT fall through to generic classifier
    let proc = make_test_process("any-binary", 456, false);
    let strategy = classify_process(&proc, Path::new("/nix"));
    // Generic classifier would return Safe, nix classifier returns Skip
    assert_eq!(strategy, RestartStrategy::Skip);
}

#[test]
fn test_nix_nix_daemon_safe() {
    let proc = make_test_process("nix-daemon", 234, false);
    let strategy = classify_process(&proc, Path::new("/nix"));
    assert_eq!(strategy, RestartStrategy::Safe);
}

#[test]
fn test_nix_cwd_in_target_risky() {
    let proc = make_test_process("build-process", 345, true);
    let strategy = classify_process(&proc, Path::new("/nix"));
    assert_eq!(strategy, RestartStrategy::Risky);
}

#[test]
fn test_nix_only_mmaps_skip() {
    let mut proc = make_test_process("firefox", 5678, false);
    proc.has_mmap_in_target = true;
    let strategy = classify_process(&proc, Path::new("/nix"));
    assert_eq!(strategy, RestartStrategy::Skip);
}

#[test]
fn test_nix_only_fds_skip() {
    let mut proc = make_test_process("bash", 1234, false);
    proc.has_open_fds_in_target = true;
    let strategy = classify_process(&proc, Path::new("/nix"));
    assert_eq!(strategy, RestartStrategy::Skip);
}

#[test]
fn test_nix_no_references_skip() {
    // Process detected as using /nix but has no cwd - should be Skip
    let proc = make_test_process("systemd", 1, false);
    let strategy = classify_process(&proc, Path::new("/nix"));
    assert_eq!(strategy, RestartStrategy::Skip);
}

// Tests for generic overlay process classification (Story 14.10)
#[test]
fn test_unknown_volume_user_no_restart() {
    let proc = make_test_process("some-app", 1234, true);
    let strategy = classify_process(&proc, Path::new("/home/user"));
    assert_eq!(strategy, RestartStrategy::NoRestart);
}

#[test]
fn test_unknown_volume_system_safe() {
    let proc = make_test_process("some-daemon", 1234, false);
    let strategy = classify_process(&proc, Path::new("/opt"));
    assert_eq!(strategy, RestartStrategy::Safe);
}

#[test]
fn test_generic_overlay_tmp_safe() {
    let proc = make_test_process("some-daemon", 1234, false);
    let strategy = classify_process(&proc, Path::new("/tmp"));
    assert_eq!(strategy, RestartStrategy::Safe);
}

#[test]
fn test_generic_overlay_srv_safe() {
    let proc = make_test_process("httpd", 1234, false);
    let strategy = classify_process(&proc, Path::new("/srv"));
    assert_eq!(strategy, RestartStrategy::Safe);
}

#[test]
fn test_generic_overlay_usr_safe() {
    let proc = make_test_process("some-binary", 1234, false);
    let strategy = classify_process(&proc, Path::new("/usr"));
    assert_eq!(strategy, RestartStrategy::Safe);
}

#[test]
fn test_generic_overlay_boot_safe() {
    let proc = make_test_process("grub-probe", 1234, false);
    let strategy = classify_process(&proc, Path::new("/boot"));
    assert_eq!(strategy, RestartStrategy::Safe);
}

#[test]
fn test_nix_uses_nix_classifier_not_generic() {
    // /nix now routes to classify_nix_process, not generic
    let proc = make_test_process("nix-build", 1234, false);
    let strategy = classify_process(&proc, Path::new("/nix"));
    assert_eq!(strategy, RestartStrategy::Skip);
}

#[test]
fn test_generic_overlay_persistent_safe() {
    let proc = make_test_process("some-daemon", 1234, false);
    let strategy = classify_process(&proc, Path::new("/persistent"));
    assert_eq!(strategy, RestartStrategy::Safe);
}

#[test]
fn test_generic_overlay_cwd_in_target_risky() {
    let proc = make_test_process("some-process", 1234, true);
    let strategy = classify_process(&proc, Path::new("/opt"));
    assert_eq!(strategy, RestartStrategy::Risky);
}

#[test]
fn test_generic_overlay_cwd_in_tmp_risky() {
    let proc = make_test_process("build-runner", 1234, true);
    let strategy = classify_process(&proc, Path::new("/tmp"));
    assert_eq!(strategy, RestartStrategy::Risky);
}

#[test]
fn test_generic_overlay_root_homedir_uses_home_rules() {
    // /root is root's home dir - firefox there should be NoRestart
    let proc = make_test_process("firefox", 1234, true);
    let strategy = classify_process(&proc, Path::new("/root"));
    assert_eq!(strategy, RestartStrategy::NoRestart);
}

#[test]
fn test_generic_overlay_root_homedir_audio_risky() {
    let proc = make_test_process("pulseaudio", 1234, false);
    let strategy = classify_process(&proc, Path::new("/root"));
    assert_eq!(strategy, RestartStrategy::Risky);
}

#[test]
fn test_generic_overlay_root_homedir_unknown_no_restart() {
    let proc = make_test_process("unknown-app", 1234, false);
    let strategy = classify_process(&proc, Path::new("/root"));
    assert_eq!(strategy, RestartStrategy::NoRestart);
}

// Edge cases
#[test]
fn test_restart_strategy_enum_equality() {
    assert_eq!(RestartStrategy::Safe, RestartStrategy::Safe);
    assert_eq!(RestartStrategy::Risky, RestartStrategy::Risky);
    assert_eq!(RestartStrategy::NoRestart, RestartStrategy::NoRestart);
    assert_eq!(RestartStrategy::Skip, RestartStrategy::Skip);
    assert_ne!(RestartStrategy::Safe, RestartStrategy::Risky);
    assert_ne!(RestartStrategy::Safe, RestartStrategy::Skip);
    assert_ne!(RestartStrategy::Skip, RestartStrategy::NoRestart);
}

#[test]
fn test_restart_strategy_debug() {
    let strategy = RestartStrategy::Safe;
    let debug_str = format!("{:?}", strategy);
    assert_eq!(debug_str, "Safe");
}

#[test]
fn test_restart_strategy_skip_debug() {
    let strategy = RestartStrategy::Skip;
    let debug_str = format!("{:?}", strategy);
    assert_eq!(debug_str, "Skip");
}

#[test]
fn test_restart_strategy_skip_clone_copy() {
    let strategy = RestartStrategy::Skip;
    let cloned = strategy;
    assert_eq!(strategy, cloned);
}
