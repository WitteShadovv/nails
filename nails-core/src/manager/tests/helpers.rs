//! The manager helpers: network config cleanup, overlay targets and system profiles.

use super::*;

// ========== DNS Preservation ==========

#[test]
fn test_clean_stale_network_config_removes_resolv_conf() {
    let fs = MockFilesystem::new();
    let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

    // Create stale resolv.conf
    let resolv_path = upper_dir.join("resolv.conf");
    fs.write_file_content(&resolv_path, "nameserver 8.8.8.8")
        .unwrap();

    // Clean it
    let result = clean_stale_network_config(&upper_dir, &fs);
    assert!(result.is_ok());

    // File should be removed
    assert!(!fs.path_exists(&resolv_path).unwrap());
}

#[test]
fn test_clean_stale_network_config_removes_nsswitch_conf() {
    let fs = MockFilesystem::new();
    let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

    // Create stale nsswitch.conf
    let nsswitch_path = upper_dir.join("nsswitch.conf");
    fs.write_file_content(&nsswitch_path, "hosts: files dns")
        .unwrap();

    // Clean it
    let result = clean_stale_network_config(&upper_dir, &fs);
    assert!(result.is_ok());

    // File should be removed
    assert!(!fs.path_exists(&nsswitch_path).unwrap());
}

#[test]
fn test_clean_stale_network_config_removes_both_files() {
    let fs = MockFilesystem::new();
    let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

    // Create both stale files
    let resolv_path = upper_dir.join("resolv.conf");
    let nsswitch_path = upper_dir.join("nsswitch.conf");
    fs.write_file_content(&resolv_path, "nameserver 8.8.8.8")
        .unwrap();
    fs.write_file_content(&nsswitch_path, "hosts: files dns")
        .unwrap();

    // Clean them
    let result = clean_stale_network_config(&upper_dir, &fs);
    assert!(result.is_ok());

    // Both files should be removed
    assert!(!fs.path_exists(&resolv_path).unwrap());
    assert!(!fs.path_exists(&nsswitch_path).unwrap());
}

#[test]
fn test_clean_stale_network_config_no_files_exists() {
    let fs = MockFilesystem::new();
    let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

    // No files created - should succeed without error
    let result = clean_stale_network_config(&upper_dir, &fs);
    assert!(result.is_ok());
}

#[test]
#[tracing_test::traced_test]
fn test_clean_stale_network_config_logs_removal() {
    let fs = MockFilesystem::new();
    let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

    // Create stale resolv.conf
    let resolv_path = upper_dir.join("resolv.conf");
    fs.write_file_content(&resolv_path, "nameserver 8.8.8.8")
        .unwrap();

    // Clean it
    let result = clean_stale_network_config(&upper_dir, &fs);
    assert!(result.is_ok());

    // Behaviour: the stale resolv.conf is removed from the upper layer so the
    // live host DNS is inherited rather than a captured nameserver.
    assert!(
        !fs.path_exists(&resolv_path).unwrap(),
        "stale resolv.conf should have been removed"
    );
}

#[test]
fn test_clean_stale_network_config_does_not_remove_other_files() {
    let fs = MockFilesystem::new();
    let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

    // Create files that should NOT be removed
    let passwd_path = upper_dir.join("passwd");
    let shadow_path = upper_dir.join("shadow");
    let hostname_path = upper_dir.join("hostname");
    fs.write_file_content(&passwd_path, "root:x:0:0").unwrap();
    fs.write_file_content(&shadow_path, "root:*").unwrap();
    fs.write_file_content(&hostname_path, "myhostname").unwrap();

    // Also create one that should be removed
    let resolv_path = upper_dir.join("resolv.conf");
    fs.write_file_content(&resolv_path, "nameserver 8.8.8.8")
        .unwrap();

    // Clean
    let result = clean_stale_network_config(&upper_dir, &fs);
    assert!(result.is_ok());

    // Only resolv.conf should be removed
    assert!(!fs.path_exists(&resolv_path).unwrap());
    assert!(fs.path_exists(&passwd_path).unwrap());
    assert!(fs.path_exists(&shadow_path).unwrap());
    assert!(fs.path_exists(&hostname_path).unwrap());
}

// ========== Overlay Targets and Exclusions ==========

#[test]
fn test_apply_exclusion_filter_empty_exclusions() {
    let dirs = vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
    ];
    let exclusions: Vec<PathBuf> = vec![];

    let filtered = apply_exclusion_filter(dirs.clone(), &exclusions);

    assert_eq!(filtered.len(), 3);
    assert_eq!(
        filtered,
        vec![
            PathBuf::from("/etc"),
            PathBuf::from("/home"),
            PathBuf::from("/var"),
        ]
    );
}

#[test]
fn test_apply_exclusion_filter_with_exclusions() {
    let dirs = vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/proc"),
        PathBuf::from("/var"),
    ];
    let exclusions = vec![PathBuf::from("/proc")];

    let filtered = apply_exclusion_filter(dirs, &exclusions);

    assert_eq!(filtered.len(), 3);
    assert!(!filtered.contains(&PathBuf::from("/proc")));
    assert!(filtered.contains(&PathBuf::from("/home")));
    assert!(filtered.contains(&PathBuf::from("/etc")));
    assert!(filtered.contains(&PathBuf::from("/var")));
}

#[test]
fn test_apply_exclusion_filter_all_excluded() {
    let dirs = vec![
        PathBuf::from("/proc"),
        PathBuf::from("/sys"),
        PathBuf::from("/dev"),
    ];
    let exclusions = vec![
        PathBuf::from("/proc"),
        PathBuf::from("/sys"),
        PathBuf::from("/dev"),
    ];

    let filtered = apply_exclusion_filter(dirs, &exclusions);

    assert_eq!(filtered.len(), 0);
}

#[test]
fn test_apply_exclusion_filter_sorts_results() {
    let dirs = vec![
        PathBuf::from("/var"),
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
    ];
    let exclusions: Vec<PathBuf> = vec![];

    let filtered = apply_exclusion_filter(dirs, &exclusions);

    // Should be sorted alphabetically
    assert_eq!(filtered[0], PathBuf::from("/etc"));
    assert_eq!(filtered[1], PathBuf::from("/home"));
    assert_eq!(filtered[2], PathBuf::from("/var"));
}

#[test]
fn test_build_overlay_targets_auto_mode_with_defaults() {
    let fs = MockFilesystem::new();

    // A Debian/Ubuntu (FHS) host: its overlay policy excludes /usr and /bin
    // (kept read-only) from overlay enumeration.
    fs.mock_add_file("/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n");
    fs.mock_add_file("/proc/1/comm", "systemd");

    // Setup root directories (typical Linux system)
    fs.mock_set_root_directories(vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/nix"),
        PathBuf::from("/var"),
        PathBuf::from("/tmp"),
        PathBuf::from("/usr"),
        PathBuf::from("/bin"),
        PathBuf::from("/proc"), // Default exclusion
        PathBuf::from("/sys"),  // Default exclusion
        PathBuf::from("/dev"),  // Default exclusion
        PathBuf::from("/boot"), // Now included (removed from default exclusions)
    ]);

    let config = Config {
        overlay_mode: OverlayMode::Auto,
        ..Config::default()
    };

    let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

    // Should include most dirs, exclude /proc, /sys, /dev + critical /bin, /usr
    assert_eq!(targets.len(), 6);
    assert!(targets.contains(&PathBuf::from("/home")));
    assert!(targets.contains(&PathBuf::from("/etc")));
    assert!(targets.contains(&PathBuf::from("/nix")));
    assert!(targets.contains(&PathBuf::from("/var")));
    assert!(targets.contains(&PathBuf::from("/tmp")));
    assert!(targets.contains(&PathBuf::from("/boot")));
    assert!(!targets.contains(&PathBuf::from("/usr"))); // Critical binary root
    assert!(!targets.contains(&PathBuf::from("/bin"))); // Critical binary root
    assert!(!targets.contains(&PathBuf::from("/proc")));
    assert!(!targets.contains(&PathBuf::from("/sys")));
    assert!(!targets.contains(&PathBuf::from("/dev")));
}

#[test]
fn test_build_overlay_targets_auto_mode_with_user_exclusions() {
    let fs = MockFilesystem::new();

    fs.mock_set_root_directories(vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/nix"),
        PathBuf::from("/var"),
        PathBuf::from("/boot"),
    ]);

    let mut config = Config {
        overlay_mode: OverlayMode::Auto,
        ..Config::default()
    };
    // Add /var and /nix as additional user exclusions
    config.overlay_exclusions = vec![PathBuf::from("/var"), PathBuf::from("/nix")];

    let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

    // Should exclude user-specified directories, /boot now included
    assert_eq!(targets.len(), 3);
    assert!(targets.contains(&PathBuf::from("/home")));
    assert!(targets.contains(&PathBuf::from("/etc")));
    assert!(targets.contains(&PathBuf::from("/boot")));
    assert!(!targets.contains(&PathBuf::from("/nix")));
    assert!(!targets.contains(&PathBuf::from("/var")));
}

#[test]
fn test_build_overlay_targets_auto_mode_with_user_removals() {
    let fs = MockFilesystem::new();

    fs.mock_set_root_directories(vec![
        PathBuf::from("/home"),
        PathBuf::from("/mnt"), // Default exclusion that user wants to remove
    ]);

    let mut config = Config {
        overlay_mode: OverlayMode::Auto,
        ..Config::default()
    };
    config.overlay_exclusions_remove = vec![
        PathBuf::from("/mnt"), // Remove from default exclusions
    ];

    let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

    // /mnt should now be included (removed from exclusions)
    assert_eq!(targets.len(), 2);
    assert!(targets.contains(&PathBuf::from("/home")));
    assert!(targets.contains(&PathBuf::from("/mnt")));
}

#[test]
fn test_build_overlay_targets_auto_mode_empty_root() {
    let fs = MockFilesystem::new();

    // Empty root directory
    fs.mock_set_root_directories(vec![]);

    let config = Config {
        overlay_mode: OverlayMode::Auto,
        ..Config::default()
    };

    let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

    assert_eq!(targets.len(), 0);
}

#[test]
fn test_build_overlay_targets_auto_mode_all_excluded() {
    let fs = MockFilesystem::new();

    fs.mock_set_root_directories(vec![
        PathBuf::from("/proc"),
        PathBuf::from("/sys"),
        PathBuf::from("/dev"),
    ]);

    let config = Config {
        overlay_mode: OverlayMode::Auto,
        ..Config::default()
    };

    let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

    // All directories are in default exclusions
    assert_eq!(targets.len(), 0);
}

#[test]
fn test_build_overlay_targets_auto_mode_sorted_output() {
    let fs = MockFilesystem::new();

    // Unsorted input
    fs.mock_set_root_directories(vec![
        PathBuf::from("/var"),
        PathBuf::from("/etc"),
        PathBuf::from("/home"),
    ]);

    let config = Config {
        overlay_mode: OverlayMode::Auto,
        ..Config::default()
    };

    let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

    // Should be sorted alphabetically
    assert_eq!(targets[0], PathBuf::from("/etc"));
    assert_eq!(targets[1], PathBuf::from("/home"));
    assert_eq!(targets[2], PathBuf::from("/var"));
}

#[test]
fn test_build_overlay_targets_explicit_mode() {
    let fs = MockFilesystem::new();

    // Root has many directories, but explicit mode should ignore them
    fs.mock_set_root_directories(vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
        PathBuf::from("/tmp"),
        PathBuf::from("/boot"),
    ]);

    let config = Config {
        overlay_mode: OverlayMode::Explicit,
        overlays: vec![
            OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/home"),
                upper: PathBuf::from("/mnt/hidden/home"),
                work: PathBuf::from("/mnt/hidden/.work/home"),
                target: PathBuf::from("/home"),
            },
            OverlayConfig {
                name: "etc".to_string(),
                lower: PathBuf::from("/etc"),
                upper: PathBuf::from("/mnt/hidden/etc"),
                work: PathBuf::from("/mnt/hidden/.work/etc"),
                target: PathBuf::from("/etc"),
            },
        ],
        ..Config::default()
    };

    let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

    // Should only use configured overlays, not all discovered directories
    assert_eq!(targets.len(), 2);
    assert!(targets.contains(&PathBuf::from("/home")));
    assert!(targets.contains(&PathBuf::from("/etc")));
    assert!(!targets.contains(&PathBuf::from("/var")));
    assert!(!targets.contains(&PathBuf::from("/tmp")));
}

#[test]
fn test_build_overlay_targets_explicit_mode_empty_overlays() {
    let fs = MockFilesystem::new();

    fs.mock_set_root_directories(vec![PathBuf::from("/home"), PathBuf::from("/etc")]);

    let config = Config {
        overlay_mode: OverlayMode::Explicit,
        overlays: vec![], // No overlays configured
        ..Config::default()
    };

    let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

    // No overlays configured = no targets
    assert_eq!(targets.len(), 0);
}

// ========== parse_system_generation Tests ==========

#[test]
fn test_parse_system_generation_valid() {
    assert_eq!(
        crate::manager::helpers::parse_system_generation("system-1-link"),
        Some(1)
    );
    assert_eq!(
        crate::manager::helpers::parse_system_generation("system-42-link"),
        Some(42)
    );
    assert_eq!(
        crate::manager::helpers::parse_system_generation("system-100-link"),
        Some(100)
    );
    assert_eq!(
        crate::manager::helpers::parse_system_generation("system-0-link"),
        Some(0)
    );
}

#[test]
fn test_parse_system_generation_invalid_no_prefix() {
    assert_eq!(
        crate::manager::helpers::parse_system_generation("1-link"),
        None
    );
    assert_eq!(
        crate::manager::helpers::parse_system_generation("foo-1-link"),
        None
    );
}

#[test]
fn test_parse_system_generation_invalid_no_suffix() {
    assert_eq!(
        crate::manager::helpers::parse_system_generation("system-1"),
        None
    );
    assert_eq!(
        crate::manager::helpers::parse_system_generation("system-1-symlink"),
        None
    );
}

#[test]
fn test_parse_system_generation_non_numeric() {
    assert_eq!(
        crate::manager::helpers::parse_system_generation("system-abc-link"),
        None
    );
    assert_eq!(
        crate::manager::helpers::parse_system_generation("system--link"),
        None
    );
}

#[test]
fn test_parse_system_generation_empty() {
    assert_eq!(crate::manager::helpers::parse_system_generation(""), None);
}

// ========== find_newest_system_profile / select_system_profile Tests ==========

/// Takes the environment lock with `NAILS_SYSTEM_PROFILE_PATH` removed, so the
/// profile lookup uses the default `/nix/var/nix/profiles/system` even while a
/// deactivation test elsewhere points it at a stub profile.
fn default_system_profile_env() -> EnvGuard {
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");
    env
}

#[test]
fn test_find_newest_system_profile_directory_not_exist() {
    let _env = default_system_profile_env();
    let fs = MockFilesystem::new();
    // Profiles dir doesn't exist
    let result = crate::manager::helpers::find_newest_system_profile(&fs);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[test]
fn test_find_newest_system_profile_picks_highest_generation() {
    let _env = default_system_profile_env();
    let fs = MockFilesystem::new();
    let profiles_dir = PathBuf::from("/nix/var/nix/profiles");
    fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
    fs.mock_set_directory_contents(
        &profiles_dir,
        vec![
            profiles_dir.join("system-1-link"),
            profiles_dir.join("system-5-link"),
            profiles_dir.join("system-3-link"),
            profiles_dir.join("not-a-generation"),
        ],
    );

    let result = crate::manager::helpers::find_newest_system_profile(&fs).unwrap();
    assert!(result.is_some());
    let path = result.unwrap();
    assert!(path.to_string_lossy().contains("system-5-link"));
}

#[test]
fn test_find_newest_system_profile_no_valid_entries() {
    let _env = default_system_profile_env();
    let fs = MockFilesystem::new();
    let profiles_dir = PathBuf::from("/nix/var/nix/profiles");
    fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
    fs.mock_set_directory_contents(
        &profiles_dir,
        vec![
            profiles_dir.join("not-a-generation"),
            profiles_dir.join("system"),
        ],
    );

    let result = crate::manager::helpers::find_newest_system_profile(&fs).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_select_system_profile_finds_newest() {
    let _env = default_system_profile_env();
    let fs = MockFilesystem::new();
    let profiles_dir = PathBuf::from("/nix/var/nix/profiles");
    fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
    fs.mock_set_directory_contents(
        &profiles_dir,
        vec![
            profiles_dir.join("system-2-link"),
            profiles_dir.join("system-1-link"),
        ],
    );

    let result = select_system_profile(&fs).unwrap();
    assert!(result.is_some());
    assert!(result.unwrap().to_string_lossy().contains("system-2-link"));
}

#[test]
fn test_select_system_profile_falls_back_to_system_symlink() {
    let _env = default_system_profile_env();
    let fs = MockFilesystem::new();
    // No newest generation found, but system symlink exists
    let system_path = PathBuf::from("/nix/var/nix/profiles/system");
    // profiles dir doesn't exist (so no generations found)
    // but the system symlink itself exists
    fs.mock_set_path_exists(system_path.to_str().unwrap(), true);

    let result = select_system_profile(&fs).unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap(), system_path);
}

#[test]
fn test_select_system_profile_returns_none_when_nothing_found() {
    let _env = default_system_profile_env();
    let fs = MockFilesystem::new();
    // Neither profiles dir nor system symlink exist
    let result = select_system_profile(&fs).unwrap();
    assert!(result.is_none());
}

// ========== ensure_run_current_system_symlink Tests ==========

#[test]
fn test_ensure_run_current_system_symlink_creates_new_when_not_exists() {
    let fs = MockFilesystem::new();
    let run_current = PathBuf::from("/run/current-system");
    let target = PathBuf::from("/nix/var/nix/profiles/system-1-link");

    // run_current does not exist (neither symlink nor regular file)
    let result = ensure_run_current_system_symlink(&fs, &target);
    assert!(result.is_ok());
    assert_eq!(fs.mock_get_symlink_target(&run_current), Some(target));
}

#[test]
fn test_ensure_run_current_system_symlink_replaces_existing_symlink() {
    let fs = MockFilesystem::new();
    let run_current = PathBuf::from("/run/current-system");
    let target = PathBuf::from("/nix/var/nix/profiles/system-1-link");

    fs.mock_set_path_exists(run_current.to_str().unwrap(), true);
    fs.mock_set_is_symlink(run_current.to_str().unwrap(), true);

    let result = ensure_run_current_system_symlink(&fs, &target);
    assert!(result.is_ok());
    assert_eq!(fs.mock_get_symlink_target(&run_current), Some(target));
}

#[test]
fn test_ensure_run_current_system_symlink_rejects_non_symlink() {
    let fs = MockFilesystem::new();
    let run_current = PathBuf::from("/run/current-system");
    let target = PathBuf::from("/nix/var/nix/profiles/system-1-link");

    fs.mock_set_path_exists(run_current.to_str().unwrap(), true);
    fs.mock_set_is_symlink(run_current.to_str().unwrap(), false);

    let result = ensure_run_current_system_symlink(&fs, &target);
    assert!(result.is_err());
}
