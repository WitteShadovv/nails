// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

/// A kernel that made no mount point for selinuxfs runs no SELinux: no policy
/// gives a domain, and PID 1's context is not read. Without the sysfs the
/// mount point would be in, nothing tells.
#[test]
fn without_a_mount_point_for_selinuxfs_no_policy_gives_a_domain() {
    let dir = tempfile::tempdir().unwrap();
    let selinuxfs = dir.path().join("sys/fs/selinux");
    let pid1 = dir.path().join("current");
    let error = pid1_context(&selinuxfs, &pid1).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert!(
        error
            .to_string()
            .starts_with(&dir.path().join("sys/fs").display().to_string()),
        "{error}"
    );

    std::fs::create_dir_all(dir.path().join("sys/fs")).unwrap();
    assert_eq!(pid1_context(&selinuxfs, &pid1).unwrap(), None);

    std::fs::create_dir_all(&selinuxfs).unwrap();
    let error = pid1_context(&selinuxfs, &pid1).unwrap_err();
    assert!(
        error.to_string().starts_with(&pid1.display().to_string()),
        "{error}"
    );

    // As the kernel gives it: with its NUL.
    std::fs::write(&pid1, "system_u:system_r:init_t:s0\0").unwrap();
    assert_eq!(
        pid1_context(&selinuxfs, &pid1).unwrap().as_deref(),
        Some("system_u:system_r:init_t:s0")
    );
    // SELinux runs with no policy loaded.
    std::fs::write(&pid1, "kernel\0").unwrap();
    assert_eq!(pid1_context(&selinuxfs, &pid1).unwrap(), None);
}

/// The running kernel of a test host without SELinux, as the build servers
/// and CI run: nothing to ask there.
#[test]
fn the_running_kernel_without_selinux_gives_no_domain() {
    if Path::new(SELINUXFS).exists() {
        return;
    }
    assert_eq!(Kernel.pid1().unwrap(), None);
}

#[test]
fn a_context_reads_without_its_end() {
    for raw in [
        &b"system_u:system_r:init_t:s0"[..],
        b"system_u:system_r:init_t:s0\0",
        b"system_u:system_r:init_t:s0\n",
        b"system_u:system_r:init_t:s0\n\0",
    ] {
        assert_eq!(context_text(raw).unwrap(), "system_u:system_r:init_t:s0");
    }
    for odd in [
        &b""[..],
        b"\0",
        b"a b:c:d",
        b"a:b\0c:d",
        b"\xff:b:c",
        b"a:b:c\td",
    ] {
        let error = context_text(odd).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{odd:?}");
    }
}

#[test]
fn the_type_is_the_third_field_of_a_context() {
    assert_eq!(type_of("system_u:system_r:init_t:s0"), Some("init_t"));
    assert_eq!(
        type_of("system_u:system_r:udev_t:s0-s0:c0.c1023"),
        Some("udev_t")
    );
    assert_eq!(type_of("user_u:user_r:user_t"), Some("user_t"));
    for none in ["kernel", "a:b", "a:b:", "a:b::s0", ""] {
        assert_eq!(type_of(none), None, "{none:?}");
    }
}

/// The classes and permissions as selinuxfs lists the loaded policy's, at
/// `selinuxfs`.
fn classes(selinuxfs: &Path, class: &str, index: &str, perms: &[(&str, &str)]) {
    let dir = selinuxfs.join("class").join(class);
    std::fs::create_dir_all(dir.join("perms")).unwrap();
    std::fs::write(dir.join("index"), index).unwrap();
    for (perm, number) in perms {
        std::fs::write(dir.join("perms").join(perm), number).unwrap();
    }
}

#[test]
fn a_class_and_its_permissions_are_named_by_the_policy_s_numbers() {
    let dir = tempfile::tempdir().unwrap();
    let selinuxfs = dir.path();
    classes(
        selinuxfs,
        "file",
        "6\n",
        &[
            ("read", "4\n"),
            ("execute", "14"),
            ("first", "1"),
            ("last", "32"),
        ],
    );
    assert_eq!(class_index(selinuxfs, "file").unwrap(), 6);
    assert_eq!(perm_bit(selinuxfs, "file", "read").unwrap(), 1 << 3);
    assert_eq!(perm_bit(selinuxfs, "file", "execute").unwrap(), 1 << 13);
    assert_eq!(perm_bit(selinuxfs, "file", "first").unwrap(), 1);
    assert_eq!(perm_bit(selinuxfs, "file", "last").unwrap(), 1 << 31);

    // What the policy does not define, or a number out of range, is an error.
    assert_eq!(
        class_index(selinuxfs, "no_class").unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    let missing = perm_bit(selinuxfs, "file", "map").unwrap_err();
    assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    assert!(
        missing.to_string().contains("class/file/perms/map: "),
        "{missing}"
    );
    classes(
        selinuxfs,
        "odd",
        "x",
        &[("zero", "0"), ("high", "33"), ("word", "x")],
    );
    assert_eq!(
        class_index(selinuxfs, "odd").unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    for perm in ["zero", "high", "word"] {
        assert_eq!(
            perm_bit(selinuxfs, "odd", perm).unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "{perm}"
        );
    }
}

#[test]
fn an_access_decision_allows_the_bits_of_its_first_word() {
    // allowed, decided, auditallow, auditdeny, seqno, flags
    assert_eq!(allowed_of(b"1d0 ffffffff 0 ffffffff 3 0").unwrap(), 0x1d0);
    assert_eq!(allowed_of(b"0 ffffffff 0 ffffffff 1 1\0").unwrap(), 0);
    for odd in [&b""[..], b" ", b"xyz 0", b"100000000 0"] {
        assert_eq!(
            allowed_of(odd).unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "{odd:?}"
        );
    }
}

/// A transaction file that is not there, as without a mounted selinuxfs,
/// fails with its path.
#[test]
fn a_transaction_needs_its_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("create");
    let error = transact(&path, "a b 2").unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert!(
        error.to_string().starts_with(&path.display().to_string()),
        "{error}"
    );
}

/// The policy's classes as selinuxfs lists them, with the numbers of a
/// loaded targeted policy.
fn targeted_classes(selinuxfs: &Path) {
    classes(selinuxfs, "process", "2\n", &[("transition", "2\n")]);
    classes(
        selinuxfs,
        "file",
        "6\n",
        &[
            ("read", "4"),
            ("execute", "14"),
            ("open", "20"),
            ("entrypoint", "15"),
        ],
    );
}

/// The `create` request names both contexts and the number of the process
/// class, and its answer, with its NUL, is the context the start enters.
#[test]
fn a_start_s_context_is_asked_of_the_create_file() {
    let dir = tempfile::tempdir().unwrap();
    targeted_classes(dir.path());
    fn create(path: &Path, request: &str) -> io::Result<Vec<u8>> {
        assert!(path.ends_with("create"), "{}", path.display());
        assert_eq!(
            request,
            "system_u:system_r:init_t:s0 system_u:object_r:bin_t:s0 2"
        );
        Ok(b"system_u:system_r:unconfined_service_t:s0\0".to_vec())
    }
    assert_eq!(
        exec_context_in(
            dir.path(),
            "system_u:system_r:init_t:s0",
            "system_u:object_r:bin_t:s0",
            create
        )
        .unwrap(),
        "system_u:system_r:unconfined_service_t:s0"
    );
    fn refused(_: &Path, _: &str) -> io::Result<Vec<u8>> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
    assert_eq!(
        exec_context_in(dir.path(), "a:b:c", "d:e:f", refused)
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
}

/// The `access` request names both contexts and the number of the class, and
/// each permission whose bit its answer leaves out is denied, in the order
/// asked.
#[test]
fn the_denied_permissions_are_the_bits_the_access_file_leaves_out() {
    let dir = tempfile::tempdir().unwrap();
    targeted_classes(dir.path());
    // read (bit 3) and open (bit 19) allowed, execute (bit 13) not.
    fn access(path: &Path, request: &str) -> io::Result<Vec<u8>> {
        assert!(path.ends_with("access"), "{}", path.display());
        assert_eq!(
            request,
            "system_u:system_r:init_t:s0 unconfined_u:object_r:admin_home_t:s0 6"
        );
        Ok(b"80008 ffffffff 0 ffffffff 7 0".to_vec())
    }
    let ask = |perms: &[&'static str]| {
        denied_in(
            dir.path(),
            (
                "system_u:system_r:init_t:s0",
                "unconfined_u:object_r:admin_home_t:s0",
                "file",
            ),
            perms,
            access,
        )
    };
    assert_eq!(ask(&["execute", "read", "open"]).unwrap(), ["execute"]);
    assert_eq!(ask(&["read", "open"]).unwrap(), Vec::<&str>::new());
    assert_eq!(
        ask(&["entrypoint", "execute"]).unwrap(),
        ["entrypoint", "execute"]
    );
    // A permission the policy does not define is no answer.
    assert_eq!(ask(&["map"]).unwrap_err().kind(), io::ErrorKind::NotFound);
    // Nor is an answer that reads as no access decision.
    fn odd(_: &Path, _: &str) -> io::Result<Vec<u8>> {
        Ok(b"denied".to_vec())
    }
    assert_eq!(
        denied_in(dir.path(), ("a:b:c", "d:e:f", "file"), &["read"], odd)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}
