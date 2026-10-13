// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Hermetic tests for target-user resolution.
//!
//! Every test drives [`resolve_from`] through injected sources, so the real
//! environment, passwd database and logind are never consulted and the invoking
//! user is irrelevant.

use super::*;
use std::collections::HashMap;

/// Environment source backed by a fixed map.
#[derive(Default)]
struct FakeEnv {
    vars: HashMap<String, String>,
}

impl FakeEnv {
    fn with(mut self, key: &str, value: &str) -> Self {
        self.vars.insert(key.to_string(), value.to_string());
        self
    }
}

impl EnvSource for FakeEnv {
    fn var(&self, key: &str) -> Option<String> {
        self.vars.get(key).cloned()
    }
}

/// Passwd source backed by fixed uid/name maps.
#[derive(Default)]
struct FakePasswd {
    by_uid: HashMap<u32, PasswdEntry>,
    by_name: HashMap<String, PasswdEntry>,
}

impl FakePasswd {
    fn with_user(mut self, uid: u32, gid: u32, name: &str, dir: &str, shell: &str) -> Self {
        let entry = PasswdEntry {
            uid,
            gid,
            name: name.to_string(),
            dir: PathBuf::from(dir),
            shell: PathBuf::from(shell),
        };
        self.by_uid.insert(uid, entry.clone());
        self.by_name.insert(name.to_string(), entry);
        self
    }
}

impl PasswdSource for FakePasswd {
    fn by_uid(&self, uid: u32) -> Option<PasswdEntry> {
        self.by_uid.get(&uid).cloned()
    }

    fn by_name(&self, name: &str) -> Option<PasswdEntry> {
        self.by_name.get(name).cloned()
    }
}

/// Session-owner source returning a fixed answer.
struct FakeSession(Option<u32>);

impl SessionOwnerSource for FakeSession {
    fn seat0_active_uid(&self) -> Option<u32> {
        self.0
    }
}

fn no_session() -> FakeSession {
    FakeSession(None)
}

/// A passwd database with one ordinary operator whose primary group is `users`
/// (gid 100) — the NixOS `isNormalUser` shape that broke `chown user:user`.
fn operator_passwd() -> FakePasswd {
    FakePasswd::default().with_user(1000, 100, "operator", "/home/operator", "/bin/bash")
}

#[test]
fn sudo_uid_resolves_passwd_home_and_primary_gid_ignoring_home_env() {
    // The mandated case: under `sudo` HOME is /root, but SUDO_UID points at the
    // operator. Resolution must come from passwd, not HOME, and must carry the
    // real primary gid (100, not 1000).
    let env = FakeEnv::default()
        .with(ENV_SUDO_UID, "1000")
        .with("HOME", "/root");
    let passwd = operator_passwd();

    let user = resolve_from(&env, &passwd, &no_session()).expect("resolves via SUDO_UID");

    assert_eq!(user.uid, 1000);
    assert_eq!(user.gid, 100);
    assert_eq!(user.name, "operator");
    assert_eq!(user.home(), Path::new("/home/operator"));
    assert_eq!(user.shell, PathBuf::from("/bin/bash"));
}

#[test]
fn uid_precedence_is_target_then_sudo_then_pkexec_then_doas() {
    let passwd = FakePasswd::default()
        .with_user(10, 10, "target", "/home/target", "/bin/sh")
        .with_user(20, 20, "sudo", "/home/sudo", "/bin/sh")
        .with_user(30, 30, "pkexec", "/home/pkexec", "/bin/sh")
        .with_user(40, 40, "doas", "/home/doas", "/bin/sh");

    let all = FakeEnv::default()
        .with(ENV_TARGET_UID, "10")
        .with(ENV_SUDO_UID, "20")
        .with(ENV_PKEXEC_UID, "30")
        .with(ENV_DOAS_UID, "40");
    assert_eq!(
        resolve_from(&all, &passwd, &no_session()).unwrap().name,
        "target"
    );

    let no_target = FakeEnv::default()
        .with(ENV_SUDO_UID, "20")
        .with(ENV_PKEXEC_UID, "30")
        .with(ENV_DOAS_UID, "40");
    assert_eq!(
        resolve_from(&no_target, &passwd, &no_session())
            .unwrap()
            .name,
        "sudo"
    );

    let only_pkexec_doas = FakeEnv::default()
        .with(ENV_PKEXEC_UID, "30")
        .with(ENV_DOAS_UID, "40");
    assert_eq!(
        resolve_from(&only_pkexec_doas, &passwd, &no_session())
            .unwrap()
            .name,
        "pkexec"
    );

    let only_doas = FakeEnv::default().with(ENV_DOAS_UID, "40");
    assert_eq!(
        resolve_from(&only_doas, &passwd, &no_session())
            .unwrap()
            .name,
        "doas"
    );
}

#[test]
fn doas_uid_and_doas_user_are_honored() {
    let passwd = operator_passwd();

    let by_uid = FakeEnv::default().with(ENV_DOAS_UID, "1000");
    assert_eq!(
        resolve_from(&by_uid, &passwd, &no_session()).unwrap().uid,
        1000
    );

    let by_name = FakeEnv::default().with(ENV_DOAS_USER, "operator");
    assert_eq!(
        resolve_from(&by_name, &passwd, &no_session()).unwrap().name,
        "operator"
    );
}

#[test]
fn uids_take_priority_over_names() {
    let passwd = FakePasswd::default()
        .with_user(1000, 100, "operator", "/home/operator", "/bin/bash")
        .with_user(2000, 200, "other", "/home/other", "/bin/zsh");
    // UID points at operator, name points at other: the uid wins.
    let env = FakeEnv::default()
        .with(ENV_SUDO_UID, "1000")
        .with(ENV_SUDO_USER, "other");

    assert_eq!(
        resolve_from(&env, &passwd, &no_session()).unwrap().name,
        "operator"
    );
}

#[test]
fn name_sources_resolve_when_no_uid_is_present() {
    let passwd = operator_passwd();
    let env = FakeEnv::default().with(ENV_SUDO_USER, "operator");

    let user = resolve_from(&env, &passwd, &no_session()).unwrap();
    assert_eq!(user.uid, 1000);
    assert_eq!(user.gid, 100);
}

#[test]
fn name_precedence_is_target_then_sudo_then_doas() {
    let passwd = FakePasswd::default()
        .with_user(10, 10, "target", "/home/target", "/bin/sh")
        .with_user(20, 20, "sudo", "/home/sudo", "/bin/sh")
        .with_user(40, 40, "doas", "/home/doas", "/bin/sh");

    let all = FakeEnv::default()
        .with(ENV_TARGET_USER, "target")
        .with(ENV_SUDO_USER, "sudo")
        .with(ENV_DOAS_USER, "doas");
    assert_eq!(
        resolve_from(&all, &passwd, &no_session()).unwrap().name,
        "target"
    );

    let no_target = FakeEnv::default()
        .with(ENV_SUDO_USER, "sudo")
        .with(ENV_DOAS_USER, "doas");
    assert_eq!(
        resolve_from(&no_target, &passwd, &no_session())
            .unwrap()
            .name,
        "sudo"
    );
}

#[test]
fn uid_without_passwd_entry_falls_through_to_name_source() {
    // A uid is present but has no passwd entry (e.g. stale forwarded value);
    // resolution must not fail outright while a usable name source remains.
    let passwd = operator_passwd();
    let env = FakeEnv::default()
        .with(ENV_SUDO_UID, "4242")
        .with(ENV_SUDO_USER, "operator");

    let user = resolve_from(&env, &passwd, &no_session()).unwrap();
    assert_eq!(user.name, "operator");
}

#[test]
fn blank_and_unparsable_values_are_skipped() {
    let passwd = operator_passwd();
    let env = FakeEnv::default()
        .with(ENV_TARGET_UID, "not-a-number")
        .with(ENV_SUDO_UID, "   ")
        .with(ENV_SUDO_USER, "  operator  ");

    // The numeric sources are unusable; the name source wins after trimming.
    let user = resolve_from(&env, &passwd, &no_session()).unwrap();
    assert_eq!(user.name, "operator");
}

#[test]
fn no_source_and_no_session_errors_without_root_fallback() {
    let env = FakeEnv::default().with("HOME", "/root");
    let passwd = operator_passwd();

    let err = resolve_from(&env, &passwd, &no_session()).unwrap_err();
    assert!(matches!(err, NailsError::InvalidState(_)));
}

#[test]
fn logind_seat0_owner_is_the_last_resort() {
    let passwd = operator_passwd();
    let env = FakeEnv::default();
    let session = FakeSession(Some(1000));

    let user = resolve_from(&env, &passwd, &session).unwrap();
    assert_eq!(user.name, "operator");
    assert_eq!(user.uid, 1000);
}

#[test]
fn logind_owner_without_passwd_entry_errors() {
    let passwd = operator_passwd();
    let env = FakeEnv::default();
    let session = FakeSession(Some(9999));

    assert!(resolve_from(&env, &passwd, &session).is_err());
}

#[test]
fn resolve_from_is_reachable_through_the_public_wrapper() {
    let env = FakeEnv::default().with(ENV_SUDO_UID, "1000");
    let passwd = operator_passwd();

    let user = TargetUser::resolve_from(&env, &passwd, &no_session()).unwrap();
    assert_eq!(user.name, "operator");
}
