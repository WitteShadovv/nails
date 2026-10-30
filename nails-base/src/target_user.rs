// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Resolving the unprivileged account NAILS acts on behalf of.
//!
//! NAILS runs as root — invoked through `sudo`, `pkexec` or `doas`, or re-execed
//! into a detached `systemd-run` unit — but it has to read and clean files that
//! belong to the operator's real account: shell history, caches, the home that
//! the hidden overlay is mounted over. Historically each subsystem re-derived
//! that account from a different subset of environment variables with different
//! precedence, and the history cleaner fell back to `$HOME` — which under `sudo`
//! is `/root` and under the detached unit is unset. The operator's own history
//! was never touched.
//!
//! [`TargetUser`] centralises that decision so every subsystem agrees on who the
//! operator is. Resolution order, highest priority first:
//!
//! 1. `NAILS_TARGET_UID` — forwarded across the detached `systemd-run` boundary.
//! 2. `PKEXEC_UID`, `SUDO_UID`, `DOAS_UID` — set by the privilege-escalation tool.
//!    `PKEXEC_UID` comes first because pkexec of polkit 127 and later sets
//!    `SUDO_UID` and `SUDO_GID` too: where both are set, pkexec started this
//!    process, and `PKEXEC_UID` names the account that asked it to.
//! 3. `NAILS_TARGET_USER`, `SUDO_USER`, `DOAS_USER` — the name-based equivalents.
//! 4. The owner of the active graphical session on seat0, via logind.
//!
//! If none of these yields a user, resolution fails. There is deliberately no
//! fallback to root: silently targeting root's home is the exact bug this
//! resolver exists to prevent.
//!
//! The uid, gid, home and shell are read from the passwd database. The numeric
//! gid matters: on NixOS an `isNormalUser` account's primary group is `users`,
//! not a per-user group, so the old `chown user:user` assumption was wrong.
//! Callers now have the real gid to `chown` with.
//!
//! # musl / NSS limitation
//!
//! The static musl build resolves only local `/etc/passwd` entries; it does not
//! consult NSS, so network-directory (LDAP/SSSD) accounts will not resolve, and
//! neither will the logind fallback for them. This is acceptable for the
//! single-operator threat model but is noted at the call sites that run under
//! the musl build.

use crate::constants::{ENV_TARGET_UID, ENV_TARGET_USER};
use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

// Environment variables consulted during resolution. Keeping the literals here
// — and nowhere else in the crate — is what lets every other module drop its
// bespoke lookup and defer to this one resolver.
const ENV_SUDO_UID: &str = "SUDO_UID";
const ENV_PKEXEC_UID: &str = "PKEXEC_UID";
const ENV_DOAS_UID: &str = "DOAS_UID";
const ENV_SUDO_USER: &str = "SUDO_USER";
const ENV_DOAS_USER: &str = "DOAS_USER";

/// UID environment sources, highest priority first.
const UID_ENV_SOURCES: &[&str] = &[ENV_TARGET_UID, ENV_PKEXEC_UID, ENV_SUDO_UID, ENV_DOAS_UID];

/// Username environment sources, highest priority first.
const NAME_ENV_SOURCES: &[&str] = &[ENV_TARGET_USER, ENV_SUDO_USER, ENV_DOAS_USER];

/// The environment variables a privilege-escalation tool (`sudo`, `pkexec`,
/// `doas`) sets to identify the operator. Centralised here so code that must
/// clear or forward the escalation context — notably the session-detection test
/// harness — reuses this list instead of re-spelling the literals, keeping this
/// module the single place those variable names appear.
pub const PRIVILEGE_ENV_VARS: &[&str] = &[
    ENV_SUDO_UID,
    ENV_PKEXEC_UID,
    ENV_DOAS_UID,
    ENV_SUDO_USER,
    ENV_DOAS_USER,
];

/// The unprivileged user a privileged NAILS run is acting on behalf of.
///
/// Construct one with [`TargetUser::resolve_with`] in production, or
/// [`TargetUser::resolve_from`] with injected sources in tests. The fields are
/// taken verbatim from the passwd entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetUser {
    /// Numeric user id.
    pub uid: u32,
    /// Numeric primary group id (from passwd, not assumed equal to the uid).
    pub gid: u32,
    /// Login name.
    pub name: String,
    /// Passwd home directory.
    home: PathBuf,
    /// Login shell.
    pub shell: PathBuf,
}

impl TargetUser {
    /// The home directory.
    pub fn home(&self) -> &Path {
        self.home.as_path()
    }

    /// The passwd home directory (the same as [`Self::home`]).
    pub fn passwd_home(&self) -> &Path {
        self.home.as_path()
    }

    fn from_entry(entry: PasswdEntry) -> Self {
        Self {
            uid: entry.uid,
            gid: entry.gid,
            name: entry.name,
            home: entry.dir,
            shell: entry.shell,
        }
    }

    /// Resolve the target user from the given startup environment snapshot,
    /// passwd database and logind. Returns an error when no source identifies an
    /// account; it never falls back to root.
    ///
    /// The environment is taken from the [`RuntimeEnv`](crate::RuntimeEnv)
    /// `main` captured once, not re-read here, so every subsystem that resolves
    /// the operator agrees on the same escalation context.
    pub fn resolve_with(env: &crate::RuntimeEnv) -> Result<TargetUser> {
        resolve_from(env, &SystemPasswd, &SystemSessionOwner)
    }

    /// Resolve using injected sources. Available to unit tests so they can drive
    /// resolution hermetically, without touching the real environment, passwd
    /// database or logind.
    #[cfg(test)]
    pub(crate) fn resolve_from<E, P, S>(env: &E, passwd: &P, session: &S) -> Result<TargetUser>
    where
        E: EnvSource,
        P: PasswdSource,
        S: SessionOwnerSource,
    {
        resolve_from(env, passwd, session)
    }

    /// Construct a `TargetUser` directly from fixed fields. Test-only: production
    /// code must go through [`TargetUser::resolve_with`] so resolution stays in one
    /// place. Lets tests in other modules (filesystem, shell, notification)
    /// exercise owner-aware writes without a real passwd entry.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(
        uid: u32,
        gid: u32,
        name: &str,
        home: impl Into<PathBuf>,
        shell: impl Into<PathBuf>,
    ) -> Self {
        Self {
            uid,
            gid,
            name: name.to_string(),
            home: home.into(),
            shell: shell.into(),
        }
    }
}

fn resolve_from<E, P, S>(env: &E, passwd: &P, session: &S) -> Result<TargetUser>
where
    E: EnvSource,
    P: PasswdSource,
    S: SessionOwnerSource,
{
    // 1 & 2: uid-based environment sources, in priority order.
    for key in UID_ENV_SOURCES {
        if let Some(uid) = env
            .var(key)
            .and_then(|value| value.trim().parse::<u32>().ok())
            && let Some(entry) = passwd.by_uid(uid)
        {
            return Ok(TargetUser::from_entry(entry));
        }
    }

    // 3: name-based environment sources, in priority order.
    for key in NAME_ENV_SOURCES {
        if let Some(name) = env
            .var(key)
            .map(|value| value.trim().to_string())
            .filter(|name| !name.is_empty())
            && let Some(entry) = passwd.by_name(&name)
        {
            return Ok(TargetUser::from_entry(entry));
        }
    }

    // 4: owner of the active seat0 session.
    if let Some(uid) = session.seat0_active_uid()
        && let Some(entry) = passwd.by_uid(uid)
    {
        return Ok(TargetUser::from_entry(entry));
    }

    Err(NailsError::InvalidState(
        "Could not determine the target user: none of NAILS_TARGET_UID, PKEXEC_UID, SUDO_UID, \
         DOAS_UID, NAILS_TARGET_USER, SUDO_USER or DOAS_USER resolved to a passwd entry, and no \
         active seat0 session was found. Set NAILS_TARGET_UID or NAILS_TARGET_USER to the \
         operator's account."
            .to_string(),
    ))
}

/// A resolved passwd entry. Decoupled from `nix::unistd::User` so the resolver
/// can be tested without a real passwd database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PasswdEntry {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    pub dir: PathBuf,
    pub shell: PathBuf,
}

/// Environment-variable lookup, injectable for tests.
pub(crate) trait EnvSource {
    fn var(&self, key: &str) -> Option<String>;
}

impl EnvSource for crate::RuntimeEnv {
    fn var(&self, key: &str) -> Option<String> {
        self.lookup(key).map(str::to_string)
    }
}

/// Passwd-database lookup, injectable for tests.
pub(crate) trait PasswdSource {
    fn by_uid(&self, uid: u32) -> Option<PasswdEntry>;
    fn by_name(&self, name: &str) -> Option<PasswdEntry>;
}

/// Active-session owner lookup, injectable for tests.
pub(crate) trait SessionOwnerSource {
    fn seat0_active_uid(&self) -> Option<u32>;
}

struct SystemPasswd;

impl PasswdSource for SystemPasswd {
    fn by_uid(&self, uid: u32) -> Option<PasswdEntry> {
        nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .ok()
            .flatten()
            .map(PasswdEntry::from)
    }

    fn by_name(&self, name: &str) -> Option<PasswdEntry> {
        nix::unistd::User::from_name(name)
            .ok()
            .flatten()
            .map(PasswdEntry::from)
    }
}

impl From<nix::unistd::User> for PasswdEntry {
    fn from(user: nix::unistd::User) -> Self {
        Self {
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            name: user.name,
            dir: user.dir,
            shell: user.shell,
        }
    }
}

struct SystemSessionOwner;

impl SessionOwnerSource for SystemSessionOwner {
    fn seat0_active_uid(&self) -> Option<u32> {
        // Never shell out to logind from a test or test-like runtime.
        if crate::runtime_safety::should_skip_host_interaction() {
            return None;
        }

        let session = run_loginctl(&["show-seat", "seat0", "-p", "ActiveSession", "--value"])?;
        let session = session.trim();
        if session.is_empty() {
            return None;
        }

        let uid = run_loginctl(&["show-session", session, "-p", "User", "--value"])?;
        uid.trim().parse::<u32>().ok()
    }
}

/// Run `loginctl` with the given arguments and return stdout on success.
///
/// Routed through the shared runner so it resolves `loginctl` from the fixed
/// system directories, starts from a cleared environment, and carries a deadline:
/// a hung `loginctl` cannot stall target-user resolution.
fn run_loginctl(args: &[&str]) -> Option<String> {
    use crate::process::run::{LOGINCTL_BUDGET, ProcessCommand, ProcessRunner, RealProcessRunner};

    let (success, stdout, _stderr) = RealProcessRunner
        .run_text(
            &ProcessCommand::tool("loginctl")
                .args(args)
                .deadline(LOGINCTL_BUDGET),
        )
        .ok()?;
    if !success {
        return None;
    }
    Some(stdout)
}

#[cfg(test)]
mod tests;
