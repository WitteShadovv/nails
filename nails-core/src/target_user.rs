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
//! 2. `SUDO_UID`, `PKEXEC_UID`, `DOAS_UID` — set by the privilege-escalation tool.
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

/// Root's home directory, always cleaned alongside the operator's own home: a
/// `sudo` invocation leaves residue there regardless of who the operator is.
const ROOT_HOME: &str = "/root";

// Environment variables consulted during resolution. Keeping the literals here
// — and nowhere else in the crate — is what lets every other module drop its
// bespoke lookup and defer to this one resolver.
const ENV_SUDO_UID: &str = "SUDO_UID";
const ENV_PKEXEC_UID: &str = "PKEXEC_UID";
const ENV_DOAS_UID: &str = "DOAS_UID";
const ENV_SUDO_USER: &str = "SUDO_USER";
const ENV_DOAS_USER: &str = "DOAS_USER";

/// UID environment sources, highest priority first.
const UID_ENV_SOURCES: &[&str] = &[ENV_TARGET_UID, ENV_SUDO_UID, ENV_PKEXEC_UID, ENV_DOAS_UID];

/// Username environment sources, highest priority first.
const NAME_ENV_SOURCES: &[&str] = &[ENV_TARGET_USER, ENV_SUDO_USER, ENV_DOAS_USER];

/// The unprivileged user a privileged NAILS run is acting on behalf of.
///
/// Construct one with [`TargetUser::resolve`] in production, or
/// [`TargetUser::resolve_from`] with injected sources in tests. The fields are
/// taken verbatim from the passwd entry, except [`TargetUser::home`], which can
/// be overridden by an opt-in persona home (see [`TargetUser::with_persona_home`]).
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
    /// Optional alternative home for the opt-in fresh-home persona mode. When
    /// set it shadows [`Self::home`] everywhere [`Self::home`] is consulted, so
    /// callers never special-case persona mode.
    persona_home: Option<PathBuf>,
}

impl TargetUser {
    /// The home directory to operate on: the persona home when one is set,
    /// otherwise the passwd home.
    pub fn home(&self) -> &Path {
        self.persona_home.as_deref().unwrap_or(self.home.as_path())
    }

    /// The passwd home directory, ignoring any persona override.
    pub fn passwd_home(&self) -> &Path {
        self.home.as_path()
    }

    /// Override the home directory with a persona home (fresh-home mode).
    pub fn with_persona_home(mut self, persona_home: PathBuf) -> Self {
        self.persona_home = Some(persona_home);
        self
    }

    /// Homes that history and artifact cleanup must cover: the operator's home
    /// plus `/root`, deduplicated. `/root` is always included because a `sudo`
    /// run leaves residue there whoever the operator is.
    pub fn cleanup_homes(&self) -> Vec<PathBuf> {
        let mut homes = vec![self.home().to_path_buf()];
        let root = PathBuf::from(ROOT_HOME);
        if !homes.contains(&root) {
            homes.push(root);
        }
        homes
    }

    fn from_entry(entry: PasswdEntry) -> Self {
        Self {
            uid: entry.uid,
            gid: entry.gid,
            name: entry.name,
            home: entry.dir,
            shell: entry.shell,
            persona_home: None,
        }
    }

    /// Resolve the target user from the real environment, passwd database and
    /// logind. Returns an error when no source identifies an account; it never
    /// falls back to root.
    pub fn resolve() -> Result<TargetUser> {
        resolve_from(&SystemEnv, &SystemPasswd, &SystemSessionOwner)
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
        "Could not determine the target user: none of NAILS_TARGET_UID, SUDO_UID, PKEXEC_UID, \
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

/// Passwd-database lookup, injectable for tests.
pub(crate) trait PasswdSource {
    fn by_uid(&self, uid: u32) -> Option<PasswdEntry>;
    fn by_name(&self, name: &str) -> Option<PasswdEntry>;
}

/// Active-session owner lookup, injectable for tests.
pub(crate) trait SessionOwnerSource {
    fn seat0_active_uid(&self) -> Option<u32>;
}

struct SystemEnv;

impl EnvSource for SystemEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
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

/// Run `loginctl` with the given arguments and return trimmed stdout on success.
fn run_loginctl(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("loginctl")
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

#[cfg(test)]
mod tests;
