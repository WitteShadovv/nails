// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Entering a hidden NixOS toplevel without touching the bootloader.
//!
//! A soft-reboot executes `/run/current-system/systemd/lib/systemd/systemd`
//! directly; NixOS's stage-2 activation does not run again. So before the
//! switch, NAILS:
//!
//! 1. builds the hidden toplevel **into the next root's store**
//!    (`nix build --store /run/nextroot`): the build reads the decoy store
//!    through the overlay's lower and writes every new path, the database
//!    included, into the overlay's upper on the hidden volume. Nothing reaches
//!    the decoy's `/nix`; the evaluation cache goes to the hidden volume too;
//! 2. runs the toplevel's `activate` chrooted into the next root, in a private
//!    mount namespace with `/dev`, `/proc` and `/sys` bound and a **fresh tmpfs
//!    at `/run`**, the way `nixos-enter` does. It writes the hidden `/etc`,
//!    users and groups into the upper and never touches the real `/run`;
//! 3. leaves the last step to the transition (in `nails-teardown`): it repoints
//!    `/run/current-system` to the hidden toplevel after every decoy unit has
//!    stopped, so PID 1 executes the hidden systemd against the hidden `/etc`.
//!    One grey-out, and the greeter already belongs to the hidden configuration.
//!
//! The way back repoints the link to the decoy toplevel recorded here. Only
//! `activate` ever runs: no `switch-to-configuration boot`, no bootloader
//! install. The hidden toplevel must run on the decoy's kernel, because the
//! modules come from `/run/booted-system`.

use crate::error::{NailsError, Result};
use crate::nixos::NixOSBuilder;
use crate::process::{ProcessCommand, ProcessRunner};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The init PID 1 executes on NixOS (`SYSTEMD_BINARY_PATH`).
pub const NIXOS_INIT: &str = "/run/current-system/systemd/lib/systemd/systemd";

/// The decoy's running toplevel: where `/run/current-system` points now.
pub fn decoy_system(run: &Path) -> Option<PathBuf> {
    let link = run.join("current-system");
    std::fs::canonicalize(&link)
        .ok()
        .filter(|p| p.starts_with("/nix/store"))
}

/// The `nixpkgs=` search-path entry for a legacy build whose caller has no
/// `NIX_PATH`: root's `nixos` channel, which NixOS's default `nix.nixPath`
/// names. A login shell sets `NIX_PATH`; a systemd unit (a panic key,
/// `systemd-run`) does not, and `<nixpkgs/nixos>` would not resolve.
fn default_nixpkgs(caller_nix_path: bool, root_channel: &Path) -> Option<String> {
    (!caller_nix_path && root_channel.is_dir())
        .then(|| format!("nixpkgs={}", root_channel.display()))
}

/// The kernel image a toplevel boots, to compare the hidden toplevel's kernel
/// with the running one.
pub fn kernel_of(store_root: &Path, system: &Path) -> Option<PathBuf> {
    let inner = store_root.join(system.strip_prefix("/").unwrap_or(system));
    std::fs::read_link(inner.join("kernel")).ok()
}

/// Build the hidden toplevel described by `builder` into the store of the
/// next root at `store_root`. Returns the toplevel's store path.
pub fn build_into(
    runner: &dyn ProcessRunner,
    builder: &NixOSBuilder,
    store_root: &Path,
    cache_dir: &Path,
) -> Result<PathBuf> {
    std::fs::create_dir_all(cache_dir).map_err(|e| NailsError::io(cache_dir, e))?;
    let store = store_root.to_string_lossy().into_owned();
    let command = match builder.legacy_config() {
        None => {
            let installable = builder.toplevel_installable()?;
            ProcessCommand::caller_path("nix").args([
                "--extra-experimental-features",
                "nix-command flakes",
                "build",
                "--store",
                &store,
                &installable,
                "--no-link",
                "--print-out-paths",
                "--no-update-lock-file",
                "--impure",
            ])
        }
        Some(config) => {
            // The configuration as the hidden root will see it: the decoy's
            // file through the overlay, its hardware-configuration.nix the
            // hidden one in the upper.
            let in_root = store_root.join(config.strip_prefix("/").unwrap_or(config));
            let command = ProcessCommand::caller_path("nix-build")
                .args([
                    "--store",
                    &store,
                    "<nixpkgs/nixos>",
                    "-A",
                    "system",
                    "--no-out-link",
                ])
                .arg("-I")
                .arg(format!("nixos-config={}", in_root.display()))
                .allow_env("NIX_PATH");
            let caller_nix_path = nails_base::runtime_env::current().inherited.has("NIX_PATH");
            match default_nixpkgs(
                caller_nix_path,
                Path::new(nails_base::constants::NIXOS_ROOT_CHANNEL),
            ) {
                Some(nixpkgs) => command.arg("-I").arg(nixpkgs),
                None => command,
            }
        }
    }
    .set_env("XDG_CACHE_HOME", cache_dir)
    .set_env("HOME", cache_dir)
    .allow_in_test_runtime();
    let (ok, stdout, stderr) = runner.run_streaming_text(
        &command,
        crate::process::run::BUILD_PROGRESS_INTERVAL,
        &mut |elapsed, last| crate::reporter::progress::heartbeat("building", elapsed, last),
    )?;
    if !ok {
        return Err(NailsError::NixOSError(format!(
            "building the hidden NixOS system failed: {}",
            build_error(&stderr)
        )));
    }
    stdout
        .lines()
        .map(str::trim)
        .rfind(|l| l.starts_with("/nix/store/"))
        .map(PathBuf::from)
        .ok_or_else(|| NailsError::NixOSError("the build printed no store path".to_string()))
}

/// Why a build failed, from its output: nix's last `error:` and what
/// follows it up to the `nix log` hint (the build log tail included), else the
/// last line.
fn build_error(stderr: &str) -> String {
    let lines: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    match lines.iter().rposition(|l| l.starts_with("error:")) {
        Some(start) => lines[start..]
            .iter()
            .take_while(|l| !l.starts_with("For full logs"))
            .copied()
            .collect::<Vec<_>>()
            .join(" / "),
        None => lines.last().copied().unwrap_or("no output").to_string(),
    }
}

fn c_path(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| NailsError::InvalidArgument(format!("NUL in {}", path.display())))
}

/// Run `<system>/activate` chrooted into `root`, in a private mount namespace
/// with `/dev`, `/proc`, `/sys` bound and a fresh tmpfs at `/run`. Nothing it
/// mounts is visible outside the child.
#[allow(unsafe_code)]
pub fn activate_in(root: &Path, system: &Path) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let activate = system.join("activate");
    let inner = root.join(activate.strip_prefix("/").unwrap_or(&activate));
    if !inner.is_file() {
        return Err(NailsError::NixOSError(format!(
            "{} has no activate script in the next root",
            system.display()
        )));
    }
    // Everything the child touches is prepared here: no allocation after fork.
    let root_c = c_path(root)?;
    let binds: Vec<(CString, CString)> = ["dev", "proc", "sys"]
        .iter()
        .map(|d| Ok((c_path(&Path::new("/").join(d))?, c_path(&root.join(d))?)))
        .collect::<Result<_>>()?;
    let run_c = c_path(&root.join("run"))?;
    let slash = c_path(Path::new("/"))?;
    let tmpfs = c_path(Path::new("tmpfs"))?;
    let mode = c_path(Path::new("mode=0755"))?;

    let mut command = std::process::Command::new(&activate);
    command
        .env_clear()
        .env("PATH", system.join("sw/bin"))
        .env(
            "LOCALE_ARCHIVE",
            system.join("sw/lib/locale/locale-archive"),
        )
        .env("IN_NIXOS_ENTER", "1")
        .stdin(std::process::Stdio::null());
    // SAFETY: the closure runs in the forked child before exec and only makes
    // raw syscalls (unshare, mount, chroot, chdir) on CStrings prepared above.
    unsafe {
        command.pre_exec(move || {
            use rustix::mount::{MountFlags, MountPropagationFlags};
            rustix::thread::unshare_unsafe(rustix::thread::UnshareFlags::NEWNS)?;
            rustix::mount::mount_change(
                slash.as_c_str(),
                MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
            )?;
            for (source, target) in &binds {
                rustix::mount::mount_bind_recursive(source.as_c_str(), target.as_c_str())?;
            }
            rustix::mount::mount(
                tmpfs.as_c_str(),
                run_c.as_c_str(),
                tmpfs.as_c_str(),
                MountFlags::NOSUID | MountFlags::NODEV,
                mode.as_c_str(),
            )?;
            rustix::process::chroot(root_c.as_c_str())?;
            rustix::process::chdir(slash.as_c_str())?;
            Ok(())
        });
    }
    let output = command.output().map_err(|e| NailsError::io(&activate, e))?;
    if !output.status.success() {
        tracing::warn!(
            status = ?output.status.code(),
            stderr = %String::from_utf8_lossy(&output.stderr).lines().rev().take(5).collect::<Vec<_>>().join(" | "),
            "the hidden system's activation reported errors (as nixos-enter tolerates)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_build_reports_nix_error_line_not_the_log_hint() {
        let stderr = "error: Cannot build '/nix/store/x.drv'.\n       Reason: builder failed with exit code 127.\n       > bash: sleep: command not found\n       For full logs, run:\n         nix log /nix/store/x.drv\n";
        assert_eq!(
            build_error(stderr),
            "error: Cannot build '/nix/store/x.drv'. / Reason: builder failed with exit code \
             127. / > bash: sleep: command not found"
        );
        assert_eq!(build_error("warning: a\nlast\n\n"), "last");
        assert_eq!(build_error(""), "no output");
    }

    #[test]
    fn the_decoy_system_is_the_resolved_current_system_link_in_the_store_only() {
        let run = tempfile::tempdir().unwrap();
        assert_eq!(decoy_system(run.path()), None);
        let target = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(target.path(), run.path().join("current-system")).unwrap();
        // Outside /nix/store: not a NixOS toplevel.
        assert_eq!(decoy_system(run.path()), None);
    }

    #[test]
    fn without_a_caller_nix_path_the_root_channel_supplies_nixpkgs() {
        let channel = tempfile::tempdir().unwrap();
        assert_eq!(
            default_nixpkgs(false, channel.path()),
            Some(format!("nixpkgs={}", channel.path().display()))
        );
        // The caller's NIX_PATH wins, and a host without the channel adds nothing.
        assert_eq!(default_nixpkgs(true, channel.path()), None);
        assert_eq!(
            default_nixpkgs(false, &channel.path().join("missing")),
            None
        );
    }

    #[test]
    fn an_activation_without_a_script_is_refused_before_any_fork() {
        let root = tempfile::tempdir().unwrap();
        let error = activate_in(root.path(), Path::new("/nix/store/x-nixos-system")).unwrap_err();
        assert!(error.to_string().contains("no activate script"), "{error}");
    }
}
