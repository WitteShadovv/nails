use nix::{libc, unistd::setsid};
use std::env;
use std::ffi::OsString;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use nails_core::NailsError;

/// Detach and re-exec the CLI so it survives GUI session teardown.
///
/// Returns Ok(()) in the parent (which will exit shortly after calling).
/// In the child, this function never returns because the process image is
/// replaced by /proc/self/exe.
pub fn maybe_detach_for_session_kill(
    kill_session: bool,
    args: &[OsString],
) -> Result<(), NailsError> {
    // Testing override: allow tests to bypass actual detaching/spawn.
    if env::var_os("NAILS_SKIP_DETACH").is_some() {
        return Ok(());
    }

    // Only detach when --kill-session is requested and we look like a GUI session.
    if !kill_session {
        return Ok(());
    }

    // Prevent recursion after re-exec.
    if env::var_os("NAILS_DETACHED").is_some() {
        return Ok(());
    }

    // If no graphical markers, nothing to detach from.
    if env::var_os("DISPLAY").is_none() && env::var_os("WAYLAND_DISPLAY").is_none() {
        return Ok(());
    }

    // Build child command: re-exec the same binary with same args.
    let mut cmd = Command::new("/proc/self/exe");
    cmd.args(args);

    // Strip session-identifying env so we are not killed with the GUI session.
    for var in [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_SESSION_ID",
        "XDG_RUNTIME_DIR",
    ] {
        cmd.env_remove(var);
    }

    // Mark as detached to avoid infinite loop.
    cmd.env("NAILS_DETACHED", "1");

    // If the parent dies, we should keep running; ignore SIGHUP.
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    unsafe {
        cmd.pre_exec(|| {
            // New session/process group so terminal death doesn't kill us.
            setsid().map_err(|e| io::Error::from_raw_os_error(e as i32))?;

            // Ignore SIGHUP.
            libc::signal(libc::SIGHUP, libc::SIG_IGN);

            // Clear parent-death signal if set (best-effort).
            #[cfg(target_os = "linux")]
            {
                let _ = libc::prctl(libc::PR_SET_PDEATHSIG, 0, 0, 0, 0);
            }

            Ok(())
        });
    }

    let child = cmd.spawn().map_err(NailsError::from)?;

    eprintln!(
        "Handoff complete; activation continues in background (pid {}).",
        child.id()
    );

    // Parent exits cleanly; child keeps running.
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn with_env<K: AsRef<str>, V: AsRef<str>, F: FnOnce()>(key: K, val: V, f: F) {
        unsafe {
            env::set_var(key.as_ref(), val.as_ref());
        }
        f();
        unsafe {
            env::remove_var(key.as_ref());
        }
    }

    #[test]
    fn does_nothing_when_kill_session_false() {
        with_env("NAILS_SKIP_DETACH", "1", || {
            unsafe { env::set_var("DISPLAY", ":0") };
            let res = maybe_detach_for_session_kill(false, &[OsString::from("nails")]);
            unsafe { env::remove_var("DISPLAY") };
            assert!(res.is_ok());
        });
    }

    #[test]
    fn does_nothing_without_graphical_env() {
        with_env("NAILS_SKIP_DETACH", "1", || {
            unsafe { env::remove_var("DISPLAY") };
            unsafe { env::remove_var("WAYLAND_DISPLAY") };
            let res = maybe_detach_for_session_kill(true, &[OsString::from("nails")]);
            assert!(res.is_ok());
        });
    }

    #[test]
    fn skips_when_already_detached() {
        with_env("NAILS_SKIP_DETACH", "1", || {
            unsafe { env::set_var("DISPLAY", ":1") };
            unsafe { env::set_var("NAILS_DETACHED", "1") };
            let res = maybe_detach_for_session_kill(true, &[OsString::from("nails")]);
            unsafe { env::remove_var("DISPLAY") };
            unsafe { env::remove_var("NAILS_DETACHED") };
            assert!(res.is_ok());
        });
    }
}
