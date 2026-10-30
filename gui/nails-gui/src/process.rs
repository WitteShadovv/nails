// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! What the window's own process shows to whoever lists it.
//!
//! The program is called `session` (see [`text::APP_ID`]), so the name the
//! kernel gives the process at `exec`, the name a process list shows, is
//! neutral already. The window sets it again first thing, so a start through
//! another file name (a bundled loader, say) still shows `session`, and every
//! thread it starts afterwards inherits it.

use crate::text;

/// Give the calling thread, and so every thread it starts afterwards, the
/// window's neutral name. Called first thing on the main thread, it is the
/// name of the process.
///
/// # Errors
///
/// The error of `prctl(PR_SET_NAME)`.
pub fn name_neutrally() -> std::io::Result<()> {
    let name = std::ffi::CString::new(text::APP_ID).map_err(std::io::Error::other)?;
    rustix::thread::set_name(&name)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_thread_takes_the_neutral_name() {
        // A test runs on a thread of its own, which the name is given to
        // alone: nothing else of the test binary changes its name.
        name_neutrally().unwrap();
        let comm = std::fs::read_to_string("/proc/thread-self/comm").unwrap();
        assert_eq!(comm.trim_end(), "session");
        let child = std::thread::spawn(|| std::fs::read_to_string("/proc/thread-self/comm"))
            .join()
            .unwrap()
            .unwrap();
        assert_eq!(
            child.trim_end(),
            "session",
            "a thread started afterwards inherits it"
        );
    }
}
