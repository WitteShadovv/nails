// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Telling one process apart from a later one that reused its pid.

/// Parse the start time (field 22, clock ticks since boot) out of a
/// `/proc/<pid>/stat` body. `comm` may contain spaces and parentheses, so the
/// fields are counted from past its closing `)`.
pub(crate) fn parse_stat_start_time(stat: &str) -> Option<u64> {
    let after_comm = stat.get(stat.rfind(')')? + 1..)?;
    // After `comm`: state (field 3) ... starttime (field 22), i.e. index 19.
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// The start time of `pid`, from `/proc/<pid>/stat`; `None` when it is gone.
pub(crate) fn proc_start_time(pid: u32) -> Option<u64> {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .as_deref()
        .and_then(parse_stat_start_time)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_start_time_is_field_22_even_with_a_tricky_comm() {
        let stat =
            "4242 (a) b (c)) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 100";
        assert_eq!(parse_stat_start_time(stat), Some(987_654));
        assert_eq!(parse_stat_start_time("4242 (x) S 1"), None);
    }

    #[test]
    fn this_process_has_a_stable_start_time_and_a_child_a_later_one() {
        let own = proc_start_time(std::process::id()).expect("own start time");
        assert_eq!(proc_start_time(std::process::id()), Some(own));
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let theirs = proc_start_time(child.id()).expect("child start time");
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(theirs >= own);
        assert_eq!(proc_start_time(child.id()), None);
    }
}
