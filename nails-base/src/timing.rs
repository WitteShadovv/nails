// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Timing utilities for measuring operation durations
//!
//! This module provides utilities for timing operations and formatting
//! duration output in a human-readable format.

use std::time::{Duration, Instant};

/// A simple stopwatch for measuring elapsed time
///
/// # Examples
///
/// ```
/// use nails_base::Stopwatch;
/// use std::thread;
/// use std::time::Duration;
///
/// let stopwatch = Stopwatch::start();
/// thread::sleep(Duration::from_millis(100));
/// let elapsed = stopwatch.elapsed();
/// assert!(elapsed.as_millis() >= 100);
/// ```
#[derive(Debug, Clone)]
pub struct Stopwatch {
    start: Instant,
}

impl Stopwatch {
    /// Create a new stopwatch and start timing
    ///
    /// # Examples
    ///
    /// ```
    /// use nails_base::Stopwatch;
    ///
    /// let stopwatch = Stopwatch::start();
    /// // ... perform operations ...
    /// println!("Elapsed: {}", stopwatch);
    /// ```
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Get the elapsed duration since the stopwatch started
    ///
    /// # Examples
    ///
    /// ```
    /// use nails_base::Stopwatch;
    /// use std::time::Duration;
    ///
    /// let stopwatch = Stopwatch::start();
    /// let elapsed = stopwatch.elapsed();
    /// assert!(elapsed < Duration::from_secs(1));
    /// ```
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Get the elapsed time in seconds as a floating point number
    ///
    /// # Examples
    ///
    /// ```
    /// use nails_base::Stopwatch;
    ///
    /// let stopwatch = Stopwatch::start();
    /// let secs = stopwatch.elapsed_secs();
    /// assert!(secs >= 0.0);
    /// ```
    pub fn elapsed_secs(&self) -> f64 {
        self.elapsed().as_secs_f64()
    }
}

/// Format elapsed time for human-readable output
///
/// - Times < 0.1s: format as milliseconds (e.g., "45ms")
/// - Times >= 0.1s: format as seconds with 1 decimal place (e.g., "1.2s")
impl std::fmt::Display for Stopwatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let secs = self.elapsed_secs();
        if secs < 0.1 {
            write!(f, "{:.0}ms", secs * 1000.0)
        } else {
            write!(f, "{:.1}s", secs)
        }
    }
}

/// Formats `elapsed` as a compact label: `45s`, `2m10s`, or `1h02m03s`.
///
/// Shared by the long-step heartbeat, the activation progress display and
/// `nails status`, so every surface writes durations the same way.
pub fn format_elapsed(elapsed: Duration) -> String {
    let total = elapsed.as_secs();
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;
    if hours > 0 {
        format!("{hours}h{minutes:02}m{seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m{seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

/// Formats how long an activation took, as `activate` and `status` both show
/// it: tenths of a second under a minute (`11.0s`), whole seconds from a
/// minute on (`1m32s`, as [`format_elapsed`]), each rounded to the nearest.
pub fn format_duration(duration: Duration) -> String {
    let millis = duration.as_millis();
    let tenths = (millis + 50) / 100;
    if tenths < 600 {
        format!("{}.{}s", tenths / 10, tenths % 10)
    } else {
        let seconds = u64::try_from((millis + 500) / 1000).unwrap_or(u64::MAX);
        format_elapsed(Duration::from_secs(seconds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn format_duration_shows_tenths_under_a_minute_and_whole_seconds_above() {
        let ms = Duration::from_millis;
        assert_eq!(format_duration(ms(0)), "0.0s");
        assert_eq!(format_duration(ms(2_331)), "2.3s");
        assert_eq!(format_duration(ms(10_960)), "11.0s");
        assert_eq!(format_duration(ms(59_940)), "59.9s");
        assert_eq!(format_duration(ms(59_960)), "1m00s");
        assert_eq!(format_duration(ms(92_000)), "1m32s");
        assert_eq!(format_duration(ms(92_600)), "1m33s");
        assert_eq!(format_duration(ms(3_723_000)), "1h02m03s");
    }

    #[test]
    fn test_stopwatch_start() {
        let stopwatch = Stopwatch::start();
        assert!(stopwatch.elapsed() < Duration::from_millis(10));
    }

    #[test]
    fn test_stopwatch_elapsed() {
        let stopwatch = Stopwatch::start();
        thread::sleep(Duration::from_millis(50));
        let elapsed = stopwatch.elapsed();
        assert!(elapsed >= Duration::from_millis(50));
        assert!(elapsed < Duration::from_millis(150));
    }

    #[test]
    fn test_stopwatch_elapsed_secs() {
        let stopwatch = Stopwatch::start();
        thread::sleep(Duration::from_millis(100));
        let secs = stopwatch.elapsed_secs();
        assert!(secs >= 0.1);
        assert!(secs < 0.2);
    }

    #[test]
    fn test_stopwatch_display_milliseconds() {
        let stopwatch = Stopwatch::start();
        thread::sleep(Duration::from_millis(20));
        let display = format!("{}", stopwatch);
        // Should be formatted as milliseconds (less than 0.1s)
        assert!(display.ends_with("ms"));
    }

    #[test]
    fn test_stopwatch_display_seconds() {
        let stopwatch = Stopwatch::start();
        thread::sleep(Duration::from_millis(150));
        let display = format!("{}", stopwatch);
        // Should be formatted as seconds (>= 0.1s)
        assert!(display.ends_with("s") && !display.ends_with("ms"));
    }

    #[test]
    fn test_stopwatch_clone() {
        let stopwatch1 = Stopwatch::start();
        thread::sleep(Duration::from_millis(10));
        let stopwatch2 = stopwatch1.clone();

        // Both should measure from the same start time
        let elapsed1 = stopwatch1.elapsed();
        let elapsed2 = stopwatch2.elapsed();

        // Should be very close (within 1ms)
        let diff = elapsed1.as_millis().abs_diff(elapsed2.as_millis());
        assert!(diff < 1);
    }
}
