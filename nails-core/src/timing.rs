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
/// use nails_core::Stopwatch;
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
    /// use nails_core::Stopwatch;
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
    /// use nails_core::Stopwatch;
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
    /// use nails_core::Stopwatch;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

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
