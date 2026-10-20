// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Human output for `nails rehearse`.

use nails_core::output::{Mark, Style, Tone};
use nails_core::rehearse::{ChannelRecord, ScanReport};

/// One line per channel: planted, or why not.
pub(crate) fn print_channels(style: Style, channels: &[ChannelRecord]) {
    for record in channels {
        match &record.skipped {
            None => println!(
                "  {} {:?}: {}",
                style.glyph(Mark::Pass),
                record.kind,
                record.location
            ),
            Some(reason) => println!(
                "  {} {:?}: {}",
                style.glyph(Mark::Neutral),
                record.kind,
                style.paint(format_args!("not planted ({reason})"), Tone::Dim)
            ),
        }
    }
}

/// The scan result: the headline, each device with its hits by offset, the
/// channels the canary never went into, and what the scan cannot see.
/// `fingerprint` names the canary; the token itself never reaches the renderer.
pub(crate) fn print_scan(
    style: Style,
    report: &ScanReport,
    fingerprint: &str,
    channels: &[ChannelRecord],
) {
    let hits = report.total_hits();
    let headline = if hits > 0 {
        style.paint_bold(
            format_args!(
                "{} Canary {fingerprint} FOUND on the decoy: {}",
                style.glyph(Mark::Fail),
                super::count_noun(hits, "hit", "hits")
            ),
            Tone::Red,
        )
    } else {
        style.paint_bold(
            format_args!(
                "{} Canary {fingerprint} not found on the scanned devices",
                style.glyph(Mark::Pass),
            ),
            Tone::Green,
        )
    };
    println!("{headline}");
    for device in &report.devices {
        match &device.error {
            Some(error) => println!(
                "  {} {}: not scanned ({error})",
                style.glyph(Mark::Warn),
                device.device.display()
            ),
            None => {
                println!(
                    "  {} {}: {} of {} bytes read{}{}",
                    style.glyph(Mark::Bullet),
                    device.device.display(),
                    device.bytes_scanned,
                    device.size,
                    if device.bytes_skipped > 0 {
                        " (sparse holes skipped)"
                    } else {
                        ""
                    },
                    if device.limit_reached {
                        ", stopped at --max-bytes"
                    } else {
                        ""
                    }
                );
                for hit in &device.hits {
                    println!("      offset {} ({:?})", hit.offset, hit.encoding);
                }
                if device.hits_capped {
                    println!("      more hits not listed");
                }
            }
        }
    }
    print_untested(style, channels);
    println!();
    println!("{}", style.paint("Not visible to this scan:", Tone::Dim));
    for line in &report.not_visible {
        println!(
            "  {} {}",
            style.glyph(Mark::Arrow),
            style.paint(line, Tone::Dim)
        );
    }
}

/// The channels the canary was never planted in: a clean scan says nothing
/// about them, so they are listed with every result.
fn print_untested(style: Style, channels: &[ChannelRecord]) {
    let mut untested = channels
        .iter()
        .filter_map(|record| Some((record.kind, record.skipped.as_deref()?)))
        .peekable();
    if untested.peek().is_none() {
        return;
    }
    println!();
    println!(
        "{}",
        style.paint(
            "Not tested, because the canary was never planted there:",
            Tone::Dim
        )
    );
    for (kind, reason) in untested {
        println!(
            "  {} {kind:?}: {}",
            style.glyph(Mark::Neutral),
            style.paint(reason, Tone::Dim)
        );
    }
}
