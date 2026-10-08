// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The examiner checks that read the raw disk: encryption headers on
//! partitions and in gaps, and random-looking regions no table explains.

use super::{ExaminerFinding, ExaminerOptions};
use crate::forensic::entropy;
use crate::forensic::layout::{Signature, TableKind, read_layout, signature_at};
use crate::forensic::raw::RawSource;
use crate::verify::Severity;
use std::io;
use std::path::Path;

/// Gaps smaller than this are alignment padding and not sampled.
const MIN_GAP: u64 = 1 << 20;
/// Bytes per entropy sample.
const SAMPLE: usize = 64 << 10;
/// Most 1 MiB-aligned header probes per gap.
const MAX_GAP_PROBES: u64 = 64;
/// Share of samples that must read as random to report a region.
const HIGH_SHARE: f64 = 0.75;

/// Mean entropy and the share of high-entropy samples over `[start, end)`.
fn sample(source: &RawSource, start: u64, end: u64, count: usize) -> io::Result<(f64, f64)> {
    let span = end.saturating_sub(start);
    if span == 0 || count == 0 {
        return Ok((0.0, 0.0));
    }
    let len = (SAMPLE as u64).min(span) as usize;
    let mut buf = vec![0u8; len];
    let mut total = 0.0;
    let mut high = 0usize;
    let mut taken = 0usize;
    for index in 0..count as u64 {
        let offset = start + (span - len as u64) * index / (count as u64 - 1).max(1);
        let read = source.read_at(&mut buf, offset)?;
        if read == 0 {
            continue;
        }
        let bits = entropy::bits_per_byte(&buf[..read]);
        total += bits;
        taken += 1;
        if bits >= entropy::HIGH_ENTROPY {
            high += 1;
        }
    }
    if taken == 0 {
        return Ok((0.0, 0.0));
    }
    Ok((total / taken as f64, high as f64 / taken as f64))
}

fn finding(id: &'static str, location: String, evidence: String) -> ExaminerFinding {
    ExaminerFinding {
        catalog_id: id,
        severity: Severity::Warn,
        location,
        evidence,
    }
}

/// A header finding, if `signature` is an encryption header.
fn header_finding(signature: Signature, location: String) -> Option<ExaminerFinding> {
    let evidence = match signature {
        Signature::Luks(version) => format!("LUKS{version} header"),
        Signature::Luks2Secondary(offset) => {
            format!("LUKS2 secondary header {offset:#x} bytes in, with no primary header")
        }
        Signature::Format("bitlocker") => "BitLocker volume header".to_string(),
        _ => return None,
    };
    Some(finding("luks-headers", location, evidence))
}

/// Audit the raw disk or image at `path`.
///
/// # Errors
///
/// Fails when the source cannot be opened or read.
pub(super) fn audit(path: &Path, options: &ExaminerOptions) -> io::Result<Vec<ExaminerFinding>> {
    let source = RawSource::open(path)?;
    let layout = read_layout(&source)?;
    let mut out = Vec::new();
    let samples = options.samples_per_region.max(2);

    if layout.table == TableKind::None {
        let signature = signature_at(&source, 0)?;
        if let Some(found) = header_finding(signature, "whole device".to_string()) {
            out.push(found);
        } else if signature == Signature::Unknown {
            let (mean, share) = sample(&source, 0, source.size(), samples)?;
            if share >= HIGH_SHARE {
                out.push(finding(
                    "high-entropy-space",
                    "whole device".to_string(),
                    format!("no partition table and no known format; reads as random ({mean:.3} bits/byte)"),
                ));
            }
        }
        return Ok(out);
    }

    for partition in &layout.partitions {
        let location = format!(
            "partition {} ({}..{}, type {})",
            partition.number,
            partition.start,
            partition.end(),
            partition.type_id
        );
        let signature = signature_at(&source, partition.start)?;
        if let Some(found) = header_finding(signature, location.clone()) {
            out.push(found);
            continue;
        }
        if signature == Signature::Unknown {
            let (mean, share) = sample(&source, partition.start, partition.end(), samples)?;
            if share >= HIGH_SHARE {
                out.push(finding(
                    "high-entropy-space",
                    location,
                    format!("no known format; reads as random ({mean:.3} bits/byte)"),
                ));
            }
        }
    }

    for &(start, end) in &layout.gaps {
        if end - start < MIN_GAP {
            continue;
        }
        let location = format!("unpartitioned space {start}..{end}");
        let first_probe = start.div_ceil(MIN_GAP) * MIN_GAP;
        let mut probes = vec![start];
        probes.extend(
            (0..MAX_GAP_PROBES)
                .map(|i| first_probe + i * MIN_GAP)
                .take_while(|offset| *offset < end)
                .filter(|offset| *offset != start),
        );
        let mut headed = false;
        for offset in probes {
            if let Some(found) = header_finding(
                signature_at(&source, offset)?,
                format!("unpartitioned space at {offset}"),
            ) {
                out.push(found);
                headed = true;
                break;
            }
        }
        if headed {
            continue;
        }
        let (mean, share) = sample(&source, start, end, samples)?;
        if share >= HIGH_SHARE {
            out.push(finding(
                "high-entropy-space",
                location,
                format!("reads as random ({mean:.3} bits/byte) where a fresh disk holds zeros"),
            ));
        }
    }
    Ok(out)
}
