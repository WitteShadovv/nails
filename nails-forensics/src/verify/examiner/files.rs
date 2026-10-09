// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The examiner checks that read files on the mounted decoy root.

use super::{ExaminerFinding, ExaminerOptions, rebase};
use crate::filesystem::real::{OpenKind, open_noatime, read_dir_noatime};
use crate::forensic::entropy;
use crate::forensic::tree::{WalkLimits, walk_files};
use crate::verify::Severity;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

/// Most bytes read from a configuration or history file.
const TEXT_LIMIT: u64 = 4 << 20;
/// Bytes per entropy sample of a container candidate.
const SAMPLE: usize = 64 << 10;
/// Directories the container walk never enters: pseudo filesystems, the
/// read-only Nix store, whose build outputs are not where a container hides,
/// and the firmware directories, whose blobs (Intel microcode among them) are
/// encrypted by their vendors and read as random. On a real Debian install the
/// microcode alone put seven "containers" in every report.
const WALK_SKIP: &[&str] = &[
    "proc",
    "sys",
    "dev",
    "run",
    "nix/store",
    "usr/lib/firmware",
    "lib/firmware",
];

/// Read at most `limit` bytes of a file without following a final symlink or
/// touching its access time.
fn read_text(path: &Path, limit: u64) -> Option<String> {
    let file = File::from(open_noatime(path, OpenKind::FileNoFollow).ok()?);
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn finding(
    id: &'static str,
    severity: Severity,
    location: impl Into<String>,
    evidence: impl Into<String>,
) -> ExaminerFinding {
    ExaminerFinding {
        catalog_id: id,
        severity,
        location: location.into(),
        evidence: evidence.into(),
    }
}

/// Lines of a config file without comments and blank lines.
fn config_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

/// crypttab entries, and fstab entries that mount a mapper or a loop file.
pub(super) fn config_entries(root: &Path) -> Vec<ExaminerFinding> {
    let mut out = Vec::new();
    if let Some(text) = read_text(&rebase(root, "/etc/crypttab"), TEXT_LIMIT) {
        for line in config_lines(&text) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let name = fields.first().copied().unwrap_or("");
            let device = fields.get(1).copied().unwrap_or("");
            let options = fields.get(3).copied().unwrap_or("");
            let deniable = ["tcrypt", "veracrypt", "plain", "tcrypt-hidden"]
                .iter()
                .any(|kind| options.split(',').any(|opt| opt == *kind));
            let file_backed = device.starts_with('/') && !device.starts_with("/dev/");
            let severity = if deniable || file_backed {
                Severity::Warn
            } else {
                Severity::Info
            };
            let mut evidence = format!("encrypted mapping {name} from {device}");
            if !options.is_empty() {
                evidence.push_str(&format!(" ({options})"));
            }
            out.push(finding(
                "crypttab-fstab",
                severity,
                "/etc/crypttab",
                evidence,
            ));
        }
    }
    if let Some(text) = read_text(&rebase(root, "/etc/fstab"), TEXT_LIMIT) {
        for line in config_lines(&text) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let source = fields.first().copied().unwrap_or("");
            let target = fields.get(1).copied().unwrap_or("");
            let options = fields.get(3).copied().unwrap_or("");
            let loop_mount = options.split(',').any(|opt| opt == "loop");
            if source.starts_with("/dev/mapper/") || loop_mount {
                let severity = if loop_mount {
                    Severity::Warn
                } else {
                    Severity::Info
                };
                out.push(finding(
                    "crypttab-fstab",
                    severity,
                    "/etc/fstab",
                    format!("{source} mounted on {target} ({options})"),
                ));
            }
        }
    }
    out
}

/// The value of `key = "..."` (or `key = N`) in LVM metadata text.
fn lvm_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().map(str::trim).find_map(|line| {
        let rest = line
            .strip_prefix(key)?
            .trim_start()
            .strip_prefix('=')?
            .trim();
        let value = rest.split('#').next()?.trim();
        Some(value.trim_matches('"'))
    })
}

/// The volume group name: the first top-level `name {` block.
fn lvm_vg_name(text: &str) -> Option<&str> {
    text.lines().find_map(|line| {
        let trimmed = line.trim_end();
        if line.starts_with(char::is_whitespace) {
            return None;
        }
        trimmed.strip_suffix('{').map(str::trim)
    })
}

/// Every metadata file under /etc/lvm/archive and /etc/lvm/backup.
pub(super) fn lvm_metadata(root: &Path) -> Vec<ExaminerFinding> {
    let mut out = Vec::new();
    for dir in ["/etc/lvm/archive", "/etc/lvm/backup"] {
        let path = rebase(root, dir);
        let Ok(entries) = read_dir_noatime(&path) else {
            continue;
        };
        let mut names: Vec<_> = entries.into_iter().map(|entry| entry.name).collect();
        names.sort();
        for name in names {
            let file = path.join(&name);
            let Some(text) = read_text(&file, TEXT_LIMIT) else {
                continue;
            };
            let vg = lvm_vg_name(&text).unwrap_or("?");
            let mut evidence = format!("volume group {vg}");
            if let Some(description) = lvm_value(&text, "description") {
                evidence.push_str(&format!(": {description}"));
            }
            if let Some(host) = lvm_value(&text, "creation_host") {
                evidence.push_str(&format!(" on host {host}"));
            }
            if let Some(time) = lvm_value(&text, "creation_time")
                .and_then(|value| value.parse::<i64>().ok())
                .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
            {
                evidence.push_str(&format!(" at {}", time.format("%Y-%m-%dT%H:%M:%SZ")));
            }
            out.push(finding(
                "lvm-metadata-archive",
                Severity::Warn,
                format!("{dir}/{}", name.to_string_lossy()),
                evidence,
            ));
        }
    }
    out
}

/// The encryption tools whose presence and use an examiner reads.
const TOOLS: &[(&str, Severity)] = &[
    ("veracrypt", Severity::Warn),
    ("truecrypt", Severity::Warn),
    ("tcplay", Severity::Warn),
    ("zuluCrypt-cli", Severity::Warn),
    ("cryptsetup", Severity::Info),
];
/// Where the tools are installed on an FHS system.
const TOOL_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt/veracrypt/bin",
];

/// Installed encryption tools and their access times.
///
/// On an FHS root the usual bin directories are probed; on a NixOS root the
/// store directory names are listed (without reading the store) and the tool
/// binary inside each matching store path is probed.
pub(super) fn tooling(root: &Path) -> Vec<ExaminerFinding> {
    let mut found: Vec<(String, PathBuf, Severity)> = Vec::new();
    for (tool, severity) in TOOLS {
        for dir in TOOL_DIRS {
            let rel = format!("{dir}/{tool}");
            let path = rebase(root, &rel);
            if std::fs::symlink_metadata(&path).is_ok() {
                found.push((rel, path, *severity));
            }
        }
    }
    if let Ok(entries) = read_dir_noatime(&rebase(root, "/nix/store")) {
        for entry in entries {
            let name = entry.name.to_string_lossy();
            for (tool, severity) in TOOLS {
                let marker = format!("-{}-", tool.to_lowercase());
                if name.to_lowercase().contains(&marker) && !name.ends_with(".drv") {
                    for sub in ["bin", "sbin"] {
                        let rel = format!("/nix/store/{name}/{sub}/{tool}");
                        let path = rebase(root, &rel);
                        if std::fs::symlink_metadata(&path).is_ok() {
                            found.push((rel, path, *severity));
                        }
                    }
                }
            }
        }
    }
    found
        .into_iter()
        .map(|(rel, path, severity)| {
            let evidence = match std::fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_symlink() => "installed (a link)".to_string(),
                Ok(meta) => {
                    let atime = stamp(meta.atime());
                    let used = if meta.atime() > meta.mtime().max(meta.ctime()) {
                        format!(", read after it was installed (last access {atime})")
                    } else {
                        format!(", last access {atime}")
                    };
                    format!("installed{used}")
                }
                Err(_) => "installed".to_string(),
            };
            finding("backend-tooling", severity, rel, evidence)
        })
        .collect()
}

fn stamp(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|time| time.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| secs.to_string())
}

/// Leading bytes of the formats a container candidate must not start with.
const FILE_MAGICS: &[(usize, &[u8])] = &[
    (0, b"\x1f\x8b"),
    (0, b"\xfd7zXZ\x00"),
    (0, b"\x28\xb5\x2f\xfd"),
    (0, b"BZh"),
    (0, b"7z\xbc\xaf\x27\x1c"),
    (0, b"PK\x03\x04"),
    (0, b"Rar!"),
    (0, b"\x89PNG"),
    (0, b"\xff\xd8\xff"),
    (0, b"GIF8"),
    (0, b"%PDF"),
    (0, b"\x7fELF"),
    (0, b"OggS"),
    (0, b"RIFF"),
    (4, b"ftyp"),
    (0, b"\x1a\x45\xdf\xa3"),
    (0, b"SQLite format 3"),
    (0, b"hsqs"),
    (0, b"\x04\x22\x4d\x18"),
    (0, b"MSCF"),
    (0, b"!<arch>"),
    (0, b"fLaC"),
    (0, b"ID3"),
    (0, b"QFI\xfb"),
    (0, b"KDMV"),
    (0, b"LPKSHHRH"),
    (0, b"PACK"),
    (0, b"\xca\xfe\xba\xbe"),
    (0, b"\x00asm"),
    (0, b"-----BEGIN"),
];

/// What the container walk found.
pub(super) struct Containers {
    /// The findings.
    pub findings: Vec<ExaminerFinding>,
    /// Decoy paths of the candidates, for the history check.
    pub candidates: Vec<String>,
    /// What the walk could not cover.
    pub not_checked: Vec<String>,
}

/// The TCHunt heuristic: a file at least `container_min_size` long whose size
/// is a multiple of 512, that starts with no known format and whose samples
/// all read as random. A file that starts with a LUKS header is a LUKS
/// container and is reported as such.
pub(super) fn containers(root: &Path, options: &ExaminerOptions) -> Containers {
    let mut findings = Vec::new();
    let mut candidates = Vec::new();
    let limits = WalkLimits {
        max_entries: options.max_walk_entries,
        ..WalkLimits::default()
    };
    let summary = walk_files(root, WALK_SKIP, limits, |path, meta| {
        let size = meta.size();
        if size < options.container_min_size || size % 512 != 0 {
            return;
        }
        let Ok(fd) = open_noatime(path, OpenKind::FileNoFollow) else {
            return;
        };
        let file = File::from(fd);
        let mut head = vec![0u8; SAMPLE];
        let Ok(read) = file.read_at(&mut head, 0) else {
            return;
        };
        head.truncate(read);
        let decoy_path = format!("/{}", path.strip_prefix(root).unwrap_or(path).display());
        if head.starts_with(b"LUKS\xba\xbe") {
            findings.push(finding(
                "container-candidates",
                Severity::Warn,
                decoy_path.clone(),
                format!("LUKS container file ({size} bytes)"),
            ));
            candidates.push(decoy_path);
            return;
        }
        if FILE_MAGICS.iter().any(|(at, magic)| {
            head.len() >= at + magic.len() && &head[*at..at + magic.len()] == *magic
        }) {
            return;
        }
        let mut samples = vec![entropy::bits_per_byte(&head)];
        for offset in [size / 2, size.saturating_sub(SAMPLE as u64)] {
            let mut buf = vec![0u8; SAMPLE];
            if let Ok(read) = file.read_at(&mut buf, offset) {
                buf.truncate(read);
                samples.push(entropy::bits_per_byte(&buf));
            }
        }
        if entropy::all_high(&samples) {
            let lowest = samples.iter().copied().fold(f64::INFINITY, f64::min);
            findings.push(finding(
                "container-candidates",
                Severity::Warn,
                decoy_path.clone(),
                format!(
                    "{size} bytes, a multiple of 512, no known header, random-looking ({lowest:.3} bits/byte or more)"
                ),
            ));
            candidates.push(decoy_path);
        }
    });
    let mut not_checked = vec![format!(
        "container files under {} (skipped by the container walk)",
        WALK_SKIP
            .iter()
            .map(|dir| format!("/{dir}"))
            .collect::<Vec<_>>()
            .join(", ")
    )];
    if summary.truncated {
        not_checked.push(format!(
            "files beyond the first {} entries of the container walk",
            options.max_walk_entries
        ));
    }
    Containers {
        findings,
        candidates,
        not_checked,
    }
}

/// The homes to read history from: /root and every passwd home on the image.
fn homes(root: &Path) -> Vec<String> {
    let mut homes = vec!["/root".to_string()];
    if let Some(passwd) = read_text(&rebase(root, "/etc/passwd"), TEXT_LIMIT) {
        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 7
                && fields[5].starts_with("/home/")
                && !homes.iter().any(|h| h == fields[5])
            {
                homes.push(fields[5].to_string());
            }
        }
    }
    if let Ok(entries) = read_dir_noatime(&rebase(root, "/home")) {
        for entry in entries {
            let home = format!("/home/{}", entry.name.to_string_lossy());
            if !homes.contains(&home) {
                homes.push(home);
            }
        }
    }
    homes
}

/// Shell commands that open encrypted storage.
const UNLOCK_COMMANDS: &[&str] = &[
    "cryptsetup",
    "veracrypt",
    "truecrypt",
    "tcplay",
    "udisksctl unlock",
    "zulucrypt",
];
/// File-name endings conventionally used for containers.
const CONTAINER_SUFFIXES: &[&str] = &[".hc", ".tc", ".vc", ".luks"];

/// Recent-files entries, VeraCrypt history and shell lines that name a
/// container or an unlock.
pub(super) fn history(root: &Path, candidates: &[String]) -> Vec<ExaminerFinding> {
    let mut out = Vec::new();
    let names_container = |text: &str| {
        candidates.iter().any(|path| text.contains(path.as_str()))
            || CONTAINER_SUFFIXES.iter().any(|suffix| {
                text.split(['"', '\'', ' ', '<', '>'])
                    .any(|word| word.to_lowercase().ends_with(suffix))
            })
    };
    for home in homes(root) {
        let recent = format!("{home}/.local/share/recently-used.xbel");
        if let Some(text) = read_text(&rebase(root, &recent), TEXT_LIMIT) {
            for line in text.lines().filter(|line| line.contains("href=")) {
                if names_container(line) {
                    let href = line
                        .split("href=\"")
                        .nth(1)
                        .and_then(|rest| rest.split('"').next())
                        .unwrap_or(line.trim());
                    out.push(finding(
                        "container-history",
                        Severity::Warn,
                        recent.clone(),
                        format!("recently used: {href}"),
                    ));
                }
            }
        }
        for name in ["History.xml", "Favorite Volumes.xml"] {
            let rel = format!("{home}/.config/VeraCrypt/{name}");
            if let Some(text) = read_text(&rebase(root, &rel), TEXT_LIMIT) {
                let volumes: Vec<&str> = text
                    .split("<volume")
                    .skip(1)
                    .filter_map(|rest| rest.split_once('>').map(|(_, tail)| tail))
                    .filter_map(|tail| tail.split("</volume>").next())
                    .collect();
                for volume in volumes {
                    out.push(finding(
                        "container-history",
                        Severity::Warn,
                        rel.clone(),
                        format!("VeraCrypt volume: {}", volume.trim()),
                    ));
                }
            }
        }
        for name in [
            ".bash_history",
            ".zsh_history",
            ".local/share/fish/fish_history",
        ] {
            let rel = format!("{home}/{name}");
            if let Some(text) = read_text(&rebase(root, &rel), TEXT_LIMIT) {
                for line in text.lines() {
                    let lower = line.to_lowercase();
                    if UNLOCK_COMMANDS.iter().any(|cmd| lower.contains(cmd))
                        || names_container(line)
                    {
                        out.push(finding(
                            "container-history",
                            Severity::Warn,
                            rel.clone(),
                            format!("command: {}", line.trim()),
                        ));
                    }
                }
            }
        }
    }
    out
}
