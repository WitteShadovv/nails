// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Step one of a rehearsal: plant the canary in the hidden session.
//!
//! Every file write goes through [`redirect_for`] first: the directory must sit
//! on an overlay whose upper is on the hidden volume, or on the hidden volume
//! itself, according to the live mount table. A directory on the decoy disk is
//! refused, so the rehearsal can never put its own token on the decoy. After a
//! file is written, its copy in the upper is checked, so a channel is recorded
//! as planted only when the write is known to have been redirected.

use super::{ChannelKind, ChannelRecord, FILE_PREFIX};
use crate::filesystem::MountEntry;
use crate::filesystem::real::{OpenKind, open_noatime};
use crate::{RuntimeEnv, TargetUser};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// What a plant needs to know.
#[derive(Debug, Clone, Copy)]
pub struct PlantContext<'a> {
    /// The canary token.
    pub token: &'a str,
    /// The mounted hidden volume.
    pub hidden_root: &'a Path,
    /// The live mount table.
    pub mounts: &'a [MountEntry],
    /// The operator whose home, recent files and notifications are used.
    pub operator: Option<&'a TargetUser>,
    /// The startup environment, for the notification.
    pub env: Option<&'a RuntimeEnv>,
    /// Whether to touch the host-wide channels (the log socket, a child
    /// process, a notification). Tests that only exercise the file channels
    /// leave it off.
    pub host_channels: bool,
}

/// Where a write to a directory really lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Redirect {
    /// The mount the directory is on.
    pub mount_point: PathBuf,
    /// The directory's counterpart on the hidden volume: inside the overlay's
    /// upper, or the directory itself when it is on the hidden volume.
    pub hidden_dir: PathBuf,
}

/// The device (`major:minor`) of the mount at `hidden_root`, if mounted.
fn hidden_device<'a>(mounts: &'a [MountEntry], hidden_root: &Path) -> Option<&'a str> {
    mounts
        .iter()
        .rev()
        .find(|entry| entry.mount_point == hidden_root)
        .map(|entry| entry.dev.as_str())
}

/// Where a write to `dir` lands, or `None` when it would reach the decoy.
///
/// `dir` must be absolute and canonical. The deepest mount containing it
/// decides: an overlay whose upperdir is on the hidden volume redirects into
/// that upper; a mount of the hidden volume's own device (the volume itself, a
/// persona bind from it) is the hidden volume; anything else is the decoy.
pub(crate) fn redirect_for(
    dir: &Path,
    mounts: &[MountEntry],
    hidden_root: &Path,
) -> Option<Redirect> {
    let entry = mounts
        .iter()
        .filter(|entry| dir.starts_with(&entry.mount_point))
        .max_by_key(|entry| entry.mount_point.components().count())?;
    let relative = dir.strip_prefix(&entry.mount_point).ok()?;
    if entry.fstype == "overlay" {
        let upper = crate::filesystem::parse_overlay_opts(&entry.super_opts).upperdir?;
        if upper.starts_with(hidden_root) {
            return Some(Redirect {
                mount_point: entry.mount_point.clone(),
                hidden_dir: upper.join(relative),
            });
        }
        return None;
    }
    let on_hidden_device = hidden_device(mounts, hidden_root) == Some(entry.dev.as_str());
    (on_hidden_device || entry.mount_point.starts_with(hidden_root)).then(|| Redirect {
        mount_point: entry.mount_point.clone(),
        hidden_dir: dir.to_path_buf(),
    })
}

/// The overlay targets whose upper is on the hidden volume.
fn overlay_targets(mounts: &[MountEntry], hidden_root: &Path) -> Vec<PathBuf> {
    let mut targets: Vec<PathBuf> = mounts
        .iter()
        .filter(|entry| entry.fstype == "overlay")
        .filter(|entry| {
            crate::filesystem::parse_overlay_opts(&entry.super_opts)
                .upperdir
                .is_some_and(|upper| upper.starts_with(hidden_root))
        })
        .map(|entry| entry.mount_point.clone())
        .collect();
    targets.sort();
    targets.dedup();
    targets
}

fn skipped(
    kind: ChannelKind,
    location: impl Into<String>,
    reason: impl Into<String>,
) -> ChannelRecord {
    ChannelRecord {
        kind,
        location: location.into(),
        upper_copy: None,
        skipped: Some(reason.into()),
    }
}

/// Write a new file `dir/name` holding `content`, refusing unless `dir` is
/// redirected, then confirm the copy on the hidden volume.
fn plant_file(
    ctx: &PlantContext<'_>,
    kind: ChannelKind,
    dir: &Path,
    name: &str,
    content: &str,
    owner: Option<&TargetUser>,
) -> ChannelRecord {
    let path = dir.join(name);
    let location = path.display().to_string();
    let Ok(canonical) = dir.canonicalize() else {
        return skipped(kind, location, "the directory does not exist");
    };
    let Some(redirect) = redirect_for(&canonical, ctx.mounts, ctx.hidden_root) else {
        return skipped(
            kind,
            location,
            "not overlaid onto the hidden volume; nothing was written",
        );
    };
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(canonical.join(name))
        .and_then(|mut file| {
            file.write_all(content.as_bytes())
                .and_then(|()| file.sync_all())
        });
    if let Err(err) = written {
        return skipped(kind, location, format!("could not write: {err}"));
    }
    if let Some(user) = owner {
        let _ = std::os::unix::fs::lchown(canonical.join(name), Some(user.uid), Some(user.gid));
    }
    let upper_copy = redirect.hidden_dir.join(name);
    if std::fs::symlink_metadata(&upper_copy).is_err() {
        return skipped(
            kind,
            location,
            "the write did not appear on the hidden volume",
        );
    }
    ChannelRecord {
        kind,
        location,
        upper_copy: Some(upper_copy),
        skipped: None,
    }
}

/// The XBEL document with a bookmark for `href` added before `</xbel>`.
fn xbel_with_bookmark(existing: Option<&str>, href: &str, stamp: &str) -> String {
    let bookmark = format!(
        "  <bookmark href=\"{href}\" added=\"{stamp}\" modified=\"{stamp}\" visited=\"{stamp}\">\n\
         \x20   <info>\n\
         \x20     <metadata owner=\"http://freedesktop.org\">\n\
         \x20       <mime:mime-type type=\"text/plain\"/>\n\
         \x20     </metadata>\n\
         \x20   </info>\n\
         \x20 </bookmark>\n"
    );
    match existing.and_then(|text| text.rfind("</xbel>").map(|at| (text, at))) {
        Some((text, at)) => format!("{}{bookmark}{}", &text[..at], &text[at..]),
        None => format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <xbel version=\"1.0\"\n\
             \x20     xmlns:bookmark=\"http://www.freedesktop.org/standards/desktop-bookmarks\"\n\
             \x20     xmlns:mime=\"http://www.freedesktop.org/standards/shared-mime-info\">\n\
             {bookmark}</xbel>\n"
        ),
    }
}

/// Add a bookmark naming the token to the operator's `recently-used.xbel`.
///
/// The file is rewritten by writing a new file next to it and renaming it over
/// the old one, so the decoy's copy in the lower layer is read (with
/// `O_NOATIME`) but never opened for writing.
fn plant_recent_files(ctx: &PlantContext<'_>, user: &TargetUser, home: &Path) -> ChannelRecord {
    let kind = ChannelKind::RecentFiles;
    let dir = home.join(".local/share");
    let path = dir.join("recently-used.xbel");
    let location = path.display().to_string();
    // The nearest existing ancestor decides where new directories land.
    let ancestor = dir.ancestors().find(|p| p.exists()).map(Path::to_path_buf);
    let redirected = ancestor
        .and_then(|p| p.canonicalize().ok())
        .and_then(|p| redirect_for(&p, ctx.mounts, ctx.hidden_root));
    if redirected.is_none() {
        return skipped(
            kind,
            location,
            "not overlaid onto the hidden volume; nothing was written",
        );
    }
    for created in dir
        .ancestors()
        .take_while(|p| !p.exists())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        if std::fs::create_dir(created).is_err() {
            return skipped(kind, location, "could not create the directory");
        }
        let _ = std::os::unix::fs::lchown(created, Some(user.uid), Some(user.gid));
    }
    let Some(redirect) = dir
        .canonicalize()
        .ok()
        .and_then(|canonical| redirect_for(&canonical, ctx.mounts, ctx.hidden_root))
    else {
        return skipped(
            kind,
            location,
            "not overlaid onto the hidden volume; nothing was written",
        );
    };
    let existing = open_noatime(&path, OpenKind::FileNoFollow)
        .ok()
        .and_then(|fd| {
            let mut text = String::new();
            std::fs::File::from(fd)
                .read_to_string(&mut text)
                .ok()
                .map(|_| text)
        });
    let href = format!("file://{}/{FILE_PREFIX}{}.txt", home.display(), ctx.token);
    let document = xbel_with_bookmark(existing.as_deref(), &href, &super::now());
    let temp = dir.join(format!(".{FILE_PREFIX}{}.xbel", ctx.token));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .and_then(|mut file| {
            file.write_all(document.as_bytes())
                .and_then(|()| file.sync_all())
        })
        .and_then(|()| std::os::unix::fs::lchown(&temp, Some(user.uid), Some(user.gid)))
        .and_then(|()| std::fs::rename(&temp, &path));
    if let Err(err) = written {
        let _ = std::fs::remove_file(&temp);
        return skipped(kind, location, format!("could not write: {err}"));
    }
    ChannelRecord {
        kind,
        location,
        upper_copy: Some(redirect.hidden_dir.join("recently-used.xbel")),
        skipped: None,
    }
}

/// Send one line to the system log socket.
fn plant_system_log(token: &str) -> ChannelRecord {
    let kind = ChannelKind::SystemLog;
    let line = format!("<14>rehearse: {FILE_PREFIX}{token}");
    match std::os::unix::net::UnixDatagram::unbound()
        .and_then(|socket| socket.send_to(line.as_bytes(), "/dev/log"))
    {
        Ok(_) => ChannelRecord {
            kind,
            location: "/dev/log".to_string(),
            upper_copy: None,
            skipped: None,
        },
        Err(err) => skipped(
            kind,
            "/dev/log",
            format!("the log socket refused the line: {err}"),
        ),
    }
}

/// Run a short-lived child whose command line holds the token.
fn plant_process(token: &str) -> ChannelRecord {
    use crate::process::{ProcessCommand, ProcessRunner, RealProcessRunner};
    let kind = ChannelKind::ProcessCmdline;
    let command = ProcessCommand::tool("sh")
        .arg("-c")
        .arg("sleep 1")
        .arg(format!("{FILE_PREFIX}{token}"))
        .deadline(std::time::Duration::from_secs(10));
    match RealProcessRunner.run(&command) {
        Ok(output) if output.status.success() => ChannelRecord {
            kind,
            location: "sh -c 'sleep 1' <canary>".to_string(),
            upper_copy: None,
            skipped: None,
        },
        Ok(output) => skipped(
            kind,
            "sh",
            format!("the child exited with {}", output.status),
        ),
        Err(err) => skipped(kind, "sh", format!("could not start the child: {err}")),
    }
}

/// Show a desktop notification whose body holds the token.
fn plant_notification(token: &str, env: Option<&RuntimeEnv>) -> ChannelRecord {
    let kind = ChannelKind::Notification;
    let Some(env) = env else {
        return skipped(kind, "desktop", "no session environment");
    };
    let notification = crate::Notification {
        title: "Reminder".to_string(),
        body: format!("{FILE_PREFIX}{token}"),
        urgency: "low".to_string(),
        icon: None,
        created_at: super::now(),
    };
    match crate::notification::send_immediate(&notification, env) {
        Ok(()) => ChannelRecord {
            kind,
            location: "the operator's notification daemon".to_string(),
            upper_copy: None,
            skipped: None,
        },
        Err(err) => skipped(kind, "desktop", format!("no notification was shown: {err}")),
    }
}

/// Plant the canary in every channel this session offers.
pub fn plant(ctx: &PlantContext<'_>) -> Vec<ChannelRecord> {
    let name = format!("{FILE_PREFIX}{}.txt", ctx.token);
    let content = format!("{FILE_PREFIX}{}\n", ctx.token);
    let mut records = Vec::new();

    let targets = overlay_targets(ctx.mounts, ctx.hidden_root);
    if targets.is_empty() {
        records.push(skipped(
            ChannelKind::OverlayFile,
            "overlays",
            "no overlay with its upper on the hidden volume is mounted; activate first",
        ));
    }
    for target in &targets {
        records.push(plant_file(
            ctx,
            ChannelKind::OverlayFile,
            target,
            &name,
            &content,
            None,
        ));
    }

    match ctx.operator {
        Some(user) => {
            let home = user.home().to_path_buf();
            records.push(plant_file(
                ctx,
                ChannelKind::HomeFile,
                &home,
                &name,
                &content,
                Some(user),
            ));
            records.push(plant_recent_files(ctx, user, &home));
        }
        None => {
            records.push(skipped(
                ChannelKind::HomeFile,
                "home",
                "no operator could be resolved",
            ));
            records.push(skipped(
                ChannelKind::RecentFiles,
                "home",
                "no operator could be resolved",
            ));
        }
    }

    if ctx.host_channels {
        records.push(plant_system_log(ctx.token));
        records.push(plant_process(ctx.token));
        records.push(plant_notification(ctx.token, ctx.env));
    }
    records
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    /// [`xbel_with_bookmark`] for the tests.
    pub(crate) fn xbel(existing: Option<&str>, href: &str, stamp: &str) -> String {
        xbel_with_bookmark(existing, href, stamp)
    }

    /// Plant one overlay file in `dir`.
    pub(crate) fn plant_file(ctx: &PlantContext<'_>, dir: &Path) -> ChannelRecord {
        let name = format!("{FILE_PREFIX}{}.txt", ctx.token);
        super::plant_file(ctx, ChannelKind::OverlayFile, dir, &name, "x", None)
    }
}
