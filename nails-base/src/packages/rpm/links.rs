// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The symbolic links rpm's records say the packages installed, and where a
//! path a package records lies once they are followed.
//!
//! A package can record its files through a directory link another package
//! installed: Fedora's `filesystem` package installs `/lib` as a link to
//! `usr/lib`, and the kernel's packages record their modules below
//! `/lib/modules`, which rpm installs into `/usr/lib/modules`. The links are
//! taken from the records (each link's target, `FILELINKTOS`), never read on
//! the disk: following or reading a link there changes its access time.
//!
//! The links are kept as a tree of the names on their way, each name once
//! however many links lie below it, and what the tree keeps is taken from the
//! reader's [`Budget`]. A path is resolved one name at a time against that
//! tree, so the cost of resolving it grows with its length alone, and a path
//! whose links make a loop, or that grows to [`PATH_MAX`] bytes or more as
//! they are followed, cannot be resolved ([`Unresolved`]): the kernel
//! resolves neither.

use super::{Budget, GHOST, NORMAL, PATH_MAX, Package};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;

/// The most links one path is followed through, as the kernel's lookup
/// follows at most (`MAXSYMLINKS`): more say the links make a loop.
const MAX_LINKS: usize = 40;

/// Why a path cannot be resolved through the links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unresolved {
    /// Its links make a loop: they are more than the kernel follows in one
    /// lookup.
    Loop,
    /// It grows to [`PATH_MAX`] bytes or more as its links are followed.
    TooLong,
}

impl fmt::Display for Unresolved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unresolved::Loop => write!(f, "the links on its way make a loop"),
            Unresolved::TooLong => write!(
                f,
                "the links on its way lead to a path of {PATH_MAX} bytes or more"
            ),
        }
    }
}

/// The names below one directory that lead to a link.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Node {
    /// Where the entry points, when it is a link.
    target: Option<Box<str>>,
    /// The entries below it on the way to a link, by name.
    below: BTreeMap<Box<str>, Node>,
}

/// About what the tree holds for one name besides the name's bytes: its
/// entry in its directory's map, twice over for the room a map keeps spare.
const NODE: usize = 2 * size_of::<(Box<str>, Node)>();

/// The symbolic links some packages installed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Links {
    root: Node,
}

impl Links {
    /// The links `packages` installed: each of their files that is a
    /// symbolic link rpm installed (no ghost, in the state
    /// [`NORMAL`](super::NORMAL)) and whose header records its target. Where
    /// two packages record a link at one path, the first one counts. What
    /// the links keep is taken from `budget`: an error when they need more.
    pub fn of<'a>(
        packages: impl IntoIterator<Item = &'a Package>,
        budget: &mut Budget,
    ) -> Result<Self, String> {
        let mut root = Node::default();
        for package in packages {
            for (index, target) in &package.links {
                let Some(file) = package.files.get(*index as usize) else {
                    continue;
                };
                let installed = file.is_link() && file.flags & GHOST == 0 && file.state == NORMAL;
                if !installed || file.name.is_empty() {
                    continue;
                }
                let dir = package.dirs.get(file.dir as usize).map_or("", |dir| dir);
                let mut node = &mut root;
                let names = dir.split('/').filter(|name| !name.is_empty());
                for name in names.chain([&*file.name]) {
                    if !node.below.contains_key(name) {
                        budget.take(NODE + Budget::allocation(name.len()))?;
                    }
                    node = node.below.entry(name.into()).or_default();
                }
                if node.target.is_none() {
                    budget.take(Budget::allocation(target.len()))?;
                    node.target = Some(target.clone());
                }
            }
        }
        Ok(Self { root })
    }

    /// Where the absolute path `path` lies once each link on its way, its
    /// last component too, is followed, and each `.` and `..` is resolved,
    /// as the kernel resolves a path: a relative target from the link's own
    /// directory, an absolute one from the root. A relative `path` is given
    /// back as it is: no link of the root's lies on its way.
    pub fn resolve(&self, path: &str) -> Result<String, Unresolved> {
        if !path.starts_with('/') {
            return Ok(path.to_string());
        }
        if path.len() >= PATH_MAX {
            return Err(Unresolved::TooLong);
        }
        // The names still to walk, and about the bytes they take: each name
        // and the `/` before it.
        let mut todo: VecDeque<&str> = path.split('/').collect();
        let mut pending = path.len() + 1;
        // The path walked so far, a `/` and a name for each of its names,
        // with where each name starts in it and the names below it that lead
        // to a link (`None` where none does).
        let mut resolved = String::new();
        let mut walked: Vec<(usize, Option<&Node>)> = Vec::new();
        let mut followed = 0;
        while let Some(name) = todo.pop_front() {
            pending = pending.saturating_sub(name.len() + 1);
            match name {
                "" | "." => {}
                ".." => {
                    if let Some((start, _)) = walked.pop() {
                        resolved.truncate(start);
                    }
                }
                name => {
                    let here = walked.last().map_or(Some(&self.root), |(_, node)| *node);
                    let node = here.and_then(|node| node.below.get(name));
                    if let Some(target) = node.and_then(|node| node.target.as_deref()) {
                        followed += 1;
                        if followed > MAX_LINKS {
                            return Err(Unresolved::Loop);
                        }
                        if target.starts_with('/') {
                            resolved.clear();
                            walked.clear();
                        }
                        pending += target.len() + 1;
                        if resolved.len() + pending > PATH_MAX {
                            return Err(Unresolved::TooLong);
                        }
                        for part in target.rsplit('/') {
                            todo.push_front(part);
                        }
                    } else {
                        walked.push((resolved.len(), node));
                        resolved.push('/');
                        resolved.push_str(name);
                        if resolved.len() + pending > PATH_MAX {
                            return Err(Unresolved::TooLong);
                        }
                    }
                }
            }
        }
        if resolved.is_empty() {
            resolved.push('/');
        }
        if resolved.len() >= PATH_MAX {
            return Err(Unresolved::TooLong);
        }
        Ok(resolved)
    }
}
