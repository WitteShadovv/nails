// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The orders a Qt display manager may read the files of a directory in.
//!
//! SDDM and Plasma Login Manager list a directory with `QDir`, sorted by the
//! collation of the locale they run in (`QDir::LocaleAware`). Which one that
//! is the files do not tell, and collations disagree: with ICU, `_` comes
//! before `-` and case counts only between names that are otherwise equal;
//! glibc's locales and ICU's Thai skip punctuation, so `a` and `a.` are
//! equal in Thai; the C locale sorts by code point, so `K` comes before `a`;
//! and a language may sort a letter, or two letters together, apart from the
//! others: Welsh takes `ng` for one letter before `n`, so `ang` comes before
//! `an`, and Igbo takes `ch` for one before `c`. All of them agree only on
//! two names that first differ in an ASCII digit, `10-a.conf` before
//! `20-b.conf`, and on a name before a longer one it starts when that goes on
//! with an ASCII digit or punctuation and holds an ASCII digit or letter past
//! it, `a.conf` before `a.conf.bak`. Any other two names may come in either
//! order, and the reader takes the files in every order that keeps those
//! pairs.

/// The most orders read; past it, every account the files name counts.
pub(super) const MAX_ORDERS: usize = 720;

/// The most files of one directory whose orders are worked out, past which
/// the same holds: the search takes time that grows with the cube of their
/// number, even where they have one order.
const MAX_FILES: usize = 64;

/// Whether every collation sorts the name `a` before `b`: at the first byte
/// where they differ, both hold an ASCII digit, `a` the lower; or `b` goes on
/// past all of `a` with an ASCII digit or punctuation, which no collation
/// joins to the character before it, and holds an ASCII digit or letter past
/// `a`, which none skips. A letter right past `a` may make one letter with
/// the last of `a`, as `ng` in Welsh, and punctuation alone may count for
/// nothing, as in Thai.
fn sorts_before(a: &[u8], b: &[u8]) -> bool {
    match a.iter().zip(b).position(|(x, y)| x != y) {
        Some(i) => a[i].is_ascii_digit() && b[i].is_ascii_digit() && a[i] < b[i],
        None => {
            let rest = b.get(a.len()..).unwrap_or_default();
            rest.first()
                .is_some_and(|next| next.is_ascii_graphic() && !next.is_ascii_alphabetic())
                && rest.iter().any(u8::is_ascii_alphanumeric)
        }
    }
}

/// Every order of the files of one directory, by their `names`, that keeps
/// each pair [`sorts_before`] orders, as indices into `names`; `None` when
/// there are more than `limit`, or more than [`MAX_FILES`] files.
pub(super) fn orders(names: &[&[u8]], limit: usize) -> Option<Vec<Vec<usize>>> {
    if names.len() > MAX_FILES {
        return None;
    }
    let mut search = Search {
        names,
        used: vec![false; names.len()],
        order: Vec::with_capacity(names.len()),
        found: Vec::new(),
        limit,
    };
    search.extend().then_some(search.found)
}

struct Search<'a> {
    names: &'a [&'a [u8]],
    used: Vec<bool>,
    order: Vec<usize>,
    found: Vec<Vec<usize>>,
    limit: usize,
}

impl Search<'_> {
    /// Complete `order` in every way; false once more than `limit` orders
    /// are found.
    fn extend(&mut self) -> bool {
        if self.order.len() == self.names.len() {
            self.found.push(self.order.clone());
            return self.found.len() <= self.limit;
        }
        for next in 0..self.names.len() {
            // A file may come next when no file left has to come before it.
            let blocked = (0..self.names.len()).any(|other| {
                !self.used[other] && sorts_before(self.names[other], self.names[next])
            });
            if self.used[next] || blocked {
                continue;
            }
            self.used[next] = true;
            self.order.push(next);
            let within = self.extend();
            self.order.pop();
            self.used[next] = false;
            if !within {
                return false;
            }
        }
        true
    }
}

/// Every way of reading `dirs` one after the other, each in one of its
/// orders: for each, the indices of the files read as `(directory, file)`.
/// `None` when there are more than `limit`.
pub(super) fn reading_orders(
    dirs: &[Vec<&[u8]>],
    limit: usize,
) -> Option<Vec<Vec<(usize, usize)>>> {
    let mut readings: Vec<Vec<(usize, usize)>> = vec![Vec::new()];
    for (dir, names) in dirs.iter().enumerate() {
        let orders = orders(names, limit)?;
        if readings.len().saturating_mul(orders.len()) > limit {
            return None;
        }
        readings = readings
            .iter()
            .flat_map(|before| {
                orders.iter().map(move |order| {
                    let mut reading = before.clone();
                    reading.extend(order.iter().map(|&file| (dir, file)));
                    reading
                })
            })
            .collect();
    }
    Some(readings)
}
