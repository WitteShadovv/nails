// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The worker's updates on their way to the window's thread.
//!
//! The worker reports each update as it comes, on its own thread; the window
//! draws them on its own. Between the two lies a mailbox: the updates wait in
//! a queue, and the window's event loop holds at most one task that takes
//! them. So a helper that sends a flood of events never fills the event loop
//! ahead of the person's input, the Emergency control's above all. Each turn
//! takes at most [`TURN`] updates and the window draws once for them; a turn
//! that leaves some posts the next before it ends, so input that came
//! meanwhile goes first.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::worker::Update;

/// The most updates one turn takes.
pub const TURN: usize = 64;

/// Updates from the worker for the window's thread. Clones share it.
#[derive(Clone)]
pub struct Mailbox(Arc<Inner>);

struct Inner {
    queue: Mutex<Queue>,
    /// Asks the window's thread to take a turn: it is handed the mailbox.
    post: Box<dyn Fn(Mailbox) + Send + Sync>,
}

#[derive(Default)]
struct Queue {
    updates: VecDeque<Update>,
    /// A turn is posted and has not taken its updates yet.
    posted: bool,
}

impl Mailbox {
    /// A mailbox that asks for a turn with `post`, which hands the window's
    /// thread a task that calls [`Mailbox::take`].
    pub fn new(post: impl Fn(Mailbox) + Send + Sync + 'static) -> Self {
        Self(Arc::new(Inner {
            queue: Mutex::new(Queue::default()),
            post: Box::new(post),
        }))
    }

    fn queue(&self) -> MutexGuard<'_, Queue> {
        self.0.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// On the worker's thread: queue `update`, and ask for a turn unless one
    /// waits already.
    pub fn put(&self, update: Update) {
        let post = {
            let mut queue = self.queue();
            queue.updates.push_back(update);
            !std::mem::replace(&mut queue.posted, true)
        };
        if post {
            (self.0.post)(self.clone());
        }
    }

    /// On the window's thread: this turn's updates, in the order they came,
    /// at most [`TURN`]. When more wait, the next turn is asked for.
    #[must_use]
    pub fn take(&self) -> Vec<Update> {
        let (turn, more) = {
            let mut queue = self.queue();
            let count = queue.updates.len().min(TURN);
            let turn: Vec<Update> = queue.updates.drain(..count).collect();
            let more = !queue.updates.is_empty();
            queue.posted = more;
            (turn, more)
        };
        if more {
            (self.0.post)(self.clone());
        }
        turn
    }

    /// How many updates wait.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.queue().updates.len()
    }
}

#[cfg(test)]
#[path = "mailbox_tests.rs"]
mod tests;
