// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use nails_api::Event;

/// A mailbox that counts the turns it asked for, and keeps the last one's
/// mailbox for the test to take from.
fn counted() -> (Mailbox, Arc<AtomicUsize>) {
    let posts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&posts);
    let mailbox = Mailbox::new(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
    });
    (mailbox, posts)
}

fn heartbeat(seconds: u64) -> Update {
    Update::Event(Event::Heartbeat {
        phase: "build".to_string(),
        elapsed_seconds: seconds,
    })
}

#[test]
fn a_flood_of_updates_waits_behind_one_turn() {
    let (mailbox, posts) = counted();
    for second in 0..100_000 {
        mailbox.put(heartbeat(second));
    }
    assert_eq!(
        posts.load(Ordering::SeqCst),
        1,
        "one task on the event loop"
    );
    assert_eq!(mailbox.waiting(), 100_000);
}

#[test]
fn a_turn_takes_its_share_in_order_and_asks_for_the_next() {
    let (mailbox, posts) = counted();
    let count = TURN as u64 * 2 + 5;
    for second in 0..count {
        mailbox.put(heartbeat(second));
    }
    let mut seen = Vec::new();
    let mut turns = 0;
    loop {
        let turn = mailbox.take();
        if turn.is_empty() {
            break;
        }
        assert!(turn.len() <= TURN);
        turns += 1;
        seen.extend(turn);
    }
    assert_eq!(turns, 3);
    assert_eq!(seen, (0..count).map(heartbeat).collect::<Vec<_>>());
    // The first put asked for a turn, and each turn that left some asked
    // for the next one.
    assert_eq!(posts.load(Ordering::SeqCst), 3);
    // Once all were taken, the next update asks for a turn again.
    mailbox.put(heartbeat(0));
    assert_eq!(posts.load(Ordering::SeqCst), 4);
}

#[test]
fn the_turn_is_handed_the_mailbox_it_takes_from() {
    let handed: Arc<Mutex<Option<Mailbox>>> = Arc::default();
    let keep = Arc::clone(&handed);
    let mailbox = Mailbox::new(move |mailbox| {
        *keep.lock().unwrap() = Some(mailbox);
    });
    mailbox.put(Update::Withdrawn);
    let turn = handed.lock().unwrap().take().expect("a turn was asked for");
    assert_eq!(turn.take(), vec![Update::Withdrawn]);
    assert_eq!(mailbox.waiting(), 0);
}
