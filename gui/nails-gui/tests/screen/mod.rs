// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The window on Slint's headless platform: no display, fixed font metrics,
//! and the element tree to query. A test drives the controller with the
//! worker's updates, presses keys, and reads what the window shows and what
//! it asked the worker for.

#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;

use i_slint_backend_testing::{AccessibleRole, ElementHandle, ElementQuery};
use nails_gui::model::Model;
use nails_gui::ui::{Controller, Hooks};
use nails_gui::worker::{Ask, Update};
use nails_gui::{Adw, AppWindow};
use slint::ComponentHandle;
use slint::platform::{Key, WindowEvent};

/// The window, its controller, and what it asked and did.
pub struct Screen {
    pub window: AppWindow,
    pub controller: Rc<RefCell<Controller>>,
    asks: Rc<RefCell<Vec<Ask>>>,
    hang_ups: Rc<Cell<u32>>,
    closed: Rc<Cell<bool>>,
    emergencies: Rc<Cell<u32>>,
}

impl Screen {
    /// A window for the engine `/mnt/data/nails`, shown on the headless
    /// platform.
    pub fn new(waits_for_password: bool) -> Self {
        Self::with(Model::new(
            Some(PathBuf::from("/mnt/data/nails")),
            waits_for_password,
        ))
    }

    /// A window that read the mount table of a hidden session, before the
    /// helper answered.
    pub fn in_hidden_session() -> Self {
        Self::with(
            Model::new(Some(PathBuf::from("/mnt/data/nails")), false).in_hidden_session(true),
        )
    }

    /// A window with `model`, shown on the headless platform.
    pub fn with(model: Model) -> Self {
        Self::with_emergency(model, Box::new(|| {}))
    }

    /// As [`Screen::with`], and the emergency, once counted, also fires
    /// through `emergency`.
    pub fn with_emergency(model: Model, emergency: Box<dyn Fn()>) -> Self {
        thread_local! {
            static PLATFORM: Cell<bool> = const { Cell::new(false) };
        }
        // The headless platform can be set once per thread; a test may open
        // several windows on it.
        if !PLATFORM.get() {
            i_slint_backend_testing::init_no_event_loop();
            PLATFORM.set(true);
        }
        let window = AppWindow::new().expect("the window builds");
        let asks = Rc::new(RefCell::new(Vec::new()));
        let hang_ups = Rc::new(Cell::new(0));
        let closed = Rc::new(Cell::new(false));
        let emergencies = Rc::new(Cell::new(0));
        let controller = {
            let asks = Rc::clone(&asks);
            let hang_ups = Rc::clone(&hang_ups);
            let closed = Rc::clone(&closed);
            let emergencies = Rc::clone(&emergencies);
            Controller::new(
                &window,
                model,
                Hooks {
                    ask: Box::new(move |ask| asks.borrow_mut().push(ask)),
                    hang_up: Box::new(move || hang_ups.set(hang_ups.get() + 1)),
                    close: Box::new(move || closed.set(true)),
                    emergency: Box::new(move || {
                        emergencies.set(emergencies.get() + 1);
                        emergency();
                    }),
                },
            )
        };
        window.show().expect("the window shows");
        Self {
            window,
            controller,
            asks,
            hang_ups,
            closed,
            emergencies,
        }
    }

    /// How many times the window fired the emergency.
    pub fn emergencies(&self) -> u32 {
        self.emergencies.get()
    }

    /// Let `ms` milliseconds of Slint's mocked time pass: animations,
    /// timers and the bindings that read the time move on.
    pub fn wait_ms(&self, ms: u64) {
        i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(ms));
    }

    /// The middle of `element`, in the window's coordinates.
    pub fn middle(&self, element: &ElementHandle) -> slint::LogicalPosition {
        let at = element.absolute_position();
        let size = element.size();
        slint::LogicalPosition::new(at.x + size.width / 2.0, at.y + size.height / 2.0)
    }

    /// Press the left button at `position`.
    pub fn press_at(&self, position: slint::LogicalPosition) {
        self.window
            .window()
            .dispatch_event(WindowEvent::PointerMoved { position });
        self.window
            .window()
            .dispatch_event(WindowEvent::PointerPressed {
                position,
                button: slint::platform::PointerEventButton::Left,
            });
    }

    /// Move the pointer, its button held or not, to `position`.
    pub fn move_to(&self, position: slint::LogicalPosition) {
        self.window
            .window()
            .dispatch_event(WindowEvent::PointerMoved { position });
    }

    /// Release the left button at `position`.
    pub fn release_at(&self, position: slint::LogicalPosition) {
        self.window
            .window()
            .dispatch_event(WindowEvent::PointerReleased {
                position,
                button: slint::platform::PointerEventButton::Left,
            });
    }

    /// Make the window tall enough to show a page of every recorded check at
    /// once. The element queries skip what the page's scroll area clips;
    /// the keyboard still reaches it, since Slint scrolls a row that takes
    /// the focus into view.
    pub fn tall(&self) {
        self.window
            .window()
            .set_size(slint::LogicalSize::new(480.0, 8000.0));
    }

    /// Hand the controller what the worker reported.
    pub fn update(&self, update: Update) {
        self.controller.borrow_mut().update(update);
    }

    /// The asks made since the last call.
    pub fn asks(&self) -> Vec<Ask> {
        self.asks.borrow_mut().drain(..).collect()
    }

    /// Whether the window asked to close.
    pub fn closed(&self) -> bool {
        self.closed.get()
    }

    /// How many times the window hung up on the helper.
    pub fn hang_ups(&self) -> u32 {
        self.hang_ups.get()
    }

    /// Type `text` into the control that has the focus, a key at a time.
    pub fn type_text(&self, text: &str) {
        for c in text.chars() {
            let text: slint::SharedString = c.to_string().into();
            self.window
                .window()
                .dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
            self.window
                .window()
                .dispatch_event(WindowEvent::KeyReleased { text });
        }
    }

    /// Press and release `key`.
    pub fn press(&self, key: Key) {
        let text: slint::SharedString = key.into();
        self.window
            .window()
            .dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
        self.window
            .window()
            .dispatch_event(WindowEvent::KeyReleased { text });
    }

    /// Hold `key` down: its press, `repeats` of the repeated presses a
    /// keyboard sends while a key stays down, `gap_ms` of mocked time apart,
    /// and its release.
    pub fn hold_key(&self, key: Key, repeats: usize, gap_ms: u64) {
        let text: slint::SharedString = key.into();
        self.window
            .window()
            .dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
        for _ in 0..repeats {
            self.wait_ms(gap_ms);
            self.window
                .window()
                .dispatch_event(WindowEvent::KeyPressRepeated { text: text.clone() });
        }
        self.window
            .window()
            .dispatch_event(WindowEvent::KeyReleased { text });
    }

    /// The accessible label of the control that has the keyboard focus.
    pub fn focused(&self) -> String {
        // A field names itself when its focus changes, in a handler Slint
        // runs with the timers.
        slint::platform::update_timers_and_animations();
        self.window.global::<Adw>().get_focused_label().to_string()
    }

    /// The focused control after each of `n` presses of `key`.
    pub fn walk(&self, key: Key, n: usize) -> Vec<String> {
        (0..n)
            .map(|_| {
                self.press(key);
                self.focused()
            })
            .collect()
    }

    /// Every element in view with `role`, once for each node a screen reader
    /// sees.
    ///
    /// Slint merges some elements into one item, and the query hands out each
    /// of them with the item's role, one after another; only the first of
    /// them carries the item's name and state. Items of one role laid exactly
    /// over one another are not drawn here, so a run of handles with the same
    /// place and size is one node.
    pub fn with_role(&self, role: AccessibleRole) -> Vec<ElementHandle> {
        let mut nodes: Vec<ElementHandle> = Vec::new();
        for element in ElementQuery::from_root(&self.window)
            .match_accessible_role(role)
            .find_all()
        {
            let same_node = nodes.last().is_some_and(|last| {
                last.absolute_position() == element.absolute_position()
                    && last.size() == element.size()
            });
            if !same_node {
                nodes.push(element);
            }
        }
        nodes
    }

    /// The accessible labels of every element in view with `role`.
    pub fn labels(&self, role: AccessibleRole) -> Vec<String> {
        self.with_role(role)
            .iter()
            .map(|element| element.accessible_label().unwrap_or_default().to_string())
            .collect()
    }

    /// The elements in view labelled `label` that an assistive technology
    /// sees (their role is not `none`).
    fn labelled(&self, label: &str) -> Vec<ElementHandle> {
        ElementHandle::find_by_accessible_label(&self.window, label)
            .filter(|element| element.accessible_role() != Some(AccessibleRole::None))
            .collect()
    }

    /// The one element in view labelled `label`.
    pub fn find(&self, label: &str) -> ElementHandle {
        let found = self.labelled(label);
        assert_eq!(
            found.len(),
            1,
            "one element labelled {label:?}, found {}",
            found.len()
        );
        found.into_iter().next().unwrap()
    }

    /// The one element in view labelled `label` with `role`.
    pub fn find_with(&self, label: &str, role: AccessibleRole) -> ElementHandle {
        let found: Vec<ElementHandle> = self
            .labelled(label)
            .into_iter()
            .filter(|element| element.accessible_role() == Some(role))
            .collect();
        assert_eq!(
            found.len(),
            1,
            "one {role:?} labelled {label:?}, found {}",
            found.len()
        );
        found.into_iter().next().unwrap()
    }

    /// Whether some element in view is labelled `label`.
    pub fn shows(&self, label: &str) -> bool {
        !self.labelled(label).is_empty()
    }

    /// The texts in view, in tree order.
    pub fn texts(&self) -> Vec<String> {
        self.labels(AccessibleRole::Text)
    }
}
