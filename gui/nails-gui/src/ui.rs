// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Drawing the page in the window, and wiring its controls.
//!
//! The [`Controller`] lives on the window's thread. It hands each
//! [`Update`] to the [`Model`], passes on the asks that follow, and draws the
//! page the model gives; the window's controls come back to it as the
//! effects the model gives for them. It never touches the pipe:
//! [`Controller::new`] takes the way to the worker as functions, so the tests
//! can stand in for the worker. The Emergency control's gesture fires the
//! emergency from its input event, through a function that only signals
//! ([`crate::emergency::Emergency::fire`]), before the page is drawn again.
//! While the page is that of a switch the window waits for, a timer of the
//! controller's runs, and once [`SWITCH_OVERDUE`] passed it tells the model
//! that the switch did not come.

use std::cell::RefCell;
use std::rc::{Rc, Weak};

use nails_api::CheckOutcome;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::model::{ActionKind, Asker, Effect, Model, Page, SWITCH_OVERDUE};
use crate::text;
use crate::worker::{Ask, Update};
use crate::{AppWindow, CheckLine, Fact, Outcome, StepLine};

/// The ways from the window to the worker and the window itself.
pub struct Hooks {
    /// Hand the worker an ask.
    pub ask: Box<dyn Fn(Ask)>,
    /// Hang up on the helper: shut the window's writing half of the pipe.
    pub hang_up: Box<dyn Fn()>,
    /// Close the window (the person's Close, or a dismissed password dialog).
    pub close: Box<dyn Fn()>,
    /// Fire the emergency. It must not wait for anything.
    pub emergency: Box<dyn Fn()>,
}

/// The window's half of a session.
pub struct Controller {
    window: slint::Weak<AppWindow>,
    model: Model,
    hooks: Hooks,
    /// The controller itself, for its timer to call back.
    me: Weak<RefCell<Controller>>,
    /// Times the switch whose page shows.
    switch_timer: slint::Timer,
    /// Whether the timer runs for the page that shows.
    timing_switch: bool,
}

impl Controller {
    /// Take over `window` with `model`, reaching the worker and the window
    /// through `hooks`.
    pub fn new(window: &AppWindow, model: Model, hooks: Hooks) -> Rc<RefCell<Self>> {
        let controller = Rc::new(RefCell::new(Self {
            window: window.as_weak(),
            model,
            hooks,
            me: Weak::new(),
            switch_timer: slint::Timer::default(),
            timing_switch: false,
        }));
        controller.borrow_mut().me = Rc::downgrade(&controller);
        wire(window, &controller);
        controller.borrow_mut().refresh();
        controller
    }

    /// Take in what the worker reported.
    pub fn update(&mut self, update: Update) {
        self.take(std::iter::once(update));
    }

    /// Take one turn of `mailbox`'s updates, at most
    /// [`TURN`](crate::mailbox::TURN), and draw once: the task the window's
    /// event loop runs each time the mailbox asks for a turn.
    pub fn take_turn(&mut self, mailbox: &crate::mailbox::Mailbox) {
        self.take(mailbox.take());
    }

    /// Take in several of the worker's updates, in order, and draw once.
    pub fn take(&mut self, updates: impl IntoIterator<Item = Update>) {
        for update in updates {
            for ask in self.model.apply(update) {
                (self.hooks.ask)(ask);
            }
        }
        if self.model.quits() {
            (self.hooks.close)();
        }
        self.refresh();
    }

    /// Ask for a plan, whose question `asker` words once it holds: what a
    /// screen of an operation the engine confirms first calls.
    pub fn plan(&mut self, plan: crate::client::Plan, asker: Asker) {
        let ask = self.model.plan(plan, asker);
        (self.hooks.ask)(ask);
        self.refresh();
    }

    /// The page drawn now.
    #[must_use]
    pub fn page(&self) -> Page {
        self.model.page()
    }

    fn draw(&self) {
        if let Some(window) = self.window.upgrade() {
            draw(&window, &self.model.page());
        }
    }

    /// Draw the page, and time the switch it waits for, if any: a timer
    /// starts when such a page comes, and stops when it goes.
    fn refresh(&mut self) {
        match (self.model.switch_pending(), self.timing_switch) {
            (true, false) => {
                self.timing_switch = true;
                self.model.set_switch_overdue(false);
                let me = self.me.clone();
                self.switch_timer
                    .start(slint::TimerMode::SingleShot, SWITCH_OVERDUE, move || {
                        if let Some(controller) = me.upgrade() {
                            controller.borrow_mut().overdue();
                        }
                    });
            }
            (false, true) => {
                self.timing_switch = false;
                self.switch_timer.stop();
                self.model.set_switch_overdue(false);
            }
            _ => {}
        }
        self.draw();
    }

    fn overdue(&mut self) {
        if self.timing_switch {
            self.model.set_switch_overdue(true);
        }
        self.draw();
    }

    fn effect(&self, effect: Option<Effect>) {
        match effect {
            Some(Effect::Ask(ask)) => (self.hooks.ask)(ask),
            Some(Effect::HangUp) => (self.hooks.hang_up)(),
            Some(Effect::Emergency) => (self.hooks.emergency)(),
            None => {}
        }
    }

    fn action(&mut self) {
        let effect = self.model.action();
        self.effect(effect);
        self.refresh();
    }

    fn emergency(&mut self) {
        let effect = self.model.emergency();
        self.effect(effect);
        self.refresh();
    }

    fn escape(&mut self) {
        let effect = self.model.escape();
        self.effect(effect);
        self.refresh();
    }

    fn allow(&mut self, index: usize) {
        self.model.allow(index);
        self.refresh();
    }

    fn typed(&mut self, typed: &str) {
        self.model.typed(typed);
        self.refresh();
    }

    fn answer(&mut self, confirmed: bool) {
        if let Some(ask) = self.model.answer(confirmed) {
            (self.hooks.ask)(ask);
        }
        self.refresh();
    }

    fn alternative(&mut self) {
        if let Some(ask) = self.model.alternative() {
            (self.hooks.ask)(ask);
        }
        self.refresh();
    }
}

fn wire(window: &AppWindow, controller: &Rc<RefCell<Controller>>) {
    let weak = Rc::downgrade(controller);
    window.on_close_window(move || {
        if let Some(controller) = weak.upgrade() {
            (controller.borrow().hooks.close)();
        }
    });
    let weak = Rc::downgrade(controller);
    window.on_action_activated(move || {
        if let Some(controller) = weak.upgrade() {
            controller.borrow_mut().action();
        }
    });
    let weak = Rc::downgrade(controller);
    window.on_emergency_fired(move || {
        if let Some(controller) = weak.upgrade() {
            controller.borrow_mut().emergency();
        }
    });
    let weak = Rc::downgrade(controller);
    window.on_escape_pressed(move || {
        if let Some(controller) = weak.upgrade() {
            controller.borrow_mut().escape();
        }
    });
    let weak = Rc::downgrade(controller);
    window.on_allow_requested(move |index| {
        if let (Some(controller), Ok(index)) = (weak.upgrade(), usize::try_from(index)) {
            controller.borrow_mut().allow(index);
        }
    });
    let weak = Rc::downgrade(controller);
    window.on_question_typed(move |typed| {
        if let Some(controller) = weak.upgrade() {
            controller.borrow_mut().typed(&typed);
        }
    });
    let weak = Rc::downgrade(controller);
    window.on_question_answered(move |confirmed| {
        if let Some(controller) = weak.upgrade() {
            controller.borrow_mut().answer(confirmed);
        }
    });
    let weak = Rc::downgrade(controller);
    window.on_question_alternative_chosen(move || {
        if let Some(controller) = weak.upgrade() {
            controller.borrow_mut().alternative();
        }
    });
}

/// Draw `page` in `window`.
pub fn draw(window: &AppWindow, page: &Page) {
    window.set_heading(page.heading.as_str().into());
    window.set_description(page.description.as_str().into());
    window.set_note(page.note.as_str().into());
    window.set_urgent(page.urgent);
    window.set_busy(page.busy.is_some());
    window.set_busy_label(page.busy.as_deref().unwrap_or_default().into());
    let facts: Vec<Fact> = page
        .facts
        .iter()
        .map(|(title, value)| Fact {
            title: title.as_str().into(),
            value: value.as_str().into(),
        })
        .collect();
    window.set_facts(ModelRc::new(VecModel::from(facts)));
    let steps: Vec<StepLine> = page
        .steps
        .iter()
        .map(|step| StepLine {
            label: step.label.as_str().into(),
            state: step.state.into(),
        })
        .collect();
    window.set_steps(ModelRc::new(VecModel::from(steps)));
    let checks: Vec<CheckLine> = page
        .checks
        .iter()
        .map(|check| CheckLine {
            outcome: outcome(check.outcome),
            word: check.word.as_str().into(),
            message: check.message.as_str().into(),
            fix: check.fix.as_str().into(),
            allow: if check.allow.is_some() {
                text::ALLOW
            } else {
                ""
            }
            .into(),
        })
        .collect();
    window.set_checks(ModelRc::new(VecModel::from(checks)));
    window.set_fix(page.fix.as_str().into());
    window.set_action(page.action.unwrap_or_default().into());
    window.set_action_plain(page.action_kind == ActionKind::Plain);
    window.set_takes_input(!page.no_input);
    window.set_emergency_shown(page.emergency);
    match &page.question {
        Some(question) => {
            window.set_question_heading(question.heading.as_str().into());
            window.set_question_body(question.body.as_str().into());
            window.set_question_confirm(question.confirm.as_str().into());
            window.set_question_destructive(question.destructive);
            window.set_question_prompt(question.prompt.as_deref().unwrap_or_default().into());
            window.set_question_locked(question.locked);
            window.set_question_alternative(
                question.alternative.as_deref().unwrap_or_default().into(),
            );
            window.set_question_open(true);
        }
        None => {
            let was_open = window.get_question_open();
            window.set_question_open(false);
            window.set_question_heading(SharedString::default());
            window.set_question_body(SharedString::default());
            window.set_question_confirm(SharedString::default());
            window.set_question_destructive(false);
            window.set_question_prompt(SharedString::default());
            window.set_question_locked(false);
            window.set_question_alternative(SharedString::default());
            if was_open {
                window.invoke_focus_page();
            }
        }
    }
}

fn outcome(outcome: CheckOutcome) -> Outcome {
    match outcome {
        CheckOutcome::Pass => Outcome::Passed,
        CheckOutcome::Warn => Outcome::Warning,
        CheckOutcome::Fail => Outcome::Problem,
        CheckOutcome::Skipped => Outcome::Skipped,
    }
}
