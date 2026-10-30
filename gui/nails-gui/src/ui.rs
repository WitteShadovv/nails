// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Drawing the page in the window, and wiring its controls.
//!
//! The [`Controller`] lives on the window's thread. It hands each
//! [`Update`] to the [`Model`], passes on the asks that follow, and draws the
//! page the model gives; the window's controls come back to it as asks of
//! their own. It never touches the pipe: [`Controller::new`] takes the way to
//! the worker as a function, so the tests can stand in for the worker.

use std::cell::RefCell;
use std::rc::Rc;

use nails_api::CheckOutcome;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::model::{Asker, Model, Page};
use crate::worker::{Ask, Update};
use crate::{AppWindow, CheckLine, Fact, Outcome};

/// The window's half of a session.
pub struct Controller {
    window: slint::Weak<AppWindow>,
    model: Model,
    ask: Box<dyn Fn(Ask)>,
    close: Box<dyn Fn()>,
}

impl Controller {
    /// Take over `window` with `model`: `ask` reaches the worker, and `close`
    /// closes the window (the person's Close, or a dismissed password
    /// dialog).
    pub fn new(
        window: &AppWindow,
        model: Model,
        ask: impl Fn(Ask) + 'static,
        close: impl Fn() + 'static,
    ) -> Rc<RefCell<Self>> {
        let controller = Rc::new(RefCell::new(Self {
            window: window.as_weak(),
            model,
            ask: Box::new(ask),
            close: Box::new(close),
        }));
        wire(window, &controller);
        controller.borrow().draw();
        controller
    }

    /// Take in what the worker reported.
    pub fn update(&mut self, update: Update) {
        for ask in self.model.apply(update) {
            (self.ask)(ask);
        }
        if self.model.quits() {
            (self.close)();
        }
        self.draw();
    }

    /// Ask for a plan, whose question `asker` words once it holds: what a
    /// screen of an operation the engine confirms first calls.
    pub fn plan(&mut self, plan: crate::client::Plan, asker: Asker) {
        let ask = self.model.plan(plan, asker);
        (self.ask)(ask);
        self.draw();
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

    fn action(&mut self) {
        if let Some(ask) = self.model.action() {
            (self.ask)(ask);
        }
    }

    fn answer(&mut self, confirmed: bool) {
        let ask = self.model.answer(confirmed);
        (self.ask)(ask);
        self.draw();
    }
}

fn wire(window: &AppWindow, controller: &Rc<RefCell<Controller>>) {
    let weak = Rc::downgrade(controller);
    window.on_close_window(move || {
        if let Some(controller) = weak.upgrade() {
            (controller.borrow().close)();
        }
    });
    let weak = Rc::downgrade(controller);
    window.on_action_activated(move || {
        if let Some(controller) = weak.upgrade() {
            controller.borrow_mut().action();
        }
    });
    let weak = Rc::downgrade(controller);
    window.on_question_answered(move |confirmed| {
        if let Some(controller) = weak.upgrade() {
            controller.borrow_mut().answer(confirmed);
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
    let checks: Vec<CheckLine> = page
        .checks
        .iter()
        .map(|check| CheckLine {
            outcome: outcome(check.outcome),
            word: check.word.as_str().into(),
            message: check.message.as_str().into(),
            fix: check.fix.as_str().into(),
        })
        .collect();
    window.set_checks(ModelRc::new(VecModel::from(checks)));
    window.set_fix(page.fix.as_str().into());
    window.set_action(page.action.unwrap_or_default().into());
    match &page.question {
        Some(question) => {
            window.set_question_heading(question.heading.as_str().into());
            window.set_question_body(question.body.as_str().into());
            window.set_question_confirm(question.confirm.as_str().into());
            window.set_question_destructive(question.destructive);
            window.set_question_open(true);
        }
        None => {
            window.set_question_open(false);
            window.set_question_heading(SharedString::default());
            window.set_question_body(SharedString::default());
            window.set_question_confirm(SharedString::default());
            window.set_question_destructive(false);
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
