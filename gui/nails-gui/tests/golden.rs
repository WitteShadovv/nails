// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Golden images of key pages. The window (its markup, controller and model)
//! is drawn by Slint's software renderer, the renderer it ships with, on a
//! platform of this test's own whose clock moves only on request, and each
//! page is compared with the PNG committed in `tests/golden/`. A layout that
//! moves (a page drawn 40 px low, a label over the window's title, a button
//! that cuts its label) fails here, where the element queries of the other
//! UI tests cannot see it.
//!
//! The text is drawn with one font, the Inter that Slint itself bundles
//! (`tests/golden/Inter-VariableFont.ttf`), and no other: the test runs
//! itself again as a child with SLINT_DEFAULT_FONT naming it and a
//! fontconfig that knows no font, which Slint reads once, before the first
//! text, and a test cannot set in its own environment. The pages come from
//! the controller, fed with envelopes recorded from the real CLI; nothing
//! runs a worker, a helper or an emergency.
//!
//! `NAILS_GUI_GOLDEN=update` writes the images instead of comparing them;
//! `NAILS_GUI_GOLDEN_OUT=<directory>` also saves each page drawn there, and
//! on a mismatch the difference.

mod support;

use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;
use std::time::{Duration, Instant};

use nails_api::Event;
use nails_gui::client::{Answer, PlanData, ours};
use nails_gui::model::Model;
use nails_gui::ui::{Controller, Hooks};
use nails_gui::worker::{Ask, Kind, Update};
use nails_gui::{Adw, AppWindow};
use serde_json::{Value, json};
use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Key, Platform, PointerEventButton, WindowAdapter, WindowEvent};
use slint::{ComponentHandle, LogicalPosition, LogicalSize, SharedString};
use support::fixture;

/// The window's preferred size, and its minimum width.
const WIDTH: f32 = 480.0;
const HEIGHT: f32 = 560.0;
const NARROW: f32 = 360.0;
/// A pixel differs where one of its channels is further than this from the
/// golden image's, and a page differs where more than `SPREAD` pixels do: room
/// for the rounding of another processor, none for a layout that moved.
const TOLERANCE: u8 = 32;
const SPREAD: usize = 40;
/// How long the child that draws may take.
const CHILD_LIMIT: Duration = Duration::from_secs(240);
const CHILD: &str = "NAILS_GUI_GOLDEN_CHILD";
const TEST: &str = "key_pages_look_as_their_golden_images";

#[test]
fn key_pages_look_as_their_golden_images() {
    if std::env::var_os(CHILD).is_some() {
        draw_and_compare();
    } else {
        run_child();
    }
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

/// Run this test again with the font pinned, and fail as it fails.
fn run_child() {
    let scratch = std::env::temp_dir().join(format!("nails-gui-golden-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("a scratch directory");
    let fonts = scratch.join("fonts.conf");
    std::fs::write(
        &fonts,
        format!(
            "<?xml version=\"1.0\"?>\n<!DOCTYPE fontconfig SYSTEM \"urn:fontconfig:fonts.dtd\">\n\
             <fontconfig><cachedir>{}</cachedir></fontconfig>\n",
            scratch.join("cache").display()
        ),
    )
    .expect("an empty fontconfig");
    let mut child = Command::new(std::env::current_exe().expect("the test binary"))
        .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .env(
            "SLINT_DEFAULT_FONT",
            golden_dir().join("Inter-VariableFont.ttf"),
        )
        .env_remove("SLINT_FONT_PATH")
        .env("FONTCONFIG_FILE", &fonts)
        .spawn()
        .expect("the drawing child starts");
    let deadline = Instant::now() + CHILD_LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("the child's state") {
            break Some(status);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = std::fs::remove_dir_all(&scratch);
    match status {
        Some(status) => assert!(status.success(), "the pages differ: {status}"),
        None => panic!("drawing the pages took longer than {CHILD_LIMIT:?}"),
    }
}

thread_local! {
    static WINDOWS: RefCell<Vec<Rc<MinimalSoftwareWindow>>> = const { RefCell::new(Vec::new()) };
    static CLOCK: Cell<Duration> = const { Cell::new(Duration::ZERO) };
}

/// Software windows, and a clock that moves only on request.
struct Golden;

impl Platform for Golden {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
        WINDOWS.with(|windows| windows.borrow_mut().push(Rc::clone(&window)));
        Ok(window)
    }

    fn duration_since_start(&self) -> Duration {
        CLOCK.get()
    }
}

/// Let `ms` milliseconds pass.
fn wait_ms(ms: u64) {
    CLOCK.set(CLOCK.get() + Duration::from_millis(ms));
    slint::platform::update_timers_and_animations();
}

/// The window on a page, with its controller.
struct Win {
    app: AppWindow,
    adapter: Rc<MinimalSoftwareWindow>,
    controller: Rc<RefCell<Controller>>,
}

impl Drop for Win {
    fn drop(&mut self) {
        let _ = self.app.hide();
    }
}

/// The window, opened for the engine as the tests open it, in a hidden
/// session when `hidden`.
fn open(hidden: bool) -> Win {
    let app = AppWindow::new().expect("the window builds");
    let adapter = WINDOWS
        .with(|windows| windows.borrow().last().cloned())
        .expect("the window's adapter");
    let model = Model::new(Some(PathBuf::from("/mnt/data/nails")), false).in_hidden_session(hidden);
    let controller = Controller::new(
        &app,
        model,
        Hooks {
            ask: Box::new(|_: Ask| {}),
            hang_up: Box::new(|| {}),
            close: Box::new(|| {}),
            // Nothing: no emergency line, no power-off.
            emergency: Box::new(|| {}),
        },
    );
    app.show().expect("the window shows");
    app.window().set_size(LogicalSize::new(WIDTH, HEIGHT));
    Win {
        app,
        adapter,
        controller,
    }
}

impl Win {
    fn update(&self, update: Update) {
        self.controller.borrow_mut().update(update);
    }

    fn answered(&self, kind: Kind, exit: u8, envelope: Value) {
        self.update(Update::Answered(kind, Answer { exit, envelope }));
    }

    fn resize(&self, width: f32) {
        self.app.window().set_size(LogicalSize::new(width, HEIGHT));
    }

    fn press_key(&self, key: Key) {
        let text: SharedString = key.into();
        let window = self.app.window();
        window.dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
        window.dispatch_event(WindowEvent::KeyReleased { text });
    }

    /// Tab until the control labelled `label` has the focus.
    fn tab_to(&self, label: &str) {
        for _ in 0..64 {
            slint::platform::update_timers_and_animations();
            if self.app.global::<Adw>().get_focused_label() == label {
                return;
            }
            self.press_key(Key::Tab);
        }
        panic!("Tab never reached {label:?}");
    }

    /// Draw the window as it stands, as RGB.
    fn render(&self) -> (u32, u32, Vec<u8>) {
        let mut drawn = (0, 0, Vec::new());
        // The first frame lays out what a change of size or state brought.
        for _ in 0..2 {
            slint::platform::update_timers_and_animations();
            let size = self.app.window().size();
            let mut pixels =
                vec![slint::Rgb8Pixel::default(); size.width as usize * size.height as usize];
            self.app.window().request_redraw();
            self.adapter.draw_if_needed(|renderer| {
                renderer.render(&mut pixels, size.width as usize);
            });
            let rgb = pixels.iter().flat_map(|p| [p.r, p.g, p.b]).collect();
            drawn = (size.width, size.height, rgb);
        }
        drawn
    }
}

fn status(place: &str) -> Value {
    json!({"schema_version": 2, "command": "status", "ok": true, "data": {
        "place": place, "attention": null, "uptime_seconds": 7800,
        "hidden_root": "/mnt/data", "hidden_root_mounted": true}})
}

/// The recorded check of a decoy that is not ready, read as ready: its
/// failures and the warning that the engine runs off the decoy disk passed.
fn ready_check() -> Value {
    let mut recorded = fixture("check-decoy");
    let data = &mut recorded["data"];
    let (mut passed, mut warnings) = (0, 0);
    for check in data["checks"].as_array_mut().expect("the checks") {
        if check["status"] == "fail" || check["name"] == "binary-location" {
            check["status"] = json!("pass");
            if let Some(row) = check.as_object_mut() {
                row.remove("remediation");
            }
        }
        match check["status"].as_str() {
            Some("pass") => passed += 1,
            Some("warn") => warnings += 1,
            _ => {}
        }
    }
    data["ready"] = json!(true);
    data["refusal"] = Value::Null;
    data["summary"] = json!({"failed": 0, "passed": passed, "warnings": warnings});
    recorded["ok"] = json!(true);
    recorded
}

/// A decoy whose check settled on `check`.
fn decoy(check: Value, exit: u8) -> Win {
    let win = open(false);
    win.update(Update::Connected(ours()));
    win.answered(Kind::Status, 0, fixture("status-decoy"));
    win.answered(Kind::Check, exit, check);
    win
}

/// A hidden session's page.
fn hidden() -> Win {
    let win = open(true);
    win.update(Update::Connected(ours()));
    win.answered(Kind::Status, 0, status("hidden"));
    win
}

/// The activation of a ready decoy, asked: its question is open.
fn activation_asked() -> Win {
    let win = decoy(ready_check(), 0);
    win.app.invoke_action_activated();
    win.update(Update::Planned(PlanData::Activate(
        serde_json::from_value(json!({"warning": null, "defaults_notice": null,
            "builds_hidden_system": false, "token": "c".repeat(32)}))
        .expect("an activation's plan"),
    )));
    win
}

/// The activation under way: four of its six steps streamed.
fn activating() -> Win {
    let win = activation_asked();
    win.app.invoke_question_answered(true);
    win.update(Update::Running(Kind::Apply));
    let steps = [
        ("runtime", "Staging the runtime"),
        ("overlay", "Mounting the root overlay"),
        ("mount_policy", "Applying the mount policy"),
        ("mask_units", "Masking decoy units"),
    ];
    for (index, (phase, label)) in (1..).zip(steps) {
        win.update(Update::Event(Event::Step {
            phase: phase.to_string(),
            label: label.to_string(),
            index,
            total: 6,
        }));
    }
    wait_ms(250);
    win
}

/// The tool of the session page's row `row` open on a hidden session.
fn tool(row: i32) -> Win {
    let win = hidden();
    win.app.invoke_link_activated(row);
    win
}

/// A page: its name, and the function that draws it.
type Page = (&'static str, fn() -> Win);

/// The pages.
const PAGES: &[Page] = &[
    ("01-decoy-not-ready", not_ready),
    ("02-decoy-ready-narrow", ready_narrow),
    ("03-activate-question-narrow", activation_asked_narrow),
    ("04-activating", activating),
    ("05-logging-out", logging_out),
    ("06-clean-up", clean_up),
    ("07-hidden", hidden),
    ("08-emergency-armed-narrow", emergency_armed),
    ("09-emergency-held-dark", emergency_held),
    ("10-verify-found", verify_found),
    ("11-rehearsal-planting", planting),
    ("12-settings-number", settings_number),
];

fn narrow(win: Win) -> Win {
    win.resize(NARROW);
    win
}

/// A decoy that is not ready, as the recorded check found it.
fn not_ready() -> Win {
    decoy(fixture("check-decoy"), 1)
}

/// A ready decoy at the window's narrowest.
fn ready_narrow() -> Win {
    narrow(decoy(ready_check(), 0))
}

/// The question before an activation, at the window's narrowest.
fn activation_asked_narrow() -> Win {
    narrow(activation_asked())
}

/// Past the point of no return: the page takes no input, Close included.
fn logging_out() -> Win {
    let win = activating();
    win.update(Update::Event(Event::PointOfNoReturn));
    win
}

/// An activation that was interrupted, with its Clean Up.
fn clean_up() -> Win {
    let win = open(false);
    win.update(Update::Connected(ours()));
    win.answered(
        Kind::Status,
        0,
        json!({"schema_version": 2, "command": "status", "ok": true, "data": {
            "place": "decoy", "attention": "interrupted", "hidden_root": "/mnt/data",
            "hidden_root_mounted": true,
            "remediation": "Run `sudo /mnt/data/nails recover` to remove them"}}),
    );
    win
}

/// The Emergency control after the keyboard's first press, at the window's
/// narrowest: its longest label.
fn emergency_armed() -> Win {
    let win = narrow(hidden());
    win.tab_to("Emergency");
    win.press_key(Key::Return);
    win
}

/// The Emergency control held for half its time, in the dark scheme.
fn emergency_held() -> Win {
    let win = hidden();
    win.app.global::<Adw>().set_dark(true);
    let _ = win.render();
    let position = LogicalPosition::new(40.0, 23.0);
    let window = win.app.window();
    window.dispatch_event(WindowEvent::PointerMoved { position });
    window.dispatch_event(WindowEvent::PointerPressed {
        position,
        button: PointerEventButton::Left,
    });
    wait_ms(500);
    win
}

/// Verify's result: traces found, recorded from the real CLI.
fn verify_found() -> Win {
    let win = tool(0);
    win.app.invoke_action_activated();
    win.update(Update::Running(Kind::Verify));
    win.answered(Kind::Verify, 11, fixture("verify-findings"));
    win
}

/// The rehearsal while it plants: a busy page.
fn planting() -> Win {
    let win = tool(1);
    win.answered(Kind::Rehearse, 0, fixture("rehearse-status-none"));
    win.app.invoke_action_activated();
    win.update(Update::Running(Kind::Rehearse));
    wait_ms(200);
    win
}

/// Settings: a number's page, its field and its facts.
fn settings_number() -> Win {
    let win = tool(2);
    win.answered(Kind::Config, 0, fixture("config-show"));
    win.app.invoke_choice_activated(3);
    win
}

fn draw_and_compare() {
    slint::platform::set_platform(Box::new(Golden)).expect("the test's own platform");
    let update = std::env::var("NAILS_GUI_GOLDEN").is_ok_and(|value| value == "update");
    let out = std::env::var_os("NAILS_GUI_GOLDEN_OUT").map(PathBuf::from);
    let mut differ = Vec::new();
    for (name, page) in PAGES {
        let win = page();
        let drawn = win.render();
        drop(win);
        if let Some(out) = &out {
            write_png(&out.join(format!("{name}.png")), &drawn);
        }
        let golden = golden_dir().join(format!("{name}.png"));
        if update {
            write_png(&golden, &drawn);
            continue;
        }
        if let Some(why) = compare(&golden, &drawn) {
            if let Some(out) = &out {
                write_png(
                    &out.join(format!("{name}-diff.png")),
                    &difference(&golden, &drawn),
                );
            }
            differ.push(format!("{name}: {why}"));
        }
    }
    assert!(
        differ.is_empty(),
        "pages that differ from their golden images (NAILS_GUI_GOLDEN=update redraws them, \
         NAILS_GUI_GOLDEN_OUT=<dir> saves what was drawn):\n{}",
        differ.join("\n")
    );
}

type Image = (u32, u32, Vec<u8>);

fn write_png(path: &Path, (width, height, rgb): &Image) {
    let file = std::fs::File::create(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), *width, *height);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().expect("the PNG header");
    writer.write_image_data(rgb).expect("the PNG data");
}

fn read_png(path: &Path) -> Option<Image> {
    let file = std::fs::File::open(path).ok()?;
    let mut reader = png::Decoder::new(std::io::BufReader::new(file))
        .read_info()
        .ok()?;
    let mut rgb = vec![0; reader.output_buffer_size()?];
    let info = reader.next_frame(&mut rgb).ok()?;
    (info.color_type == png::ColorType::Rgb && info.bit_depth == png::BitDepth::Eight)
        .then(|| (info.width, info.height, rgb[..info.buffer_size()].to_vec()))
}

/// Why `drawn` is not the image at `golden`, if it is not.
fn compare(golden: &Path, drawn: &Image) -> Option<String> {
    let Some(expected) = read_png(golden) else {
        return Some(format!("no golden image at {}", golden.display()));
    };
    if (expected.0, expected.1) != (drawn.0, drawn.1) {
        return Some(format!(
            "{}x{} drawn, {}x{} expected",
            drawn.0, drawn.1, expected.0, expected.1
        ));
    }
    let differing = expected
        .2
        .chunks(3)
        .zip(drawn.2.chunks(3))
        .filter(|(a, b)| {
            a.iter()
                .zip(b.iter())
                .any(|(a, b)| a.abs_diff(*b) > TOLERANCE)
        })
        .count();
    (differing > SPREAD).then(|| format!("{differing} pixels differ"))
}

/// The pixels of `drawn` that differ from the golden image, in red over a
/// faint copy of it.
fn difference(golden: &Path, drawn: &Image) -> Image {
    let expected = read_png(golden).filter(|image| (image.0, image.1) == (drawn.0, drawn.1));
    let rgb = drawn
        .2
        .chunks(3)
        .enumerate()
        .flat_map(|(at, pixel)| {
            let other = expected.as_ref().map(|image| &image.2[at * 3..at * 3 + 3]);
            let differs = other.is_none_or(|other| {
                other
                    .iter()
                    .zip(pixel.iter())
                    .any(|(a, b)| a.abs_diff(*b) > TOLERANCE)
            });
            if differs {
                [255, 0, 0]
            } else {
                [191 + pixel[0] / 4, 191 + pixel[1] / 4, 191 + pixel[2] / 4]
            }
        })
        .collect();
    (drawn.0, drawn.1, rgb)
}
