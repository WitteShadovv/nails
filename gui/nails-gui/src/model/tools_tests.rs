// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The tools through the model: the rows that open them, each tool's asks
//! and pages from envelopes recorded from the real CLI (which the helper
//! answers with word for word), Back and Escape, and the plans of a discard
//! and a set up with their questions, typed word and apply.

use std::path::PathBuf;

use nails_api::CheckOutcome;
use nails_api::protocol::{
    ActivateArgs, CheckArgs, DiscardPlanArgs, DiscardPlanData, InitArgs, InitPlanData,
    RehearsePlantArgs, RehearseScanArgs, VerifyArgs,
};
use serde_json::{Value, json};

use super::*;
use crate::client::{Answer, Plan, PlanData};
use crate::model::{Group, View};
use crate::worker::{Ask, Kind, Rehearse, Update};

fn fixture(name: &str) -> Value {
    let text = match name {
        "verify-findings" => include_str!("../../tests/fixtures/verify-findings.json"),
        "verify-clean" => include_str!("../../tests/fixtures/verify-clean.json"),
        "verify-live" => include_str!("../../tests/fixtures/verify-live.json"),
        "rehearse-status-none" => include_str!("../../tests/fixtures/rehearse-status-none.json"),
        "rehearse-status-planted" => {
            include_str!("../../tests/fixtures/rehearse-status-planted.json")
        }
        "rehearse-scan-found" => include_str!("../../tests/fixtures/rehearse-scan-found.json"),
        "rehearse-scan-blind" => include_str!("../../tests/fixtures/rehearse-scan-blind.json"),
        "rehearse-scan-clean" => include_str!("../../tests/fixtures/rehearse-scan-clean.json"),
        "rehearse-scan-incomplete" => {
            include_str!("../../tests/fixtures/rehearse-scan-incomplete.json")
        }
        "discard-refused" => include_str!("../../tests/fixtures/discard-refused.json"),
        "init-refused-decoy-storage" => {
            include_str!("../../tests/fixtures/init-refused-decoy-storage.json")
        }
        "init-plan-decoy-storage" => {
            include_str!("../../tests/fixtures/init-plan-decoy-storage.json")
        }
        "discard-refused-decoy-storage" => {
            include_str!("../../tests/fixtures/discard-refused-decoy-storage.json")
        }
        "discard-plan-decoy-storage" => {
            include_str!("../../tests/fixtures/discard-plan-decoy-storage.json")
        }
        "init-refused" => include_str!("../../tests/fixtures/init-refused.json"),
        "rehearse-plant-no-such-user" => {
            include_str!("../../tests/fixtures/rehearse-plant-no-such-user.json")
        }
        "verify-image-examiner" => include_str!("../../tests/fixtures/verify-image-examiner.json"),
        "rehearse-scan-image-absent" => {
            include_str!("../../tests/fixtures/rehearse-scan-image-absent.json")
        }
        "init-plan-hardware" => include_str!("../../tests/fixtures/init-plan-hardware.json"),
        "init-plan-no-layout" => include_str!("../../tests/fixtures/init-plan-no-layout.json"),
        other => panic!("no fixture {other}"),
    };
    serde_json::from_str(text).unwrap()
}

fn answered(kind: Kind, exit: u8, envelope: Value) -> Update {
    Update::Answered(kind, Answer { exit, envelope })
}

fn status(place: &str, attention: Value) -> Update {
    answered(
        Kind::Status,
        0,
        json!({"schema_version": 2, "command": "status", "ok": true, "data": {
            "place": place, "attention": attention, "hidden_root": "/mnt/data"}}),
    )
}

fn ready() -> Update {
    answered(
        Kind::Check,
        0,
        json!({"schema_version": 2, "command": "check", "ok": true, "data": {
            "ready": true, "checks": [], "summary": {"passed": 3, "warnings": 0, "failed": 0}}}),
    )
}

/// A decoy's window whose check passed.
fn decoy() -> Model {
    let mut model = Model::new(Some(PathBuf::from("/mnt/data/nails")), false);
    model.apply(Update::Connected(crate::client::ours()));
    assert_eq!(model.apply(status("decoy", Value::Null)).len(), 1);
    model.apply(ready());
    model
}

/// A hidden session's window.
fn hidden() -> Model {
    let mut model =
        Model::new(Some(PathBuf::from("/mnt/data/nails")), false).in_hidden_session(true);
    model.apply(Update::Connected(crate::client::ours()));
    assert!(model.apply(status("hidden", Value::Null)).is_empty());
    model
}

/// Open `tool` from the session page's rows: what it asks for first.
fn open(model: &mut Model, tool: ToolKind) -> Option<Ask> {
    let index = model
        .page()
        .links
        .iter()
        .position(|link| link.tool == tool)
        .unwrap_or_else(|| panic!("{tool:?} is offered"));
    let first = model.open(index);
    assert_eq!(model.page().view, View::Tool(tool));
    first
}

fn titles(groups: &[Group]) -> Vec<&str> {
    groups.iter().map(|group| group.title.as_str()).collect()
}

fn words(group: &Group) -> Vec<&str> {
    group.rows.iter().map(|row| row.word.as_str()).collect()
}

#[test]
fn a_settled_session_page_offers_the_tools_of_its_side() {
    let tools = |model: &Model| -> Vec<ToolKind> {
        model.page().links.iter().map(|link| link.tool).collect()
    };
    let model = decoy();
    assert_eq!(
        tools(&model),
        [
            ToolKind::Verify,
            ToolKind::Rehearsal,
            ToolKind::Discard,
            ToolKind::SetUp,
            ToolKind::Options
        ]
    );
    assert_eq!(model.page().links[2].title, text::DISCARD);
    assert_eq!(model.page().links[2].subtitle, text::DISCARD_WHAT);
    // The engine refuses a discard in a hidden session, and the window
    // withholds Set Up there: the engine would run it. Settings change there.
    assert_eq!(
        tools(&hidden()),
        [ToolKind::Verify, ToolKind::Rehearsal, ToolKind::Settings]
    );

    // None while the check runs, nor while anything runs.
    let mut model = Model::new(Some(PathBuf::from("/mnt/data/nails")), false);
    model.apply(Update::Connected(crate::client::ours()));
    model.apply(status("decoy", Value::Null));
    assert!(model.page().links.is_empty(), "the check runs");
    let mut model = hidden();
    model.apply(Update::Running(Kind::Status));
    assert!(model.page().links.is_empty());
    // None where something else comes first, or without the hidden volume.
    let mut model = Model::new(Some(PathBuf::from("/mnt/data/nails")), false);
    model.apply(Update::Connected(crate::client::ours()));
    model.apply(status("decoy", json!("interrupted")));
    assert!(model.page().links.is_empty());
    let mut model = hidden();
    model.apply(status("hidden", json!("volume_lost")));
    assert!(model.page().links.is_empty());
    model.apply(status("hidden", json!("no_way_back")));
    assert!(model.page().links.is_empty());
}

#[test]
fn verify_runs_standard_or_deep_and_shows_what_it_found_and_did_not_check() {
    let mut model = hidden();
    assert_eq!(
        open(&mut model, ToolKind::Verify),
        None,
        "it waits for the person"
    );
    let page = model.page();
    assert_eq!(page.heading, text::VERIFY);
    assert_eq!(page.description, text::VERIFY_WHAT);
    assert!(page.back);
    assert!(
        page.emergency,
        "the Emergency control stays on a tool's page"
    );
    assert_eq!(
        (page.action, page.secondary),
        (Some(text::VERIFY), Some(text::DEEP_SCAN))
    );

    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Verify(VerifyArgs::default())))
    );
    model.apply(Update::Running(Kind::Verify));
    let page = model.page();
    assert_eq!(page.heading, text::VERIFYING);
    assert_eq!(page.busy.as_deref(), Some(text::LOOKING_FOR_TRACES));
    assert_eq!(
        (page.action, page.secondary, page.back),
        (None, None, false)
    );
    assert_eq!(model.back(), None, "Back waits for the answer");

    model.apply(answered(Kind::Verify, 11, fixture("verify-findings")));
    let page = model.page();
    assert_eq!(page.heading, text::TRACES_FOUND);
    assert!(page.urgent);
    assert_eq!(page.description, text::traces_found(2));
    assert_eq!(
        titles(&page.groups),
        [text::GROUP_FOUND, text::GROUP_NOT_CHECKED_RUN]
    );
    // The trace first, then what may be one, each with the engine's fix.
    assert_eq!(
        words(&page.groups[0]),
        [text::SEVERITY_CRITICAL, text::SEVERITY_WARN]
    );
    assert_eq!(page.groups[0].rows[0].outcome, CheckOutcome::Fail);
    assert_eq!(
        page.groups[0].rows[0].message,
        "Artifact file found: /mnt/nails-pivot."
    );
    assert_eq!(
        page.groups[0].rows[0].fix,
        "Fix: Trace on the decoy filesystem; remove it: rm -rf /mnt/nails-pivot"
    );
    // Every area the run did not check, as the engine lists it.
    assert_eq!(page.groups[1].rows.len(), 20);
    assert_eq!(
        page.groups[1].rows[0].message,
        "The systemd journal (not searched by verify)."
    );
    assert_eq!(page.action, Some(text::VERIFY_AGAIN));

    assert_eq!(
        model.secondary(),
        Some(Effect::Ask(Ask::Verify(VerifyArgs {
            deep: true,
            ..VerifyArgs::default()
        })))
    );
    model.apply(Update::Running(Kind::Verify));
    assert_eq!(model.page().note, text::DEEP_SCAN_WHAT);
}

#[test]
fn a_clean_verify_is_no_proof_and_still_lists_what_it_did_not_check() {
    let mut model = hidden();
    open(&mut model, ToolKind::Verify);
    model.action();
    model.apply(answered(Kind::Verify, 0, fixture("verify-clean")));
    let page = model.page();
    assert_eq!(page.heading, text::NO_KNOWN_TRACES);
    assert!(!page.urgent);
    assert_eq!(
        page.description,
        "A standard scan of 2 checks found no known trace. This is not proof that there is none."
    );
    assert_eq!(titles(&page.groups), [text::GROUP_NOT_CHECKED_RUN]);
    assert!(
        page.groups[0]
            .rows
            .iter()
            .all(|row| row.word == text::NOT_CHECKED)
    );

    // Possible traces count what is no note.
    model.apply(answered(Kind::Verify, 10, fixture("verify-live")));
    let page = model.page();
    assert_eq!(page.heading, text::POSSIBLE_TRACES);
    assert_eq!(page.description, text::possible_traces(1));
    assert_eq!(page.groups[0].rows[0].word, text::SEVERITY_WARN);
    assert_eq!(
        page.groups[0].rows.last().unwrap().word,
        text::SEVERITY_NOTE
    );
}

/// Scan an Image opens from Verify's page and asks for `verify --offline
/// --root` with the mounted image's path; the examiner's view adds
/// `--examiner`, and the disk behind the image `--disk`, which counts only
/// with that view. Back returns to Verify's page.
/// The scan of `/mnt/decoy` with the examiner's view and the disk behind
/// it, answered as the real helper did.
fn image_scanned() -> Model {
    let mut model = hidden();
    open(&mut model, ToolKind::Verify);
    model.choose(0);
    model.edited("/mnt/decoy");
    model.toggled(true);
    model.edited_more(0, "/mnt/decoy.img");
    assert!(model.action().is_some());
    model.apply(Update::Running(Kind::Verify));
    model.apply(answered(Kind::Verify, 0, fixture("verify-image-examiner")));
    assert_eq!(model.page().heading, text::NO_KNOWN_TRACES);
    model
}

/// An image's result reads as Verify's, the examiner's view after it, each
/// conclusion with its traces, where each lies first; it names the image it
/// is of, and the form stays for a scan of another.
#[test]
fn an_image_scans_result_shows_the_examiners_view_and_names_the_image() {
    let model = image_scanned();
    let page = model.page();
    let examiner: Vec<&str> = page
        .groups
        .iter()
        .map(|group| group.title.as_str())
        .filter(|title| title.starts_with("An examiner would conclude: "))
        .collect();
    assert_eq!(examiner.len(), 1, "{:?}", titles(&page.groups));
    let traces = &page
        .groups
        .iter()
        .find(|group| group.title == examiner[0])
        .unwrap()
        .rows;
    assert!(
        traces.iter().any(|row| row.message
            == "/etc/lvm/archive/vg_00001.vg: Volume group vg: Created *before* executing \
                    'vgcreate vg /dev/sdb'."),
        "{traces:?}"
    );
    assert!(page.facts.contains(&(
        text::FACT_SCANNED_IMAGE.to_string(),
        "/mnt/decoy".to_string()
    )));
    assert_eq!(page.field.unwrap().text, "/mnt/decoy");
    assert_eq!(page.action, Some(text::SCAN_IMAGE_ACTION));
}

/// A result holds only for what it scanned: typing the same again keeps
/// it, and any change of the image, the disk behind it or the examiner's
/// view drops it, so no result reads as another image's.
#[test]
fn an_image_scans_result_goes_once_what_it_scanned_changes() {
    let mut model = image_scanned();
    model.edited("/mnt/decoy");
    assert_eq!(model.page().heading, text::NO_KNOWN_TRACES);
    model.edited("/mnt/other");
    let page = model.page();
    assert_eq!(page.heading, text::SCAN_IMAGE);
    assert!(page.groups.is_empty() && page.facts.is_empty());

    let mut model = image_scanned();
    model.edited_more(0, "/mnt/other.img");
    assert_eq!(model.page().heading, text::SCAN_IMAGE);

    let mut model = image_scanned();
    model.toggled(false);
    assert_eq!(model.page().heading, text::SCAN_IMAGE);
}

#[test]
fn scan_an_image_asks_for_an_offline_verify_of_the_mounted_image() {
    let mut model = hidden();
    open(&mut model, ToolKind::Verify);
    let page = model.page();
    assert_eq!(page.choices.len(), 1);
    assert_eq!(page.choices[0].title, text::SCAN_IMAGE_ROW);
    assert_eq!(model.choose(0), None, "opening the page asks nothing");
    let page = model.page();
    assert_eq!(page.heading, text::SCAN_IMAGE);
    assert_eq!(page.description, text::SCAN_IMAGE_WHAT);
    assert!(page.choices.is_empty());
    assert_eq!(page.field.as_ref().unwrap().label, text::FIELD_IMAGE_ROOT);
    let switch = page.switch.clone().unwrap();
    assert_eq!(
        (switch.title.as_str(), switch.on),
        (text::SWITCH_EXAMINER, false)
    );
    assert!(
        page.more_fields.is_empty(),
        "the disk belongs to the examiner's view"
    );
    assert_eq!(page.action, Some(text::SCAN_IMAGE_ACTION));
    assert!(page.action_locked, "the scan waits for the image's path");

    model.edited("mnt/decoy");
    let page = model.page();
    assert!(page.action_locked);
    assert_eq!(page.field.unwrap().hint, text::IMAGE_ROOT_NOT_ABSOLUTE);
    assert_eq!(model.action(), None);

    model.edited(" /mnt/decoy ");
    // A disk typed without the examiner's view is not sent.
    model.toggled(true);
    model.edited_more(0, "/mnt/decoy.img");
    model.toggled(false);
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Verify(VerifyArgs {
            offline: true,
            root: Some("/mnt/decoy".to_string()),
            ..VerifyArgs::default()
        })))
    );

    let mut model = hidden();
    open(&mut model, ToolKind::Verify);
    model.choose(0);
    model.edited("/mnt/decoy");
    model.toggled(true);
    let page = model.page();
    assert!(page.switch.unwrap().on);
    assert_eq!(page.more_fields.len(), 1);
    assert_eq!(page.more_fields[0].label, text::FIELD_DISK);
    model.edited_more(0, "decoy.img");
    let page = model.page();
    assert!(page.action_locked, "a disk is a full path or nothing");
    assert_eq!(page.more_fields[0].hint, text::DISK_NOT_ABSOLUTE);
    model.edited_more(0, "/mnt/decoy.img");
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Verify(VerifyArgs {
            offline: true,
            root: Some("/mnt/decoy".to_string()),
            examiner: true,
            disk: Some("/mnt/decoy.img".to_string()),
            ..VerifyArgs::default()
        })))
    );
    model.apply(Update::Running(Kind::Verify));
    assert_eq!(model.page().heading, text::SCANNING_IMAGE);
    model.apply(answered(Kind::Verify, 0, fixture("verify-image-examiner")));
    assert_eq!(model.page().heading, text::NO_KNOWN_TRACES);
    assert_eq!(model.back(), None, "Back returns to Verify's page");
    let page = model.page();
    assert_eq!(page.heading, ToolKind::Verify.title());
    assert_eq!(
        page.action,
        Some(text::VERIFY),
        "its own result is untouched"
    );
    assert_eq!(model.back(), Some(Ask::Status));
}

#[test]
fn a_verify_that_could_not_run_says_why() {
    let mut model = hidden();
    open(&mut model, ToolKind::Verify);
    model.action();
    model.apply(answered(
        Kind::Verify,
        1,
        json!({"schema_version": 2, "command": "verify", "ok": false, "error": {
            "code": "verify_error", "message": "Error running verification: no /proc",
            "next": null}}),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::VERIFY_FAILED);
    assert_eq!(page.note, "Error running verification: no /proc.");
    assert_eq!(page.action, Some(text::VERIFY_AGAIN));
    // An answer the window cannot read is said as such.
    model.apply(answered(Kind::Verify, 0, json!({"command": "verify"})));
    assert_eq!(model.page().heading, text::VERIFY_FAILED);
}

#[test]
fn back_and_escape_leave_a_tool_and_bring_the_session_page_up_to_date() {
    let mut model = decoy();
    open(&mut model, ToolKind::Verify);
    assert_eq!(model.escape(), Some(Effect::Ask(Ask::Status)));
    assert_eq!(model.page().view, View::Session);
    assert_eq!(model.open_tool(), None);
    // The check stands: Verify changed nothing.
    assert!(model.apply(status("decoy", Value::Null)).is_empty());
    assert_eq!(model.page().heading, text::READY);

    open(&mut model, ToolKind::Verify);
    assert_eq!(model.back(), Some(Ask::Status));
    assert_eq!(model.back(), None, "nothing is open any more");
}

#[test]
fn a_rehearsal_in_a_hidden_session_plants_and_says_what_comes_next() {
    let mut model = hidden();
    assert_eq!(
        open(&mut model, ToolKind::Rehearsal),
        Some(Ask::Rehearse(Rehearse::Status))
    );
    model.apply(Update::Running(Kind::Rehearse));
    assert_eq!(model.page().busy.as_deref(), Some(text::READING_REHEARSAL));
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-status-none")));
    let page = model.page();
    assert_eq!(page.heading, text::REHEARSAL);
    let states: Vec<&str> = page.steps.iter().map(|step| step.state).collect();
    assert_eq!(states, [text::STEP_NOW, text::STEP_NEXT, text::STEP_NEXT]);
    assert_eq!(page.action, Some(text::PLANT));
    assert_eq!(page.secondary, None);

    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Rehearse(Rehearse::Plant(
            RehearsePlantArgs::default()
        ))))
    );
    model.apply(Update::Running(Kind::Rehearse));
    assert_eq!(model.page().busy.as_deref(), Some(text::PLANTING));
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::PLANTED);
    assert_eq!(page.description, text::planted_in(5));
    assert_eq!(
        titles(&page.groups),
        [text::GROUP_PLANTED, text::GROUP_NOT_TESTED]
    );
    assert_eq!(
        page.groups[0].rows[0].message,
        "File in a system folder: /etc/(test words)"
    );
    assert_eq!(
        page.groups[1].rows[0].message,
        "Desktop notification: no session bus to send it on"
    );
    let states: Vec<&str> = page.steps.iter().map(|step| step.state).collect();
    assert_eq!(states, [text::STEP_DONE, text::STEP_NOW, text::STEP_NEXT]);
    assert_eq!(page.fix, text::AFTER_PLANT);
    // No scan in the session that planted: the engine would refuse it.
    assert_eq!(page.action, None);
}

/// The plant's field names the account it is for (`rehearse plant
/// --user`), spaces around the name dropped; left empty, the plant is for
/// the window's own. A name no account has is refused as the CLI refuses
/// it, in the engine's words, as the real helper answered.
#[test]
fn the_plant_is_for_the_account_its_field_names() {
    let mut model = hidden();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-status-none")));
    let field = model.page().field.expect("the account field");
    assert_eq!(field.label, text::FIELD_ACCOUNT);
    assert_eq!(field.text, "");
    assert_eq!(field.hint, text::ACCOUNT_HINT);
    model.edited("   ");
    assert_eq!(model.page().field.unwrap().text, "   ");
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Rehearse(Rehearse::Plant(
            RehearsePlantArgs { user: None }
        ))))
    );

    let mut model = hidden();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-status-none")));
    model.edited(" no-such-account-7f3a ");
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Rehearse(Rehearse::Plant(
            RehearsePlantArgs {
                user: Some("no-such-account-7f3a".to_string())
            }
        ))))
    );
    model.apply(Update::Running(Kind::Rehearse));
    model.apply(answered(
        Kind::Rehearse,
        2,
        fixture("rehearse-plant-no-such-user"),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::PLANT_FAILED);
    assert!(
        page.note.starts_with(
            "No account is named no-such-account-7f3a: name an account of this system"
        ),
        "{}",
        page.note
    );
    // The field keeps the name, for a plant that names another.
    assert_eq!(page.field.unwrap().text, " no-such-account-7f3a ");
}

/// A name the helper would refuse unread, which would end the window's
/// session, is never sent: the plant waits for a name.
#[test]
fn the_plant_waits_for_a_name_the_helper_takes() {
    let mut model = hidden();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-status-none")));
    let long = "a".repeat(257);
    for typed in ["ali/ce", "alice:x", "al\u{7}ice", long.as_str()] {
        model.edited(typed);
        let page = model.page();
        assert!(page.action_locked, "{typed:?}");
        assert_eq!(page.field.unwrap().hint, text::ACCOUNT_NOT_A_NAME);
        assert_eq!(model.action(), None, "{typed:?}");
        assert_eq!(model.tool_action(text::PLANT), None, "{typed:?}");
    }
    model.edited(&"a".repeat(256));
    assert!(!model.page().action_locked);
}

/// The page that scans other disks, opened where planted test words are
/// offered a scan.
fn other_disks() -> Model {
    let mut model = decoy();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    model.choose(0);
    model
}

/// Scan Other Disks, where a scan is offered, asks for `rehearse scan`
/// with the disk named (`--device`), or with its switch the image
/// (`--offline --image`) and the token file (`--token-file`), and where each
/// read stops (`--max-bytes`, from megabytes). Each field takes one full
/// path, spaces in it included, and a disk must be named: an empty field
/// would scan this computer's own disks. What the helper would refuse
/// unread is never sent. The scan's result is the rehearsal's, a scan that
/// read its token from a file leaves the rehearsal's known phase as it was,
/// and what was typed stays for the next.
#[test]
fn scan_other_disks_asks_for_the_disks_or_images_named() {
    let mut model = decoy();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    let page = model.page();
    assert_eq!(page.action, Some(text::SCAN));
    assert_eq!(page.choices[0].title, text::SCAN_OTHER_ROW);
    assert_eq!(model.choose(0), None);
    let page = model.page();
    assert_eq!(page.heading, text::SCAN_OTHER);
    assert!(page.switch_first);
    assert!(!page.switch.unwrap().on);
    assert!(page.action_locked, "a disk is named first");
    let field = page.field.unwrap();
    assert_eq!(field.label, text::FIELD_DISK_SCAN);
    assert_eq!(field.hint, text::DISK_SCAN_NEEDED);
    let more: Vec<&str> = page.more_fields.iter().map(|f| f.label.as_str()).collect();
    assert_eq!(more, [text::FIELD_STOP_AFTER]);

    model.edited("dev/sdc");
    let page = model.page();
    assert!(page.action_locked);
    assert_eq!(page.field.unwrap().hint, text::PATH_NOT_ABSOLUTE);
    model.edited(" /dev/sdb ");
    model.edited_more(0, "64x");
    let page = model.page();
    assert!(page.action_locked);
    assert_eq!(page.more_fields[0].hint, text::STOP_AFTER_NOT_A_NUMBER);
    model.edited_more(0, "64");
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Rehearse(Rehearse::Scan(
            RehearseScanArgs {
                devices: vec!["/dev/sdb".to_string()],
                max_bytes: Some(64_000_000),
                ..RehearseScanArgs::default()
            }
        ))))
    );
    // The scan's page is the rehearsal's; the other disks' page reopens
    // with what was typed.
    model.apply(Update::Running(Kind::Rehearse));
    assert_eq!(model.page().busy.as_deref(), Some(text::READING_DISKS));
}

/// With its switch, Scan Other Disks scans an image (`--offline --image`)
/// with the token file named (`--token-file`); a scan that read its token
/// from a file leaves the rehearsal's known phase as it was.
#[test]
fn scan_other_disks_asks_for_an_image_and_its_token_file() {
    let mut model = other_disks();
    model.toggled(true);
    let page = model.page();
    assert!(page.switch.unwrap().on);
    assert_eq!(page.field.as_ref().unwrap().label, text::FIELD_IMAGE);
    assert_eq!(page.field.unwrap().hint, text::IMAGE_NEEDED);
    let more: Vec<&str> = page.more_fields.iter().map(|f| f.label.as_str()).collect();
    assert_eq!(more, [text::FIELD_TOKEN_FILE, text::FIELD_STOP_AFTER]);
    assert!(page.action_locked, "the switch needs an image");
    model.edited("/srv/decoy.raw");
    model.edited_more(0, "token");
    let page = model.page();
    assert!(page.action_locked, "a token file is a full path");
    assert_eq!(page.more_fields[0].hint, text::PATH_NOT_ABSOLUTE);
    model.edited_more(0, "/srv/token");
    model.edited_more(1, "64");
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Rehearse(Rehearse::Scan(
            RehearseScanArgs {
                offline: true,
                images: vec!["/srv/decoy.raw".to_string()],
                token_file: Some("/srv/token".to_string()),
                max_bytes: Some(64_000_000),
                ..RehearseScanArgs::default()
            }
        ))))
    );
    model.apply(Update::Running(Kind::Rehearse));
    // The image is not there: the helper's scan of it, recorded with a token
    // file, could not read it, so the scan is incomplete.
    model.apply(answered(
        Kind::Rehearse,
        9,
        fixture("rehearse-scan-image-absent"),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::SCAN_INCOMPLETE);
    let rows: Vec<&str> = page
        .groups
        .iter()
        .flat_map(|group| group.rows.iter().map(|row| row.message.as_str()))
        .collect();
    assert!(
        rows.iter().any(|row| row.contains("/srv/decoy.raw")),
        "{rows:?}"
    );
    // That scan read its token from a file and no rehearsal state: what it
    // answered of a phase is not the volume's, whose planted test words still
    // offer their scan, the other disks and their removal.
    assert_eq!(page.action, Some(text::SCAN));
    assert_eq!(page.secondary, Some(text::REMOVE_TEST_WORDS));
    assert_eq!(page.choices.len(), 1);
}

/// Each field takes one full path, spaces in it included, and none longer
/// than the line the helper takes: such a request would end the window's
/// session. Back returns to the rehearsal's page, what was typed kept.
#[test]
fn scan_other_disks_takes_one_full_path_per_field() {
    let mut model = other_disks();
    model.toggled(true);
    model.edited("/srv/my images/decoy.raw");
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Rehearse(Rehearse::Scan(
            RehearseScanArgs {
                offline: true,
                images: vec!["/srv/my images/decoy.raw".to_string()],
                ..RehearseScanArgs::default()
            }
        ))))
    );
    // A path longer than the helper takes in a line is never sent: the
    // helper would end the window's session.
    let mut model = other_disks();
    model.edited(&format!(
        "/dev/{}",
        "a".repeat(nails_api::protocol::MAX_LINE_BYTES)
    ));
    assert!(model.page().action_locked);
    assert_eq!(model.action(), None);

    // Back from the page leaves the rehearsal's, typed values kept.
    let mut model = other_disks();
    model.edited("/dev/sdb");
    assert_eq!(model.back(), None, "Back returns to the rehearsal's page");
    assert_eq!(model.page().action, Some(text::SCAN));
    model.choose(0);
    assert_eq!(model.page().field.unwrap().text, "/dev/sdb");
}

/// Scan Again repeats the scan that ran last, of the disk named on Scan
/// Other Disks too, rather than scanning this computer instead.
#[test]
fn scan_again_repeats_the_other_disk_scanned_last() {
    let mut model = decoy();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    model.choose(0);
    model.edited("/dev/sdb");
    let scan = || {
        Some(Effect::Ask(Ask::Rehearse(Rehearse::Scan(
            RehearseScanArgs {
                devices: vec!["/dev/sdb".to_string()],
                ..RehearseScanArgs::default()
            },
        ))))
    };
    assert_eq!(model.action(), scan());
    model.apply(Update::Running(Kind::Rehearse));
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-scan-clean")));
    assert_eq!(model.page().action, Some(text::SCAN_AGAIN));
    assert_eq!(model.action(), scan());
}

/// Only the plant takes an account: once the test words are planted, the
/// page has no field.
#[test]
fn only_the_plant_has_the_account_field() {
    let mut model = hidden();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    assert_eq!(model.page().field, None);
}

#[test]
fn a_rehearsal_on_the_decoy_scans_and_removes_but_never_plants() {
    let mut model = decoy();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-status-none")));
    let page = model.page();
    assert_eq!(page.action, None);
    assert_eq!(page.fix, text::REHEARSAL_STARTS_HIDDEN);
    assert_eq!(model.tool_action(text::PLANT), None);

    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::REHEARSAL);
    assert_eq!(
        (page.action, page.secondary),
        (Some(text::SCAN), Some(text::REMOVE_TEST_WORDS))
    );
    assert_eq!(page.fix, text::REHEARSAL_PLANTED_DECOY);
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Rehearse(Rehearse::Scan(
            RehearseScanArgs::default()
        ))))
    );
    model.apply(Update::Running(Kind::Rehearse));
    let page = model.page();
    assert_eq!(page.heading, text::SCANNING);
    assert_eq!(page.description, text::SCAN_HOW_LONG);
    assert_eq!(page.busy.as_deref(), Some(text::READING_DISKS));

    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-scan-clean")));
    assert_eq!(
        model.secondary(),
        Some(Effect::Ask(Ask::Rehearse(Rehearse::Reset)))
    );
    model.apply(answered(
        Kind::Rehearse,
        0,
        json!({"schema_version": 2, "command": "rehearse", "ok": true, "data": {
            "phase": "none", "fingerprint": "012345\u{2026}", "channels": [],
            "removed": ["/mnt/data/rehearse/state.json", "/mnt/data/root/upper/etc/<canary>"],
            "next_step": "Step 1 of 3: activate a hidden session, then run `sudo /mnt/data/nails rehearse plant`."}}),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::TEST_WORDS_REMOVED);
    assert_eq!(
        page.groups[0].rows[1].message,
        "/mnt/data/root/upper/etc/(test words)"
    );
    assert!(page.steps.is_empty(), "the result takes the steps' place");
}

#[test]
fn a_scan_that_found_the_test_words_says_where_first() {
    let mut model = decoy();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    model.action();
    model.apply(answered(Kind::Rehearse, 11, fixture("rehearse-scan-found")));
    let page = model.page();
    assert_eq!(page.heading, text::TEST_WORDS_FOUND);
    assert!(page.urgent);
    assert_eq!(
        page.description,
        text::test_words_found("/tmp/scratch/hit.img", 524_288)
    );
    assert_eq!(
        titles(&page.groups),
        [
            text::GROUP_DISKS,
            text::GROUP_NOT_CHECKED_SCAN,
            text::GROUP_NOT_TESTED
        ]
    );
    assert_eq!(page.groups[0].rows[0].word, text::FOUND_WORD);
    assert_eq!(
        page.groups[0].rows[0].message,
        "/tmp/scratch/hit.img, byte 524288"
    );
    assert_eq!(page.action, Some(text::SCAN_AGAIN));
}

#[test]
fn a_scan_whose_disk_can_hide_the_test_words_is_never_a_pass() {
    let mut model = decoy();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    model.action();
    model.apply(answered(Kind::Rehearse, 9, fixture("rehearse-scan-blind")));
    let page = model.page();
    assert_eq!(page.heading, text::NOT_A_CLEAN_RESULT);
    assert_eq!(page.description, text::blind_spots(1));
    // What the scan did not check comes first: that disk, then each blind
    // spot of every such scan.
    assert_eq!(page.groups[0].title, text::GROUP_NOT_CHECKED_SCAN);
    let first = &page.groups[0].rows[0];
    assert_eq!(first.word, text::NOT_CHECKED);
    assert_eq!(first.outcome, CheckOutcome::Warn);
    assert!(
        first
            .message
            .starts_with("/tmp/scratch/plain.img: The scan identifies no filesystem here"),
        "{}",
        first.message
    );
    assert_eq!(page.groups[0].rows.len(), 1 + 6);
    assert!(
        page.groups
            .iter()
            .all(|group| group.title != text::GROUP_DISKS),
        "the disk is not listed as read"
    );
    for group in &page.groups {
        for row in &group.rows {
            assert_ne!(row.word, text::READ_WORD);
        }
    }
}

#[test]
fn a_scan_reads_as_a_pass_only_when_the_engine_and_every_disk_say_so() {
    let mut model = decoy();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    model.action();
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-scan-clean")));
    let page = model.page();
    assert_eq!(page.heading, text::PASSED);
    assert_eq!(page.description, text::passed(1, 8_388_608));
    assert_eq!(
        titles(&page.groups),
        [
            text::GROUP_NOT_CHECKED_SCAN,
            text::GROUP_DISKS,
            text::GROUP_NOT_TESTED
        ]
    );
    assert_eq!(page.groups[0].rows.len(), 6, "every blind spot of the scan");
    assert_eq!(
        page.groups[1].rows[0].message,
        "/tmp/scratch/ext4.img: 8.4\u{a0}MB read in full"
    );

    // A disk not read in full makes it incomplete.
    model.action();
    model.apply(answered(
        Kind::Rehearse,
        9,
        fixture("rehearse-scan-incomplete"),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::SCAN_INCOMPLETE);
    assert_eq!(page.description, text::incomplete(1));
    assert_eq!(
        words(&page.groups[1]),
        [text::READ_WORD, text::INCOMPLETE_WORD]
    );

    // The same clean disks, but the engine did not end it clean: no pass.
    model.action();
    model.apply(answered(Kind::Rehearse, 9, fixture("rehearse-scan-clean")));
    assert_eq!(model.page().heading, text::NOT_A_CLEAN_RESULT);
    assert_eq!(model.page().description, text::NOT_CLEAN_UNEXPLAINED);
}

/// In the session that planted, the scan the engine refuses is offered
/// behind a question (`rehearse scan --allow-same-boot`): it says what such
/// a scan proves, and its button acts only once the word is typed.
#[test]
fn a_scan_in_the_planting_session_asks_first_and_needs_the_word() {
    let mut model = hidden();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-status-none")));
    model.action();
    model.apply(Update::Running(Kind::Rehearse));
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    let page = model.page();
    assert_eq!(
        page.action, None,
        "no plain scan in the session that planted"
    );
    assert_eq!(page.secondary, Some(text::SCAN_SAME_BOOT));
    assert_eq!(model.secondary(), None, "the question comes first");
    let question = model.page().question.expect("the question is open");
    assert_eq!(question.heading, text::SAME_BOOT_QUESTION);
    assert_eq!(
        question.body,
        format!("{}\n{}", text::SAME_BOOT_WHAT, text::SAME_BOOT_ONCE)
    );
    assert!(question.locked && question.destructive);
    assert_eq!(model.answer(true), None, "not without the word");
    model.secondary();
    model.typed("allow");
    assert!(!model.page().question.unwrap().locked);
    assert_eq!(
        model.answer(true),
        Some(Ask::Rehearse(Rehearse::Scan(RehearseScanArgs {
            allow_same_boot: true,
            ..RehearseScanArgs::default()
        })))
    );
    model.apply(Update::Running(Kind::Rehearse));
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-scan-clean")));
    let page = model.page();
    // Such a scan proves little: never a pass.
    assert_eq!(page.heading, text::NOT_A_CLEAN_RESULT);
    assert_eq!(page.description, text::NOT_CLEAN_SAME_SESSION);
    // Scanned, the session still planted: a scan again asks again.
    assert_eq!(page.secondary, Some(text::SCAN_SAME_BOOT));
    assert_eq!(page.action, None);
    assert!(page.choices.is_empty(), "no other disks from here");
    // Opened again, the session still has to end: nothing reads as done
    // that is not, and nothing says the test words can go.
    assert_eq!(model.back(), Some(Ask::Status));
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-scan-clean")));
    let page = model.page();
    let states: Vec<&str> = page.steps.iter().map(|step| step.state).collect();
    assert_eq!(states, [text::STEP_DONE, text::STEP_NOW, text::STEP_NEXT]);
    assert_eq!(page.fix, text::AFTER_PLANT);
    assert_eq!(page.secondary, Some(text::SCAN_SAME_BOOT));
    // Cancelled, it asks for nothing.
    model.secondary();
    model.typed("allow");
    assert_eq!(model.answer(false), None);
}

#[test]
fn a_scan_refused_in_the_planting_session_offers_only_the_one_that_asks_first() {
    let mut model = hidden();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    assert_eq!(model.page().action, Some(text::SCAN));
    assert_eq!(model.page().secondary, None, "no reset in a hidden session");
    assert_eq!(model.tool_action(text::REMOVE_TEST_WORDS), None);
    model.action();
    model.apply(answered(
        Kind::Rehearse,
        6,
        json!({"schema_version": 2, "command": "rehearse", "ok": false, "error": {
            "code": "same_boot", "message": "the canary was planted in this session",
            "next": null}}),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::SCAN_FAILED);
    assert_eq!(page.note, text::REHEARSAL_SAME_SESSION);
    assert_eq!(page.action, None);
    assert_eq!(page.secondary, Some(text::SCAN_SAME_BOOT));
    assert_eq!(page.fix, text::AFTER_PLANT);
    // Closed and opened again, the page still knows.
    assert_eq!(model.back(), Some(Ask::Status));
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    let page = model.page();
    assert_eq!(page.action, None, "no scan in the session that planted");
    assert_eq!(page.fix, text::AFTER_PLANT);

    // Any other refusal is said in the engine's words.
    let mut model = hidden();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-status-none")));
    model.action();
    model.apply(answered(
        Kind::Rehearse,
        6,
        json!({"schema_version": 2, "command": "rehearse", "ok": false, "error": {
            "code": "not_active", "message": "no hidden session is active",
            "next": null}}),
    ));
    assert_eq!(model.page().note, "No hidden session is active.");
    assert_eq!(model.page().action, Some(text::PLANT));
}

#[test]
fn a_plant_is_remembered_when_the_page_opens_again_in_its_session() {
    let mut model = hidden();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-status-none")));
    model.action();
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    assert_eq!(model.back(), Some(Ask::Status));
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    let page = model.page();
    let states: Vec<&str> = page.steps.iter().map(|step| step.state).collect();
    assert_eq!(states, [text::STEP_DONE, text::STEP_NOW, text::STEP_NEXT]);
    assert_eq!(page.action, None);
    assert_eq!(page.fix, text::AFTER_PLANT);
    assert!(!page.fix.contains("decoy"), "{}", page.fix);
    // A rehearsal removed since is no rehearsal of this session's.
    model.back();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-status-none")));
    model.back();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    assert_eq!(model.page().action, Some(text::SCAN));
}

#[test]
fn a_scan_that_could_not_run_never_reads_as_the_scan_before_it() {
    let mut model = decoy();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    model.action();
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-scan-clean")));
    assert_eq!(model.page().heading, text::PASSED);
    model.action();
    model.apply(answered(
        Kind::Rehearse,
        6,
        json!({"schema_version": 2, "command": "rehearse", "ok": false, "error": {
            "code": "no_token", "message": "no rehearsal state under /mnt/data",
            "next": null}}),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::SCAN_FAILED);
    assert!(page.urgent);
    assert_eq!(page.description, text::REHEARSAL_WHAT);
    assert_eq!(page.note, "No rehearsal state under /mnt/data.");
    assert!(page.groups.is_empty(), "nothing of the scan before");
    assert_eq!(page.action, Some(text::SCAN_AGAIN));
    // An answer the window cannot read is no verdict either.
    model.action();
    model.apply(answered(Kind::Rehearse, 0, json!({"command": "rehearse"})));
    assert_eq!(model.page().heading, text::SCAN_FAILED);
    // Nor a reset that failed.
    model.secondary();
    model.apply(answered(
        Kind::Rehearse,
        1,
        json!({"schema_version": 2, "command": "rehearse", "ok": false, "error": {
            "code": "reset", "message": "Permission denied", "next": null}}),
    ));
    assert_eq!(model.page().heading, text::REMOVE_FAILED);
    assert_eq!(model.page().note, "Permission denied.");
}

#[test]
fn a_hidden_sessions_page_gives_the_line_that_removes_the_test_words() {
    let mut model = hidden();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        0,
        fixture("rehearse-status-planted"),
    ));
    assert_eq!(model.page().fix, text::REHEARSAL_PLANTED);
    model.action();
    model.apply(answered(Kind::Rehearse, 0, fixture("rehearse-scan-clean")));
    let page = model.page();
    assert_eq!(page.secondary, None, "no reset in a hidden session");
    assert_eq!(
        page.fix.lines().collect::<Vec<_>>(),
        [
            text::REHEARSAL_SCANNED,
            "Once you are done, remove the test words on the decoy, with the hidden volume \
             mounted: sudo /mnt/data/nails rehearse reset",
        ]
    );
}

#[test]
fn a_rehearsal_whose_status_failed_offers_nothing_but_back() {
    let mut model = hidden();
    open(&mut model, ToolKind::Rehearsal);
    model.apply(answered(
        Kind::Rehearse,
        6,
        json!({"schema_version": 2, "command": "rehearse", "ok": false, "error": {
            "code": "rehearse_state", "message": "the rehearsal state is unreadable",
            "next": null}}),
    ));
    let page = model.page();
    assert_eq!(page.note, "The rehearsal state is unreadable.");
    assert_eq!(page.action, None);
    assert!(page.back);
}

fn discard_plan(target: &str, removals: &[&str], nix: bool) -> Update {
    Update::Planned(PlanData::Discard(DiscardPlanData {
        target: target.to_string(),
        removals: removals.iter().map(|path| (*path).to_string()).collect(),
        resets_nix_store: nix,
        token: "d".repeat(32),
    }))
}

fn discarded(target: &str, removed: &[&str]) -> Value {
    json!({"schema_version": 2, "command": "discard", "ok": true,
        "data": {"target": target, "removed": removed}})
}

#[test]
fn a_discard_asks_for_a_full_path_and_says_exactly_what_goes() {
    let mut model = decoy();
    assert_eq!(open(&mut model, ToolKind::Discard), None);
    let page = model.page();
    let field = page.field.unwrap();
    assert_eq!(
        (field.label.as_str(), field.hint.as_str()),
        (text::FIELD_FOLDER, text::FOLDER_HINT)
    );
    assert_eq!(page.action, Some(text::DISCARD_ACTION));
    assert_eq!(page.action_kind, crate::model::ActionKind::Destructive);
    assert!(page.action_locked);
    assert_eq!(model.action(), None, "nothing to discard yet");

    model.edited("etc/apt");
    assert_eq!(model.page().field.unwrap().hint, text::FOLDER_NOT_ABSOLUTE);
    assert_eq!(model.action(), None, "the helper takes only a full path");
    model.edited("/etc/apt");
    assert!(!model.page().action_locked);
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Discard(DiscardPlanArgs {
            target: "/etc/apt".to_string(),
            allow_decoy_storage: false,
        }))))
    );
    model.apply(Update::Running(Kind::Plan));
    assert_eq!(model.page().busy.as_deref(), Some(text::LOOKING_AT_CHANGES));
    let removals = [
        "/mnt/data/root/upper/etc/apt",
        "/mnt/data/root/mounts/etc-apt",
    ];
    assert!(
        model
            .apply(discard_plan("/etc/apt", &removals, false))
            .is_empty()
    );
    let question = model.page().question.unwrap();
    assert_eq!(question.heading, text::DISCARD_QUESTION);
    assert_eq!(
        question.body.lines().collect::<Vec<_>>(),
        [
            text::discard_consequence("/etc/apt").as_str(),
            text::DISCARD_LIST,
            removals[0],
            removals[1],
        ]
    );
    assert!(question.destructive);
    assert_eq!(question.confirm, text::DELETE);
    assert_eq!(question.prompt, None, "no warning, no word to type");

    assert_eq!(model.answer(true), Some(Ask::Apply));
    model.apply(Update::Running(Kind::Apply));
    assert_eq!(model.page().busy.as_deref(), Some(text::DELETING));
    model.apply(answered(Kind::Apply, 0, discarded("/etc/apt", &removals)));
    let page = model.page();
    assert_eq!(page.heading, text::DISCARDED);
    assert_eq!(page.description, text::discarded("/etc/apt"));
    assert_eq!(
        words(&page.groups[0]),
        [text::DELETED_WORD, text::DELETED_WORD]
    );

    // Back brings the check again: what it finds may have changed.
    assert_eq!(model.back(), Some(Ask::Status));
    assert_eq!(model.apply(status("decoy", Value::Null)).len(), 1);
}

#[test]
fn a_discard_that_takes_a_home_or_nix_asks_for_the_folder_typed() {
    for (target, nix, home) in [
        ("/home", false, true),
        ("/home/alice/notes", false, true),
        ("/var", false, true),
        ("/nix", true, false),
    ] {
        let mut model = decoy();
        open(&mut model, ToolKind::Discard);
        model.edited(target);
        model.action();
        model.apply(discard_plan(target, &["/mnt/data/root/upper/x"], nix));
        let question = model.page().question.unwrap();
        assert_eq!(
            question.prompt.as_deref(),
            Some(text::discard_type(target, home).as_str()),
            "{target}"
        );
        assert!(question.locked, "{target}");
        assert_eq!(question.body.contains(text::DISCARD_NIX), nix, "{target}");
        // Delete waits for the folder; without it the answer withdraws.
        model.typed("/hom");
        assert!(model.page().question.unwrap().locked);
        model.typed(&format!(" {target}/ "));
        assert!(!model.page().question.unwrap().locked, "{target}");
        assert_eq!(model.answer(true), Some(Ask::Apply), "{target}");
    }
    let mut model = decoy();
    open(&mut model, ToolKind::Discard);
    model.edited("/home");
    model.action();
    model.apply(discard_plan("/home", &["/mnt/data/root/upper/home"], false));
    assert_eq!(model.answer(true), Some(Ask::Withdraw), "not typed");
}

#[test]
fn a_discard_with_nothing_to_delete_or_refused_says_so() {
    let mut model = decoy();
    open(&mut model, ToolKind::Discard);
    model.edited("/srv/notes");
    model.action();
    model.apply(answered(Kind::Plan, 0, discarded("/srv/notes", &[])));
    let page = model.page();
    assert_eq!(page.note, text::nothing_to_discard("/srv/notes"));
    assert_eq!(page.question, None);
    assert_eq!(model.back(), Some(Ask::Status));
    assert!(
        model.apply(status("decoy", Value::Null)).is_empty(),
        "nothing changed, so the check stands"
    );

    let mut model = decoy();
    open(&mut model, ToolKind::Discard);
    model.edited("/etc/apt");
    model.action();
    model.apply(answered(Kind::Plan, 4, fixture("discard-refused")));
    let page = model.page();
    assert_eq!(page.heading, text::NOT_DISCARDED);
    assert!(
        page.note
            .starts_with("/mnt/data is not a volume of its own"),
        "{}",
        page.note
    );
    assert_eq!(page.field.unwrap().text, "/etc/apt", "the folder stays");
}

#[test]
fn an_apply_that_failed_says_so_and_a_cancel_withdraws() {
    let mut model = decoy();
    open(&mut model, ToolKind::Discard);
    model.edited("/etc/apt");
    model.action();
    model.apply(discard_plan(
        "/etc/apt",
        &["/mnt/data/root/upper/etc/apt"],
        false,
    ));
    assert_eq!(model.answer(false), Some(Ask::Withdraw));
    model.apply(Update::Withdrawn);
    assert_eq!(model.page().question, None);
    assert_eq!(model.page().view, View::Tool(ToolKind::Discard));

    model.action();
    model.apply(discard_plan(
        "/etc/apt",
        &["/mnt/data/root/upper/etc/apt"],
        false,
    ));
    model.answer(true);
    model.apply(answered(
        Kind::Apply,
        1,
        json!({"schema_version": 2, "command": "discard", "ok": false, "error": {
            "code": "discard", "message": "Permission denied", "next": null}}),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::DISCARD_FAILED);
    assert!(page.urgent);
    assert_eq!(page.note, "Permission denied.");
}

fn init_plan(warnings: &[&str]) -> Update {
    Update::Planned(PlanData::Init(InitPlanData {
        path: "/mnt/data".to_string(),
        hardware_config: Some("/etc/nixos/hardware-configuration.nix".to_string()),
        skipped: None,
        warnings: warnings.iter().map(|w| (*w).to_string()).collect(),
        token: "e".repeat(32),
    }))
}

/// Activation Options, on the decoy: this computer's system
/// (`--overlay-only`), or else a flake (`--nixos-flake`). Back on the
/// session's page the check runs again with them, the page names them, and
/// the activation takes them too. A flake the helper would refuse unread is
/// kept out.
#[test]
fn activation_options_reach_the_check_and_the_activation() {
    let mut model = decoy();
    assert_eq!(open(&mut model, ToolKind::Options), None);
    let page = model.page();
    assert_eq!(page.heading, text::ACTIVATION_OPTIONS);
    assert_eq!(page.description, text::ACTIVATION_OPTIONS_WHAT);
    assert!(page.switch_first);
    assert!(!page.switch.unwrap().on);
    assert_eq!(page.field.unwrap().label, text::FIELD_FLAKE);
    assert_eq!(page.action, None);
    model.edited(" /srv/flake#decoy ");
    assert_eq!(model.back(), Some(Ask::Status));
    assert_eq!(
        model.apply(status("decoy", Value::Null)),
        vec![Ask::Check(CheckArgs {
            nixos_flake: Some("/srv/flake#decoy".to_string()),
            ..CheckArgs::default()
        })]
    );
    model.apply(ready());
    let page = model.page();
    assert!(page.facts.contains(&(
        text::FACT_OPTIONS.to_string(),
        text::option_flake("/srv/flake#decoy")
    )));
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Activate(ActivateArgs {
            nixos_flake: Some("/srv/flake#decoy".to_string()),
            ..ActivateArgs::default()
        }))))
    );

    // This computer's own system takes no flake.
    let mut model = decoy();
    open(&mut model, ToolKind::Options);
    model.edited("/srv/flake#decoy");
    model.toggled(true);
    assert_eq!(model.page().field, None);
    model.back();
    assert_eq!(
        model.apply(status("decoy", Value::Null)),
        vec![Ask::Check(CheckArgs {
            overlay_only: true,
            ..CheckArgs::default()
        })]
    );
    model.apply(ready());
    assert!(model.page().facts.contains(&(
        text::FACT_OPTIONS.to_string(),
        text::OPTION_OVERLAY_ONLY.to_string()
    )));

    // A flake the helper would refuse is kept out, and the field says why.
    let mut model = decoy();
    open(&mut model, ToolKind::Options);
    model.edited("/srv/fla\u{7}ke");
    assert_eq!(
        model.page().field.unwrap().hint,
        text::FLAKE_NOT_A_REFERENCE
    );
    // Nothing changed for the check, which needs not run again.
    model.back();
    assert!(model.apply(status("decoy", Value::Null)).is_empty());
}

/// Set Up refused for a hidden volume on this computer's storage, which the
/// engine names `--allow-decoy-storage` for, offers to allow it: the
/// question repeats the refusal, its button acts only once the word is
/// typed, and the next plan carries the flag; as the real helper answered.
#[test]
fn a_set_up_on_this_computers_storage_is_allowed_only_behind_the_word() {
    let mut model = decoy();
    open(&mut model, ToolKind::SetUp);
    model.toggled(false);
    let plan = |allow: bool| {
        Some(Effect::Ask(Ask::Plan(Plan::Init(InitArgs {
            path: "/mnt/data".to_string(),
            allow_decoy_storage: allow,
            hardware_config: None,
            no_hardware_config: true,
        }))))
    };
    assert_eq!(model.action(), plan(false));
    model.apply(Update::Running(Kind::Plan));
    model.apply(answered(
        Kind::Plan,
        4,
        fixture("init-refused-decoy-storage"),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::SET_UP_FAILED);
    assert_eq!(page.secondary, Some(text::ALLOW_FOR_SET_UP));
    assert_eq!(model.secondary(), None, "the question comes first");
    let question = model.page().question.expect("the question is open");
    assert_eq!(question.heading, text::ALLOW_FOR_SET_UP_QUESTION);
    assert_eq!(
        question.body,
        format!(
            "/mnt/data is not a volume of its own: it is a bind mount of a folder of /. \
             Nothing was written.\n{}",
            text::STORAGE_ONCE
        )
    );
    assert!(question.locked && question.destructive);
    assert_eq!(model.answer(true), None, "not without the word");
    model.secondary();
    model.typed("allow");
    assert_eq!(
        model.answer(true).map(Effect::Ask),
        plan(true),
        "the plan again, with the flag"
    );
    model.apply(Update::Running(Kind::Plan));
    model.apply(recorded_init_plan("init-plan-decoy-storage"));
    let question = model.page().question.expect("the plan's question");
    assert!(
        question
            .body
            .contains("--allow-decoy-storage: using /mnt/data although it is a bind mount"),
        "{}",
        question.body
    );

    // A refusal no flag covers offers nothing.
    let mut model = decoy();
    open(&mut model, ToolKind::SetUp);
    model.action();
    model.apply(answered(Kind::Plan, 4, fixture("init-refused")));
    assert_eq!(model.page().secondary, None);
    assert_eq!(model.tool_action(text::ALLOW_FOR_SET_UP), None);
    assert_eq!(model.page().question, None);
}

/// The flag the word allowed goes to the one plan it was allowed for, and
/// no further: a plan that held and was cancelled leaves the next plain
/// Set Up… without it, and asks nothing on its own.
#[test]
fn a_set_up_allowed_once_and_cancelled_plans_plainly_after() {
    let mut model = decoy();
    open(&mut model, ToolKind::SetUp);
    model.toggled(false);
    let plan = |allow: bool| {
        Some(Effect::Ask(Ask::Plan(Plan::Init(InitArgs {
            path: "/mnt/data".to_string(),
            allow_decoy_storage: allow,
            hardware_config: None,
            no_hardware_config: true,
        }))))
    };
    model.action();
    model.apply(Update::Running(Kind::Plan));
    model.apply(answered(
        Kind::Plan,
        4,
        fixture("init-refused-decoy-storage"),
    ));
    model.secondary();
    model.typed("allow");
    assert_eq!(model.answer(true).map(Effect::Ask), plan(true));
    model.apply(Update::Running(Kind::Plan));
    model.apply(recorded_init_plan("init-plan-decoy-storage"));
    // Cancelled: the plan is withdrawn.
    assert_eq!(model.answer(false), Some(Ask::Withdraw));
    model.apply(Update::Withdrawn);
    model.apply(status("decoy", Value::Null));
    let page = model.page();
    assert_eq!(
        page.secondary, None,
        "nothing is offered for a plan not refused"
    );
    assert_eq!(model.action(), plan(false), "the next plan carries no flag");

    // Refused again, then a plain plan that held: no stale offer either.
    let mut model = decoy();
    open(&mut model, ToolKind::SetUp);
    model.toggled(false);
    model.action();
    model.apply(answered(
        Kind::Plan,
        4,
        fixture("init-refused-decoy-storage"),
    ));
    model.action();
    model.apply(recorded_init_plan("init-plan-no-layout"));
    assert_eq!(model.answer(false), Some(Ask::Withdraw));
    model.apply(Update::Withdrawn);
    assert_eq!(model.page().secondary, None);
    assert_eq!(model.tool_action(text::ALLOW_FOR_SET_UP), None);
    assert_eq!(model.page().question, None);
}

/// No allow is armed while no plan could go: with a hardware configuration
/// that is no full path, the override is not offered, and asking for it
/// opens nothing.
#[test]
fn a_set_up_offers_no_allow_while_its_plan_cannot_go() {
    let mut model = decoy();
    open(&mut model, ToolKind::SetUp);
    model.action();
    model.apply(answered(
        Kind::Plan,
        4,
        fixture("init-refused-decoy-storage"),
    ));
    assert_eq!(model.page().secondary, Some(text::ALLOW_FOR_SET_UP));
    model.edited("hardware.nix");
    let page = model.page();
    assert!(page.action_locked);
    assert_eq!(page.secondary, None, "no allow while the plan cannot go");
    assert_eq!(model.tool_action(text::ALLOW_FOR_SET_UP), None);
    assert_eq!(model.page().question, None);
    model.edited("/srv/hardware.nix");
    assert_eq!(model.page().secondary, Some(text::ALLOW_FOR_SET_UP));
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Init(InitArgs {
            path: "/mnt/data".to_string(),
            allow_decoy_storage: false,
            hardware_config: Some("/srv/hardware.nix".to_string()),
            no_hardware_config: false,
        })))),
        "the plain plan carries no flag"
    );
}

/// The same holds for a discard: allowed once, held and cancelled, the next
/// discard, of another folder, carries no flag and is offered nothing.
#[test]
fn a_discard_allowed_once_and_cancelled_plans_plainly_after() {
    let mut model = decoy();
    open(&mut model, ToolKind::Discard);
    model.edited("/srv/data");
    model.action();
    model.apply(Update::Running(Kind::Plan));
    model.apply(answered(
        Kind::Plan,
        4,
        fixture("discard-refused-decoy-storage"),
    ));
    model.secondary();
    model.typed("allow");
    assert_eq!(
        model.answer(true),
        Some(Ask::Plan(Plan::Discard(DiscardPlanArgs {
            target: "/srv/data".to_string(),
            allow_decoy_storage: true,
        })))
    );
    model.apply(Update::Running(Kind::Plan));
    model.apply(discard_plan(
        "/srv/data",
        &["/mnt/data/root/upper/srv/data/a"],
        false,
    ));
    assert_eq!(model.answer(false), Some(Ask::Withdraw));
    model.apply(Update::Withdrawn);
    model.apply(status("decoy", Value::Null));
    model.edited("/srv/other");
    assert_eq!(model.page().secondary, None);
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Discard(DiscardPlanArgs {
            target: "/srv/other".to_string(),
            allow_decoy_storage: false,
        }))))
    );
}

/// Discard refused for the same reason offers the same, and its next plan
/// carries `--allow-decoy-storage`.
#[test]
fn a_discard_on_this_computers_storage_is_allowed_only_behind_the_word() {
    let mut model = decoy();
    open(&mut model, ToolKind::Discard);
    model.edited("/srv/data");
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Discard(DiscardPlanArgs {
            target: "/srv/data".to_string(),
            allow_decoy_storage: false,
        }))))
    );
    model.apply(Update::Running(Kind::Plan));
    model.apply(answered(
        Kind::Plan,
        4,
        fixture("discard-refused-decoy-storage"),
    ));
    assert_eq!(model.page().secondary, Some(text::ALLOW_FOR_DISCARD));
    model.secondary();
    assert_eq!(
        model.page().question.unwrap().heading,
        text::ALLOW_FOR_DISCARD_QUESTION
    );
    model.typed("allow");
    assert_eq!(
        model.answer(true),
        Some(Ask::Plan(Plan::Discard(DiscardPlanArgs {
            target: "/srv/data".to_string(),
            allow_decoy_storage: true,
        })))
    );
    model.apply(Update::Running(Kind::Plan));
    model.apply(answered(
        Kind::Plan,
        0,
        fixture("discard-plan-decoy-storage"),
    ));
    let page = model.page();
    assert_eq!(page.note, text::nothing_to_discard("/srv/data"));
    assert_eq!(page.secondary, None, "allowed once, for that plan");
    // The next plan carries no flag.
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Discard(DiscardPlanArgs {
            target: "/srv/data".to_string(),
            allow_decoy_storage: false,
        }))))
    );
}

/// A plan of a set up the helper gave, recorded on a volume of its own:
/// seeded from a named hardware configuration, or without the hidden NixOS
/// layout.
fn recorded_init_plan(name: &str) -> Update {
    Update::Planned(PlanData::Init(
        serde_json::from_value(fixture(name)["data"].clone()).unwrap(),
    ))
}

/// Set Up lays out the hidden NixOS system from the file its field names
/// (`--hardware-config`), or leaves it out when its switch is off
/// (`--no-hardware-config`); the question says which, in the plan's words.
/// A path the helper would refuse unread is never sent.
#[test]
fn set_up_lays_out_hidden_nixos_from_the_file_named_or_not_at_all() {
    let mut model = decoy();
    open(&mut model, ToolKind::SetUp);
    let page = model.page();
    assert!(page.switch_first);
    let switch = page.switch.unwrap();
    assert_eq!(
        (switch.title.as_str(), switch.on),
        (text::SWITCH_LAYOUT, true)
    );
    assert_eq!(page.field.unwrap().label, text::FIELD_HARDWARE_CONFIG);
    model.edited("hardware.nix");
    let page = model.page();
    assert!(page.action_locked);
    assert_eq!(page.field.unwrap().hint, text::HARDWARE_CONFIG_NOT_ABSOLUTE);
    assert_eq!(model.action(), None);
    model.edited(" /srv/hardware.nix ");
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Init(InitArgs {
            path: "/mnt/data".to_string(),
            allow_decoy_storage: false,
            hardware_config: Some("/srv/hardware.nix".to_string()),
            no_hardware_config: false,
        }))))
    );
    model.apply(Update::Running(Kind::Plan));
    model.apply(recorded_init_plan("init-plan-hardware"));
    let question = model.page().question.unwrap();
    assert!(
        question
            .body
            .lines()
            .any(|line| line == text::set_up_nixos("/srv/hardware.nix")),
        "{}",
        question.body
    );

    let mut model = decoy();
    open(&mut model, ToolKind::SetUp);
    model.edited("/srv/hardware.nix");
    model.toggled(false);
    let page = model.page();
    assert!(!page.switch.unwrap().on);
    assert_eq!(page.field, None, "nothing to seed what is left out");
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Init(InitArgs {
            path: "/mnt/data".to_string(),
            allow_decoy_storage: false,
            hardware_config: None,
            no_hardware_config: true,
        }))))
    );
    model.apply(Update::Running(Kind::Plan));
    model.apply(recorded_init_plan("init-plan-no-layout"));
    let question = model.page().question.unwrap();
    assert!(
        !question.body.contains("hardware-configuration"),
        "{}",
        question.body
    );
}

#[test]
fn set_up_plans_asks_and_lists_each_part_it_wrote() {
    let mut model = decoy();
    assert_eq!(open(&mut model, ToolKind::SetUp), None);
    let page = model.page();
    assert_eq!(page.heading, text::SET_UP);
    assert_eq!(page.description, text::set_up_what("/mnt/data"));
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Init(InitArgs {
            path: "/mnt/data".to_string(),
            allow_decoy_storage: false,
            hardware_config: None,
            no_hardware_config: false,
        }))))
    );
    model.apply(Update::Running(Kind::Plan));
    assert_eq!(model.page().busy.as_deref(), Some(text::CHECKING_VOLUME));
    model.apply(init_plan(&["NAILS was not tested on this release"]));
    let question = model.page().question.unwrap();
    assert_eq!(question.heading, text::SET_UP_QUESTION);
    assert_eq!(
        question.body.lines().collect::<Vec<_>>(),
        [
            text::set_up_consequence("/mnt/data").as_str(),
            text::set_up_nixos("/etc/nixos/hardware-configuration.nix").as_str(),
            "NAILS was not tested on this release.",
        ]
    );
    assert!(!question.destructive);
    assert_eq!(model.answer(true), Some(Ask::Apply));
    model.apply(Update::Running(Kind::Apply));
    assert_eq!(model.page().busy.as_deref(), Some(text::SETTING_UP));
    model.apply(answered(
        Kind::Apply,
        0,
        json!({"schema_version": 2, "command": "init", "ok": true, "data": {
            "root": "/mnt/data",
            "items": [
                {"path": "/mnt/data/logs", "status": "created"},
                {"path": "/mnt/data/config/nails.toml", "status": "already_present"}],
            "notes": ["host 'debian' has no NixOS config layer (overlay-only); skipping the hidden NixOS layout"],
            "next_steps": ["check readiness"]}}),
    ));
    let page = model.page();
    assert_eq!(page.heading, text::SET_UP_DONE);
    assert_eq!(page.description, text::set_up_done("/mnt/data"));
    assert_eq!(
        titles(&page.groups),
        [text::GROUP_NOTES, text::GROUP_LAYOUT]
    );
    assert_eq!(
        words(&page.groups[1]),
        [text::CREATED_WORD, text::ALREADY_THERE]
    );
    assert_eq!(page.fix, text::SET_UP_NEXT);
    assert_eq!(page.action, None);
    assert_eq!(model.back(), Some(Ask::Status));
    assert_eq!(
        model.apply(status("decoy", Value::Null)).len(),
        1,
        "the check runs again"
    );
}

#[test]
fn a_set_up_the_engine_refused_says_why_and_can_be_asked_again() {
    let mut model = Model::new(Some(PathBuf::from("/mnt/stick/nails")), false);
    model.apply(Update::Connected(crate::client::ours()));
    model.apply(answered(
        Kind::Status,
        0,
        json!({"schema_version": 2, "command": "status", "ok": true, "data": {
            "place": "decoy", "attention": null}}),
    ));
    model.apply(ready());
    open(&mut model, ToolKind::SetUp);
    // Without a hidden volume in the status, the engine's own folder.
    assert_eq!(model.page().description, text::set_up_what("/mnt/stick"));
    model.action();
    model.apply(answered(Kind::Plan, 4, fixture("init-refused")));
    let page = model.page();
    assert_eq!(page.heading, text::SET_UP_FAILED);
    assert!(
        page.note
            .starts_with("/mnt/data is not a volume of its own")
    );
    assert_eq!(page.action, Some(text::SET_UP_ACTION));
    // A plan the tool did not ask for is dropped.
    model.action();
    assert_eq!(
        model.apply(discard_plan("/etc", &[], false)),
        vec![Ask::Withdraw]
    );
}

#[test]
fn a_folder_written_another_way_is_planned_and_asked_for_as_the_engine_reads_it() {
    for (typed, canonical) in [
        ("//home", "/home"),
        ("/./home", "/home"),
        ("/var//home", "/var/home"),
        ("/./var", "/var"),
        ("//root", "/root"),
        ("/home/alice/./notes/", "/home/alice/notes"),
    ] {
        let mut model = decoy();
        open(&mut model, ToolKind::Discard);
        model.edited(typed);
        assert_eq!(
            model.action(),
            Some(Effect::Ask(Ask::Plan(Plan::Discard(DiscardPlanArgs {
                target: canonical.to_string(),
                allow_decoy_storage: false,
            })))),
            "{typed}"
        );
        // The helper names the target the window sent.
        model.apply(discard_plan(canonical, &["/mnt/data/root/upper/x"], false));
        let question = model.page().question.unwrap();
        assert!(question.locked, "{typed}: it holds a home");
        assert_eq!(
            question.prompt.as_deref(),
            Some(text::discard_type(canonical, true).as_str()),
            "{typed}"
        );
        assert_eq!(
            model.answer(true),
            Some(Ask::Withdraw),
            "{typed}: not typed"
        );
    }
    // A plan that names a home in another spelling still asks for it.
    for target in ["//home", "/./var", "/var//home", "//root/"] {
        assert!(holds_a_home(target), "{target}");
    }
    // The engine refuses a `..`, so the window sends none.
    assert_eq!(canonical_folder("/etc/../home"), None);
    assert!(is_the_folder("/home", "//home/"));
}

#[test]
fn discard_and_set_up_fail_closed_where_the_two_readings_disagree() {
    // The window's own reading says hidden session, the status the decoy.
    let mut model =
        Model::new(Some(PathBuf::from("/mnt/data/nails")), false).in_hidden_session(true);
    model.apply(Update::Connected(crate::client::ours()));
    model.apply(status("decoy", Value::Null));
    model.apply(ready());
    let tools: Vec<ToolKind> = model.page().links.iter().map(|link| link.tool).collect();
    assert_eq!(
        tools,
        [ToolKind::Verify, ToolKind::Rehearsal, ToolKind::Settings]
    );

    // A status that turns to a hidden session under an open tool.
    let mut model = decoy();
    open(&mut model, ToolKind::Discard);
    model.edited("/etc/apt");
    model.apply(status("hidden", Value::Null));
    assert_eq!(model.page().action, None);
    assert_eq!(model.tool_action(text::DISCARD_ACTION), None);
    let mut model = decoy();
    open(&mut model, ToolKind::SetUp);
    model.apply(status("hidden", Value::Null));
    assert_eq!(model.page().action, None);
    assert_eq!(model.tool_action(text::SET_UP_ACTION), None);
}

#[test]
fn a_folder_is_typed_as_written_and_a_home_is_known_by_its_place() {
    assert!(is_the_folder("/home", "/home"));
    assert!(is_the_folder("/home", "  /home/ "));
    assert!(!is_the_folder("/home", "/Home"));
    assert!(!is_the_folder("/home", "/home/alice"));
    assert!(!is_the_folder("", ""));
    for home in [
        "/home",
        "/home/alice",
        "/root",
        "/var/home/bob",
        "/var",
        "/home/",
    ] {
        assert!(holds_a_home(home), "{home}");
    }
    for other in ["/etc/apt", "/homework", "/var/lib", "/nix", "/rootfs"] {
        assert!(!holds_a_home(other), "{other}");
    }
    for folder in ["/etc/apt", " /srv/notes "] {
        assert!(valid_folder(folder), "{folder}");
    }
    for folder in ["", "etc", "/", "/etc/\napt", " "] {
        assert!(!valid_folder(folder), "{folder:?}");
    }
}
