// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::test_support::write_executable;
use std::path::PathBuf;

/// A stand-in logind and PID 1, kept in files below one directory:
///
/// - `preparing` (`true`/`false`): whether logind holds a shutdown;
/// - `kind`: the kind it names in the shutdown's metadata;
/// - `job`: present while PID 1 holds the soft-reboot job; `stop-job`: PID 1
///   holds a job that stops the soft-reboot target;
/// - `fires-after`: logind starts the job once PID 1 has been asked this many
///   times while it holds the request;
/// - `v255`: logind cannot drop a request it holds back, and names its kind
///   nowhere but in its scheduled shutdown; `v256`: the same, but that
///   scheduled shutdown calls a soft-reboot `reboot`, as systemd 256 does;
/// - `no-logind`: logind does not answer; `gone-after-cancel`: it stops
///   answering once asked to drop what it holds; `no-delay`: it does not say
///   how long it holds a shutdown back;
/// - `logind-state`: the `ActiveState` PID 1 gives for logind's unit;
/// - `start-refused`: PID 1 refuses a job enqueued directly;
/// - `inhibitors`: the `ListInhibitors` reply;
/// - `on-soft-reboot`: what `systemctl soft-reboot` does, shell code;
/// - `calls`: every `systemctl` call, one per line.
struct Fake {
    dir: tempfile::TempDir,
    systemctl: PathBuf,
    busctl: PathBuf,
}

impl Fake {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().display().to_string();
        let systemctl = dir.path().join("systemctl");
        write_executable(
            &systemctl,
            format!(
                "#!/bin/sh\nd={d}\necho \"$*\" >> $d/calls\n\
                 case \"$*\" in\n\
                 '--no-wall soft-reboot') . $d/on-soft-reboot ;;\n\
                 list-jobs*)\n\
                 n=$(cat $d/polls 2>/dev/null || echo 0); echo $((n + 1)) > $d/polls\n\
                 if [ -e $d/fires-after ] && [ \"$(cat $d/preparing)\" = true ] \
                 && [ \"$n\" -ge \"$(cat $d/fires-after)\" ]; then touch $d/job; fi\n\
                 [ -e $d/job ] && echo '7 soft-reboot.target start waiting'\n\
                 [ -e $d/stop-job ] && echo '9 soft-reboot.target stop waiting'\n\
                 exit 0 ;;\n\
                 'show --property=ActiveState --value systemd-logind.service') \
                 cat $d/logind-state ;;\n\
                 start*) [ -e $d/start-refused ] && exit 1; touch $d/job; exit 0 ;;\n\
                 esac\nexit 0\n"
            ),
            0o755,
        );
        let busctl = dir.path().join("busctl");
        write_executable(
            &busctl,
            format!(
                "#!/bin/sh\nd={d}\n[ -e $d/no-logind ] && exit 1\n\
                 case \"$*\" in\n\
                 *ListInhibitors*) cat $d/inhibitors ;;\n\
                 *PreparingForShutdownWithMetadata*) \
                 [ -e $d/v255 ] || [ -e $d/v256 ] && exit 1\n\
                 printf '{{\"type\":\"a{{sv}}\",\"data\":{{\"preparing\":{{\"type\":\"b\",\
                 \"data\":%s}},\"type\":{{\"type\":\"s\",\"data\":\"%s\"}}}}}}\\n' \
                 \"$(cat $d/preparing)\" \"$(cat $d/kind)\" ;;\n\
                 *PreparingForShutdown*) printf '{{\"type\":\"b\",\"data\":%s}}\\n' \
                 \"$(cat $d/preparing)\" ;;\n\
                 *InhibitDelayMaxUSec*) [ -e $d/no-delay ] && exit 1\n\
                 echo '{{\"type\":\"t\",\"data\":100000}}' ;;\n\
                 *CancelScheduledShutdown*) \
                 [ -e $d/v255 ] || [ -e $d/v256 ] || echo false > $d/preparing\n\
                 [ -e $d/gone-after-cancel ] && touch $d/no-logind\n\
                 echo '{{\"type\":\"b\",\"data\":[true]}}' ;;\n\
                 *ScheduledShutdown*) k=$(cat $d/kind); [ -e $d/v256 ] && k=reboot\n\
                 printf '{{\"type\":\"(st)\",\"data\":[\"%s\",0]}}\\n' \"$k\" ;;\n\
                 *) exit 1 ;;\n\
                 esac\n"
            ),
            0o755,
        );
        let fake = Fake {
            dir,
            systemctl,
            busctl,
        };
        fake.put("preparing", "false");
        fake.put("kind", "soft-reboot");
        fake.put("logind-state", "active");
        fake.put("inhibitors", r#"{"type":"a(ssssuu)","data":[[]]}"#);
        fake.put("on-soft-reboot", "exit 0");
        fake
    }

    fn put(&self, name: &str, text: &str) {
        std::fs::write(self.dir.path().join(name), format!("{text}\n")).unwrap();
    }

    /// The calls that act: those that only ask (`list-jobs`, `show`) are left
    /// out.
    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.path().join("calls"))
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.starts_with("list-jobs") && !line.starts_with("show "))
            .map(str::to_string)
            .collect()
    }

    fn request(&self, wanted: &mut dyn FnMut() -> Wanted) -> Request {
        request_soft_reboot(&self.systemctl, Some(&self.busctl), WAITS, wanted)
    }

    fn drop_it(&self) -> Pending {
        drop_soft_reboot(Some(&self.systemctl), Some(&self.busctl))
    }

    /// logind takes the request and holds it back for a delay inhibitor.
    fn held_back(&self) {
        let d = self.dir.path().display();
        self.put(
            "on-soft-reboot",
            &format!("echo true > {d}/preparing; exit 0"),
        );
    }
}

const WAITS: Waits = Waits {
    poll: Duration::from_millis(10),
    margin: Duration::from_millis(300),
    cap: Duration::from_secs(1),
};

const ASKED: &str = "--no-wall soft-reboot";
const DIRECT: &str = "start --no-block --job-mode=replace-irreversibly -- soft-reboot.target";

fn go() -> Wanted {
    Wanted::Yes
}

#[test]
fn a_soft_reboot_logind_starts_at_once_is_queued_without_a_direct_job() {
    let fake = Fake::new();
    let d = fake.dir.path().display();
    fake.put("on-soft-reboot", &format!("touch {d}/job; exit 0"));
    assert_eq!(fake.request(&mut go), Request::Queued);
    assert_eq!(fake.calls(), [ASKED]);
}

/// While logind holds the request back the switch waits; it ends once PID 1
/// holds the job, and nothing is enqueued next to it.
#[test]
fn a_soft_reboot_logind_holds_back_is_waited_for_until_pid_1_holds_the_job() {
    let fake = Fake::new();
    fake.held_back();
    fake.put("fires-after", "5");
    assert_eq!(fake.request(&mut go), Request::Queued);
    assert_eq!(fake.calls(), [ASKED]);
}

/// Only a job that starts the soft-reboot is one: a job that stops its target
/// is no switch.
#[test]
fn a_job_that_stops_the_soft_reboot_target_is_no_switch() {
    let fake = Fake::new();
    fake.put("stop-job", "");
    assert_eq!(pid1_holds_soft_reboot(&fake.systemctl), Some(false));
    fake.put("job", "");
    assert_eq!(pid1_holds_soft_reboot(&fake.systemctl), Some(true));
}

/// Cancelled while logind held it (or refused by PID 1 when the delay ended):
/// nothing is queued, so the switch reports a refusal and enqueues nothing.
#[test]
fn a_soft_reboot_logind_drops_is_a_refusal_with_nothing_enqueued() {
    let fake = Fake::new();
    fake.held_back();
    let mut looks = 0;
    let dir = fake.dir.path().to_path_buf();
    let mut cancel_on_the_third_look = || {
        looks += 1;
        if looks == 3 {
            std::fs::write(dir.join("preparing"), "false\n").unwrap();
        }
        Wanted::Yes
    };
    let result = fake.request(&mut cancel_on_the_third_look);
    assert!(
        matches!(&result, Request::Refused(why) if why.contains("dropped")),
        "{result:?}"
    );
    assert_eq!(fake.calls(), [ASKED]);
}

/// logind's refusal (a block inhibitor, a shutdown or sleep it already holds)
/// is the refusal, with logind's reason; nothing is enqueued.
#[test]
fn a_soft_reboot_logind_refuses_is_refused_with_its_reason() {
    let fake = Fake::new();
    fake.put(
        "on-soft-reboot",
        "echo 'Operation denied due to active block inhibitor' >&2; exit 1",
    );
    assert_eq!(
        fake.request(&mut go),
        Request::Refused("Operation denied due to active block inhibitor".to_string())
    );
    assert_eq!(fake.calls(), [ASKED]);
}

const INHIBITORS: &str = r#"{"type":"a(ssssuu)","data":[[["shutdown:sleep","Unattended Upgrades Shutdown","Stop ongoing upgrades","delay",0,612],["sleep","GNOME","Lock the screen","block",1000,1777],["shutdown","Backup","A backup is running","block-weak",0,900],["sleep:shutdown","fwupd","Firmware update in progress","block",0,977]]]}"#;

/// A program that blocks shutdown is in the middle of something: the switch is
/// refused, naming it, before logind is asked. A weak block and a delay do
/// not refuse it.
#[test]
fn a_program_that_blocks_shutdown_refuses_the_soft_reboot_before_logind_is_asked() {
    let fake = Fake::new();
    fake.put("inhibitors", INHIBITORS);
    assert_eq!(
        fake.request(&mut go),
        Request::Refused("fwupd blocks shutdown (Firmware update in progress, PID 977)".into())
    );
    assert!(fake.calls().is_empty(), "{:?}", fake.calls());
}

/// What blocks shutdown: the program logind names, nothing where it names
/// none or does not run, and an unknown where it does not answer and PID 1
/// does not say that it does not run.
#[test]
fn what_blocks_shutdown_is_unknown_unless_logind_answers_or_does_not_run() {
    let fake = Fake::new();
    let ask = || blocking(Some(&fake.busctl), Some(&fake.systemctl));
    assert_eq!(ask(), Blocking::Nothing);
    assert_eq!(ask().refusal(), None);
    fake.put("inhibitors", INHIBITORS);
    assert!(matches!(ask(), Blocking::By(b) if b.who == "fwupd"));
    fake.put("no-logind", "");
    assert_eq!(ask(), Blocking::Unknown);
    assert_eq!(
        ask().refusal().as_deref(),
        Some("logind did not answer whether a program blocks shutdown")
    );
    fake.put("logind-state", "inactive");
    assert_eq!(ask(), Blocking::Nothing);
    fake.put("logind-state", "failed");
    assert_eq!(ask(), Blocking::Nothing);
    // Without PID 1's word, or without busctl, it stays unknown.
    assert_eq!(blocking(Some(&fake.busctl), None), Blocking::Unknown);
    fake.put("logind-state", "active");
    assert_eq!(blocking(None, Some(&fake.systemctl)), Blocking::Unknown);
}

/// Held past logind's own delay: logind is asked to drop it. Where it does
/// (systemd 257 and newer), nothing is queued; where it keeps it (256 and
/// older), the soft-reboot is enqueued directly, as logind would do it, so
/// nothing is left to come later.
#[test]
fn a_soft_reboot_held_past_the_delay_is_dropped_or_enqueued_directly() {
    let fake = Fake::new();
    fake.held_back();
    let result = fake.request(&mut go);
    assert!(
        matches!(&result, Request::Refused(why) if why.contains("nothing is queued")),
        "{result:?}"
    );
    assert_eq!(fake.calls(), [ASKED]);

    for release in ["v255", "v256"] {
        let fake = Fake::new();
        fake.put(release, "");
        fake.held_back();
        let start = Instant::now();
        assert_eq!(fake.request(&mut go), Request::Queued, "{release}");
        assert!(start.elapsed() < Duration::from_secs(3));
        assert_eq!(fake.calls(), [ASKED, DIRECT], "{release}");
    }
}

/// Where logind does not say how long it holds a shutdown back, the switch
/// waits the longest it would, not just the margin.
#[test]
fn a_wait_logind_does_not_bound_lasts_the_cap() {
    let fake = Fake::new();
    fake.put("v255", "");
    fake.put("no-delay", "");
    fake.held_back();
    let start = Instant::now();
    assert_eq!(fake.request(&mut go), Request::Queued);
    assert!(start.elapsed() >= WAITS.cap, "{:?}", start.elapsed());
    assert_eq!(fake.calls(), [ASKED, DIRECT]);
}

/// A direct job PID 1 refuses leaves nothing queued only where logind holds
/// nothing either: while logind still holds the soft-reboot, it is held.
#[test]
fn a_direct_job_pid_1_refuses_is_held_while_logind_holds_the_soft_reboot() {
    let fake = Fake::new();
    fake.put("v255", "");
    fake.put("start-refused", "");
    fake.held_back();
    let result = fake.request(&mut go);
    assert!(
        matches!(&result, Request::Held(why) if why.starts_with("PID 1 refused")),
        "{result:?}"
    );

    let fake = Fake::new();
    fake.put("start-refused", "");
    fake.put("on-soft-reboot", "kill -KILL $$");
    assert_eq!(
        fake.request(&mut go),
        Request::Refused("PID 1 refused the soft-reboot; nothing is queued".into())
    );
}

/// Without logind, `systemctl` enqueues the soft-reboot with PID 1 itself.
/// A call cut short while logind holds nothing is enqueued directly.
#[test]
fn without_logind_or_after_a_call_cut_short_the_job_is_made_sure_of() {
    let fake = Fake::new();
    let d = fake.dir.path().display();
    fake.put("no-logind", "");
    fake.put("on-soft-reboot", &format!("touch {d}/job; exit 0"));
    assert_eq!(fake.request(&mut go), Request::Queued);
    assert_eq!(fake.calls(), [ASKED]);

    let fake = Fake::new();
    fake.put("on-soft-reboot", "kill -KILL $$");
    assert_eq!(fake.request(&mut go), Request::Queued);
    assert_eq!(fake.calls(), [ASKED, DIRECT]);
}

/// Called off while logind holds it (its plan was taken down): logind is asked
/// to drop it and nothing is enqueued, even where logind keeps it.
#[test]
fn a_switch_called_off_drops_the_request_and_never_enqueues() {
    let fake = Fake::new();
    fake.held_back();
    let mut off = || Wanted::No("its plan was taken down".to_string());
    assert!(matches!(fake.request(&mut off), Request::Refused(_)));
    assert_eq!(fake.calls(), [ASKED]);

    let fake = Fake::new();
    fake.put("v256", "");
    fake.held_back();
    let result = fake.request(&mut off);
    assert!(
        matches!(&result, Request::Held(why) if why.starts_with("its plan was taken down")),
        "{result:?}"
    );
    assert_eq!(fake.calls(), [ASKED]);
}

/// The drop cancels a soft-reboot logind holds where it can (systemd 257 and
/// newer) and leaves a shutdown it names as another kind alone. Before 257
/// logind names no kind it can be trusted with (256 calls a soft-reboot
/// `reboot`) and cannot drop it, so any shutdown it holds is held.
#[test]
fn dropping_a_held_soft_reboot_cancels_it_where_logind_can() {
    let held = |release: Option<&str>, kind: &str| {
        let fake = Fake::new();
        fake.put("preparing", "true");
        fake.put("kind", kind);
        if let Some(release) = release {
            fake.put(release, "");
        }
        let pending = fake.drop_it();
        let preparing = std::fs::read_to_string(fake.dir.path().join("preparing")).unwrap();
        (pending, preparing.trim().to_string())
    };
    assert_eq!(
        held(None, "soft-reboot"),
        (Pending::Nothing, "false".into())
    );
    // A kind left empty counts as the entry's.
    assert_eq!(held(None, ""), (Pending::Nothing, "false".into()));
    // A reboot or power-off someone asked for is left alone.
    assert_eq!(held(None, "reboot"), (Pending::Nothing, "true".into()));
    assert_eq!(
        held(Some("v255"), "soft-reboot"),
        (Pending::Held, "true".into())
    );
    assert_eq!(
        held(Some("v255"), "poweroff"),
        (Pending::Held, "true".into())
    );
    assert_eq!(
        held(Some("v256"), "soft-reboot"),
        (Pending::Held, "true".into())
    );

    let fake = Fake::new();
    fake.put("job", "");
    assert_eq!(fake.drop_it(), Pending::Started);
    // A job that stops the soft-reboot target is none.
    let fake = Fake::new();
    fake.put("stop-job", "");
    assert_eq!(fake.drop_it(), Pending::Nothing);
}

/// A logind that does not answer may hold the soft-reboot: only PID 1's word
/// that it does not run means nothing is held.
#[test]
fn a_logind_that_does_not_answer_holds_the_soft_reboot_unless_it_does_not_run() {
    let fake = Fake::new();
    fake.put("preparing", "true");
    fake.put("no-logind", "");
    assert_eq!(fake.drop_it(), Pending::Held);
    assert_eq!(drop_soft_reboot(None, Some(&fake.busctl)), Pending::Held);
    assert_eq!(drop_soft_reboot(Some(&fake.systemctl), None), Pending::Held);
    fake.put("logind-state", "inactive");
    assert_eq!(fake.drop_it(), Pending::Nothing);
    assert_eq!(
        drop_soft_reboot(Some(&fake.systemctl), None),
        Pending::Nothing
    );

    // One that stops answering once asked to drop it may still hold it.
    let fake = Fake::new();
    fake.put("preparing", "true");
    fake.put("gone-after-cancel", "");
    assert_eq!(fake.drop_it(), Pending::Held);
}

#[test]
fn the_logind_replies_are_read_from_busctl_json() {
    let fake = Fake::new();
    fake.put("preparing", "true");
    assert_eq!(preparing_for_shutdown(&fake.busctl), Some(true));
    assert_eq!(delay_max(&fake.busctl), Some(Duration::from_millis(100)));
    assert_eq!(shutdown_kind(&fake.busctl).as_deref(), Some("soft-reboot"));
    fake.put("v255", "");
    assert_eq!(shutdown_kind(&fake.busctl), None);
    assert_eq!(runs(&fake.systemctl), Some(true));
    fake.put("logind-state", "");
    assert_eq!(runs(&fake.systemctl), None);
    fake.put("no-logind", "");
    assert_eq!(preparing_for_shutdown(&fake.busctl), None);
    assert_eq!(inhibitors(&fake.busctl), None);

    assert_eq!(
        parse_inhibitors(&serde_json::json!([[[
            "shutdown", "who", "why", "delay", 0, 42
        ]]])),
        Some(vec![Inhibitor {
            what: "shutdown".into(),
            who: "who".into(),
            why: "why".into(),
            mode: "delay".into(),
            pid: 42,
        }])
    );
    assert_eq!(parse_inhibitors(&serde_json::json!([[]])), Some(Vec::new()));
    assert_eq!(parse_inhibitors(&serde_json::json!([[["shutdown"]]])), None);
}
