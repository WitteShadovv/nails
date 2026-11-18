// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::test_support::{FakeSelinux, UDEVD_CONTEXT};
use crate::whole_root::program_label::PROGRAM_LABEL;

const INIT: &str = "system_u:system_r:init_t:s0";
const SERVICE: &str = "system_u:system_r:unconfined_service_t:s0";
const VAR_RUN: &str = "system_u:object_r:var_run_t:s0";
const UDEV_RUN: &str = "system_u:object_r:udev_var_run_t:s0";

/// The `access` questions `selinux` was asked, as (source, target, class).
fn access_questions(selinux: &FakeSelinux) -> Vec<(String, String, String)> {
    selinux
        .questions()
        .iter()
        .filter_map(|question| {
            let mut words = question.strip_prefix("access ")?.split(' ');
            Some((
                words.next()?.to_string(),
                words.next()?.to_string(),
                words.next()?.to_string(),
            ))
        })
        .collect()
}

/// Where no policy is loaded the guard's start is given no domain, and
/// nothing else is asked.
#[test]
fn without_a_policy_nothing_is_asked_about_the_guard() {
    let selinux = FakeSelinux::without_policy();
    assert_eq!(check_guard(&selinux, PROGRAM_LABEL), Ok(None));
    assert_eq!(selinux.questions(), ["pid1"]);
}

/// Under a targeted policy that grants udevd's domain everything the guard
/// does, the guard runs in udevd's own context, and every question is about
/// that context: the rule and its directory, the copy, `/run`, the runtime
/// directory and the plan and record in it, the three labels of a disk's
/// node, the capability, sysfs, `/dev` and its own entry in `/proc`.
#[test]
fn the_guard_runs_in_udevd_s_domain_where_the_policy_grants_it_everything() {
    let selinux = FakeSelinux::targeted();
    assert_eq!(
        check_guard(&selinux, PROGRAM_LABEL),
        Ok(Some(UDEVD_CONTEXT.to_string()))
    );
    let questions = selinux.questions();
    for asked in [
        "pid1".to_string(),
        "udevd".to_string(),
        format!("create {UDEVD_CONTEXT} {PROGRAM_LABEL}"),
        "current".to_string(),
        format!("create {INIT} {PROGRAM_LABEL}"),
        "label /run".to_string(),
        format!("new {SERVICE} {VAR_RUN} dir overlay-runtime"),
        format!("new {SERVICE} {VAR_RUN} file -"),
        format!("new {SERVICE} {VAR_RUN} file read-only-devices"),
        format!("new {UDEVD_CONTEXT} {VAR_RUN} file read-only-devices"),
        "label /run/udev/rules.d".to_string(),
        "label /run/udev".to_string(),
        format!("new {SERVICE} {UDEV_RUN} dir rules.d"),
        format!("new {SERVICE} {UDEV_RUN} file -"),
    ] {
        assert!(questions.contains(&asked), "{asked}: {questions:?}");
    }
    let access = access_questions(&selinux);
    assert!(
        access.iter().all(|(source, _, _)| source == UDEVD_CONTEXT),
        "{access:?}"
    );
    let asked: Vec<(&str, &str)> = access
        .iter()
        .map(|(_, target, class)| (target.as_str(), class.as_str()))
        .collect();
    for expected in [
        (UDEV_RUN, "dir"),
        (UDEV_RUN, "file"),
        (PROGRAM_LABEL, "file"),
        (VAR_RUN, "dir"),
        (VAR_RUN, "file"),
        ("system_u:object_r:fixed_disk_device_t:s0", "blk_file"),
        ("system_u:object_r:removable_device_t:s0", "blk_file"),
        ("system_u:object_r:device_t:s0", "blk_file"),
        (UDEVD_CONTEXT, "capability"),
        ("system_u:object_r:sysfs_t:s0", "dir"),
        ("system_u:object_r:sysfs_t:s0", "file"),
        ("system_u:object_r:sysfs_t:s0", "lnk_file"),
        ("system_u:object_r:device_t:s0", "dir"),
        ("system_u:object_r:device_t:s0", "lnk_file"),
        ("system_u:object_r:proc_t:s0", "dir"),
        ("system_u:object_r:proc_t:s0", "lnk_file"),
        (UDEVD_CONTEXT, "dir"),
        (UDEVD_CONTEXT, "file"),
    ] {
        assert!(asked.contains(&expected), "{expected:?}: {asked:?}");
    }
    // Each question once: the two plans and the record share a label here,
    // and the record is asked to append and to create apart.
    let files = asked.iter().filter(|&&q| q == (VAR_RUN, "file")).count();
    assert_eq!(files, 3, "{asked:?}");
}

/// Each permission the guard needs fails the check where the policy denies
/// it, naming the domain, the label, the class, the permission and what the
/// guard needs it for.
#[test]
fn every_permission_the_guard_needs_fails_it_where_denied() {
    for (kind, class, perm, need, target) in [
        ("udev_var_run_t", "dir", "read", Need::Rule, UDEV_RUN),
        ("udev_var_run_t", "file", "open", Need::Rule, UDEV_RUN),
        (
            "bin_t",
            "file",
            "execute_no_trans",
            Need::Start,
            PROGRAM_LABEL,
        ),
        ("bin_t", "file", "map", Need::Start, PROGRAM_LABEL),
        ("var_run_t", "dir", "search", Need::Run, VAR_RUN),
        ("var_run_t", "dir", "add_name", Need::Runtime, VAR_RUN),
        ("var_run_t", "file", "read", Need::Plan, VAR_RUN),
        ("var_run_t", "file", "append", Need::Record, VAR_RUN),
        ("var_run_t", "file", "create", Need::CreateRecord, VAR_RUN),
        (
            "fixed_disk_device_t",
            "blk_file",
            "ioctl",
            Need::Disk,
            "system_u:object_r:fixed_disk_device_t:s0",
        ),
        (
            "removable_device_t",
            "blk_file",
            "open",
            Need::Disk,
            "system_u:object_r:removable_device_t:s0",
        ),
        (
            "device_t",
            "blk_file",
            "read",
            Need::Disk,
            "system_u:object_r:device_t:s0",
        ),
        (
            "udev_t",
            "capability",
            "sys_admin",
            Need::Disk,
            UDEVD_CONTEXT,
        ),
        (
            "sysfs_t",
            "lnk_file",
            "read",
            Need::Sysfs,
            "system_u:object_r:sysfs_t:s0",
        ),
        (
            "device_t",
            "lnk_file",
            "read",
            Need::Devices,
            "system_u:object_r:device_t:s0",
        ),
        (
            "proc_t",
            "lnk_file",
            "read",
            Need::Mounts,
            "system_u:object_r:proc_t:s0",
        ),
        ("udev_t", "file", "read", Need::Mounts, UDEVD_CONTEXT),
    ] {
        let selinux = FakeSelinux {
            denied_on: vec![(kind, class, perm)],
            ..FakeSelinux::targeted()
        };
        assert_eq!(
            check_guard(&selinux, PROGRAM_LABEL),
            Err(GuardUnfit::Denied {
                domain: UDEVD_CONTEXT.to_string(),
                target: target.to_string(),
                class,
                perms: vec![perm],
                need,
            }),
            "{kind} {class} {perm}"
        );
    }
}

/// The labels of the runtime files are the ones the policy's rules give what
/// makes them: a record the guard creates under its own label is asked
/// about under that label, and the plan the steps write under theirs.
#[test]
fn the_runtime_files_are_asked_about_under_the_labels_their_makers_give_them() {
    let udev_run = "system_u:object_r:udev_var_run_t:s0";
    let init_run = "system_u:object_r:init_var_run_t:s0";
    let selinux = FakeSelinux {
        created_by: vec![("udev_t", udev_run.to_string())],
        ..FakeSelinux::targeted()
    };
    assert!(check_guard(&selinux, PROGRAM_LABEL).is_ok());
    let access = access_questions(&selinux);
    assert!(
        access
            .iter()
            .any(|(_, target, class)| target == udev_run && class == "file"),
        "{access:?}"
    );
    let selinux = FakeSelinux {
        created_by: vec![("udev_t", udev_run.to_string())],
        denied_on: vec![("udev_var_run_t", "file", "create")],
        ..FakeSelinux::targeted()
    };
    assert_eq!(
        check_guard(&selinux, PROGRAM_LABEL),
        Err(GuardUnfit::Denied {
            domain: UDEVD_CONTEXT.to_string(),
            target: udev_run.to_string(),
            class: "file",
            perms: vec!["create"],
            need: Need::CreateRecord,
        })
    );
    // Steps that PID 1 starts in its own domain write the rule, the plan and
    // the record under the label that domain's rules give: the rule is the
    // first the guard needs to read, and the record the one it adds to.
    for (perm, need) in [("read", Need::Rule), ("append", Need::Record)] {
        let selinux = FakeSelinux {
            entered: INIT.to_string(),
            created_by: vec![("init_t", init_run.to_string())],
            denied_on: vec![("init_var_run_t", "file", perm)],
            ..FakeSelinux::targeted()
        };
        assert_eq!(
            check_guard(&selinux, PROGRAM_LABEL),
            Err(GuardUnfit::Denied {
                domain: UDEVD_CONTEXT.to_string(),
                target: init_run.to_string(),
                class: "file",
                perms: vec![perm],
                need,
            }),
            "{perm}"
        );
        let access = access_questions(&selinux);
        assert!(
            access
                .iter()
                .any(|(_, target, class)| target == init_run && class == "file"),
            "{access:?}"
        );
    }
}

/// A rule directory that is there already is asked about under its own
/// label, and the rule written into it under the label it gives.
#[test]
fn a_rule_directory_that_is_there_is_asked_about_under_its_label() {
    let rules = "system_u:object_r:udev_rules_t:s0";
    let mut selinux = FakeSelinux {
        denied_on: vec![("udev_rules_t", "file", "read")],
        ..FakeSelinux::targeted()
    };
    selinux.path_labels.push((
        std::path::PathBuf::from("/run/udev/rules.d"),
        rules.to_string(),
    ));
    assert_eq!(
        check_guard(&selinux, PROGRAM_LABEL),
        Err(GuardUnfit::Denied {
            domain: UDEVD_CONTEXT.to_string(),
            target: rules.to_string(),
            class: "file",
            perms: vec!["read"],
            need: Need::Rule,
        })
    );
    let questions = selinux.questions();
    assert!(
        !questions.iter().any(|q| q.ends_with(" dir rules.d")),
        "{questions:?}"
    );
    assert!(
        !questions.contains(&"label /run/udev".to_string()),
        "{questions:?}"
    );
}

/// No udevd running, and a policy that starts the copy from udevd in another
/// domain, fail the check: the guard is judged only in udevd's own domain.
#[test]
fn the_guard_must_run_in_the_domain_of_a_running_udevd() {
    let selinux = FakeSelinux {
        udevd: None,
        ..FakeSelinux::targeted()
    };
    assert_eq!(
        check_guard(&selinux, PROGRAM_LABEL),
        Err(GuardUnfit::NoUdevd)
    );
    let selinux = FakeSelinux {
        entered_from: vec![("udev_t", SERVICE.to_string())],
        ..FakeSelinux::targeted()
    };
    assert_eq!(
        check_guard(&selinux, PROGRAM_LABEL),
        Err(GuardUnfit::Elsewhere {
            udevd: UDEVD_CONTEXT.to_string(),
            entered: SERVICE.to_string(),
        })
    );
    let selinux = FakeSelinux {
        udevd: Some("kernel".to_string()),
        entered_from: Vec::new(),
        ..FakeSelinux::targeted()
    };
    assert!(
        matches!(
            check_guard(&selinux, PROGRAM_LABEL),
            Err(GuardUnfit::Unjudged(ref why)) if why.contains("no SELinux context with a type")
        ),
        "{:?}",
        check_guard(&selinux, PROGRAM_LABEL)
    );
}

/// A question that cannot be asked leaves the guard unjudged, which fails
/// the check: PID 1's context, udevd's, this process's, the label of `/run`
/// and the policy itself.
#[test]
fn a_question_that_fails_leaves_the_guard_unjudged() {
    let unjudged = |selinux: FakeSelinux, starts: &str| {
        let result = check_guard(&selinux, PROGRAM_LABEL);
        assert!(
            matches!(&result, Err(GuardUnfit::Unjudged(why)) if why.starts_with(starts)),
            "{starts}: {result:?}"
        );
    };
    unjudged(
        FakeSelinux {
            pid1_error: Some(libc::EACCES),
            ..FakeSelinux::targeted()
        },
        "PID 1's context cannot be read: ",
    );
    unjudged(
        FakeSelinux {
            udevd_error: Some(libc::EACCES),
            ..FakeSelinux::targeted()
        },
        "the context of systemd-udevd cannot be read: ",
    );
    unjudged(
        FakeSelinux {
            current_error: Some(libc::EACCES),
            ..FakeSelinux::targeted()
        },
        "the context of this process cannot be read: ",
    );
    unjudged(
        FakeSelinux {
            path_labels: Vec::new(),
            ..FakeSelinux::targeted()
        },
        "the label of /run cannot be read: ",
    );
    unjudged(
        FakeSelinux {
            path_labels: vec![(std::path::PathBuf::from("/run"), VAR_RUN.to_string())],
            ..FakeSelinux::targeted()
        },
        "the label of /run/udev cannot be read: ",
    );
    unjudged(
        FakeSelinux {
            policy_error: Some(libc::ENOENT),
            ..FakeSelinux::targeted()
        },
        "the policy cannot be asked: ",
    );
}

/// What each refusal says, to follow "The disk guard udev starts for NAILS".
#[test]
fn each_refusal_says_what_keeps_the_guard_from_its_work() {
    assert_eq!(
        GuardUnfit::NoUdevd.to_string(),
        "runs in the domain of systemd-udevd, which starts it, but no systemd-udevd runs here \
         to show that domain"
    );
    assert_eq!(
        GuardUnfit::Elsewhere {
            udevd: UDEVD_CONTEXT.to_string(),
            entered: SERVICE.to_string(),
        }
        .to_string(),
        "would run in system_u:system_r:unconfined_service_t:s0: the loaded SELinux policy gives \
         udevd's (system_u:system_r:udev_t:s0-s0:c0.c1023) start of the RAM copy of the binary \
         that context, not udevd's own domain, the one domain NAILS judges the guard in"
    );
    assert_eq!(
        GuardUnfit::Denied {
            domain: UDEVD_CONTEXT.to_string(),
            target: "system_u:object_r:fixed_disk_device_t:s0".to_string(),
            class: "blk_file",
            perms: vec!["open", "ioctl"],
            need: Need::Disk,
        }
        .to_string(),
        "runs in system_u:system_r:udev_t:s0-s0:c0.c1023, and the loaded SELinux policy denies \
         that domain the blk_file permission open or ioctl on \
         system_u:object_r:fixed_disk_device_t:s0, which the guard needs to set a disk read-only"
    );
    assert_eq!(
        GuardUnfit::Unjudged("the policy cannot be asked: x".to_string()).to_string(),
        "cannot be judged against the loaded SELinux policy: the policy cannot be asked: x"
    );
    for (need, text) in [
        (
            Need::Rule,
            "to be started from the rule NAILS installs in /run/udev/rules.d",
        ),
        (Need::Start, "to start from the RAM copy of the binary"),
        (
            Need::Run,
            "on the way to the RAM copy and its files in /run",
        ),
        (
            Need::Runtime,
            "to reach the runtime directory and add the record of the disks it sets read-only \
             there",
        ),
        (Need::Plan, "to read the session plan"),
        (
            Need::Record,
            "to add to the record of the disks it sets read-only",
        ),
        (
            Need::CreateRecord,
            "to create the record of the disks it sets read-only",
        ),
        (Need::Disk, "to set a disk read-only"),
        (
            Need::Sysfs,
            "to tell from sysfs which disks the session uses",
        ),
        (Need::Devices, "to look the disks up in /dev"),
        (Need::Mounts, "to read its own mount table in /proc"),
    ] {
        assert_eq!(need.to_string(), text);
    }
}
