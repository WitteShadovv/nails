// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::session::guards::GuardHost;
use nails_base::test_support::write_executable;
use nails_platform::platform::FakePlatform;
use nails_platform::{SelinuxMode, SelinuxStatus, Selinuxfs};
use nails_teardown::test_support::{BIN_T, FakeSelinux, INIT_T};
use nails_teardown::whole_root::selinux::Selinux;
use std::path::PathBuf;

/// A detected FHS host with these SELinux facts.
fn host_with(selinuxfs: Selinuxfs, enforce: Option<SelinuxMode>) -> HostProfile {
    let mut profile = FakePlatform::fhs().host_profile();
    profile.selinux = Some(SelinuxStatus {
        selinuxfs,
        enforce,
        config_mode: Some("enforcing".to_string()),
        config_policy: Some("targeted".to_string()),
    });
    profile
}

/// The security modules a stock Debian kernel lists, without SELinux.
const DEBIAN_LSMS: [&str; 7] = [
    "lockdown",
    "capability",
    "landlock",
    "yama",
    "apparmor",
    "tomoyo",
    "bpf",
];
/// The security modules Fedora's kernel lists, SELinux among them.
const FEDORA_LSMS: [&str; 6] = [
    "lockdown",
    "capability",
    "landlock",
    "yama",
    "selinux",
    "bpf",
];

/// `profile` with the kernel's list of security modules `lsms`.
fn listing(mut profile: HostProfile, lsms: &[&str]) -> HostProfile {
    profile.lsms = lsms.iter().map(|lsm| lsm.to_string()).collect();
    profile
}

/// Where SELinux runs.
const RUNNING: ExecPrefix = ExecPrefix::Trampoline(Why::Labels(Reason::SelinuxRunning));

/// A kernel without SELinux: the file alone decides.
const OFF: FakeSelinux = FakeSelinux {
    pid1: None,
    labels: Vec::new(),
    starts: Vec::new(),
    denials: Vec::new(),
    unanswered: None,
};

/// A root whose `/usr/bin/env` is an executable file.
fn root_with_env() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("usr/bin")).unwrap();
    write_executable(&root.path().join("usr/bin/env"), "", 0o755);
    root
}

/// A PID 1 that answers for the switch's unit as given: `NoNewPrivileges`
/// (or the error of a PID 1 that cannot be asked) and `SELinuxContext`, on a
/// kernel whose SELinux answers as `selinux` does.
struct Pid1 {
    no_new_privileges: std::result::Result<&'static str, &'static str>,
    selinux_context: &'static str,
    selinux: FakeSelinux,
}

/// The PID 1 of a stock host: neither setting, and a kernel without SELinux.
const STOCK: Pid1 = Pid1 {
    no_new_privileges: Ok("no"),
    selinux_context: "",
    selinux: OFF,
};

/// The PID 1 of a stock host whose kernel answers as `selinux` does.
fn stock_under(selinux: FakeSelinux) -> Pid1 {
    Pid1 { selinux, ..STOCK }
}

impl GuardHost for Pid1 {
    fn unit_stop_commands(&self, _: &str) -> Result<String> {
        unreachable!("not a guard test")
    }
    fn job_timeout_action(&self, _: &str) -> Result<String> {
        unreachable!("not a guard test")
    }
    fn job_timeout(&self, _: &str) -> Result<String> {
        unreachable!("not a guard test")
    }
    fn service_watchdogs(&self) -> Result<String> {
        unreachable!("not a guard test")
    }
    fn no_new_privileges(&self, unit: &str) -> Result<String> {
        assert_eq!(unit, SWITCH_UNIT);
        self.no_new_privileges
            .map(str::to_string)
            .map_err(|why| NailsError::InvalidState(why.to_string()))
    }
    fn selinux_context(&self, unit: &str) -> Result<String> {
        assert_eq!(unit, SWITCH_UNIT);
        Ok(self.selinux_context.to_string())
    }
    fn selinux(&self) -> &dyn Selinux {
        &self.selinux
    }
}

/// A host that asks PID 1 for neither setting, nor the kernel: the defaults
/// answer.
struct Unasked;

impl GuardHost for Unasked {
    fn unit_stop_commands(&self, _: &str) -> Result<String> {
        unreachable!("not a guard test")
    }
    fn job_timeout_action(&self, _: &str) -> Result<String> {
        unreachable!("not a guard test")
    }
    fn job_timeout(&self, _: &str) -> Result<String> {
        unreachable!("not a guard test")
    }
    fn service_watchdogs(&self) -> Result<String> {
        unreachable!("not a guard test")
    }
}

/// The one refusal `error` carries: its name, reason and fix.
fn refusal_of(error: NailsError) -> (String, String, String) {
    let NailsError::PreFlightCheckFailed(mut failures) = error else {
        panic!("expected the exec-prefix refusal, got {error:?}");
    };
    assert_eq!(failures.len(), 1, "{failures:?}");
    let (name, reason, fix) = failures.remove(0);
    (name, reason, fix.expect("the refusal says what to do"))
}

/// Where SELinux does not run, on a stock Debian, Ubuntu or NixOS host, PID 1
/// starts the copy itself: nothing changes there.
#[test]
fn a_host_without_selinux_starts_the_copy_directly() {
    for profile in [
        FakePlatform::fhs().host_profile(),
        FakePlatform::nixos().host_profile(),
        listing(FakePlatform::fhs().host_profile(), &DEBIAN_LSMS),
        listing(
            FakePlatform::nixos().host_profile(),
            &["capability", "landlock", "yama", "bpf", "ima"],
        ),
    ] {
        assert_eq!(profile.selinux, None);
        assert_eq!(ExecPrefix::for_host(Some(&profile)), ExecPrefix::Direct);
    }
    // Configured once but not running, on a kernel that lists other modules
    // and no SELinux: no policy gives a domain there.
    let configured = listing(host_with(Selinuxfs::NotMounted, None), &DEBIAN_LSMS);
    assert_eq!(ExecPrefix::for_host(Some(&configured)), ExecPrefix::Direct);
    assert_eq!(ExecPrefix::Direct.program(), None);
}

/// A kernel that lists SELinux among its security modules enforces a policy
/// it has loaded whether or not selinuxfs is mounted where the activation
/// runs: PID 1 starts the copy through `/usr/bin/env` there, though the labels
/// stay best effort, and also where the facts report SELinux and the list
/// could not be read to rule it out.
#[test]
fn a_kernel_that_lists_selinux_starts_the_copy_through_env_without_selinuxfs() {
    for (profile, why) in [
        (
            listing(host_with(Selinuxfs::NotMounted, None), &FEDORA_LSMS),
            Why::Kernel,
        ),
        (
            listing(FakePlatform::fhs().host_profile(), &FEDORA_LSMS),
            Why::Kernel,
        ),
        (host_with(Selinuxfs::NotMounted, None), Why::ModulesUnread),
    ] {
        assert_eq!(
            ExecPrefix::for_host(Some(&profile)),
            ExecPrefix::Trampoline(why)
        );
        assert_eq!(Labels::for_host(Some(&profile)), Labels::BestEffort);
    }
    assert_eq!(
        Why::Kernel.to_string(),
        "the kernel lists SELinux among its security modules (/sys/kernel/security/lsm), and \
         may enforce a policy, though no selinuxfs is mounted here"
    );
    assert_eq!(
        Why::ModulesUnread.to_string(),
        "the host facts report SELinux, no selinuxfs is mounted here, and \
         /sys/kernel/security/lsm could not be read to rule it out"
    );
    // Where the labels are required, they give the reason.
    let running = listing(
        host_with(Selinuxfs::Mounted, Some(SelinuxMode::Enforcing)),
        &FEDORA_LSMS,
    );
    assert_eq!(ExecPrefix::for_host(Some(&running)), RUNNING);
}

/// Where SELinux runs or may run, as the labels judge it, PID 1 starts the
/// copy through `/usr/bin/env`, whatever mode the policy runs in: a
/// permissive policy still gives the step PID 1's domain, and logs what it
/// would deny.
#[test]
fn a_host_that_may_run_selinux_starts_the_copy_through_env() {
    for (profile, reason) in [
        (
            Some(host_with(Selinuxfs::Mounted, Some(SelinuxMode::Enforcing))),
            Reason::SelinuxRunning,
        ),
        (
            Some(host_with(Selinuxfs::Mounted, Some(SelinuxMode::Permissive))),
            Reason::SelinuxRunning,
        ),
        (
            Some(host_with(Selinuxfs::Unknown, None)),
            Reason::MountsUnreadable,
        ),
        (None, Reason::HostUndetected),
    ] {
        let prefix = ExecPrefix::for_host(profile.as_ref());
        assert_eq!(prefix, ExecPrefix::Trampoline(Why::Labels(reason)));
        assert_eq!(prefix.program(), Some(Path::new("/usr/bin/env")));
        // The same facts require the labels, for the same reason.
        assert_eq!(Labels::for_host(profile.as_ref()), Labels::Required(reason));
    }
}

#[test]
fn starting_the_copy_directly_needs_nothing_in_either_root() {
    let empty = tempfile::tempdir().unwrap();
    for which in [Root::Decoy, Root::Next] {
        assert!(
            ExecPrefix::Direct
                .require(empty.path(), which, &Unasked)
                .is_ok()
        );
    }
}

#[test]
fn an_entry_through_env_needs_it_in_both_roots() {
    let prefix = RUNNING;
    let with = root_with_env();
    for which in [Root::Decoy, Root::Next] {
        assert!(prefix.require(with.path(), which, &STOCK).is_ok());
    }

    let without = tempfile::tempdir().unwrap();
    let (name, reason, fix) = refusal_of(
        prefix
            .require(without.path(), Root::Decoy, &STOCK)
            .unwrap_err(),
    );
    assert_eq!(name, CHECK);
    assert_eq!(
        reason,
        "SELinux runs on this host (selinuxfs is mounted), so PID 1 starts NAILS's own steps \
         through /usr/bin/env, and in the decoy root /usr/bin/env does not exist: the last step \
         before the switch into the hidden session, which keeps the hidden session's systemd \
         off the decoy's disks, would not start"
    );
    assert!(
        fix.starts_with("Install /usr/bin/env on the decoy"),
        "{fix}"
    );

    let (name, reason, fix) = refusal_of(
        ExecPrefix::Trampoline(Why::Labels(Reason::HostUndetected))
            .require(without.path(), Root::Next, &STOCK)
            .unwrap_err(),
    );
    assert_eq!(name, CHECK);
    assert_eq!(
        reason,
        "the host could not be detected and may run SELinux, so PID 1 starts NAILS's own steps \
         through /usr/bin/env, and in the hidden root /usr/bin/env does not exist: the hidden \
         session's own units and the last step of the way back would not start"
    );
    assert!(fix.starts_with("Run `sudo "), "{fix}");
    assert!(fix.contains(" discard /usr/bin/env`"), "{fix}");
}

#[test]
fn an_env_that_is_no_executable_file_refuses_the_entry_too() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("usr/bin/env")).unwrap();
    let (_, reason, _) = refusal_of(
        RUNNING
            .require(root.path(), Root::Decoy, &STOCK)
            .unwrap_err(),
    );
    assert!(
        reason.contains("in the decoy root /usr/bin/env is not an executable file:"),
        "{reason}"
    );
}

/// The way back checks the program the plan records, whatever this host's
/// facts say now: the drop-in the entry wrote names that one.
#[test]
fn a_way_back_needs_the_plan_s_program_in_the_hidden_root() {
    let without = tempfile::tempdir().unwrap();
    let mut plan = sample_plan();
    // A plan without one, from a host without SELinux or written before it
    // was recorded: nothing to check, and PID 1 is not asked.
    assert!(check_way_back(without.path(), &plan, &Unasked).is_ok());

    plan.exec_prefix = Some(PathBuf::from(TRAMPOLINE));
    assert!(check_way_back(root_with_env().path(), &plan, &STOCK).is_ok());
    let (name, reason, fix) =
        refusal_of(check_way_back(without.path(), &plan, &STOCK).unwrap_err());
    assert_eq!(name, CHECK);
    assert_eq!(
        reason,
        "PID 1 starts the last step of the way back through /usr/bin/env, and in the hidden root \
         /usr/bin/env does not exist: the switch to the decoy could go on without that step, and \
         the decoy would start with the hidden session's files in /run"
    );
    assert!(
        fix.contains(" deactivate --poweroff`, which powers off"),
        "{fix}"
    );
    assert!(fix.contains(" emergency` does here"), "{fix}");
}

/// A session plan of a hidden root on `/dev/vda2`, with no exec prefix.
fn sample_plan() -> Plan {
    Plan::from_json(
        r#"{"version":2,"hidden_root":"/mnt/data","upper":"/mnt/data/root/upper",
            "work":"/mnt/data/root/work","decoy_root":{"source":"/dev/vda2","fstype":"ext4"},
            "decoy":{"init":"/sbin/init"},"hidden":{"init":"/sbin/init"}}"#,
    )
    .unwrap()
}

/// What PID 1 says of the switch's unit decides whether it starts the step
/// through the program in the domain the policy gives the program.
#[test]
fn the_switch_unit_must_leave_the_domain_to_the_policy() {
    assert_eq!(domain_unheld(&STOCK).unwrap(), None);
    // `systemctl show --value` ends its answer with a newline.
    let newline = Pid1 {
        no_new_privileges: Ok("no\n"),
        selinux_context: "\n",
        ..STOCK
    };
    assert_eq!(domain_unheld(&newline).unwrap(), None);

    let no_new = Pid1 {
        no_new_privileges: Ok("yes\n"),
        ..STOCK
    };
    assert_eq!(
        domain_unheld(&no_new).unwrap().as_deref(),
        Some(
            "systemd-soft-reboot.service, whose start runs the last step before the switch, has \
             NoNewPrivileges=yes with every drop-in loaded: then the kernel changes the domain \
             at the start of /usr/bin/env only where the policy allows that for such a process, \
             and keeps PID 1's own otherwise"
        )
    );
    let context = Pid1 {
        selinux_context: "-system_u:system_r:init_t:s0\n",
        ..STOCK
    };
    assert_eq!(
        domain_unheld(&context).unwrap().as_deref(),
        Some(
            "systemd-soft-reboot.service, whose start runs the last step before the switch, has \
             SELinuxContext=-system_u:system_r:init_t:s0 with every drop-in loaded: PID 1 then \
             starts the step in that context, not in the domain the policy gives /usr/bin/env"
        )
    );

    // An answer that is neither, or none, is no answer.
    for answer in ["", "maybe", "no yes"] {
        let odd = Pid1 {
            no_new_privileges: Ok(answer),
            ..STOCK
        };
        assert!(
            matches!(domain_unheld(&odd), Err(NailsError::InvalidState(_))),
            "{answer:?}"
        );
    }
    let failing = Pid1 {
        no_new_privileges: Err("systemctl show failed"),
        ..STOCK
    };
    assert!(domain_unheld(&failing).is_err());
    assert!(domain_unheld(&Unasked).is_err(), "a host that does not ask");
}

#[test]
fn an_entry_through_env_needs_the_switch_unit_to_leave_the_domain_to_the_policy() {
    // PID 1 starts the copy itself: nothing to ask.
    assert!(ExecPrefix::Direct.require_domain(&Unasked).is_ok());

    let prefix = RUNNING;
    assert!(prefix.require_domain(&STOCK).is_ok());
    let (name, reason, fix) = refusal_of(
        prefix
            .require_domain(&Pid1 {
                no_new_privileges: Ok("yes"),
                ..STOCK
            })
            .unwrap_err(),
    );
    assert_eq!(name, CHECK);
    assert!(
        reason.starts_with(
            "SELinux runs on this host (selinuxfs is mounted), so PID 1 starts NAILS's own \
             steps through /usr/bin/env, but systemd-soft-reboot.service, whose start runs \
             the last step before the switch, has NoNewPrivileges=yes"
        ),
        "{reason}"
    );
    assert!(
        reason.ends_with(
            ": the last step before each switch could run in a domain the policy confines"
        ),
        "{reason}"
    );
    assert_eq!(
        fix,
        "Remove that setting from the drop-in of systemd-soft-reboot.service that sets it \
         (`systemctl cat systemd-soft-reboot.service` shows where it is) and activate again"
    );
    // A PID 1 that cannot be asked refuses the entry as well.
    assert!(prefix.require_domain(&Unasked).is_err());
}

#[test]
fn a_way_back_through_env_needs_the_hidden_pid_1_to_leave_the_domain_to_the_policy() {
    let mut plan = sample_plan();
    plan.exec_prefix = Some(PathBuf::from(TRAMPOLINE));
    let root = root_with_env();

    let (name, reason, fix) = refusal_of(
        check_way_back(
            root.path(),
            &plan,
            &Pid1 {
                selinux_context: "system_u:system_r:init_t:s0",
                ..STOCK
            },
        )
        .unwrap_err(),
    );
    assert_eq!(name, CHECK);
    assert!(
        reason.starts_with(
            "PID 1 starts the last step of the way back through /usr/bin/env, but \
             systemd-soft-reboot.service, whose start runs the last step before the switch, has \
             SELinuxContext=system_u:system_r:init_t:s0"
        ),
        "{reason}"
    );
    assert!(
        reason.ends_with(": that step could run in a domain the policy confines"),
        "{reason}"
    );
    assert!(
        fix.starts_with("Remove that setting from the drop-in"),
        "{fix}"
    );
    assert!(fix.contains("`sudo systemctl daemon-reload`"), "{fix}");
    assert!(
        fix.ends_with(" deactivate --poweroff`, which powers off"),
        "{fix}"
    );

    // A hidden PID 1 that cannot be asked refuses the return too, and the
    // fix names only the power-off.
    let (_, reason, fix) = refusal_of(
        check_way_back(
            root.path(),
            &plan,
            &Pid1 {
                no_new_privileges: Err("systemctl show failed"),
                ..STOCK
            },
        )
        .unwrap_err(),
    );
    assert!(
        reason.contains(
            "the hidden session's PID 1 could not be asked how it starts \
             systemd-soft-reboot.service: systemctl show failed"
        ),
        "{reason}"
    );
    assert!(fix.starts_with("End the session with `sudo "), "{fix}");
    assert!(
        fix.ends_with(" deactivate --poweroff`, which powers off"),
        "{fix}"
    );

    // The program is looked up first: without it PID 1 is not asked.
    let without = tempfile::tempdir().unwrap();
    let (_, reason, _) = refusal_of(check_way_back(without.path(), &plan, &Unasked).unwrap_err());
    assert!(reason.contains("/usr/bin/env does not exist"), "{reason}");
}

/// A policy-loaded host must start `/usr/bin/env` in a domain of its own: a
/// label the policy gives none, or one PID 1 may not start, refuses the entry
/// in either root, with the fix that root needs.
#[test]
fn an_entry_through_env_needs_a_label_the_policy_starts_in_a_domain_of_its_own() {
    let root = root_with_env();
    let root = root.path();
    let targeted = stock_under(FakeSelinux::targeted().with_label(root, BIN_T));
    for which in [Root::Decoy, Root::Next] {
        assert!(RUNNING.require(root, which, &targeted).is_ok());
    }

    const ETC: &str = "system_u:object_r:etc_t:s0";
    let etc = stock_under(FakeSelinux::targeted().with_label(root, ETC));
    let (name, reason, fix) = refusal_of(RUNNING.require(root, Root::Decoy, &etc).unwrap_err());
    assert_eq!(name, CHECK);
    assert_eq!(
        reason,
        "SELinux runs on this host (selinuxfs is mounted), so PID 1 starts NAILS's own steps \
         through /usr/bin/env, and in the decoy root /usr/bin/env is labelled \
         system_u:object_r:etc_t:s0, which the loaded SELinux policy gives no domain of its own \
         when PID 1 (system_u:system_r:init_t:s0) starts it: the last step before the switch \
         into the hidden session, which keeps the hidden session's systemd off the decoy's \
         disks, would run in PID 1's own domain"
    );
    assert_eq!(
        fix,
        "Give /usr/bin/env on the decoy the label its policy gives it (`restorecon -v \
         /usr/bin/env` restores it) and activate again"
    );

    // A hidden session moved a file from root's home over it: PID 1 may not
    // start it, and the discard brings back the decoy's.
    const HOME: &str = "unconfined_u:object_r:admin_home_t:s0";
    let home = stock_under(FakeSelinux {
        denials: vec![(INIT_T, HOME, "file", "execute")],
        ..FakeSelinux::targeted().with_label(root, HOME)
    });
    let (_, reason, fix) = refusal_of(RUNNING.require(root, Root::Next, &home).unwrap_err());
    assert!(
        reason.ends_with(
            "in the hidden root /usr/bin/env is labelled unconfined_u:object_r:admin_home_t:s0, \
             and the loaded SELinux policy does not let PID 1 (system_u:system_r:init_t:s0) \
             execute it: the hidden session's own units and the last step of the way back would \
             not start"
        ),
        "{reason}"
    );
    assert!(fix.starts_with("Run `sudo "), "{fix}");
    assert!(fix.contains(" discard /usr/bin/env`"), "{fix}");

    // A policy that cannot be asked refuses, in either root, with what lets
    // it be asked.
    let unanswered = stock_under(FakeSelinux {
        unanswered: Some("/sys/fs/selinux/create: No such file or directory (os error 2)"),
        ..FakeSelinux::targeted().with_label(root, BIN_T)
    });
    for which in [Root::Decoy, Root::Next] {
        let (_, reason, fix) = refusal_of(RUNNING.require(root, which, &unanswered).unwrap_err());
        assert!(
            reason.ends_with(" might not start, or might run in PID 1's own domain"),
            "{reason}"
        );
        assert!(
            reason.contains(
                "/usr/bin/env cannot be judged against the loaded SELinux policy: the policy \
                 cannot be asked: /sys/fs/selinux/create: No such file or directory (os error 2)"
            ),
            "{reason}"
        );
        assert!(
            fix.starts_with("Run nails where it can ask the loaded SELinux policy"),
            "{fix}"
        );
    }

    // Where PID 1 starts the copy itself, the kernel is not asked.
    assert!(
        ExecPrefix::Direct
            .require(root, Root::Decoy, &unanswered)
            .is_ok()
    );
}

/// The way back asks the hidden session's kernel the same: a label the policy
/// starts in PID 1's own domain, or one PID 1 may not start, refuses a return.
#[test]
fn a_way_back_through_env_needs_a_label_the_policy_starts_in_a_domain_of_its_own() {
    let mut plan = sample_plan();
    plan.exec_prefix = Some(PathBuf::from(TRAMPOLINE));
    let root = root_with_env();
    let root = root.path();
    assert!(
        check_way_back(
            root,
            &plan,
            &stock_under(FakeSelinux::targeted().with_label(root, BIN_T))
        )
        .is_ok()
    );

    let etc = stock_under(FakeSelinux::targeted().with_label(root, "system_u:object_r:etc_t:s0"));
    let (name, reason, fix) = refusal_of(check_way_back(root, &plan, &etc).unwrap_err());
    assert_eq!(name, CHECK);
    assert!(
        reason.ends_with("starts it: that step would run in PID 1's own domain"),
        "{reason}"
    );
    assert!(
        fix.starts_with(
            "Give /usr/bin/env in the hidden session the label the policy gives it (`sudo \
             restorecon -v /usr/bin/env` restores it) and deactivate again, or end the session \
             with `sudo "
        ),
        "{fix}"
    );
    assert!(fix.ends_with(" emergency` does here"), "{fix}");

    const TMP: &str = "unconfined_u:object_r:user_tmp_t:s0";
    let tmp = stock_under(FakeSelinux {
        denials: vec![(INIT_T, TMP, "file", "read")],
        ..FakeSelinux::targeted().with_label(root, TMP)
    });
    let (_, reason, _) = refusal_of(check_way_back(root, &plan, &tmp).unwrap_err());
    assert!(
        reason.ends_with(
            "read it: the switch to the decoy could go on without that step, and the decoy \
             would start with the hidden session's files in /run"
        ),
        "{reason}"
    );

    let unanswered = stock_under(FakeSelinux {
        unanswered: Some("no selinuxfs"),
        ..FakeSelinux::targeted().with_label(root, BIN_T)
    });
    let (_, reason, fix) = refusal_of(check_way_back(root, &plan, &unanswered).unwrap_err());
    assert!(
        reason.ends_with(": that step might not start, or might run in PID 1's own domain"),
        "{reason}"
    );
    assert!(fix.starts_with("End the session with `sudo "), "{fix}");
    assert!(fix.ends_with(" emergency` does here"), "{fix}");
}

/// A host that asks PID 1 for `NoNewPrivileges` but leaves `SELinuxContext`
/// and the kernel's SELinux to the defaults refuses both ways: the defaults
/// fail closed.
#[test]
fn the_questions_a_host_leaves_to_the_defaults_refuse_the_switch() {
    /// Asks for `NoNewPrivileges` alone.
    struct PrivilegesOnly(FakeSelinux);
    impl GuardHost for PrivilegesOnly {
        fn unit_stop_commands(&self, _: &str) -> Result<String> {
            unreachable!("not a guard test")
        }
        fn job_timeout_action(&self, _: &str) -> Result<String> {
            unreachable!("not a guard test")
        }
        fn job_timeout(&self, _: &str) -> Result<String> {
            unreachable!("not a guard test")
        }
        fn service_watchdogs(&self) -> Result<String> {
            unreachable!("not a guard test")
        }
        fn no_new_privileges(&self, _: &str) -> Result<String> {
            Ok("no\n".to_string())
        }
        fn selinux(&self) -> &dyn Selinux {
            &self.0
        }
    }
    let host = PrivilegesOnly(OFF);
    // The entry stops at the error itself.
    for answer in [
        RUNNING.require_domain(&host),
        domain_unheld(&host).map(drop),
    ] {
        let Err(NailsError::InvalidState(why)) = answer else {
            panic!("expected the default's error, got {answer:?}");
        };
        assert_eq!(
            why,
            "PID 1 was not asked for SELinuxContext of systemd-soft-reboot.service"
        );
    }

    let mut plan = sample_plan();
    plan.exec_prefix = Some(PathBuf::from(TRAMPOLINE));
    let root = root_with_env();
    let (_, reason, fix) = refusal_of(check_way_back(root.path(), &plan, &host).unwrap_err());
    assert!(
        reason.contains(
            "the hidden session's PID 1 could not be asked how it starts \
             systemd-soft-reboot.service: PID 1 was not asked for SELinuxContext of \
             systemd-soft-reboot.service"
        ),
        "{reason}"
    );
    assert!(fix.starts_with("End the session with `sudo "), "{fix}");

    // The default of `NoNewPrivileges` names it.
    let NailsError::InvalidState(why) = domain_unheld(&Unasked).unwrap_err() else {
        panic!("expected the default's error");
    };
    assert_eq!(
        why,
        "PID 1 was not asked for NoNewPrivileges of systemd-soft-reboot.service"
    );

    // The kernel's SELinux left to the default answers nothing: the check
    // of either root refuses once the program is there.
    let (_, reason, fix) = refusal_of(
        RUNNING
            .require(root.path(), Root::Decoy, &Unasked)
            .unwrap_err(),
    );
    assert!(
        reason.contains(
            "/usr/bin/env cannot be judged against the loaded SELinux policy: PID 1's context \
             cannot be read: the kernel's SELinux was not asked"
        ),
        "{reason}"
    );
    assert!(fix.starts_with("Run nails where it can ask"), "{fix}");
    let (_, reason, _) = refusal_of(check_way_back(root.path(), &plan, &Unasked).unwrap_err());
    assert!(
        reason.contains("PID 1's context cannot be read: the kernel's SELinux was not asked"),
        "{reason}"
    );
}
