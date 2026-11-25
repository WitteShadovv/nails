// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use nails_platform::platform::FakePlatform;
use nails_platform::{SelinuxMode, SelinuxStatus, Selinuxfs};
use nails_teardown::test_support::FakeSelinux;

/// A Debian host as the facts read it: AppArmor among the security modules,
/// no SELinux.
fn debian() -> HostProfile {
    let mut profile = FakePlatform::fhs().host_profile();
    profile.lsms = [
        "lockdown",
        "capability",
        "landlock",
        "yama",
        "apparmor",
        "bpf",
    ]
    .map(str::to_string)
    .to_vec();
    profile
}

/// A host whose facts report SELinux as `selinuxfs` says, and whose kernel
/// lists `lsms`.
fn with_selinux(selinuxfs: Selinuxfs, lsms: &[&str]) -> HostProfile {
    let mut profile = FakePlatform::fhs().host_profile();
    profile.lsms = lsms.iter().map(|lsm| lsm.to_string()).collect();
    profile.selinux = Some(SelinuxStatus {
        selinuxfs,
        enforce: Some(SelinuxMode::Enforcing),
        config_mode: Some("enforcing".to_string()),
        config_policy: Some("targeted".to_string()),
    });
    profile
}

/// The copies take the label wherever SELinux runs or may run, from the host
/// facts alone: and on a stock Debian, Ubuntu or NixOS host, which lists no
/// SELinux among its security modules and reports none, they take none.
#[test]
fn the_copies_take_the_label_wherever_the_facts_leave_selinux_possible() {
    assert_eq!(for_host(Some(&debian())), None);
    assert_eq!(for_host(Some(&FakePlatform::nixos().host_profile())), None);
    // Packages installed once leave a configuration, but the kernel lists no
    // SELinux and the mount table no selinuxfs.
    assert_eq!(
        for_host(Some(&with_selinux(
            Selinuxfs::NotMounted,
            &["capability", "apparmor"]
        ))),
        None
    );

    assert_eq!(
        for_host(Some(&with_selinux(
            Selinuxfs::Mounted,
            &["capability", "selinux"]
        ))),
        Some(Why::Labels(Reason::SelinuxRunning))
    );
    assert_eq!(
        for_host(Some(&with_selinux(Selinuxfs::Unknown, &[]))),
        Some(Why::Labels(Reason::MountsUnreadable))
    );
    assert_eq!(for_host(None), Some(Why::Labels(Reason::HostUndetected)));
    // The kernel enforces a loaded policy without a mounted selinuxfs.
    assert_eq!(
        for_host(Some(&with_selinux(
            Selinuxfs::NotMounted,
            &["capability", "selinux"]
        ))),
        Some(Why::Kernel)
    );
    // Nothing rules SELinux out where the list cannot be read.
    assert_eq!(
        for_host(Some(&with_selinux(Selinuxfs::NotMounted, &[]))),
        Some(Why::ModulesUnread)
    );
    assert!(Why::Kernel.to_string().contains("/sys/kernel/security/lsm"));
}

/// The one failure of `failures`, under the program label's name.
fn refused(error: &NailsError) -> (&str, &str) {
    let NailsError::PreFlightCheckFailed(failures) = error else {
        panic!("expected the program label's refusal, got {error:?}");
    };
    assert_eq!(failures.len(), 1, "{error}");
    assert_eq!(failures[0].0, CHECK, "{error}");
    (&failures[0].1, failures[0].2.as_deref().unwrap_or_default())
}

/// Where the copies take no label nothing is asked or written; where they do,
/// the entry is refused before it writes anything unless the policy starts a
/// program of the label from PID 1 in the unconfined service domain.
#[test]
fn the_entry_needs_a_policy_that_starts_the_label_unconfined() {
    let untouched = FakeSelinux {
        write_error: Some(rustix::io::Errno::PERM.raw_os_error()),
        ..FakeSelinux::targeted()
    };
    require(None, &untouched).unwrap();
    assert!(untouched.questions().is_empty());

    require(Some(Why::Kernel), &FakeSelinux::targeted()).unwrap();
    require(Some(Why::Kernel), &FakeSelinux::without_policy()).unwrap();

    let own = FakeSelinux {
        entered: "system_u:system_r:init_t:s0".to_string(),
        ..FakeSelinux::targeted()
    };
    let error = require(Some(Why::Labels(Reason::SelinuxRunning)), &own).unwrap_err();
    let (reason, fix) = refused(&error);
    assert!(
        reason.starts_with(
            "SELinux runs on this host (selinuxfs is mounted), so NAILS gives the RAM copy of \
             the binary"
        ),
        "{reason}"
    );
    assert!(reason.contains("runs in PID 1's own domain"), "{reason}");
    assert!(
        reason.ends_with("would run in a domain the policy confines"),
        "{reason}"
    );
    assert!(fix.contains("unconfined_service_t"), "{fix}");
    assert!(
        fix.contains("NAILS installs nothing into the policy"),
        "{fix}"
    );

    let denied = FakeSelinux {
        denied: vec![("file", "entrypoint")],
        ..FakeSelinux::targeted()
    };
    let error = require(Some(Why::Kernel), &denied).unwrap_err();
    let (reason, _) = refused(&error);
    assert!(
        reason.ends_with("would not start, and a switch would go on without its step"),
        "{reason}"
    );

    let unasked = FakeSelinux {
        policy_error: Some(rustix::io::Errno::NOENT.raw_os_error()),
        ..FakeSelinux::targeted()
    };
    let error = require(Some(Why::Kernel), &unasked).unwrap_err();
    let (_, fix) = refused(&error);
    assert!(
        fix.starts_with("Run nails where it can ask the loaded SELinux policy"),
        "{fix}"
    );
}

/// The entry's copy takes the label, and again before the switch; one that
/// does not refuses the entry with what to do.
#[test]
fn the_entry_s_copy_takes_the_label_or_refuses_the_entry() {
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("control");
    std::fs::write(&copy, b"\x7fELF").unwrap();

    let untouched = FakeSelinux {
        write_error: Some(rustix::io::Errno::PERM.raw_os_error()),
        ..FakeSelinux::targeted()
    };
    label_copy(None, &untouched, &copy).unwrap();
    ready_for_entry(None, &untouched, &copy).unwrap();
    assert!(untouched.labels_written().is_empty() && untouched.questions().is_empty());

    let selinux = FakeSelinux::targeted();
    label_copy(Some(Why::Kernel), &selinux, &copy).unwrap();
    ready_for_entry(Some(Why::Kernel), &selinux, &copy).unwrap();
    assert_eq!(selinux.labels_written().len(), 2, "written, then again");

    let refused_label = FakeSelinux {
        write_error: Some(rustix::io::Errno::OPNOTSUPP.raw_os_error()),
        ..FakeSelinux::targeted()
    };
    for error in [
        label_copy(Some(Why::Kernel), &refused_label, &copy).unwrap_err(),
        ready_for_entry(Some(Why::Kernel), &refused_label, &copy).unwrap_err(),
    ] {
        let (reason, fix) = refused(&error);
        assert!(
            reason.contains(&format!(
                "so the RAM copy of the binary at {}, which PID 1 starts NAILS's own steps from, \
                 must carry the SELinux label system_u:object_r:bin_t:s0, but it could not take \
                 the label: ",
                copy.display()
            )),
            "{reason}"
        );
        assert!(
            fix.starts_with("Run nails as root from an unconfined domain"),
            "{fix}"
        );
    }

    let own = FakeSelinux {
        entered: "system_u:system_r:init_t:s0".to_string(),
        ..FakeSelinux::targeted()
    };
    let error = ready_for_entry(Some(Why::Kernel), &own, &copy).unwrap_err();
    assert!(refused(&error).0.contains("runs in PID 1's own domain"));
}

/// What PID 1 answers for the switch's unit, and the SELinux it runs under;
/// it records the targets it is asked to start, and starts none.
struct Pid1 {
    context: Option<&'static str>,
    selinux: FakeSelinux,
    started: std::cell::RefCell<Vec<String>>,
}

impl super::super::leave::TargetHost for Pid1 {
    fn start_target(&self, target: &str) -> Result<()> {
        self.started.borrow_mut().push(target.to_string());
        Ok(())
    }
}

impl GuardHost for Pid1 {
    fn unit_stop_commands(&self, _: &str) -> Result<String> {
        Ok(String::new())
    }
    fn job_timeout_action(&self, _: &str) -> Result<String> {
        Ok("poweroff-force".to_string())
    }
    fn job_timeout(&self, _: &str) -> Result<String> {
        Ok("30min".to_string())
    }
    fn service_watchdogs(&self) -> Result<String> {
        Ok("yes".to_string())
    }
    fn selinux_context(&self, unit: &str) -> Result<String> {
        assert_eq!(unit, SWITCH_UNIT);
        self.context
            .map(str::to_string)
            .ok_or_else(|| NailsError::InvalidState("systemctl show failed".to_string()))
    }
    fn selinux(&self) -> &dyn Selinux {
        &self.selinux
    }
}

/// A host whose PID 1 starts the switch's unit with `context`.
fn pid1(context: Option<&'static str>) -> Pid1 {
    Pid1 {
        context,
        selinux: FakeSelinux::targeted(),
        started: Default::default(),
    }
}

/// An `SELinuxContext=` of the switch's unit keeps the policy's change of
/// domain from applying: the entry refuses it, and an answer PID 1 does not
/// give as well. Where the copies take no label PID 1 is not asked.
#[test]
fn the_entry_refuses_a_switch_unit_with_a_context_of_its_own() {
    check_switch_unit(None, &pid1(None)).unwrap();
    check_switch_unit(Some(Why::Kernel), &pid1(Some("\n"))).unwrap();

    let error = check_switch_unit(
        Some(Why::Kernel),
        &pid1(Some("system_u:system_r:init_t:s0\n")),
    )
    .unwrap_err();
    let (reason, fix) = refused(&error);
    assert!(
        reason.contains(
            "systemd-soft-reboot.service, whose start runs the last step before the switch, has \
             SELinuxContext=system_u:system_r:init_t:s0 with every drop-in loaded"
        ),
        "{reason}"
    );
    assert!(
        fix.starts_with("Remove that setting from the drop-in"),
        "{fix}"
    );

    let error = check_switch_unit(Some(Why::Kernel), &pid1(None)).unwrap_err();
    assert!(
        error.to_string().contains("systemctl show failed"),
        "{error}"
    );

    /// A host that does not ask PID 1 fails by default.
    struct Unasked;
    impl GuardHost for Unasked {
        fn unit_stop_commands(&self, _: &str) -> Result<String> {
            Ok(String::new())
        }
        fn job_timeout_action(&self, _: &str) -> Result<String> {
            Ok(String::new())
        }
        fn job_timeout(&self, _: &str) -> Result<String> {
            Ok(String::new())
        }
        fn service_watchdogs(&self) -> Result<String> {
            Ok(String::new())
        }
    }
    let error = check_switch_unit(Some(Why::Kernel), &Unasked).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("PID 1 was not asked for SELinuxContext of systemd-soft-reboot.service"),
        "{error}"
    );
}

/// A plan whose copies take `label`.
fn plan_with(label: Option<&str>) -> Plan {
    let text = r#"{"version":2,"hidden_root":"/mnt/data","upper":"/mnt/data/root/upper",
        "work":"/mnt/data/root/work","decoy_root":{"source":"/dev/vda2","fstype":"ext4"},
        "decoy":{"init":"/sbin/init"},"hidden":{"init":"/sbin/init"}}"#;
    let mut plan = Plan::from_json(text).unwrap();
    plan.program_label = label.map(str::to_string);
    plan
}

/// The way back is refused before anything is prepared where the policy
/// would not start its step from the labelled copy as it needs, or the hidden
/// session's PID 1 starts the switch's unit in a context of its own, or
/// cannot be asked; a plan without a label asks nothing.
#[test]
fn a_return_needs_the_policy_and_the_switch_unit_to_start_the_step_unconfined() {
    let unasked = pid1(None);
    check_way_back(&plan_with(None), &unasked).unwrap();
    assert!(unasked.selinux.questions().is_empty());

    let labelled = plan_with(Some(PROGRAM_LABEL));
    check_way_back(&labelled, &pid1(Some(""))).unwrap();

    let own = Pid1 {
        context: Some(""),
        selinux: FakeSelinux {
            entered: "system_u:system_r:init_t:s0".to_string(),
            ..FakeSelinux::targeted()
        },
        started: Default::default(),
    };
    let error = check_way_back(&labelled, &own).unwrap_err();
    let (reason, fix) = refused(&error);
    assert!(
        reason.starts_with(
            "PID 1 starts the last step of the way back from the RAM copy of the binary, \
             labelled system_u:object_r:bin_t:s0, but its start of a file so labelled runs in \
             PID 1's own domain"
        ),
        "{reason}"
    );
    assert!(reason.contains("the kernel log's cursor"), "{reason}");
    assert!(fix.contains("deactivate --poweroff"), "{fix}");
    assert!(fix.contains("emergency"), "{fix}");

    // The emergency here gives the label again and asks the policy too: it
    // powers off where deactivate refuses, so the fix may name it.
    assert!(
        fix.contains(&format!("`{}`", sudo_line(NextStep::Emergency))),
        "{fix}"
    );

    // The emergency asks PID 1 nothing, and its last step, started in that
    // context, starts itself again or powers off: the fixes of the switch's
    // unit name only the power-offs besides deactivating again.
    let error = check_way_back(&labelled, &pid1(Some("system_u:system_r:init_t:s0"))).unwrap_err();
    let (reason, fix) = refused(&error);
    assert!(
        reason.contains("SELinuxContext=system_u:system_r:init_t:s0"),
        "{reason}"
    );
    assert!(
        fix.starts_with(
            "Remove that setting from the hidden session's drop-in of \
             systemd-soft-reboot.service that sets it"
        ),
        "{fix}"
    );
    for named in [NextStep::DeactivatePoweroff, NextStep::EmergencyPoweroff] {
        assert!(fix.contains(&format!("`{}`", sudo_line(named))), "{fix}");
    }
    assert!(
        !fix.contains(&format!("`{}`", sudo_line(NextStep::Emergency))),
        "{fix}"
    );
    assert!(fix.ends_with(", which power off"), "{fix}");

    let error = check_way_back(&labelled, &unasked).unwrap_err();
    let (reason, fix) = refused(&error);
    assert!(
        reason.contains("the hidden session's PID 1 could not be asked how it starts"),
        "{error}"
    );
    assert!(fix.starts_with("Deactivate again once PID 1 answers, or end the session with"));
    assert!(
        fix.contains(&format!("`{}`", sudo_line(NextStep::EmergencyPoweroff))),
        "{fix}"
    );
    assert!(
        !fix.contains(&format!("`{}`", sudo_line(NextStep::Emergency))),
        "{fix}"
    );
}

/// Right before the way back is armed the copy takes the plan's label again;
/// one that does not, or whose start the policy would not give the domain,
/// refuses the return.
#[test]
fn the_copy_takes_the_label_again_before_the_way_back_is_armed() {
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("control");
    std::fs::write(&copy, b"\x7fELF").unwrap();

    let untouched = FakeSelinux {
        write_error: Some(rustix::io::Errno::PERM.raw_os_error()),
        ..FakeSelinux::targeted()
    };
    ready_for_way_back(&plan_with(None), &untouched, &copy).unwrap();
    assert!(untouched.labels_written().is_empty() && untouched.questions().is_empty());

    let labelled = plan_with(Some(PROGRAM_LABEL));
    let selinux = FakeSelinux::targeted();
    ready_for_way_back(&labelled, &selinux, &copy).unwrap();
    assert_eq!(selinux.labels_written().len(), 1);

    let error = ready_for_way_back(&labelled, &untouched, &copy).unwrap_err();
    let (reason, fix) = refused(&error);
    assert!(reason.contains("could not take the label: "), "{reason}");
    assert!(
        reason.ends_with("the decoy's journal would take in the hidden session's kernel log"),
        "{reason}"
    );
    assert!(fix.contains("deactivate --poweroff"), "{fix}");

    let missing = dir.path().join("missing");
    let error = ready_for_way_back(&labelled, &FakeSelinux::targeted(), &missing).unwrap_err();
    assert!(
        refused(&error)
            .0
            .contains("would not start, and the switch to the decoy would go on without it"),
        "{error}"
    );
}

/// `deactivate` ends a labelled session in a power-off and asks SELinux and
/// PID 1 nothing about the RAM copy's label: no last step of a way back will
/// start from it.
#[test]
fn a_labelled_session_ends_in_a_power_off_without_asking_about_the_label() {
    use super::super::leave::leave;
    for host in [
        Pid1 {
            context: Some(""),
            selinux: FakeSelinux {
                capability: false,
                ..FakeSelinux::targeted()
            },
            started: Default::default(),
        },
        pid1(Some("system_u:system_r:unconfined_service_t:s0")),
        pid1(None),
    ] {
        leave(&host).unwrap();
        assert_eq!(*host.started.borrow(), ["poweroff.target"]);
        assert!(host.selinux.labels_written().is_empty());
    }
}
