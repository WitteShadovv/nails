// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The emergency hot path acts before the CLI reads its configuration (ADR
//! 0007, ADR 0008).
//!
//! The real `nails` binary runs `emergency` on the decoy side of an interrupted
//! activation: a session plan in `/run` and a real overlay populating
//! `/run/nextroot`, in a private user, mount and PID namespace, with `--config`
//! pointing at a FIFO. Opening a
//! FIFO for reading blocks until a writer appears, and nothing ever writes to
//! it, so the process stops at the first configuration read. The test then
//! sees the next root already detached from the binary's mount table while the binary
//! is still alive and blocked: the teardown ran before the configuration
//! (and, since `main` reads the configuration only after clap and tracing are
//! set up, before those too; `cli::early`'s tests pin that order in `main`).
//!
//! The PID namespace with its own `/proc` keeps the hot path's shell and
//! process kills inside the test: the binary sees no process but itself.

mod kernel_tests {
    use nails_core::test_support::{Rerun, ScratchTmpfs};
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::time::{Duration, Instant};

    fn in_mount_table(pid: i32, target: &Path) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/mountinfo"))
            .unwrap_or_default()
            .lines()
            .any(|line| line.split(' ').nth(4) == Some(target.to_str().unwrap()))
    }

    /// SIGKILLs the namespaced child when the test ends, pass or fail, so a
    /// failed assertion never leaves it blocked on the FIFO (and holding the
    /// test harness's output pipe open).
    struct KillOnDrop(nix::unistd::Pid);

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = nix::sys::signal::kill(self.0, nix::sys::signal::Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(self.0, None);
        }
    }

    fn alive(pid: nix::unistd::Pid) -> bool {
        matches!(
            nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)),
            Ok(nix::sys::wait::WaitStatus::StillAlive)
        )
    }

    /// Start `argv` as PID 1 of a new PID and mount namespace, with a fresh
    /// `/proc` of that namespace mounted first.
    #[allow(unsafe_code)]
    fn spawn_pid1(argv: &[CString]) -> nix::unistd::Pid {
        use nix::sched::CloneFlags;
        let proc_ = c"proc";
        let target = c"/proc";
        let mut argv_ptrs: Vec<*const nix::libc::c_char> =
            argv.iter().map(|a| a.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());
        let envp: [*const nix::libc::c_char; 1] = [std::ptr::null()];
        let mut stack = vec![0u8; 256 * 1024];
        let child = move || -> isize {
            // SAFETY: the clone child only makes raw syscalls on data prepared
            // before the clone (C strings and pointer arrays that outlive it),
            // then execs or exits, touching no lock or allocator.
            unsafe {
                if nix::libc::mount(
                    proc_.as_ptr(),
                    target.as_ptr(),
                    proc_.as_ptr(),
                    0,
                    std::ptr::null(),
                ) != 0
                {
                    nix::libc::_exit(90);
                }
                nix::libc::execve(argv_ptrs[0], argv_ptrs.as_ptr(), envp.as_ptr());
                nix::libc::_exit(91)
            }
        };
        // SAFETY: the callback is async-signal-safe (see above) and the stack
        // outlives the child's use of it (the child execs at once).
        unsafe {
            nix::sched::clone(
                Box::new(child),
                &mut stack,
                CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS,
                Some(nix::libc::SIGCHLD),
            )
        }
        .expect("clone into a new PID namespace")
    }

    #[test]
    fn emergency_detaches_the_next_root_before_the_configuration_is_read() {
        let _ = Rerun::new(
            "kernel_tests::emergency_detaches_the_next_root_before_the_configuration_is_read",
        )
        .in_user_mount_ns()
        .run(|| {
            // A private /run for the plan, as the decoy's tmpfs would be.
            nix::mount::mount(
                Some("tmpfs"),
                "/run",
                Some("tmpfs"),
                nix::mount::MsFlags::empty(),
                Some("mode=0755"),
            )
            .expect("a private /run");
            let hidden = ScratchTmpfs::new("");
            let decoy = ScratchTmpfs::new("");
            let lower = decoy.mkdir("root");
            let target = std::path::PathBuf::from("/run/nextroot");
            std::fs::create_dir_all(&target).unwrap();
            let upper = hidden.mkdir("root/upper");
            let work = hidden.mkdir("root/work");
            nix::mount::mount(
                Some("overlay"),
                &target,
                Some("overlay"),
                nix::mount::MsFlags::empty(),
                Some(
                    format!(
                        "lowerdir={},upperdir={},workdir={}",
                        lower.display(),
                        upper.display(),
                        work.display()
                    )
                    .as_str(),
                ),
            )
            .expect("mount the next root");

            use nails_teardown::whole_root::plan::{
                DecoyRoot, PLAN_VERSION, Plan, RootSide, Tools,
            };
            let side = RootSide {
                init: "/usr/lib/systemd/systemd".into(),
                system: None,
            };
            let plan = Plan {
                version: PLAN_VERSION,
                hidden_root: hidden.path().to_path_buf(),
                upper,
                work,
                owner: None,
                decoy_root: DecoyRoot {
                    source: "/dev/null".into(),
                    fstype: "ext4".into(),
                    data: None,
                },
                decoy: side.clone(),
                hidden: side,
                policy_mounts: Vec::new(),
                masks: Vec::new(),
                session_units: Vec::new(),
                backend: Vec::new(),
                tools: Tools::default(),
                armed: None,
                entered_at: None,
            };
            let plan_path = nails_teardown::whole_root::plan::default_plan_path();
            std::fs::create_dir_all(plan_path.parent().unwrap()).unwrap();
            plan.write_atomic(&plan_path).unwrap();

            let fifo = Path::new("/run/settings.fifo");
            nix::unistd::mkfifo(fifo, nix::sys::stat::Mode::from_bits_truncate(0o600))
                .expect("mkfifo");

            let argv: Vec<CString> = [
                env!("CARGO_BIN_EXE_nails").as_ref(),
                "--config".as_ref(),
                fifo.as_os_str(),
                "emergency".as_ref(),
            ]
            .iter()
            .map(|a: &&std::ffi::OsStr| CString::new(a.as_bytes()).unwrap())
            .collect();
            let child = spawn_pid1(&argv);
            let _reaper = KillOnDrop(child);

            let deadline = Instant::now() + Duration::from_secs(20);
            while in_mount_table(child.as_raw(), &target) {
                assert!(alive(child), "nails exited before detaching the next root");
                assert!(
                    Instant::now() < deadline,
                    "the next root was never detached"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            // Gone from the binary's table, while the binary is still waiting
            // to read its configuration.
            std::thread::sleep(Duration::from_millis(300));
            assert!(
                alive(child),
                "nails must still be blocked on the configuration FIFO"
            );
        });
    }
}
