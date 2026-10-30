// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for preparing the entry into the hidden root.

use super::*;
use crate::session::fstab::{parse_fstab, parse_in_root};
use nails_teardown::mountinfo::parse_mountinfo;

#[test]
fn the_decoy_root_is_read_from_the_mount_table() {
    let ext4 = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");
    let root = decoy_root_of(&ext4, Path::new("/")).unwrap();
    assert_eq!(root.source, Path::new("/dev/vda2"));
    assert_eq!(root.fstype, "ext4");
    assert_eq!(root.data, None);
    let btrfs = parse_mountinfo("1 0 0:30 /@ / rw - btrfs /dev/nvme0n1p2 rw,subvol=/@\n");
    assert_eq!(
        decoy_root_of(&btrfs, Path::new("/"))
            .unwrap()
            .data
            .as_deref(),
        Some("subvol=/@")
    );
}

/// A host that only answers the stop-command query.
struct StopHost(&'static str);

impl EntryHost for StopHost {
    fn daemon_reload(&self) -> Result<()> {
        Ok(())
    }
    fn build_hidden_system(&self, _: &NixOSBuilder, _: &Path, _: &Path) -> Result<PathBuf> {
        unreachable!("not used by the stop-guard check")
    }
    fn keep_hidden_closure(&self, _: &Path, _: &Path, _: &Path) -> Result<store::KeepReport> {
        unreachable!("not used by the stop-guard check")
    }
    fn activate_hidden_system(&self, _: &Path, _: &Path) -> Result<()> {
        unreachable!("not used by the stop-guard check")
    }
    fn unit_stop_commands(&self, _: &str) -> Result<String> {
        Ok(self.0.to_string())
    }
}

#[test]
fn a_prefix_guard_is_not_asked_about_by_name() {
    /// Answers with a stop command for anything but blk-availability.
    struct PrefixOnly;
    impl EntryHost for PrefixOnly {
        fn daemon_reload(&self) -> Result<()> {
            Ok(())
        }
        fn build_hidden_system(&self, _: &NixOSBuilder, _: &Path, _: &Path) -> Result<PathBuf> {
            unreachable!()
        }
        fn keep_hidden_closure(&self, _: &Path, _: &Path, _: &Path) -> Result<store::KeepReport> {
            unreachable!()
        }
        fn activate_hidden_system(&self, _: &Path, _: &Path) -> Result<()> {
            unreachable!()
        }
        fn unit_stop_commands(&self, unit: &str) -> Result<String> {
            assert!(
                !unit.ends_with("-.service"),
                "asked about the prefix {unit}"
            );
            Ok(if unit == "blk-availability.service" {
                String::new()
            } else {
                "{ path=/bin/true }".to_string()
            })
        }
    }
    assert!(check_stop_guards(&PrefixOnly).is_ok());
}

#[test]
fn a_stop_command_left_after_the_guard_refuses_the_entry() {
    assert!(check_stop_guards(&StopHost("\n")).is_ok());
    let error = check_stop_guards(&StopHost(
        "{ path=/usr/sbin/blkdeactivate ; argv[]=/usr/sbin/blkdeactivate -u ; }\n",
    ))
    .unwrap_err();
    let text = error.to_string();
    assert!(text.contains("blk-availability.service"), "{text}");
    assert!(text.contains("zz-overlay-runtime.conf"), "{text}");
    assert!(matches!(error, NailsError::PreFlightCheckFailed(_)));
}

#[test]
fn a_build_is_refused_below_the_space_floor() {
    let dir = tempfile::tempdir().unwrap();
    assert!(ensure_build_space(dir.path(), 0).is_ok());
    let error = ensure_build_space(dir.path(), u64::MAX).unwrap_err();
    assert!(error.to_string().contains("rebuild_space_mb"), "{error}");
}

#[test]
fn a_root_that_cannot_be_mounted_again_is_refused() {
    for table in [
        "1 0 0:20 / / rw - tmpfs none rw\n",
        "1 0 0:21 / / rw - overlay overlay rw,lowerdir=/a\n",
        "1 0 0:22 / / rw - zfs /dev/zd0 rw\n",
        "1 0 8:2 /sub / rw - ext4 /dev/vda2 rw\n",
        // A btrfs bind of a plain folder inside the subvolume /@: the mount
        // root (/@/srv) is not the subvolume (subvol=/@), so the way back
        // cannot mount it again by subvol.
        "1 0 0:30 /@/srv / rw - btrfs /dev/nvme0n1p2 rw,subvolid=256,subvol=/@\n",
    ] {
        let entries = parse_mountinfo(table);
        assert!(decoy_root_of(&entries, Path::new("/")).is_err(), "{table}");
    }
}

#[test]
fn a_btrfs_bind_of_a_plain_folder_is_refused_by_path() {
    // The refusal names the folder, never the device-mapper node or device.
    let table = "1 0 0:30 /@/srv / rw - btrfs /dev/nvme0n1p2 rw,subvolid=256,subvol=/@\n";
    let err = decoy_root_of(&parse_mountinfo(table), Path::new("/")).unwrap_err();
    assert!(err.to_string().contains("/@/srv"), "{err}");

    // A genuine subvolume mount, whose root equals its subvol=, is accepted
    // even when the subvolume lives at a deeper path.
    let table =
        "1 0 0:30 /@/snapshots/root / rw - btrfs /dev/nvme0n1p2 rw,subvol=/@/snapshots/root\n";
    assert_eq!(
        decoy_root_of(&parse_mountinfo(table), Path::new("/"))
            .unwrap()
            .data
            .as_deref(),
        Some("subvol=/@/snapshots/root")
    );
}

#[test]
fn a_btrfs_subvolume_whose_path_the_kernel_escapes_is_a_subvolume() {
    // The kernel writes a space, a tab or a backslash of the subvolume's path
    // as an octal escape both in the mount root and in its subvol= option;
    // decoded, the two are the same path.
    for (escaped, path) in [
        ("/@ubuntu\\04026.04", "/@ubuntu 26.04"),
        ("/@root\\011tab", "/@root\ttab"),
        ("/@back\\134slash", "/@back\\slash"),
    ] {
        let table = format!(
            "1 0 0:30 {escaped} / rw - btrfs /dev/nvme0n1p2 rw,subvolid=256,subvol={escaped}\n"
        );
        let root = decoy_root_of(&parse_mountinfo(&table), Path::new("/"))
            .unwrap_or_else(|e| panic!("{table}: {e}"));
        assert_eq!(
            root.data.as_deref(),
            Some(format!("subvol={path}").as_str()),
            "{table}"
        );
    }

    // A bind of a folder with such a path is still refused.
    let table = "1 0 0:30 /@ubuntu\\04026.04/srv / rw - btrfs /dev/nvme0n1p2 \
                 rw,subvol=/@ubuntu\\04026.04\n";
    assert!(decoy_root_of(&parse_mountinfo(table), Path::new("/")).is_err());
}

#[test]
fn a_btrfs_subvolume_with_a_comma_in_its_path_is_refused() {
    // The mount root keeps the comma, the option escapes it. The two match,
    // but the way back passes `subvol=` to mount(2), which splits at commas,
    // so it could not mount the decoy root again.
    let table = "1 0 0:30 /@a,b / rw - btrfs /dev/nvme0n1p2 rw,subvolid=256,subvol=/@a\\054b\n";
    let error = decoy_root_of(&parse_mountinfo(table), Path::new("/")).unwrap_err();
    let text = error.to_string();
    assert!(text.contains("comma"), "{text}");
    assert!(text.contains("/@a,b"), "{text}");
}

/// A minimal `EntryInputs` for the helpers that do not build a system:
/// no builder, no operator, the persona at its default, and a host whose facts
/// report no SELinux.
fn minimal_inputs<'a>(
    hidden_root: &'a Path,
    binary: &'a Path,
    config_toml: Option<String>,
) -> EntryInputs<'a> {
    EntryInputs {
        hidden_root,
        decoy_root: DecoyRoot {
            source: PathBuf::from("/dev/vda2"),
            fstype: "ext4".into(),
            data: None,
        },
        nixos: false,
        builder: None,
        binary,
        config_toml,
        session_units: Vec::new(),
        backend: Vec::new(),
        persona: Default::default(),
        operator: None,
        labels: Labels::BestEffort,
        rebuild_space_mb: 0,
        read_only_disks: false,
        accepted_decoy_storage: None,
    }
}

#[test]
fn write_runtime_populates_the_runtime_directory() {
    let run = tempfile::tempdir().unwrap();
    let hidden = tempfile::tempdir().unwrap();
    let binary = run.path().join("nails-running-binary");
    std::fs::write(&binary, b"the running binary bytes").unwrap();
    let paths = Paths {
        root: PathBuf::from("/"),
        run: run.path().to_path_buf(),
    };
    // A scratch tree, not the real system, so the runtime lands under it.
    assert!(!paths.is_system());
    let toml = "hidden_volume_root = \"/x\"\n".to_string();
    let inputs = minimal_inputs(hidden.path(), &binary, Some(toml.clone()));
    let snapshot = Snapshot::take(&paths.run);

    write_runtime(&paths, &inputs, &snapshot).unwrap();

    let runtime = paths.runtime();
    // The RAM copy of the binary is the running binary, byte for byte: the
    // whole point of write_runtime, skipped by a body replaced with Ok(()).
    assert_eq!(
        std::fs::read(paths.binary_copy()).unwrap(),
        std::fs::read(&binary).unwrap()
    );
    // The `/run` snapshot and the saved utab the way back reads are written.
    assert!(runtime.join(SNAPSHOT_NAME).exists());
    assert!(runtime.join(UTAB_NAME).exists());
    assert!(runtime.join(UTAB_MOUNTS_NAME).exists());
    // The configuration copy carries the effective TOML verbatim.
    assert_eq!(
        std::fs::read_to_string(runtime.join(CONFIG_COPY_NAME)).unwrap(),
        toml
    );
    // The runtime directory is private (0o700), as write_runtime sets it.
    let mode = std::fs::metadata(&runtime).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn fresh_home_without_the_operator_is_refused() {
    let run = tempfile::tempdir().unwrap();
    let hidden = tempfile::tempdir().unwrap();
    let binary = run.path().join("nails-running-binary");
    std::fs::write(&binary, b"bin").unwrap();
    let paths = Paths {
        root: run.path().join("root"),
        run: run.path().to_path_buf(),
    };
    let layout = Layout::new(hidden.path());
    // Fresh-home needs the operator (the sudo user) whose home is reset; with
    // none, the entry must refuse rather than silently do nothing. A body
    // replaced with Ok(()) would accept it.
    let inputs = minimal_inputs(hidden.path(), &binary, None);
    assert!(inputs.operator.is_none());

    let error = fresh_home(&paths, &inputs, &layout, &[]).unwrap_err();

    let text = error.to_string();
    assert!(text.contains("fresh-home"), "{text}");
    assert!(text.contains("operator"), "{text}");
    assert!(matches!(error, NailsError::InvalidState(_)));
}

#[test]
fn a_symlinked_fstab_mount_point_is_decided_at_its_real_path() {
    // The decoy keeps /home at var/home (an ostree layout).
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("var/home")).unwrap();
    std::os::unix::fs::symlink("var/home", root.path().join("home")).unwrap();

    // fstab names /home; nothing is mounted there now, so it is masked. The
    // masked unit is the one systemd generates for the real mount point,
    // var-home.mount, not home.mount, so the hidden session really masks it.
    let fstab = parse_in_root(b"/dev/sdb1 /home ext4 defaults 0 2\n", root.path());
    let decisions = decide_fstab(&fstab, &[], Path::new("/mnt/data")).unwrap();
    assert_eq!(policy::masked_units(&decisions), ["var-home.mount"]);
}

#[test]
fn the_automount_of_an_overlaid_symlinked_mount_point_is_masked_by_its_real_path() {
    // The decoy keeps /home at var/home, mounts the filesystem there, and
    // its fstab names /home behind an automount.
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("var/home")).unwrap();
    std::os::unix::fs::symlink("var/home", root.path().join("home")).unwrap();
    let mounts = parse_mountinfo(
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n\
         2 1 8:3 / /var/home rw - ext4 /dev/vda3 rw\n",
    );
    let fstab = parse_in_root(
        b"UUID=a /home ext4 defaults,x-systemd.automount 0 2\n",
        root.path(),
    );
    let decisions = decide_fstab(&fstab, &mounts, Path::new("/mnt/data")).unwrap();
    // The filesystem is overlaid where the decoy has it, and the automount
    // the hidden systemd generates for that path is masked with the same
    // resolved entries: left free, it would find the mount point taken and
    // fail local-fs.target, the emergency mode the mask prevents.
    assert_eq!(
        decisions,
        [Decision::Overlay {
            target: PathBuf::from("/var/home")
        }]
    );
    assert_eq!(policy::masks(&fstab, &decisions), ["var-home.automount"]);
}

#[test]
fn only_the_entries_the_next_root_resolves_elsewhere_are_decided_again() {
    let decoy = parse_fstab(
        "/dev/sdb1 /var/home ext4 defaults 0 2\n\
         /dev/sdc1 /srv ext4 defaults 0 2\n",
    );
    // In the next root the first entry's path is a directory of the hidden
    // session's own (no link to var/home there), the second unchanged.
    let in_nextroot = parse_fstab(
        "/dev/sdb1 /home ext4 defaults 0 2\n\
         /dev/sdc1 /srv ext4 defaults 0 2\n",
    );
    let elsewhere = resolved_elsewhere(&decoy, in_nextroot);
    assert_eq!(elsewhere.len(), 1, "{elsewhere:?}");
    assert_eq!(elsewhere[0].file, Path::new("/home"));
    // Decided there, where the decoy mounts nothing: masked, so the hidden
    // systemd never mounts the decoy's disk read-write at /home.
    let decisions = decide_elsewhere(&elsewhere, &[], Path::new("/mnt/data")).unwrap();
    assert_eq!(policy::masked_units(&decisions), ["home.mount"]);
}

#[test]
fn an_entry_a_link_leads_into_the_hidden_volume_is_masked_there() {
    // The decoy keeps /data and /media for disks it does not mount now. An
    // earlier session moved both onto the hidden volume, replacing each
    // directory with a link into it.
    let decoy = parse_fstab(
        "UUID=X /data ext4 defaults,nofail 0 2\n\
         UUID=Y /media ext4 noauto,x-systemd.automount 0 2\n",
    );
    let in_nextroot = parse_fstab(
        "UUID=X /mnt/data/data ext4 defaults,nofail 0 2\n\
         UUID=Y /mnt/data/media ext4 noauto,x-systemd.automount 0 2\n",
    );
    let elsewhere = resolved_elsewhere(&decoy, in_nextroot);
    assert_eq!(elsewhere.len(), 2, "{elsewhere:?}");
    // The hidden volume's own rule would leave them to the bind of the
    // volume, and the hidden systemd would mount the decoy's disks read-write
    // inside it. They are masked there, the automount with its mount.
    let decisions = decide_elsewhere(&elsewhere, &[], Path::new("/mnt/data")).unwrap();
    assert_eq!(
        policy::masked_units(&decisions),
        [
            "mnt-data-data.mount",
            "mnt-data-media.mount",
            "mnt-data-media.automount"
        ]
    );
}

/// Where SELinux runs.
const REQUIRED: Labels = Labels::Required(crate::session::labels::Reason::SelinuxRunning);

/// `alice`, with the uid and gid of whoever runs the tests and her home at
/// `home`.
fn alice(home: &str) -> crate::target_user::TargetUser {
    crate::target_user::TargetUser::for_test(
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw(),
        "alice",
        home,
        "/bin/sh",
    )
}

/// The status change time of `path`, which any attribute written moves.
fn ctime(path: &Path) -> (i64, i64) {
    let meta = std::fs::symlink_metadata(path).unwrap();
    (meta.ctime(), meta.ctime_nsec())
}

/// Long enough for a write to move a time, on a kernel whose timestamps are
/// coarse.
fn tick() {
    std::thread::sleep(std::time::Duration::from_millis(20));
}

/// A decoy root under `dir` without the operator's home, and the layout of a
/// hidden volume next to it.
fn home_world(dir: &Path) -> (Paths, Layout) {
    let paths = Paths {
        root: dir.join("root"),
        run: dir.join("run"),
    };
    std::fs::create_dir_all(&paths.root).unwrap();
    (paths, Layout::new(&dir.join("hidden")))
}

#[test]
fn the_way_to_the_home_starts_at_the_upper_of_the_filesystem_it_lives_on() {
    let paths = Paths {
        root: PathBuf::from("/decoy"),
        run: PathBuf::from("/scratch-run"),
    };
    let layout = Layout::new(Path::new("/mnt/data"));
    let mounts = parse_mountinfo(
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n\
         2 1 8:3 / /home rw - ext4 /dev/vda3 rw\n",
    );
    let way = HomeWay::of(&paths, &layout, &mounts, &alice("/home/alice"));
    assert_eq!(way.decoy, Path::new("/decoy/home"));
    assert_eq!(way.upper, Path::new("/mnt/data/root/mounts/home/upper"));
    assert_eq!(way.rest, Path::new("alice"));
    // A home on the decoy root is below the root upper.
    let way = HomeWay::of(&paths, &layout, &mounts[..1], &alice("/home/alice"));
    assert_eq!(way.decoy, Path::new("/decoy"));
    assert_eq!(way.upper, Path::new("/mnt/data/root/upper"));
    assert_eq!(way.rest, Path::new("home/alice"));
}

#[test]
fn a_fresh_home_entry_that_requires_the_labels_is_refused_where_the_decoy_has_none() {
    // Real calls, on any host: the decoy has no home for alice, so there is
    // no label for the home an earlier entry made, nor for its parent.
    let dir = tempfile::tempdir().unwrap();
    let (paths, layout) = home_world(dir.path());
    // That earlier entry made the home (the opaque mark on it needs
    // CAP_SYS_ADMIN, which no test has).
    let upper_home = layout.upper().join("home/alice");
    std::fs::create_dir_all(&upper_home).unwrap();
    let mut inputs = minimal_inputs(layout.hidden_root(), Path::new("/proc/self/exe"), None);
    inputs.persona.mode = crate::config::PersonaMode::FreshHome;
    inputs.operator = Some(alice("/home/alice"));
    inputs.labels = REQUIRED;
    let before = (ctime(&layout.upper().join("home")), ctime(&upper_home));
    tick();

    let text = persona_home(&paths, &inputs, &layout, &[])
        .unwrap_err()
        .to_string();
    assert!(
        text.ends_with(&format!(
            "but {} does not exist",
            paths.root.join("home").display()
        )),
        "{text}"
    );
    // Without SELinux facts the entry goes on and writes nothing on the way.
    inputs.labels = Labels::BestEffort;
    persona_home(&paths, &inputs, &layout, &[]).unwrap();
    assert_eq!(
        (ctime(&layout.upper().join("home")), ctime(&upper_home)),
        before
    );
}

#[test]
fn a_shared_home_entry_walks_only_as_far_as_the_upper_holds_the_way_to_the_home() {
    // Real calls, on any host.
    let dir = tempfile::tempdir().unwrap();
    let (paths, layout) = home_world(dir.path());
    let mut inputs = minimal_inputs(layout.hidden_root(), Path::new("/proc/self/exe"), None);
    assert_eq!(inputs.persona.mode, crate::config::PersonaMode::SharedHome);
    inputs.labels = REQUIRED;
    // An entry without an operator walks nothing.
    std::fs::create_dir_all(layout.upper().join("home/alice")).unwrap();
    persona_home(&paths, &inputs, &layout, &[]).unwrap();

    // The first entry, before the upper exists: nothing to walk.
    inputs.operator = Some(alice("/home/alice"));
    std::fs::remove_dir_all(layout.hidden_root()).unwrap();
    persona_home(&paths, &inputs, &layout, &[]).unwrap();
    assert!(!layout.hidden_root().exists(), "the walk made something");

    // What a refused fresh-home entry left for an operator the decoy has no
    // home for: refused where the labels are required, left as it is
    // without SELinux facts.
    let upper_home = layout.upper().join("home/alice");
    std::fs::create_dir_all(&upper_home).unwrap();
    let before = ctime(&upper_home);
    tick();
    let text = persona_home(&paths, &inputs, &layout, &[])
        .unwrap_err()
        .to_string();
    assert!(
        text.ends_with(&format!(
            "but {} does not exist",
            paths.root.join("home").display()
        )),
        "{text}"
    );
    inputs.labels = Labels::BestEffort;
    persona_home(&paths, &inputs, &layout, &[]).unwrap();
    assert_eq!(ctime(&upper_home), before);
}

/// The entry's own reading of the decoy's process numbers against a real
/// procfs, and the way back's measure and counter after it: the test runs as
/// PID 1 of a PID namespace of its own, so the processes it starts are all the
/// userspace there is, and the counter it sets is that namespace's.
mod kernel_tests {
    use super::*;
    use nails_base::test_support::{Rerun, skip_host};
    use nails_teardown::whole_root::fresh_pids::{self, Anchor, Lowered, Places};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};

    /// A shell run as `program` with `arg0` that waits on the input the test
    /// holds open, so it runs until the test ends it. dash and bash run as
    /// themselves under any name. `sleep` would not: a multi-call coreutils
    /// picks the program by the name it was run under, and uutils coreutils,
    /// Ubuntu 26.04's, by the path the kernel ran rather than argv[0], so
    /// through a link named after another program it runs that program, or
    /// none, and ends at once.
    fn waiting(program: &Path, arg0: &str) -> Child {
        Command::new(program)
            .arg0(arg0)
            .args(["-c", "read line"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    /// A process named `comm` that runs until the test ends it: a waiting
    /// shell ([`waiting`]) run through a link of that name, which the kernel
    /// names it after.
    fn start(dir: &Path, sh: &Path, comm: &str) -> Child {
        let link = dir.join(comm);
        if std::fs::symlink_metadata(&link).is_err() {
            std::os::unix::fs::symlink(sh, &link).unwrap();
        }
        waiting(&link, "sh")
    }

    /// End `child` and reap it.
    fn stop(mut child: Child) {
        child.kill().unwrap();
        child.wait().unwrap();
    }

    /// Use up `count` process numbers with shells that end at once.
    fn use_up(sh: &Path, count: usize) {
        for _ in 0..count {
            let status = Command::new(sh).args(["-c", ":"]).status().unwrap();
            assert!(status.success());
        }
    }

    #[test]
    fn the_entry_reads_the_process_numbers_of_the_running_system() {
        let _ = Rerun::new(nails_base::test_path!(
            the_entry_reads_the_process_numbers_of_the_running_system
        ))
        .in_pid_ns()
        .run(|| {
            let Some(sh) = nails_teardown::whole_root::tools::find(None, "sh") else {
                skip_host("no sh in the system directories");
            };
            let places = Places::system();
            let Some(before) = places.current() else {
                skip_host("this kernel has no ns_last_pid (CONFIG_CHECKPOINT_RESTORE)");
            };
            let dir = tempfile::tempdir().unwrap();
            // A root storage daemon, which a soft-reboot leaves running, with
            // the lowest number: it is no part of the start the entry reads.
            let mut storage = waiting(&sh, "@storage");
            // The decoy's userspace: its journal, the floor, and further on
            // its getty.
            let mut journal = start(dir.path(), &sh, "systemd-journal");
            use_up(&sh, 50);
            let mut getty = start(dir.path(), &sh, "agetty");
            let tty = nails_teardown::proc::stat(getty.id()).unwrap().tty;
            let mut record = RealEntryHost.pid_record();
            // One that had ended would be a zombie, which the entry leaves out.
            for child in [&mut storage, &mut journal, &mut getty] {
                assert_eq!(child.try_wait().unwrap(), None, "a stand-in ended");
            }
            assert!(before < storage.id() && storage.id() < journal.id());
            assert_eq!(record.floor, Some(journal.id()));
            assert_eq!(
                record.anchors,
                [Anchor {
                    comm: "agetty".to_string(),
                    tty,
                    pid: getty.id(),
                }]
            );

            // The switch, and a hidden start whose getty follows it.
            record.at_switch = places.current();
            let hidden = start(dir.path(), &sh, "agetty");
            let used = hidden.id() - record.at_switch.unwrap();
            record.counter = fresh_pids::counter(&record, Path::new("/proc"));
            assert_eq!(record.counter, Some(getty.id() - used));

            // The hidden session runs on and stops; the way back sets the
            // counter, and the next process gets a number below where it was.
            use_up(&sh, 20);
            stop(hidden);
            let reached = places.current().unwrap();
            let target = record.way_back_counter().unwrap();
            assert_eq!(
                fresh_pids::lower(Some(target), &places),
                Lowered::Set(target)
            );
            let next = start(dir.path(), &sh, "agetty");
            assert!(
                target < next.id() && next.id() <= reached,
                "{target} < {} <= {reached}",
                next.id()
            );
            for child in [storage, journal, getty, next] {
                stop(child);
            }
        });
    }
}
