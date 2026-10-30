// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::filesystem::{MockFilesystem, PathKind};

/// The command of `line` in `table`, as text.
fn line(text: &str, table: Table) -> Option<String> {
    command(text.as_bytes(), table).map(|(command, _)| String::from_utf8(command).unwrap())
}

/// The input cron feeds the job of `line` in `table`, as text.
fn fed(text: &str, table: Table) -> Option<String> {
    command(text.as_bytes(), table).map(|(_, input)| String::from_utf8(input).unwrap())
}

#[test]
fn a_system_crontab_line_names_its_user_before_the_command() {
    assert_eq!(
        line("0 3 * * * root updatedb -e /a", Table::System).as_deref(),
        Some("updatedb -e /a")
    );
    assert_eq!(
        line(
            "  */5\t1-3 * jan mon-fri   nobody  nice updatedb",
            Table::System
        )
        .as_deref(),
        Some("nice updatedb")
    );
    assert_eq!(
        line("@daily root updatedb", Table::System).as_deref(),
        Some("updatedb")
    );
    // A user's crontab names no user.
    assert_eq!(
        line("0 3 * * * updatedb -e /a", Table::User).as_deref(),
        Some("updatedb -e /a")
    );
    assert_eq!(
        line("@reboot /usr/bin/updatedb", Table::User).as_deref(),
        Some("/usr/bin/updatedb")
    );
}

#[test]
fn comments_settings_and_short_lines_are_no_jobs() {
    for table in [Table::System, Table::User, Table::Anacron] {
        for text in [
            "",
            "   ",
            "# 0 3 * * * root updatedb",
            "#0 3 * * * root updatedb",
            "  # 1 5 daily updatedb",
            "SHELL=/bin/sh",
            "PATH=/usr/sbin:/usr/bin",
            "@bogus root updatedb",
        ] {
            assert_eq!(line(text, table), None, "{table:?}: {text:?}");
        }
    }
    // Five time fields and a user, but no command.
    assert_eq!(line("0 3 * * * root", Table::System), None);
    assert_eq!(line("0 3 * * *", Table::User), None);
}

#[test]
fn the_command_ends_at_an_unescaped_percent() {
    assert_eq!(
        line("0 3 * * * root updatedb -e /a%rest%more", Table::System).as_deref(),
        Some("updatedb -e /a")
    );
    assert_eq!(
        line("0 3 * * * root updatedb -e /a\\%b", Table::System).as_deref(),
        Some("updatedb -e /a%b")
    );
    // Any other backslash is the shell's.
    assert_eq!(
        line("0 3 * * * root updatedb -e /a\\ b\\", Table::System).as_deref(),
        Some("updatedb -e /a\\ b\\")
    );
}

#[test]
fn the_rest_after_the_percent_is_the_input_cron_feeds_the_job() {
    let job = "0 * * * * root sh%updatedb.plocate --prunepaths /tmp%echo 50\\% done\\x";
    assert_eq!(line(job, Table::System).as_deref(), Some("sh"));
    assert_eq!(
        fed(job, Table::System).as_deref(),
        Some("updatedb.plocate --prunepaths /tmp\necho 50% done\\x")
    );
    assert_eq!(
        fed("0 * * * * root updatedb", Table::System).as_deref(),
        Some("")
    );
    // anacron hands the command to the shell as it is.
    assert_eq!(
        line("1 5 locate echo 50%; updatedb", Table::Anacron).as_deref(),
        Some("echo 50%; updatedb")
    );
}

#[test]
fn cronie_runs_a_job_it_does_not_log() {
    assert_eq!(
        line("-*/5 * * * * root updatedb -e /a", Table::System).as_deref(),
        Some("updatedb -e /a")
    );
    assert_eq!(
        line("-@hourly updatedb", Table::User).as_deref(),
        Some("updatedb")
    );
    for text in [
        "- 0 * * * * root updatedb",
        "-",
        "-# 0 * * * * root updatedb",
    ] {
        assert_eq!(line(text, Table::System), None, "{text}");
    }
    assert_eq!(line("-1 5 locate updatedb", Table::Anacron), None);
}

#[test]
fn an_anacrontab_line_is_period_delay_name_command() {
    assert_eq!(
        line(
            "1 5 cron.daily run-parts --report /etc/cron.daily",
            Table::Anacron
        )
        .as_deref(),
        Some("run-parts --report /etc/cron.daily")
    );
    assert_eq!(
        line("@monthly 15 locate updatedb -e /a", Table::Anacron).as_deref(),
        Some("updatedb -e /a")
    );
    for text in [
        "RANDOM_DELAY=45",
        "START_HOURS_RANGE=3-22",
        "x 5 job updatedb",
    ] {
        assert_eq!(line(text, Table::Anacron), None, "{text}");
    }
}

#[test]
fn debians_script_ends_under_systemd_and_a_changed_one_does_not() {
    let debian = include_str!("fixtures/debian-13-cron.daily-plocate");
    assert!(ends_under_systemd(debian.as_bytes()));
    // Plain settings before the test change nothing.
    let plain = debian.replace("set -e", "set -e\nIONICE=\nA_B=/x:y,z=1-2+3@4");
    assert!(ends_under_systemd(plain.as_bytes()));
    for changed in [
        // An assignment that runs a command runs it before the test.
        debian.replace("set -e", "set -e\nX=$(updatedb.plocate)"),
        debian.replace("set -e", "set -e\nX=`updatedb.plocate`"),
        debian.replace("set -e", "set -e\nX=\"a b\""),
        debian.replace("set -e", "set -e\nupdatedb"),
        debian.replace("exit 0\nfi", "true\nfi"),
        debian.replace("if [ -d /run/systemd/system ]; then", "if false; then"),
        String::new(),
    ] {
        assert!(!ends_under_systemd(changed.as_bytes()), "{changed}");
    }
}

/// A decoy whose files are `files` under `/`, each directory listing what
/// is added below it.
fn decoy(files: &[(&str, &str)]) -> MockFilesystem {
    let fs = MockFilesystem::new();
    let mut listings: std::collections::BTreeMap<PathBuf, Vec<PathBuf>> = Default::default();
    for (path, text) in files {
        fs.mock_add_file(path, text);
        let mut child = PathBuf::from(path);
        while let Some(parent) = child.parent().map(Path::to_path_buf) {
            let entries = listings.entry(parent.clone()).or_default();
            if !entries.contains(&child) {
                entries.push(child.clone());
            }
            child = parent;
        }
    }
    for (dir, entries) in listings {
        fs.mock_set_directory_contents(&dir, entries);
    }
    fs
}

fn jobs(fs: &MockFilesystem) -> Vec<CronJob> {
    let hidden = [PathBuf::from("/mnt/data")];
    let files = DecoyFiles::new(fs, Path::new("/"), &hidden);
    cron_jobs(fs, &files)
}

fn run(program: &str, args: &[&str]) -> ExecCommand {
    ExecCommand {
        program: program.as_bytes().to_vec(),
        args: args.iter().map(|arg| arg.as_bytes().to_vec()).collect(),
    }
}

/// A job as the tests compare it: its place, its removal and its runs.
type Summary<'a> = (
    &'a str,
    Option<&'a str>,
    &'a Vec<Result<ExecCommand, String>>,
);

#[test]
fn every_crontab_and_script_is_read() {
    let fs = decoy(&[
        (
            "/etc/crontab",
            "SHELL=/bin/sh\n# 30 2 * * * root updatedb\n\
             17 * * * * root cd / && run-parts --report /etc/cron.hourly\n\
             30 2 * * * root updatedb -e /a\n",
        ),
        (
            "/etc/cron.d/locate-extra",
            "30 * * * * root /usr/bin/updatedb --config-file /etc/updatedb-extra.conf\n",
        ),
        (
            "/var/spool/cron/crontabs/root",
            "0 * * * * /usr/sbin/updatedb.plocate\n",
        ),
        (
            "/var/spool/cron/alice",
            "@hourly nice updatedb -U /home/alice\n",
        ),
        (
            "/var/spool/cron/bob",
            "-0 * * * * sh%updatedb.plocate --prunepaths /tmp\n",
        ),
        ("/etc/anacrontab", "1 5 locate updatedb -e /b\n"),
        (
            "/etc/cron.weekly/locate",
            "#!/bin/sh\nexec /usr/bin/updatedb -e /c\n",
        ),
        (
            "/etc/cron.daily/logrotate",
            "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n",
        ),
    ]);
    // Debian's spool holds the crontabs directory, which is no crontab.
    fs.mock_set_path_type("/var/spool/cron/crontabs", PathKind::Dir);
    let found = jobs(&fs);
    let summary: Vec<Summary<'_>> = found
        .iter()
        .map(|job| (job.place.as_str(), job.removal.as_deref(), &job.runs))
        .collect();
    assert_eq!(
        summary,
        [
            (
                "line 4 of /etc/crontab",
                Some("remove line 4 of /etc/crontab"),
                &vec![Ok(run("updatedb", &["-e", "/a"]))]
            ),
            (
                "line 1 of /etc/cron.d/locate-extra",
                Some("remove line 1 of /etc/cron.d/locate-extra"),
                &vec![Ok(run(
                    "/usr/bin/updatedb",
                    &["--config-file", "/etc/updatedb-extra.conf"]
                ))]
            ),
            (
                "line 1 of /var/spool/cron/crontabs/root",
                Some("remove line 1 of /var/spool/cron/crontabs/root"),
                &vec![Ok(run("/usr/sbin/updatedb.plocate", &[]))]
            ),
            (
                "line 1 of /var/spool/cron/alice",
                Some("remove line 1 of /var/spool/cron/alice"),
                &vec![Ok(run("updatedb", &["-U", "/home/alice"]))]
            ),
            (
                "line 1 of /var/spool/cron/bob",
                Some("remove line 1 of /var/spool/cron/bob"),
                &vec![Ok(run("updatedb.plocate", &["--prunepaths", "/tmp"]))]
            ),
            (
                "line 1 of /etc/anacrontab",
                Some("remove line 1 of /etc/anacrontab"),
                &vec![Ok(run("updatedb", &["-e", "/b"]))]
            ),
            (
                "/etc/cron.weekly/locate",
                Some("remove /etc/cron.weekly/locate"),
                &vec![Ok(run("/usr/bin/updatedb", &["-e", "/c"]))]
            ),
        ]
    );
}

#[test]
fn a_job_the_shell_reader_cannot_follow_is_kept_with_its_reason() {
    let fs = decoy(&[("/etc/cron.d/x", "0 * * * * root updatedb $OPTIONS\n")]);
    let found = jobs(&fs);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].place, "line 1 of /etc/cron.d/x");
    assert_eq!(
        found[0].removal.as_deref(),
        Some("remove line 1 of /etc/cron.d/x")
    );
    assert!(
        matches!(&found[0].runs[..], [Err(why)] if why.contains("something the shell expands")),
        "{found:?}"
    );
}

#[test]
fn debians_own_script_is_no_job_under_systemd() {
    let fs = decoy(&[(
        "/etc/cron.daily/plocate",
        include_str!("fixtures/debian-13-cron.daily-plocate"),
    )]);
    assert!(jobs(&fs).is_empty());
}

#[test]
fn what_nails_cannot_read_may_hold_a_job() {
    // A directory that leads onto the hidden volume is not listed, and a
    // file larger than 1 MiB is not read.
    let fs = decoy(&[
        ("/mnt/data/cron.d/x", "0 * * * * root updatedb\n"),
        ("/etc/cron.daily/plocate", "#!/bin/sh\nupdatedb\n"),
        ("/etc/crontab", "0 * * * * root updatedb\n"),
    ]);
    fs.create_symlink(Path::new("/mnt/data/cron.d"), Path::new("/etc/cron.d"))
        .unwrap();
    fs.mock_set_file_size("/etc/cron.daily/plocate", 2 << 20);
    fs.mock_set_path_type("/etc/crontab", PathKind::Dir);
    let found = jobs(&fs);
    let unread: Vec<(&str, &str)> = found
        .iter()
        .filter(|job| job.removal.is_none())
        .map(|job| {
            (
                job.place.as_str(),
                job.runs[0].as_ref().unwrap_err().as_str(),
            )
        })
        .collect();
    assert_eq!(
        unread,
        [
            (
                "the crontab /etc/crontab",
                "/etc/crontab is not a regular file"
            ),
            (
                "the crontabs in /etc/cron.d",
                "/etc/cron.d leads onto the hidden volume"
            ),
            (
                "the cron script /etc/cron.daily/plocate",
                "/etc/cron.daily/plocate is larger than 1 MiB"
            ),
        ]
    );
}

#[test]
fn a_directory_the_system_cannot_list_may_hold_a_job() {
    use crate::RealFilesystem;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let etc = root.join("etc");
    std::fs::create_dir_all(&etc).unwrap();
    // A link that leads to itself: listing it fails with ELOOP.
    std::os::unix::fs::symlink(etc.join("cron.d"), etc.join("cron.d")).unwrap();
    let hidden = [root.join("mnt/data")];
    let files = DecoyFiles::new(&RealFilesystem, &root, &hidden);
    let found = cron_jobs(&RealFilesystem, &files);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].place, "the crontabs in /etc/cron.d");
    assert_eq!(found[0].removal, None);
    let prefix = format!("NAILS cannot list {} (", etc.join("cron.d").display());
    assert!(
        matches!(&found[0].runs[..], [Err(why)] if why.starts_with(&prefix)),
        "{found:?}"
    );
}

#[test]
fn the_files_of_a_directory_are_read_in_the_order_of_their_names() {
    let fs = decoy(&[
        ("/etc/cron.d/zz-second", "0 * * * * root updatedb -e /z\n"),
        ("/etc/cron.d/aa-first", "0 * * * * root updatedb -e /a\n"),
    ]);
    let places: Vec<String> = jobs(&fs).into_iter().map(|job| job.place).collect();
    assert_eq!(
        places,
        [
            "line 1 of /etc/cron.d/aa-first",
            "line 1 of /etc/cron.d/zz-second"
        ]
    );
}

#[test]
fn a_directory_only_root_may_list_asks_for_sudo() {
    use crate::RealFilesystem;
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let locked = root.join("var/spool/cron/crontabs");
    std::fs::create_dir_all(&locked).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Root lists it all the same, and then there is nothing to see.
    let listable = std::fs::read_dir(&locked).is_ok();
    let hidden = [root.join("mnt/data")];
    let files = DecoyFiles::new(&RealFilesystem, &root, &hidden);
    let found = cron_jobs(&RealFilesystem, &files);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    if listable {
        assert!(found.is_empty(), "{found:?}");
        return;
    }
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].place, "the crontabs in /var/spool/cron/crontabs");
    let why = format!(
        "NAILS cannot list {}; run the command again with sudo",
        locked.display()
    );
    assert_eq!(found[0].runs, [Err(why)]);
}
