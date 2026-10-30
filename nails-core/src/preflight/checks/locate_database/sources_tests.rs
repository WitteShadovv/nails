// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What starts updatedb on a decoy beyond the distributions' own timers, and
//! with which options: crontabs, other units, users' units and processes.

use super::tests::{
    ARCH, DEBIAN, DEBIAN_CRON, Decoy, FEDORA, FEDORA_SERVICE, MOUNTS, NIXOS_PRUNEPATHS, TIMER,
    debian, message, nixos, pruning_mnt,
};
use std::path::{Path, PathBuf};

/// Fedora 44 with plocate as it installs it, its timer enabled by preset,
/// and `conf` as its `/etc/updatedb.conf`.
fn fedora(conf: &str) -> Decoy {
    let decoy = Decoy::new();
    decoy
        .file("/etc/updatedb.conf", conf)
        .file(
            "/usr/lib/systemd/system/plocate-updatedb.service",
            FEDORA_SERVICE,
        )
        .file("/usr/lib/systemd/system/plocate-updatedb.timer", TIMER)
        .file("/usr/bin/updatedb", "")
        .enable("/etc/systemd/system", "plocate-updatedb.timer");
    decoy
}

/// The transient timer and service `systemd-run --on-calendar=hourly
/// /usr/bin/updatedb --prunepaths /tmp` makes in `dir`, as systemd writes
/// them: no link enables the timer, which runs from when it is made.
fn transient(decoy: &Decoy, dir: &str, timer: &str) {
    let stem = timer.strip_suffix(".timer").unwrap();
    let head = "# This is a transient unit file, created programmatically via the systemd API. \
                Do not edit.\n[Unit]\nDescription=[systemd-run] /usr/bin/updatedb --prunepaths \
                /tmp\n";
    decoy
        .file(
            &format!("{dir}/{timer}"),
            &format!("{head}\n[Timer]\nOnCalendar=hourly\nRemainAfterElapse=no\n"),
        )
        .file(
            &format!("{dir}/{stem}.service"),
            &format!(
                "{head}\n[Service]\nExecStart=\nExecStart=\"/usr/bin/updatedb\" \"--prunepaths\" \
                 \"/tmp\"\n"
            ),
        );
}

/// A drop-in that replaces the command of plocate's service.
const OVERRIDE: &str = "/etc/systemd/system/plocate-updatedb.service.d/override.conf";

fn exec_start(command: &str) -> String {
    format!("[Service]\nExecStart=\nExecStart={command}\n")
}

#[test]
fn a_cron_job_with_its_own_configuration_file_is_judged_with_that_file() {
    // /etc/updatedb.conf prunes /mnt, as the check advises; the job reads
    // another file.
    let decoy = fedora(&pruning_mnt(FEDORA));
    decoy
        .file(
            "/etc/cron.d/locate-extra",
            "30 * * * * root /usr/bin/updatedb --config-file /etc/updatedb-extra.conf -o \
             /var/lib/plocate/extra.db\n",
        )
        .file("/etc/updatedb-extra.conf", "PRUNEPATHS = \"/tmp\"\n");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains(
            "the cron job at line 1 of /etc/cron.d/locate-extra runs updatedb, and it does not \
             skip the hidden volume at /mnt/data: a run while the volume is mounted writes the \
             name of every file on it into /var/lib/plocate/extra.db on the decoy disk"
        ),
        "{result:?}"
    );
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("or remove line 1 of /etc/cron.d/locate-extra"),
        "{result:?}"
    );

    // That file pruning /mnt passes, and is named.
    decoy
        .fs
        .mock_set_file_content("/etc/updatedb-extra.conf", "PRUNEPATHS = \"/mnt /tmp\"\n");
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");
    assert!(
        message(&result).contains("PRUNEPATHS in /etc/updatedb-extra.conf lists /mnt"),
        "{result:?}"
    );

    // A file it names that does not exist stops it.
    decoy
        .fs
        .mock_set_path_exists("/etc/updatedb-extra.conf", false);
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "updatedb stops before it scans, because /etc/updatedb-extra.conf, which \
             --config-file names, does not exist (line 1 of /etc/cron.d/locate-extra)"
        ),
        "{result:?}"
    );
}

#[test]
fn an_option_counts_in_every_form_getopt_takes() {
    for line in [
        // A unique prefix of --database-root, and -U in a cluster: the scan
        // starts on the volume.
        "updatedb --data=/mnt/data -o /var/lib/x.db",
        "updatedb -vU/mnt/data -o /var/lib/x.db",
        // A prefix of --config-file, and its argument after a `=`.
        "updatedb --conf /etc/updatedb-extra.conf",
        "updatedb --config-file=/etc/updatedb-extra.conf",
    ] {
        let decoy = fedora(&pruning_mnt(FEDORA));
        decoy
            .file("/etc/cron.d/x", &format!("0 * * * * root {line}\n"))
            .file("/etc/updatedb-extra.conf", "PRUNEPATHS = \"/tmp\"\n");
        let result = decoy.check(false);
        assert!(result.is_fail(), "{line}: {result:?}");
    }
}

#[test]
fn an_execstart_with_its_own_configuration_file_is_judged_with_that_file() {
    let decoy = fedora(&pruning_mnt(FEDORA));
    decoy
        .file(
            OVERRIDE,
            &exec_start("/usr/bin/updatedb --config-file /etc/updatedb.local.conf"),
        )
        .file("/etc/updatedb.local.conf", "PRUNEPATHS = \"/tmp\"\n");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains(
            "plocate-updatedb.timer schedules updatedb, and it does not skip the hidden volume"
        ),
        "{result:?}"
    );

    // Given twice, it stops updatedb.
    decoy.fs.mock_set_file_content(
        OVERRIDE,
        &exec_start("/usr/bin/updatedb --config-file /etc/a --config-file /etc/b"),
    );
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "updatedb stops before it scans, because --config-file is given twice (the \
             ExecStart of plocate-updatedb.service)"
        ),
        "{result:?}"
    );
}

#[test]
fn a_database_root_is_resolved_on_the_decoy() {
    // A scan of /home alone does not reach the volume.
    let decoy = Decoy::new();
    decoy
        .file("/etc/updatedb.conf", DEBIAN)
        .file(
            "/usr/lib/systemd/system/plocate-updatedb.service",
            FEDORA_SERVICE,
        )
        .file("/usr/lib/systemd/system/plocate-updatedb.timer", TIMER)
        .enable("/etc/systemd/system", "plocate-updatedb.timer")
        .file(
            OVERRIDE,
            &exec_start("/usr/bin/updatedb -U /home -o /var/lib/plocate/home.db"),
        );
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        message(&result),
        "updatedb skips the hidden volume: --database-root in the ExecStart of \
         plocate-updatedb.service starts the scan at /home, which does not hold /mnt/data"
    );

    // A link that leads there leads the scan onto the volume.
    decoy.link("/home", "/mnt/data/home");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
}

#[test]
fn a_relative_path_is_resolved_where_updatedb_runs() {
    // `cd /mnt && updatedb -U data -o /root/x.db`: the scan starts on the
    // volume, wherever else a /data lies.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .mask("plocate-updatedb.timer")
        .file("/data/x", "")
        .process(
            9,
            "updatedb",
            &["updatedb", "-U", "data", "-o", "/root/x.db"],
        )
        .link("/proc/9/cwd", "/mnt");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains(
            "an updatedb runs now (updatedb runs as process 9), and it does not skip the hidden \
             volume at /mnt/data: a run while the volume is mounted writes the name of every \
             file on it into /root/x.db"
        ),
        "{result:?}"
    );

    // cron runs a job from its user's home, which NAILS does not read.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .mask("plocate-updatedb.timer")
        .file("/etc/cron.d/x", "0 * * * * root updatedb -U data\n");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "it names data relative to a directory NAILS does not know: cron runs a job from \
             its user's home (line 1 of /etc/cron.d/x)"
        ),
        "{result:?}"
    );
}

#[test]
fn every_crontab_schedules_a_run() {
    for (path, text, line) in [
        (
            "/var/spool/cron/crontabs/root",
            "0 * * * * /usr/sbin/updatedb.plocate\n",
            1,
        ),
        ("/var/spool/cron/alice", "@hourly updatedb\n", 1),
        (
            "/etc/anacrontab",
            "1 10 locate /usr/sbin/updatedb.plocate\n",
            1,
        ),
        (
            "/etc/crontab",
            "# m h dom mon dow user command\n30 2 * * * root updatedb\n",
            2,
        ),
    ] {
        let decoy = debian(DEBIAN);
        decoy.mask("plocate-updatedb.timer").file(path, text);
        let result = decoy.check(false);
        assert!(result.is_fail(), "{path}: {result:?}");
        assert!(
            message(&result).contains(&format!(
                "the cron job at line {line} of {path} runs updatedb, and it does not skip"
            )),
            "{path}: {result:?}"
        );
        // The fix names the line, not the crontab that holds it.
        assert!(
            result
                .remediation()
                .unwrap()
                .contains(&format!("or remove line {line} of {path}")),
            "{path}: {result:?}"
        );
    }
}

#[test]
fn a_commented_out_job_and_a_leftover_script_install_nothing() {
    let decoy = Decoy::new();
    decoy
        .file("/etc/updatedb.conf", DEBIAN)
        .file(
            "/etc/crontab",
            "#30 2 * * * root updatedb\n17 * * * * root cd / && run-parts --report \
             /etc/cron.hourly\n",
        )
        // `apt remove plocate` leaves Debian's conffiles: its cron job ends
        // at once under systemd.
        .file("/etc/cron.daily/plocate", DEBIAN_CRON);
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        message(&result),
        "no updatedb (plocate, mlocate or findutils' locate) is installed on the decoy"
    );
}

/// Debian's service and timer without the program, so that only the units
/// count.
fn units_only() -> Decoy {
    let decoy = Decoy::new();
    decoy
        .file("/etc/updatedb.conf", DEBIAN)
        .file(
            "/usr/lib/systemd/system/plocate-updatedb.service",
            FEDORA_SERVICE,
        )
        .file("/usr/lib/systemd/system/plocate-updatedb.timer", TIMER);
    decoy
}

#[test]
fn an_installed_service_nothing_starts_runs_by_hand() {
    // Neither enabled nor masked: a person starts it.
    let result = units_only().check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result)
            .contains("updatedb can be started by hand (systemctl start plocate-updatedb.service)"),
        "{result:?}"
    );
    // A timer link that leads nowhere starts nothing either.
    let decoy = units_only();
    decoy.enable("/etc/systemd/system", "other.timer");
    assert!(decoy.check(false).is_warn());
}

#[test]
fn a_service_that_runs_no_updatedb_says_so() {
    let decoy = units_only();
    decoy
        .enable("/etc/systemd/system", "plocate-updatedb.timer")
        .file(
            "/etc/systemd/system/plocate-updatedb.service.d/off.conf",
            "[Service]\nExecStart=\n",
        );
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        message(&result),
        "nothing runs updatedb: plocate-updatedb.service runs no updatedb command"
    );

    // An empty unit file masks it, as a link to /dev/null does.
    let decoy = units_only();
    decoy
        .enable("/etc/systemd/system", "plocate-updatedb.timer")
        .file("/etc/systemd/system/plocate-updatedb.service", "");
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        message(&result),
        "nothing runs updatedb: plocate-updatedb.service is masked"
    );
}

#[test]
fn a_service_enabled_itself_runs_whenever_its_manager_starts() {
    let decoy = debian(DEBIAN);
    decoy.mask("plocate-updatedb.timer").wants(
        "/etc/systemd/system",
        "multi-user.target",
        "plocate-updatedb.service",
    );
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains(
            "plocate-updatedb.service is enabled and runs updatedb whenever its manager \
             starts, and it does not skip the hidden volume at /mnt/data"
        ),
        "{result:?}"
    );
    assert!(
        result.remediation().unwrap().contains(
            "mask plocate-updatedb.service (`sudo systemctl mask --now plocate-updatedb.service`)"
        ),
        "{result:?}"
    );
    // A dependency entry that leads to /dev/null is a masked one.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .mask("plocate-updatedb.timer")
        .link(
            "/etc/systemd/system/multi-user.target.wants/locate.service",
            "/dev/null",
        )
        .file(
            "/etc/systemd/system/locate.service",
            "[Service]\nExecStart=/usr/bin/updatedb --prunepaths /tmp\n",
        );
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn any_timer_or_path_unit_that_starts_the_service_schedules_it() {
    for (unit, target, text) in [
        (
            "nightly-index.timer",
            "timers.target",
            "[Timer]\nOnCalendar=*-*-* 03:00\nUnit=plocate-updatedb.service\n",
        ),
        (
            "index-on-change.path",
            "paths.target",
            "[Path]\nPathChanged=/etc/fstab\nUnit=plocate-updatedb.service\n",
        ),
    ] {
        let decoy = debian(DEBIAN);
        decoy
            .mask("plocate-updatedb.timer")
            .file(&format!("/etc/systemd/system/{unit}"), text)
            .wants("/etc/systemd/system", target, unit);
        let result = decoy.check(false);
        assert!(result.is_fail(), "{unit}: {result:?}");
        assert!(
            message(&result).contains(&format!("{unit} schedules updatedb")),
            "{unit}: {result:?}"
        );
        assert!(
            result
                .remediation()
                .unwrap()
                .contains(&format!("`sudo systemctl mask --now {unit}`")),
            "{unit}: {result:?}"
        );
    }

    // A timer of its own that starts a service of its own, whose updatedb
    // a wrapper runs.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .file(
            "/etc/systemd/system/reindex.service",
            "[Service]\nType=oneshot\nExecStartPre=/usr/bin/true\nExecStart=/usr/bin/flock \
             /run/x.lock /usr/sbin/updatedb.plocate --prunepaths /tmp\n",
        )
        .file("/etc/systemd/system/reindex.timer", TIMER)
        .enable("/etc/systemd/system", "reindex.timer");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains(
            "reindex.timer schedules updatedb, and it does not skip the hidden volume at \
             /mnt/data: a run while the volume is mounted writes the name of every file on it \
             into the locate database"
        ),
        "{result:?}"
    );
}

#[test]
fn an_enabled_instance_runs_its_template() {
    let decoy = debian(DEBIAN);
    decoy
        .mask("plocate-updatedb.timer")
        .file(
            "/etc/systemd/system/index@.service",
            "[Service]\nExecStart=/usr/bin/updatedb -o /var/lib/index.db\n",
        )
        .wants(
            "/etc/systemd/system",
            "multi-user.target",
            "index@home.service",
        );
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains("index@home.service is enabled and runs updatedb"),
        "{result:?}"
    );
    // The template's drop-ins apply to the instance.
    decoy.file(
        "/etc/systemd/system/index@.service.d/skip.conf",
        "[Service]\nExecStart=\nExecStart=/usr/bin/updatedb -U /home\n",
    );
    assert!(decoy.check(false).is_warn());
}

#[test]
fn a_users_timer_schedules_a_run() {
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .file(
            "/etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
        )
        .file(
            "/home/alice/.config/systemd/user/locate.service",
            "[Service]\nExecStart=/usr/bin/updatedb --prunepaths /tmp -o \
             /home/alice/.locate.db\n",
        )
        .file("/home/alice/.config/systemd/user/locate.timer", TIMER)
        .enable("/home/alice/.config/systemd/user", "locate.timer");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains("locate.timer of alice's manager schedules updatedb"),
        "{result:?}"
    );
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("mask locate.timer as alice (`systemctl --user mask --now locate.timer`)"),
        "{result:?}"
    );

    // A transient one, as `systemd-run --user --on-calendar` makes it: it
    // runs from when it is made, without any link to it.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy.file(
        "/etc/passwd",
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
    );
    transient(&decoy, "/run/user/1000/systemd/transient", "run-r9.timer");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains("run-r9.timer of alice's manager schedules updatedb"),
        "{result:?}"
    );
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("stop run-r9.timer as alice (`systemctl --user stop run-r9.timer`)"),
        "{result:?}"
    );

    // One that every user's manager runs, named once for all of them.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .file(
            "/etc/passwd",
            "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
        )
        .file(
            "/usr/lib/systemd/user/locate.service",
            "[Service]\nExecStart=/usr/bin/updatedb --prunepaths /tmp\n",
        )
        .file("/usr/lib/systemd/user/locate.timer", TIMER)
        .enable("/etc/systemd/user", "locate.timer");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains("locate.timer of every user's manager schedules updatedb"),
        "{result:?}"
    );
    assert!(!message(&result).contains("alice's manager"), "{result:?}");
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("`sudo systemctl --global mask locate.timer`"),
        "{result:?}"
    );
}

#[test]
fn a_users_service_runs_from_their_home() {
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .file(
            "/etc/passwd",
            "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
        )
        .file(
            "/home/alice/.config/systemd/user/locate.service",
            "[Service]\nExecStart=/usr/bin/updatedb --prunepaths /tmp -U data\n",
        )
        .file("/home/alice/.config/systemd/user/locate.timer", TIMER)
        .enable("/home/alice/.config/systemd/user", "locate.timer");
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");
    assert!(
        message(&result).contains("starts the scan at /home/alice/data, which does not hold"),
        "{result:?}"
    );
    // That directory leads onto the volume.
    decoy.link("/home/alice/data", "/mnt/data");
    assert!(decoy.check(false).is_fail());

    // Every user's manager runs it from each user's own home.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .file(
            "/etc/systemd/user/locate.service",
            "[Service]\nExecStart=/usr/bin/updatedb --prunepaths /tmp -U data\n",
        )
        .file("/etc/systemd/user/locate.timer", TIMER)
        .enable("/etc/systemd/user", "locate.timer");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains("every user's manager runs it from that user's home"),
        "{result:?}"
    );
}

#[test]
fn a_unit_in_any_directory_systemd_reads_counts() {
    // Arch prunes /mnt; a drop-in in /usr/local/lib replaces what the
    // timer's run prunes.
    let decoy = Decoy::new();
    decoy
        .file("/etc/updatedb.conf", ARCH)
        .file(
            "/usr/lib/systemd/system/plocate-updatedb.service",
            FEDORA_SERVICE,
        )
        .file("/usr/lib/systemd/system/plocate-updatedb.timer", TIMER)
        .enable("/usr/lib/systemd/system", "plocate-updatedb.timer")
        .file(
            "/usr/local/lib/systemd/system/plocate-updatedb.service.d/override.conf",
            &exec_start("/usr/bin/updatedb --prunepaths /tmp"),
        );
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result)
            .contains("plocate-updatedb.timer schedules updatedb, and it does not skip"),
        "{result:?}"
    );
}

#[test]
fn what_nails_cannot_read_may_start_updatedb() {
    // A link onto the volume, as a directory or file an unprivileged check
    // may not read, keeps NAILS from reading it.
    for (path, target, finding) in [
        (
            "/etc/cron.d",
            "/mnt/data/cron.d",
            "the crontabs in /etc/cron.d may start updatedb, which NAILS cannot tell: \
             /etc/cron.d leads onto the hidden volume",
        ),
        (
            "/run/systemd/system",
            "/mnt/data/units",
            "the units in /run/systemd/system may start updatedb, which NAILS cannot tell: \
             /run/systemd/system leads onto the hidden volume",
        ),
    ] {
        let decoy = debian(&pruning_mnt(DEBIAN));
        decoy.file(&format!("{target}/x"), "").link(path, target);
        let result = decoy.check(false);
        assert!(result.is_warn(), "{path}: {result:?}");
        assert!(message(&result).contains(finding), "{path}: {result:?}");
    }

    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .fs
        .mock_set_file_size("/etc/cron.daily/plocate", 2 << 20);
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "the cron script /etc/cron.daily/plocate may start updatedb, which NAILS cannot \
             tell: /etc/cron.daily/plocate is larger than 1 MiB"
        ),
        "{result:?}"
    );

    // A dependency directory NAILS cannot list leaves the others read.
    let decoy = Decoy::new();
    decoy
        .file("/mnt/data/wants/x", "")
        .link("/etc/systemd/system/aaa.target.wants", "/mnt/data/wants")
        .file("/etc/updatedb.conf", DEBIAN)
        .file(
            "/usr/lib/systemd/system/plocate-updatedb.service",
            FEDORA_SERVICE,
        )
        .file("/usr/lib/systemd/system/plocate-updatedb.timer", TIMER)
        .enable("/etc/systemd/system", "plocate-updatedb.timer");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains("plocate-updatedb.timer schedules updatedb"),
        "{result:?}"
    );

    // Nothing NAILS cannot read matters while no updatedb is installed.
    let decoy = Decoy::new();
    decoy
        .file("/mnt/data/cron.d/x", "")
        .link("/etc/cron.d", "/mnt/data/cron.d");
    assert!(decoy.check(false).is_pass());
}

#[test]
fn an_escape_systemd_does_not_know_keeps_its_backslash() {
    // systemd runs this with the list replaced: /mnt is not pruned.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy.file(
        OVERRIDE,
        &exec_start("/usr/sbin/updatedb.plocate --prunepaths \"/tmp /var/\\qtmp\""),
    );
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
}

#[test]
fn an_updatedb_that_is_a_script_cannot_be_told_about() {
    // findutils' updatedb is a shell script: its process is the shell, its
    // name updatedb.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy.process(
        7,
        "updatedb",
        &["/bin/sh", "/usr/bin/updatedb", "--prunepaths=/tmp"],
    );
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains("process 7 runs an updatedb that is a script"),
        "{result:?}"
    );

    // Where the decoy's updatedb leads to findutils', a bare `updatedb` is
    // that one.
    let decoy = Decoy::new();
    decoy
        .file("/etc/updatedb.conf", &pruning_mnt(DEBIAN))
        .file("/usr/bin/updatedb.findutils", "#!/bin/sh\n")
        .link("/usr/bin/updatedb", "/etc/alternatives/updatedb")
        .link("/etc/alternatives/updatedb", "/usr/bin/updatedb.findutils")
        .file(
            "/etc/crontab",
            "0 3 * * * root updatedb\n0 4 * * * root /usr/bin/updatedb\n",
        )
        .process(8, "updatedb", &["updatedb"]);
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    for part in [
        "line 1 of /etc/crontab runs findutils' updatedb",
        "line 2 of /etc/crontab runs findutils' updatedb",
        "the command line of process 8 runs findutils' updatedb",
        "/usr/bin/updatedb is findutils' updatedb",
    ] {
        assert!(message(&result).contains(part), "{part}: {result:?}");
    }
}

#[test]
fn a_service_that_names_no_updatedb_changes_nothing() {
    // Their commands take values from the environment, which NAILS does not
    // read, and name no updatedb.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .file(
            "/usr/lib/systemd/system/ssh.service",
            "[Service]\nExecStart=/usr/sbin/sshd -D $SSHD_OPTS\nExecReload=/bin/kill -HUP \
             $MAINPID\n",
        )
        .wants("/etc/systemd/system", "multi-user.target", "ssh.service")
        .file(
            "/usr/lib/systemd/system/getty@.service",
            "[Service]\nExecStart=-/sbin/agetty -o '-p -- %I' --noclear - $TERM\n",
        )
        .wants("/etc/systemd/system", "getty.target", "getty@tty1.service")
        .file(
            "/usr/lib/systemd/system/broken.service",
            "[Service]\nExecStart=/bin/echo 'open\n",
        )
        .wants("/etc/systemd/system", "multi-user.target", "broken.service");
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn the_nixos_fix_joins_a_list_the_configuration_sets() {
    for prune_paths in [&["/tmp", "/nix/store"][..], &[]] {
        let result = nixos(prune_paths, &[]).check(true);
        assert!(result.is_fail(), "{prune_paths:?}: {result:?}");
        let remediation = result.remediation().unwrap();
        assert!(
            remediation.contains(
                "the decoy's configuration sets its own services.locate.prunePaths, so add \
                 \"/mnt\" to that list and rebuild the decoy"
            ),
            "{remediation}"
        );
        assert!(!remediation.contains("mkOptionDefault"), "{remediation}");
    }
    // The default list in another order is still the default.
    let mut shuffled = NIXOS_PRUNEPATHS.to_vec();
    shuffled.reverse();
    let result = nixos(&shuffled, &[]).check(true);
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("lib.mkOptionDefault"),
        "{result:?}"
    );
}

#[test]
fn a_mount_below_the_hidden_root_is_pruned_with_it() {
    // A subvolume of the hidden volume mounted below its root: the fix still
    // names its parent alone, never the mount point.
    let decoy = nixos(NIXOS_PRUNEPATHS, &[]);
    decoy.fs.mock_set_mount_table(&format!(
        "{MOUNTS}41 40 254:16 /snap /mnt/data/.snapshots rw,relatime shared:21 - ext4 \
         /dev/mapper/data rw\n"
    ));
    let result = decoy.check(true);
    assert!(result.is_fail(), "{result:?}");
    let remediation = result.remediation().unwrap();
    assert!(
        remediation.contains("`services.locate.prunePaths = lib.mkOptionDefault [ \"/mnt\" ];`"),
        "{remediation}"
    );
    assert!(!remediation.contains("\"/mnt/data"), "{remediation}");
    assert!(
        remediation.contains("unmount /mnt/data and /mnt/data/.snapshots"),
        "{remediation}"
    );
}

#[test]
fn the_fix_names_each_directory_once_and_only_the_topmost() {
    // Two mounts of the volume in one directory: that directory, once.
    let decoy = debian(DEBIAN);
    decoy.fs.mock_set_mount_table(&format!(
        "{MOUNTS}41 22 254:16 / /mnt/copy rw,relatime shared:21 - ext4 /dev/mapper/data rw\n"
    ));
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("make updatedb skip /mnt: add /mnt to PRUNEPATHS in /etc/updatedb.conf"),
        "{result:?}"
    );

    // Two in different directories: both, and one below the other only
    // through it.
    for (mounts, fix) in [
        (
            "41 22 254:16 / /srv/copy rw,relatime shared:21 - ext4 /dev/mapper/data rw\n",
            "make updatedb skip /mnt and /srv: add /mnt /srv to PRUNEPATHS",
        ),
        (
            "41 22 254:16 / /mnt/data2/deeper/copy rw,relatime shared:21 - ext4 \
             /dev/mapper/data rw\n",
            "make updatedb skip /mnt: add /mnt to PRUNEPATHS",
        ),
    ] {
        let decoy = debian(DEBIAN);
        decoy.fs.mock_set_mount_table(&format!("{MOUNTS}{mounts}"));
        let result = decoy.check(false);
        assert!(result.is_fail(), "{result:?}");
        assert!(
            result.remediation().unwrap().contains(fix),
            "{fix}: {result:?}"
        );
    }
}

#[test]
fn a_command_systemd_runs_is_read_word_by_word() {
    for (command, why) in [
        // The script of `sh -c` may run another updatedb than its name.
        (
            "/bin/sh -c 'updatedb --prunepaths /tmp' updatedb",
            "it runs /bin/sh, which names updatedb before the updatedb it runs",
        ),
        // An argument from the environment.
        (
            "/usr/sbin/updatedb.plocate -e $DIR",
            "NAILS cannot read its ExecStart= (it takes an argument from an environment \
             variable)",
        ),
    ] {
        let decoy = debian(&pruning_mnt(DEBIAN));
        decoy.file(OVERRIDE, &exec_start(command));
        let result = decoy.check(false);
        assert!(result.is_warn(), "{command}: {result:?}");
        assert!(
            message(&result).contains(&format!(
                "plocate-updatedb.timer schedules updatedb, and NAILS cannot tell whether it \
                 skips the hidden volume: {why}"
            )),
            "{command}: {result:?}"
        );
    }
    // A relative path in a service that sets its own working directory.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy.file(
        OVERRIDE,
        "[Service]\nWorkingDirectory=/srv\nExecStart=\nExecStart=/usr/sbin/updatedb.plocate -U \
         data\n",
    );
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "it names data relative to a directory NAILS does not know: \
             plocate-updatedb.service sets WorkingDirectory="
        ),
        "{result:?}"
    );
}

#[test]
fn a_service_whose_files_nails_cannot_read_cannot_be_told_about() {
    // plocate's own service: its timer schedules updatedb, and its drop-ins
    // are not known.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy.file("/mnt/data/dropins/x.conf", "").link(
        "/etc/systemd/system/plocate-updatedb.service.d",
        "/mnt/data/dropins",
    );
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "plocate-updatedb.timer schedules updatedb, and NAILS cannot tell whether it skips \
             the hidden volume: /etc/systemd/system/plocate-updatedb.service.d leads onto the \
             hidden volume"
        ),
        "{result:?}"
    );

    // Another enabled service only may run updatedb.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .file(
            "/etc/systemd/system/locate.service",
            "[Service]\nExecStart=/usr/bin/true\n",
        )
        .wants("/etc/systemd/system", "multi-user.target", "locate.service")
        .file("/mnt/data/dropins/x.conf", "")
        .link("/etc/systemd/system/locate.service.d", "/mnt/data/dropins");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "locate.service may start updatedb, which NAILS cannot tell: \
             /etc/systemd/system/locate.service.d leads onto the hidden volume"
        ),
        "{result:?}"
    );
}

#[test]
fn only_the_numbered_entries_of_proc_are_processes() {
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .file("/proc/self/comm", "updatedb\n")
        .file("/proc/self/cmdline", "updatedb\0--prunepaths\0/tmp\0");
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");

    // Processes come in the order of their numbers as names, and a command
    // line without a NUL at its end keeps its last word.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .process(9, "updatedb", &["updatedb", "--prunepaths", "/tmp"])
        .process(10, "updatedb", &["updatedb", "--prunepaths", "/tmp"])
        .file("/proc/11/comm", "updatedb\n")
        .file("/proc/11/cmdline", "updatedb\0-U\0/mnt/data");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    let message = message(&result);
    let at = |pid: &str| {
        message
            .find(&format!("updatedb runs as process {pid})"))
            .unwrap_or_else(|| panic!("{pid}: {message}"))
    };
    assert!(at("10") < at("11") && at("11") < at("9"), "{message}");
}

#[test]
fn a_dropin_of_the_unit_outranks_one_of_its_type_and_only_conf_files_count() {
    // The unit's own drop-in directories come before those of its type in
    // every unit directory, so the same name in /usr/lib's
    // plocate-updatedb.service.d wins over /etc's service.d.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .file(
            "/etc/systemd/system/service.d/10-locate.conf",
            &exec_start("/usr/sbin/updatedb.plocate --prunepaths /tmp"),
        )
        .file(
            "/usr/lib/systemd/system/plocate-updatedb.service.d/10-locate.conf",
            &exec_start("/usr/sbin/updatedb.plocate -e /mnt"),
        );
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");

    // A file that does not end in .conf, or whose name starts with a dot, is
    // no drop-in.
    let decoy = debian(&pruning_mnt(DEBIAN));
    for name in ["override.conf.bak", ".override.conf"] {
        decoy.file(
            &format!("/etc/systemd/system/plocate-updatedb.service.d/{name}"),
            &exec_start("/usr/sbin/updatedb.plocate --prunepaths /tmp"),
        );
    }
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn a_store_updatedb_writes_where_its_package_says() {
    // NixOS's mlocate in the store: no database NAILS knows of.
    let decoy = Decoy::new();
    decoy
        .file("/etc/updatedb.conf", "PRUNEPATHS=\"/tmp\"\n")
        .file(
            "/nix/store/0000000000000000000000000000000-mlocate-0.26/bin/updatedb",
            "",
        )
        .link(
            "/run/current-system/sw/bin/updatedb",
            "/nix/store/0000000000000000000000000000000-mlocate-0.26/bin/updatedb",
        );
    let result = decoy.check(true);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "updatedb can be started by hand (/run/current-system/sw/bin/updatedb), and it does \
             not skip the hidden volume at /mnt/data: a run while the volume is mounted writes \
             the name of every file on it into the locate database on the decoy disk"
        ),
        "{result:?}"
    );
}

#[test]
fn a_transient_timer_schedules_a_run() {
    // `systemd-run --on-calendar=hourly /usr/bin/updatedb --prunepaths /tmp`
    // on Fedora, whose file prunes /mnt: the system manager lists the timer.
    let decoy = fedora(&pruning_mnt(FEDORA));
    transient(&decoy, "/run/systemd/transient", "run-r3e2f8c.timer");
    decoy.start("run-r3e2f8c.timer");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains(
            "run-r3e2f8c.timer schedules updatedb, and it does not skip the hidden volume"
        ),
        "{result:?}"
    );
    // Masking does not reach a transient unit: stopping it ends it.
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("stop run-r3e2f8c.timer (`sudo systemctl stop run-r3e2f8c.timer`)"),
        "{result:?}"
    );

    // Stopped, its file may stay until systemd collects it: what the system
    // manager lists decides.
    let decoy = fedora(&pruning_mnt(FEDORA));
    transient(&decoy, "/run/systemd/transient", "run-r3e2f8c.timer");
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");
    // Where NAILS cannot ask, the file counts.
    decoy.unasked("`systemctl list-units` failed (no bus)");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
}

#[test]
fn a_trigger_the_system_manager_runs_counts_without_a_file_of_its_own() {
    // `systemctl start reindex@home.timer`: an instance of a template.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .file(
            "/usr/lib/systemd/system/reindex@.timer",
            "[Timer]\nOnCalendar=hourly\n",
        )
        .file(
            "/usr/lib/systemd/system/reindex@.service",
            "[Service]\nExecStart=/usr/sbin/updatedb.plocate --prunepaths /tmp\n",
        );
    decoy.start("reindex@home.timer");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains("reindex@home.timer schedules updatedb"),
        "{result:?}"
    );

    // A timer whose file was deleted since it started runs as loaded: the
    // service of its own name is judged, and what else it may start warns.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy.file(
        "/usr/lib/systemd/system/gone.service",
        "[Service]\nExecStart=/usr/sbin/updatedb.plocate --prunepaths /tmp\n",
    );
    decoy.start("gone.timer");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains("gone.timer schedules updatedb"),
        "{result:?}"
    );
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy.start("gone.timer");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "gone.timer may start updatedb, which NAILS cannot tell: the system manager runs \
             gone.timer, and NAILS finds no file of it to read what it starts"
        ),
        "{result:?}"
    );
}

/// Debian with its file pruning /mnt and a timer a package installs that is
/// not enabled, whose service runs an updatedb that does not skip the volume.
fn reindex(timer: &str) -> Decoy {
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .file(
            "/usr/lib/systemd/system/reindex.service",
            "[Service]\nExecStart=/usr/sbin/updatedb.plocate --prunepaths /tmp\n",
        )
        .file("/usr/lib/systemd/system/reindex.timer", timer);
    decoy
}

#[test]
fn a_timer_the_system_manager_runs_schedules_a_run_whether_enabled_or_not() {
    // Not enabled and not started: a person may start it, and only its own
    // service could be started by hand, which nothing names.
    let result = reindex(TIMER).check(false);
    assert!(result.is_pass(), "{result:?}");

    // `systemctl start reindex.timer`, which leaves no file behind.
    let decoy = reindex(TIMER);
    decoy.start("reindex.timer");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        message(&result).contains("reindex.timer schedules updatedb"),
        "{result:?}"
    );
    assert!(
        result
            .remediation()
            .unwrap()
            .contains("mask reindex.timer (`sudo systemctl mask --now reindex.timer`)"),
        "{result:?}"
    );

    // Masking it does not stop it.
    decoy.mask("reindex.timer");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");

    // Where NAILS cannot ask the system manager, a run it may start warns.
    let decoy = reindex(TIMER);
    decoy.unasked("`systemctl list-units` failed (no bus)");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "updatedb can be started by hand (systemctl start reindex.timer, and NAILS cannot \
             tell whether it runs now: `systemctl list-units` failed (no bus))"
        ),
        "{result:?}"
    );
}

#[test]
fn a_trigger_starts_the_first_unit_systemd_takes() {
    // systemd keeps the first Unit= and ignores the rest; a value that is no
    // unit name of a type, or the trigger itself, it ignores too.
    for units in [
        "Unit=reindex.service\nUnit=plocate-updatedb.service\n",
        "Unit=nonsense\nUnit=reindex.timer\nUnit=\nUnit=reindex.service\n",
        "Unit=reindex.bogus\nUnit=.service\nUnit=reindex.service\n",
    ] {
        let decoy = reindex(&format!("[Timer]\nOnCalendar=hourly\n{units}"));
        decoy.mask("plocate-updatedb.timer");
        decoy.start("reindex.timer");
        let result = decoy.check(false);
        assert!(result.is_fail(), "{units}: {result:?}");
        assert!(
            message(&result).contains("reindex.timer schedules updatedb"),
            "{units}: {result:?}"
        );
    }
    // The first one wins over a later one that would not run updatedb.
    let decoy = reindex("[Timer]\nOnCalendar=hourly\nUnit=reindex.service\nUnit=other.service\n");
    decoy.start("reindex.timer");
    assert!(decoy.check(false).is_fail());
    // One named with a specifier cannot be told.
    let decoy = reindex("[Timer]\nOnCalendar=hourly\nUnit=reindex@%i.service\n");
    decoy.start("reindex.timer");
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "reindex.timer may start updatedb, which NAILS cannot tell: reindex.timer names the \
             unit it starts with a specifier"
        ),
        "{result:?}"
    );
}

#[test]
fn a_script_for_a_shell_is_never_read_as_a_bare_updatedb() {
    // The whole script of `sh -c` is no program: NAILS cannot tell what it
    // prunes, and never takes the file's lists for it.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy.file(
        OVERRIDE,
        &exec_start("/bin/sh -c 'updatedb.plocate --prunepaths tmp'"),
    );
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "plocate-updatedb.timer schedules updatedb, and NAILS cannot tell whether it skips \
             the hidden volume: it runs /bin/sh, which names updatedb in a way NAILS does not \
             follow"
        ),
        "{result:?}"
    );
    // However the script ends, as with a path to an updatedb.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy.file(
        OVERRIDE,
        &exec_start("/bin/sh -c 'updatedb --prunepaths \"\" ; ls /usr/bin/updatedb'"),
    );
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    for job in [
        "0 * * * * root sh -c 'updatedb.plocate --prunepaths tmp'",
        "0 * * * * root sh -c 'updatedb --prunepaths \"\" ; ls /usr/bin/updatedb'",
    ] {
        let decoy = debian(&pruning_mnt(DEBIAN));
        decoy.file("/etc/cron.d/x", &format!("{job}\n"));
        let result = decoy.check(false);
        assert!(result.is_warn(), "{job}: {result:?}");
        assert!(
            message(&result).contains("the cron job at line 1 of /etc/cron.d/x runs updatedb"),
            "{job}: {result:?}"
        );
    }
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy.file(
        "/etc/cron.d/x",
        "0 * * * * root sh -c 'updatedb.plocate --prunepaths tmp'\n",
    );
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains("the cron job at line 1 of /etc/cron.d/x runs updatedb"),
        "{result:?}"
    );
}

#[test]
fn a_cron_job_fed_a_script_or_not_logged_runs_it() {
    for (path, text) in [
        // cron feeds what follows the `%` to the shell the job starts.
        (
            "/etc/cron.d/x",
            "0 * * * * root sh%updatedb.plocate --prunepaths /tmp\n",
        ),
        // cronie runs a job whose line starts with `-`, and does not log it.
        (
            "/var/spool/cron/root",
            "-0 * * * * /usr/sbin/updatedb.plocate --prunepaths /tmp\n",
        ),
    ] {
        let decoy = debian(&pruning_mnt(DEBIAN));
        decoy.file(path, text);
        let result = decoy.check(false);
        assert!(result.is_fail(), "{path}: {result:?}");
        assert!(
            message(&result).contains(&format!("the cron job at line 1 of {path} runs updatedb")),
            "{path}: {result:?}"
        );
    }
}

#[test]
fn the_users_nails_cannot_list_or_read_are_no_gap() {
    // A user of a directory service, whom /etc/passwd does not name: their
    // home and their runtime directory are read all the same.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .file("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
        .file(
            "/home/carol/.config/systemd/user/locate.service",
            "[Service]\nExecStart=/usr/bin/updatedb --prunepaths /tmp\n",
        )
        .file("/home/carol/.config/systemd/user/locate.timer", TIMER)
        .enable("/home/carol/.config/systemd/user", "locate.timer");
    transient(&decoy, "/run/user/1001/systemd/transient", "run-r7.timer");
    let result = decoy.check(false);
    assert!(result.is_fail(), "{result:?}");
    for part in [
        "locate.timer of the manager of /home/carol schedules updatedb",
        "run-r7.timer of the manager of user 1001 schedules updatedb",
    ] {
        assert!(message(&result).contains(part), "{part}: {result:?}");
    }

    // An /etc/passwd NAILS cannot read may name users with units of their
    // own.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy.file("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
    decoy.fs.mock_set_file_size("/etc/passwd", 2 << 20);
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "the units of the users /etc/passwd names may start updatedb, which NAILS cannot \
             tell: /etc/passwd is larger than 1 MiB"
        ),
        "{result:?}"
    );
}

#[test]
fn a_proc_that_hides_processes_warns() {
    // /proc mounted with hidepid shows an unprivileged reader its own
    // processes alone, and not process 1.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy
        .fs
        .mock_set_directory_contents(Path::new("/proc"), Vec::new());
    let result = decoy.check(false);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "the processes in /proc may start updatedb, which NAILS cannot tell: /proc hides \
             process 1 from NAILS"
        ),
        "{result:?}"
    );
    // A process gone since the listing is no gap.
    let decoy = debian(&pruning_mnt(DEBIAN));
    decoy.fs.mock_set_directory_contents(
        Path::new("/proc"),
        vec![PathBuf::from("/proc/1"), PathBuf::from("/proc/77")],
    );
    let result = decoy.check(false);
    assert!(result.is_pass(), "{result:?}");
}
