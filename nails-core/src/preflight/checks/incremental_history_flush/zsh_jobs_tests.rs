// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The jobs the startup files start that may run on after them and signal
//! the shell later, on which zsh ends and writes its history file.

use super::*;

/// The doubts of `rc` as `~/.zshrc`, beside the files `more` holds.
fn doubts(rc: &str, more: &[(&str, &str)]) -> Vec<String> {
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", rc);
    for (path, text) in more {
        seed(&fs, path, text);
    }
    scan(&fs, UNKNOWN).doubts
}

/// Whether `found` holds the doubt of a job that may signal the shell.
fn job(found: &[String]) -> bool {
    found
        .iter()
        .any(|doubt| doubt.contains("may run on after the startup files and signal the shell"))
}

#[test]
fn a_job_that_may_signal_the_shell_later_is_a_doubt() {
    // zsh 5.9 to 5.9.2 take the signal 3 s later, write the lines typed so
    // far and exit.
    for rc in [
        "{ sleep 3; kill -HUP $$ } &!\n",
        "( sleep 3; kill -HUP $$ ) &\n",
        "( sleep 3; kill -ALRM $$ ) &!\n",
        "( sleep 3; kill -HUP $$ ) &|\n",
        "f() { sleep 3; kill -HUP $$ }\nf &!\n",
        "f() { kill -HUP $$ }\n( f ) &!\n",
        "sh -c \"sleep 3; kill -HUP $$\" &!\n",
        "exec {fd}< <(sleep 3; kill -HUP $$)\n",
        ": $( (sleep 3; kill -HUP $$) >/dev/null 2>&1 &! )\n",
        "f() { ( sleep 3; kill -HUP $$ ) &! }\nf\n",
        "repeat 1 { sleep 3; kill -HUP $$ } &!\n",
        "for i in 1; do sleep 3; kill -HUP $$; done &!\n",
        "( sleep 3; pkill -HUP -P $PPID zsh ) &!\n",
        "nohup sh -c 'sleep 3; kill -HUP $PPID' >/dev/null 2>&1 &!\n",
        "setsid -f sh -c 'sleep 3; kill -HUP $PPID'\n",
        "print x | ( sleep 3; kill -HUP $$ ) &\n",
        "true && { sleep 3; kill -HUP $$ } &\n",
        "( kill -HUP $pid ) &\n",
        "( source ~/.later.zsh ) &\n",
        "( eval $later ) &\n",
        "( zcompile x; mytool ) &!\n",
        "( command kill -HUP 1234 ) &\n",
        "disable kill\n( kill -HUP 1234 ) &\n",
        "( strftime %s 0 ) &\n",
        "cat <(sleep 3; kill -HUP $$)\n",
        "zmodload zsh/zpty\nzpty later 'sleep 3; kill -HUP $$'\n",
        "print '* * * * * kill -HUP 1' | crontab -\n",
    ] {
        assert!(job(&doubts(rc, &[])), "{rc}");
    }
    // In ~/.zshenv, and in a file the startup files source.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshenv", "{ sleep 3; kill -HUP $$ } &!\n");
    assert!(job(&scan(&fs, UNKNOWN).doubts));
    assert!(job(&doubts(
        "source ~/.zbg\n",
        &[("/home/alice/.zbg", "( sleep 3; kill -HUP $$ ) &!\n")]
    )));
}

#[test]
fn a_job_that_runs_only_builtins_that_signal_nothing_is_none() {
    // zsh 5.9 to 5.9.2 write nothing with these: an `exit` ends the job, in
    // which zsh writes no line typed after it started.
    for rc in [
        "{ zcompile ~/.zcompdump } &!\n",
        "( zcompile -R ~/.zcompdump ) &|\n",
        "( [[ -f ~/.x ]] && zcompile ~/.x ) &!\n",
        "( kill -HUP 1234 ) &\n",
        "( kill %1 ) &\n",
        "( exit ) &!\n",
        "print x &\n",
        "f() { print x }\nf &!\n",
        "print -r -- <(print x) >/dev/null\n",
    ] {
        let found = doubts(rc, &[]);
        assert!(!job(&found), "{rc}: {found:?}");
    }
}

#[test]
fn a_job_the_code_a_shell_is_given_starts_is_read() {
    // zsh 5.9 to 5.9.2 write the lines typed so far as the job `sh` leaves
    // running signals the shell, 3 s later.
    for rc in [
        "sh -c '(sleep 3; kill -HUP $PPID) >/dev/null 2>&1 &'\n",
        "bash -ec 'nohup sh -c \"sleep 3; kill -HUP $PPID\" &'\n",
        "zsh -fc '{ sleep 3; kill -HUP $PPID } &!'\n",
        "sh -c \"$later\"\n",
    ] {
        assert!(job(&doubts(rc, &[])), "{rc}");
    }
    for rc in [
        "sh -c 'print x'\n",
        "sh ~/script.sh\n",
        "bash -c 'zcompile x'\n",
    ] {
        let found = doubts(rc, &[]);
        assert!(!job(&found), "{rc}: {found:?}");
    }
}
