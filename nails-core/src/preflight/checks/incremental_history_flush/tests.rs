// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::filesystem::MockFilesystem;
use std::path::PathBuf;

const HOME: &str = "/home/alice";

/// `program`, the shell the command was typed into, started as `argv`.
fn typed(program: &str, argv: &[&str]) -> InspectedShell {
    InspectedShell {
        program: program.to_string(),
        homes: vec![PathBuf::from(HOME)],
        argv: argv.iter().map(|word| word.to_string()).collect(),
        origin: ShellOrigin::Typed,
        login: None,
    }
}

/// The check's result for `shell` on `fs`.
fn run(fs: &MockFilesystem, shell: InspectedShell) -> CheckResult {
    PreFlightCheck::run(&IncrementalHistoryFlushCheck::new(shell), fs).unwrap()
}

/// The check's result for a typed zsh on `fs`.
fn zsh(fs: &MockFilesystem) -> CheckResult {
    run(fs, typed("zsh", &["-zsh"]))
}

/// The check's result for a typed bash on `fs`.
fn bash(fs: &MockFilesystem) -> CheckResult {
    run(fs, typed("bash", &["-bash"]))
}

/// The warning `result` gives; panics on any other result.
fn warning(result: CheckResult) -> String {
    match result {
        CheckResult::Warn(message) => message,
        other => panic!("expected a warning, got {other:?}"),
    }
}

/// A file of `text` at `path`, alice's.
fn seed(fs: &MockFilesystem, path: &str, text: &str) {
    fs.mock_set_file_content(path, text);
    fs.mock_set_owner(std::path::Path::new(path), 1000, 100);
}

/// The warning for a zsh, whatever its files hold.
const ZSH_WARNING: &str = "NAILS does not read zsh's startup files, so it cannot tell whether zsh \
                           (the shell this command was typed into) writes each command line to its \
                           history file as it runs";

/// zsh always warns: with no startup file, with a clean one and with one that
/// turns INC_APPEND_HISTORY on, and the fix names the shells the check reads.
#[test]
fn a_typed_zsh_always_warns() {
    let fs = MockFilesystem::new();
    let message = warning(zsh(&fs));
    assert!(message.starts_with(ZSH_WARNING), "{message}");
    assert!(message.contains("`fish --private`"), "{message}");
    seed(&fs, "/home/alice/.zshrc", "export X=1\n");
    assert!(warning(zsh(&fs)).starts_with(ZSH_WARNING));
    seed(&fs, "/etc/zsh/zshrc", "setopt INC_APPEND_HISTORY\n");
    assert!(warning(zsh(&fs)).starts_with(ZSH_WARNING));
    // `zsh -f` too: it still reads /etc/zshenv.
    assert!(warning(run(&fs, typed("zsh", &["zsh", "-f"]))).contains("NAILS does not read zsh's"));
}

#[test]
fn warns_on_bash_history_append_in_prompt_command() {
    for (text, command) in [
        (
            "export PROMPT_COMMAND='history -a; history -n'\n",
            "history -a",
        ),
        ("PROMPT_COMMAND=\"history -w\"\n", "history -w"),
        (
            "PROMPT_COMMAND=\"${PROMPT_COMMAND:+$PROMPT_COMMAND; }history -a\"\n",
            "history -a",
        ),
        ("PROMPT_COMMAND+=(history -a)\n", "history -a"),
        (
            "save() { history -a; }\nPROMPT_COMMAND=save\n",
            "history -a",
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.bashrc", text);
        let message = warning(bash(&fs));
        assert!(
            message.starts_with(&format!(
                "bash, the shell this command was typed into, writes each command line to its \
                 history file once the command ends: /home/alice/.bashrc runs `{command}` from \
                 PROMPT_COMMAND."
            )),
            "{text}: {message}"
        );
        assert!(message.contains("set +o history"), "{message}");
    }
}

#[test]
fn a_bash_comment_starts_after_a_blank_and_ends_with_its_line() {
    // bash 5.3 runs the PROMPT_COMMAND of each: a `#` after a vertical tab or
    // a no-break space starts no comment, and a comment ends with its line,
    // a backslash at its end too; a backslash before a carriage return
    // escapes it and joins no line.
    for text in [
        ":\u{b}#; PROMPT_COMMAND='history -a'\n",
        ":\u{a0}#; PROMPT_COMMAND='history -a'\n",
        "# a comment \\\nPROMPT_COMMAND='history -a'\n",
        "# a comment \\\r\nPROMPT_COMMAND='history -a'\r\n",
        "x=1 \\\r\nPROMPT_COMMAND='history -a'\r\n",
        "PROMPT_COMMAND=\\\n'history -a'\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.bashrc", text);
        assert!(
            warning(bash(&fs)).contains("/home/alice/.bashrc runs `history -a`"),
            "{text:?}"
        );
    }
    // A `#` after a space or a tab, or at a line's start, does.
    for text in [
        ": #; PROMPT_COMMAND='history -a'\n",
        ":\t#; PROMPT_COMMAND='history -a'\n",
        "#\u{b}PROMPT_COMMAND='history -a'\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.bashrc", text);
        assert!(matches!(bash(&fs), CheckResult::Pass(_)), "{text:?}");
    }
}

#[test]
fn a_bash_comment_starts_outside_quotes_alone() {
    // bash 5.3 keeps `history -a` in PROMPT_COMMAND for each (`declare -p`
    // shows it), and runs it at each prompt: a `#` after a blank in quotes,
    // after an escaped blank or in a here-document's body starts no
    // comment.
    for text in [
        "PROMPT_COMMAND='printf \" #\" >/dev/null; history -a'\n",
        "PROMPT_COMMAND=\"printf ' #' >/dev/null; history -a\"\n",
        "PROMPT_COMMAND=$'printf \" #\\\\n\" >/dev/null; history -a'\n",
        "PROMPT_COMMAND='printf x\n #\nhistory -a'\n",
        "x=a\\ #; PROMPT_COMMAND='history -a'\n",
        "cat <<'EOF' >/dev/null\nit's\nEOF\nPROMPT_COMMAND='printf \" #\"; history -a'\n",
        "cat <<EOF >/dev/null\n # x\nEOF\nPROMPT_COMMAND='history -a'\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.bashrc", text);
        assert!(
            warning(bash(&fs)).contains("/home/alice/.bashrc runs `history -a`"),
            "{text:?}"
        );
    }
    // A `#` that starts a word outside quotes does, past a closed quote too,
    // and with interactive_comments off, which bash 5.3 reads for a line
    // typed alone, not for a startup file.
    for text in [
        "shopt -u interactive_comments\ntrue # ; PROMPT_COMMAND='history -a'\n",
        "x='a'; # PROMPT_COMMAND='history -a'\n",
        "x=\"a\" #; PROMPT_COMMAND='history -a'\n",
        "cat <<EOF >/dev/null\nx\nEOF\n# PROMPT_COMMAND='history -a'\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.bashrc", text);
        assert!(matches!(bash(&fs), CheckResult::Pass(_)), "{text:?}");
    }
}

#[test]
fn a_bash_comment_starts_only_where_bash_s_reader_starts_one() {
    // bash 5.3.9 writes each typed line with each of these in ~/.bashrc: a
    // `#` after a blank in a backquote pair, a `${...}` or arithmetic, which
    // bash reads to their end as part of a word, starts no comment, and one
    // in a command substitution's code does only to its line's end.
    for text in [
        "X=`: #`; PROMPT_COMMAND='history -a'\n",
        "Y=${X:- #}; PROMPT_COMMAND='history -a'\n",
        "W=${X:-a #}b; PROMPT_COMMAND='history -a'\n",
        "Z=$(: #\n); PROMPT_COMMAND='history -a'\n",
        "Z=$(echo ${X:- #}); PROMPT_COMMAND='history -a'\n",
        "Z=$(echo `: #`); PROMPT_COMMAND='history -a'\n",
        "Z=\"${X:- #}\"; PROMPT_COMMAND='history -a'\n",
        "Z=`: # it's`\nPROMPT_COMMAND='history -a'\n",
        "Z=${X:-'a }b'}; PROMPT_COMMAND='history -a'\n",
        "Z=${X:-'}' #}; PROMPT_COMMAND='history -a'\n",
        "Z=`echo \\` #`; PROMPT_COMMAND='history -a'\n",
        "Z=$(cat <<'EOF'\nit's # x\nEOF\n); PROMPT_COMMAND='history -a'\n",
        "Z=$(( 1 )) ; PROMPT_COMMAND='history -a' #\n",
        "Z=$((1))#; PROMPT_COMMAND='history -a'\n",
        "Z=$(echo a)#; PROMPT_COMMAND='history -a'\n",
        "echo $# ; PROMPT_COMMAND='history -a'\n",
        "X=$(case x in x) :;; esac)#; PROMPT_COMMAND='history -a'\n",
        "X=$(case x in (x) :;; esac)#; PROMPT_COMMAND='history -a'\n",
        "shopt -s extglob\nX=@(a| #b); PROMPT_COMMAND='history -a'\n",
        "shopt -s extglob\ncase x in @(a| #b)) ;; esac; PROMPT_COMMAND='history -a'\n",
        "[[ a =~ ( #) ]]; PROMPT_COMMAND='history -a'\n",
        // A `((` that a lone `)` closes is a subshell with a `(` group
        // first, read as code after it. A `$((` that one closes is a command
        // substitution, which bash reads to its `)` with quotes and no
        // comment, and parses as code only where it expands the word, which
        // it never does after `false &&`, in a function never called or in a
        // `case` arm never taken.
        "X=\"$((echo a); echo \"b #\")\"; PROMPT_COMMAND='history -a'\n",
        "X=\"$((echo a) ; echo 'b\" #')\"; PROMPT_COMMAND='history -a'\n",
        "X=\"$( ((echo a); echo b) ; echo \"c #\")\"; PROMPT_COMMAND='history -a'\n",
        "((echo a # c\n); echo b); PROMPT_COMMAND='history -a'\n",
        "true || X=\"$((echo a) ; : #)\"; PROMPT_COMMAND='history -w'\n",
        "false && X=$((echo a)#); PROMPT_COMMAND='history -a'\n",
        "f() { X=\"$((echo a); echo b #)\"; }; PROMPT_COMMAND='history -a'\n",
        "false && X=$((echo a); : #); PROMPT_COMMAND='history -a'\n",
        "f() { X=$((echo a); : #); }; PROMPT_COMMAND='history -a'\n",
        "case y in x) X=$((echo a); : #);; esac; PROMPT_COMMAND='history -a'\n",
        "false && X=$(( $(case x in x) echo 1;; esac) + 1 #)); PROMPT_COMMAND='history -a'\n",
        "false && X=$((echo a); (: #)); PROMPT_COMMAND='history -a'\n",
        "false && X=$((echo a); echo ') #'); PROMPT_COMMAND='history -a'\n",
        "false && X=$((echo a); echo \") #\"); PROMPT_COMMAND='history -a'\n",
        "false && X=$((echo a); echo `: #`); PROMPT_COMMAND='history -a'\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.bashrc", text);
        let command = if text.contains("history -w") {
            "history -w"
        } else {
            "history -a"
        };
        assert!(
            warning(bash(&fs)).contains(&format!("/home/alice/.bashrc runs `{command}`")),
            "{text:?}"
        );
    }
    // False alarms: bash 5.3.9 wrote none with these, as it expands the
    // `$((...)` and parses it as code, where the `#` starts a comment that
    // takes the `PROMPT_COMMAND` assignment along. The reader starts no
    // comment in these `$((...)`, as it cannot tell whether bash expands them.
    for text in [
        "X=$((echo a); : # ; PROMPT_COMMAND='history -a'\n)\n",
        "X=\"$((echo a); : # ; PROMPT_COMMAND='history -a'\n)\"\n",
        "X=$((echo a)#; PROMPT_COMMAND='history -a'\n)\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.bashrc", text);
        assert!(
            warning(bash(&fs)).contains("/home/alice/.bashrc runs `history -a`"),
            "{text:?}"
        );
    }
    // bash 5.3.9 wrote none with these: the comment starts in the file's
    // code, in a command or process substitution's code, after an arithmetic
    // command or a subshell, and in a `((` subshell's code after its first
    // group, and runs to its line's end.
    for text in [
        "X=1 # ; PROMPT_COMMAND='history -a'\n",
        "X=$(: #); PROMPT_COMMAND='history -a'\n)\n",
        "X=${X:-$(: #)}; PROMPT_COMMAND='history -a'\n)}\n",
        "X=\"$(: #)\"; PROMPT_COMMAND='history -a'\n)\"\n",
        "cat <(: #) >/dev/null; PROMPT_COMMAND='history -a'\n)\n",
        "((1)) #; PROMPT_COMMAND='history -a'\n",
        "Z=$(echo a) #; PROMPT_COMMAND='history -a'\n",
        "(echo)#; PROMPT_COMMAND='history -a'\n",
        "((echo a); : # ; PROMPT_COMMAND='history -a'\n)\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.bashrc", text);
        assert!(matches!(bash(&fs), CheckResult::Pass(_)), "{text:?}");
    }
}

#[test]
fn bash_reads_the_system_files_too() {
    for path in ["/etc/profile", "/etc/bash.bashrc", "/etc/bashrc"] {
        let fs = MockFilesystem::new();
        seed(&fs, path, "PROMPT_COMMAND='history -a'\n");
        assert!(
            warning(bash(&fs)).contains(&format!("{path} runs `history -a`")),
            "{path}"
        );
    }
    // rbash is bash.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.profile", "PROMPT_COMMAND='history -a'\n");
    assert!(warning(run(&fs, typed("rbash", &["rbash"]))).starts_with("rbash, "));
}

#[test]
fn bash_history_append_without_prompt_command_does_not_warn() {
    // `history -a` in an alias the operator runs by hand, with no
    // PROMPT_COMMAND hook, does not write after every command; nor does a
    // PROMPT_COMMAND that only reads, or one in a comment.
    for text in [
        "alias save='history -a'\n",
        "PROMPT_COMMAND='history -n; history -c; history -r'\n",
        "# PROMPT_COMMAND='history -a'\n",
        "export PATH=$PATH\nalias ll='ls -la'\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.bashrc", text);
        match bash(&fs) {
            CheckResult::Pass(message) => assert_eq!(
                message,
                "bash (the shell this command was typed into): no startup file the check reads \
                 runs `history -a` or `history -w` from PROMPT_COMMAND"
            ),
            other => panic!("{text}: {other:?}"),
        }
    }
}

#[test]
fn passes_on_clean_config() {
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.bashrc",
        "export PATH=$PATH\nalias ll='ls -la'\n",
    );
    match bash(&fs) {
        CheckResult::Pass(message) => assert_eq!(
            message,
            "bash (the shell this command was typed into): no startup file the check reads runs \
             `history -a` or `history -w` from PROMPT_COMMAND"
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn fish_writes_each_command_unless_it_runs_in_private_mode() {
    let fs = MockFilesystem::new();
    let message = warning(run(&fs, typed("fish", &["-fish"])));
    assert!(
        message.starts_with(
            "fish, the shell this command was typed into, writes each command line to its \
             history file as it starts the command, unless it runs in private mode."
        ),
        "{message}"
    );
    assert!(message.contains("`fish --private`"), "{message}");

    for argv in [&["fish", "--private"][..], &["fish", "-lP"]] {
        match run(&fs, typed("fish", argv)) {
            CheckResult::Pass(message) => assert_eq!(
                message,
                "fish (the shell this command was typed into) runs in private mode and writes \
                 no history"
            ),
            other => panic!("{argv:?}: {other:?}"),
        }
    }
}

/// The start of every result of the check without a typed shell.
const NOT_TYPED: &str = "This command was not typed into a shell the check can see, so it read \
                         the startup files of every shell it knows";

#[test]
fn a_login_shell_is_named_as_one_and_judged_by_its_program() {
    let operator =
        TargetUser::for_test(1000, 100, "alice", HOME, "/run/current-system/sw/bin/fish");
    let shell = InspectedShell::login(&operator);
    assert_eq!(
        shell,
        InspectedShell {
            program: "fish".to_string(),
            homes: vec![PathBuf::from(HOME)],
            argv: Vec::new(),
            origin: ShellOrigin::Login,
            login: None,
        }
    );
    let fs = MockFilesystem::new();
    assert!(warning(run(&fs, shell)).starts_with(&format!(
        "{NOT_TYPED}. fish, the operator's login shell, writes"
    )));

    // A login zsh warns though none of its files is there.
    let operator = TargetUser::for_test(1000, 100, "alice", HOME, "/bin/zsh");
    assert!(
        warning(run(&fs, InspectedShell::login(&operator))).starts_with(&format!(
            "{NOT_TYPED}. NAILS does not read zsh's startup files, so it cannot tell whether zsh \
             (the operator's login shell)"
        ))
    );
}

#[test]
fn without_a_typed_shell_every_shell_the_check_knows_is_read() {
    let operator = TargetUser::for_test(1000, 100, "alice", HOME, "/bin/bash");
    let fs = MockFilesystem::new();
    match run(&fs, InspectedShell::login(&operator)) {
        CheckResult::Pass(message) => assert_eq!(
            message,
            format!(
                "{NOT_TYPED}: bash (the operator's login shell): no startup file the check reads \
                 runs `history -a` or `history -w` from PROMPT_COMMAND"
            )
        ),
        other => panic!("{other:?}"),
    }

    // zsh where one of its startup files is there, in /etc or in the home.
    for path in [
        "/etc/zshrc",
        "/etc/zsh/zshenv",
        "/home/alice/.zshrc",
        "/home/alice/.zlogin",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, path, "\n");
        let message = warning(run(&fs, InspectedShell::login(&operator)));
        assert!(
            message.starts_with(&format!(
                "{NOT_TYPED}. NAILS does not read zsh's startup files, so it cannot tell whether \
                 zsh (a shell the operator may use)"
            )),
            "{path}: {message}"
        );
    }

    // fish when the home has its configuration.
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/home/alice/.config/fish", crate::filesystem::PathKind::Dir);
    let message = warning(run(&fs, InspectedShell::login(&operator)));
    assert!(
        message.starts_with(&format!(
            "{NOT_TYPED}. fish, a shell the operator may use, writes each command line"
        )),
        "{message}"
    );
}

/// A zsh startup file NAILS cannot look up may be there: it cannot tell.
#[test]
fn a_zsh_startup_file_nails_cannot_look_up_warns() {
    let operator = TargetUser::for_test(1000, 100, "alice", HOME, "/bin/bash");
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error("/etc/zsh", std::io::ErrorKind::PermissionDenied);
    let message = warning(run(&fs, InspectedShell::login(&operator)));
    assert!(
        message.contains(
            "NAILS cannot tell whether zsh keeps its settings in /etc/zsh/zshenv, so it cannot \
             tell whether zsh writes each command line as it runs"
        ),
        "{message}"
    );
}

#[test]
fn a_shell_of_another_account_is_read_in_both_homes() {
    // A root shell that may run with the operator's home, as `sudo -s` can
    // leave it.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.bashrc", "PROMPT_COMMAND='history -a'\n");
    let shell = InspectedShell {
        program: "bash".to_string(),
        homes: vec![PathBuf::from("/root"), PathBuf::from(HOME)],
        argv: vec!["bash".to_string()],
        origin: ShellOrigin::Typed,
        login: None,
    };
    assert!(warning(run(&fs, shell)).contains("/home/alice/.bashrc runs `history -a`"));
}

/// The start of every result of the check for a zsh the command was likely
/// typed into.
const LIKELY: &str = "This command was likely typed into zsh, but the check cannot be sure of \
                      it, so it read the startup files of every shell it knows";

#[test]
fn a_shell_the_command_was_likely_typed_into_is_read_beside_every_shell() {
    let likely = |login: &str| InspectedShell {
        program: "zsh".to_string(),
        homes: vec![PathBuf::from(HOME)],
        argv: vec!["-zsh".to_string()],
        origin: ShellOrigin::Likely,
        login: Some(login.to_string()),
    };
    let fs = MockFilesystem::new();
    let message = warning(run(&fs, likely("zsh")));
    assert!(
        message.starts_with(&format!(
            "{LIKELY}. NAILS does not read zsh's startup files, so it cannot tell whether zsh \
             (the shell this command was likely typed into)"
        )),
        "{message}"
    );

    // The operator's login shell and every other shell the check knows.
    seed(&fs, "/home/alice/.bashrc", "PROMPT_COMMAND='history -a'\n");
    let message = warning(run(&fs, likely("fish")));
    assert!(
        message.contains("fish, the operator's login shell, writes")
            && message.contains("bash, a shell the operator may use, writes"),
        "{message}"
    );
}

#[test]
fn a_shell_is_named_by_its_program_when_that_is_a_shell_s() {
    use std::path::Path;
    let comm = |name: &str| Some(name.to_string());
    // /bin/sh leads to bash.
    assert_eq!(
        program_name(Some(Path::new("/usr/bin/bash")), comm("sh")),
        comm("bash")
    );
    // xonsh is a script Python runs.
    assert_eq!(
        program_name(Some(Path::new("/usr/bin/python3.12")), comm("xonsh")),
        comm("xonsh")
    );
    assert_eq!(program_name(None, comm("zsh")), comm("zsh"));
    assert_eq!(
        program_name(Some(Path::new("/usr/bin/python3")), None),
        None
    );
}

#[test]
fn dash_keeps_no_history_and_other_shells_cannot_be_told() {
    let fs = MockFilesystem::new();
    assert!(matches!(
        run(&fs, typed("dash", &["dash"])),
        CheckResult::Pass(message) if message == "dash (the shell this command was typed into) keeps no history file"
    ));
    for program in ["ksh93", "mksh", "nu", "elvish", "tcsh", "sh"] {
        let message = warning(run(&fs, typed(program, &[program])));
        assert!(
            message.starts_with(&format!(
                "NAILS reads the history settings of bash and fish only, so it cannot tell \
                 whether {program}, the shell this command was typed into, writes"
            )),
            "{message}"
        );
    }
}

#[test]
fn a_shell_a_nixos_wrapper_starts_is_judged_by_its_own_name() {
    let fs = MockFilesystem::new();
    assert!(
        warning(run(&fs, typed(".zsh-wrapped", &["zsh"]))).contains("NAILS does not read zsh's")
    );
}

#[test]
fn a_program_is_named_by_its_file() {
    assert_eq!(file_name(Path::new("/usr/bin/zsh")), "zsh");
    assert_eq!(file_name(Path::new("/usr/bin/zsh (deleted)")), "zsh");
    assert_eq!(file_name(Path::new("/")), "");
}

#[test]
fn no_test_reads_the_shell_it_was_typed_into() {
    let operator = TargetUser::for_test(1000, 100, "alice", HOME, "/bin/bash");
    assert_eq!(InspectedShell::typed(Some(&operator)), None);
    assert_eq!(InspectedShell::typed(None), None);
}

#[test]
fn disabled_check_passes_without_inspecting() {
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.bashrc", "PROMPT_COMMAND='history -a'\n");
    let check = IncrementalHistoryFlushCheck::disabled();
    assert!(matches!(
        PreFlightCheck::run(&check, &fs).unwrap(),
        CheckResult::Pass(_)
    ));
}

#[test]
fn missing_startup_files_pass() {
    let fs = MockFilesystem::new();
    assert!(matches!(bash(&fs), CheckResult::Pass(_)));
}

proptest::proptest! {
    /// No text in a startup file makes the check panic. (`just fuzz` runs
    /// this with many more cases.)
    #[test]
    fn fuzz_no_startup_file_text_makes_the_check_panic(
        text in "(set|[-+]o|source|\\.|\
                 PROMPT_COMMAND=|history|-a|-w|#|;|&|[|(){}'\"`=~]|\\$HOME|\\$\\{|:-|\
                 <<-?|<<<|<<=|[<>=]\\(|\\(\\(|\\)\\)|for|>|EOF|2>&1|\\$'|\\$\\(|\\\\'|case|esac|\\$\\{\\||\\$\\$|\\(#|[ \\t\\n]|[a-zé_ç]|\\PC){0,48}"
    ) {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.bashrc", &text);
        let _ = bash(&fs);
    }
}
