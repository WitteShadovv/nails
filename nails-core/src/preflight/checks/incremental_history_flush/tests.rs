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

/// A file of `text` at `path`.
fn seed(fs: &MockFilesystem, path: &str, text: &str) {
    fs.mock_set_file_content(path, text);
}

#[test]
fn warns_on_zsh_inc_append_history_in_the_home() {
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "setopt INC_APPEND_HISTORY\nexport PATH=$PATH\n",
    );
    let message = warning(zsh(&fs));
    assert!(
        message.starts_with(
            "zsh, the shell this command was typed into, writes each command line to its \
             history file as you enter it: /home/alice/.zshrc sets INC_APPEND_HISTORY."
        ),
        "{message}"
    );
    assert!(message.contains("unset HISTFILE"), "{message}");
}

#[test]
fn warns_on_zsh_share_history_in_any_spelling() {
    for line in [
        "setopt share_history",
        "setopt SHAREHISTORY",
        "setopt Share_History",
        "set -o sharehistory",
        "unsetopt no_share_history",
        "[[ -o interactive ]] && setopt share_history",
        "if true; then setopt 'share_history'; fi",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{line}\n"));
        let message = warning(zsh(&fs));
        assert!(
            message.contains("/home/alice/.zshrc sets SHARE_HISTORY"),
            "{line}: {message}"
        );
    }
}

#[test]
fn warns_on_the_share_history_a_system_zshrc_sets_for_every_user() {
    // NixOS's /etc/zshrc with programs.zsh's default options, and Debian's
    // and Arch's zsh, which read /etc/zsh/.
    for path in ["/etc/zshrc", "/etc/zsh/zshrc"] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            path,
            "SAVEHIST=2000\nHISTFILE=$HOME/.zsh_history\n\
             setopt HIST_IGNORE_DUPS SHARE_HISTORY HIST_FCNTL_LOCK\n",
        );
        let message = warning(zsh(&fs));
        assert!(
            message.contains(&format!("{path} sets SHARE_HISTORY")),
            "{message}"
        );
    }
}

#[test]
fn a_later_startup_file_turns_an_option_off_again() {
    for off in [
        "unsetopt SHARE_HISTORY",
        "setopt no_share_history",
        "setopt NOSHAREHISTORY",
        "set +o share_history",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/etc/zshrc", "setopt SHARE_HISTORY\n");
        seed(&fs, "/home/alice/.zshrc", &format!("{off}\n"));
        assert!(matches!(zsh(&fs), CheckResult::Pass(_)), "{off}");
    }
    // In the order zsh reads them: a zlogin is read after the zshrc.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", "unsetopt INC_APPEND_HISTORY\n");
    seed(&fs, "/etc/zlogin", "setopt INC_APPEND_HISTORY\n");
    assert!(warning(zsh(&fs)).contains("/etc/zlogin sets INC_APPEND_HISTORY"));
}

#[test]
fn inc_append_history_time_writes_once_the_command_ends() {
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zprofile",
        "setopt inc_append_history_time\n",
    );
    let message = warning(zsh(&fs));
    assert!(
        message.contains(
            "history file once the command ends: /home/alice/.zprofile sets \
             INC_APPEND_HISTORY_TIME."
        ),
        "{message}"
    );

    // With an option that writes as a line is entered, that is what it says.
    seed(&fs, "/etc/zshenv", "setopt share_history\n");
    let message = warning(zsh(&fs));
    assert!(
        message.contains(
            "history file as you enter it: /etc/zshenv sets SHARE_HISTORY; \
             /home/alice/.zprofile sets INC_APPEND_HISTORY_TIME."
        ),
        "{message}"
    );
}

#[test]
fn oh_my_zsh_turns_share_history_on_where_it_is_loaded() {
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "export ZSH=\"$HOME/.oh-my-zsh\"\nsource $ZSH/oh-my-zsh.sh\n",
    );
    let message = warning(zsh(&fs));
    assert!(
        message.contains("Oh My Zsh, which /home/alice/.zshrc loads, sets SHARE_HISTORY"),
        "{message}"
    );

    // Turned off after it is loaded, it stays off.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "source \"${ZSH}/oh-my-zsh.sh\"\nunsetopt share_history\n",
    );
    assert!(matches!(zsh(&fs), CheckResult::Pass(_)));
}

#[test]
fn the_user_files_are_read_from_the_zdotdir_a_zshenv_sets() {
    for value in [
        "\"$HOME/.config/zsh\"",
        "${XDG_CONFIG_HOME:-$HOME/.config}/zsh",
        "~/.config/zsh",
    ] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshenv",
            &format!("export ZDOTDIR={value}\n"),
        );
        seed(
            &fs,
            "/home/alice/.config/zsh/.zshrc",
            "setopt share_history\n",
        );
        // zsh no longer reads the one in the home.
        seed(&fs, "/home/alice/.zshrc", "setopt inc_append_history\n");
        let message = warning(zsh(&fs));
        assert!(
            message.contains("/home/alice/.config/zsh/.zshrc sets SHARE_HISTORY"),
            "{value}: {message}"
        );
        assert!(
            !message.contains("INC_APPEND_HISTORY"),
            "{value}: {message}"
        );
    }

    // In quotes as `export` takes it, and not where no word starts.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshenv",
        "echo $ZDOTDIR=/nowhere\nexport \"ZDOTDIR=$HOME/.zsh\"\n",
    );
    seed(&fs, "/home/alice/.zsh/.zshrc", "setopt share_history\n");
    assert!(warning(zsh(&fs)).contains("/home/alice/.zsh/.zshrc sets SHARE_HISTORY"));
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshenv", "echo $ZDOTDIR=/nowhere\n");
    seed(&fs, "/home/alice/.zshrc", "setopt share_history\n");
    assert!(warning(zsh(&fs)).contains("/home/alice/.zshrc sets SHARE_HISTORY"));

    // XDG_CONFIG_HOME as a startup file sets it.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/etc/zshenv",
        "export XDG_CONFIG_HOME=/home/alice/cfg\nexport ZDOTDIR=$XDG_CONFIG_HOME/zsh\n",
    );
    seed(&fs, "/home/alice/cfg/zsh/.zshenv", "setopt share_history\n");
    assert!(warning(zsh(&fs)).contains("/home/alice/cfg/zsh/.zshenv sets SHARE_HISTORY"));
}

#[test]
fn a_zdotdir_the_check_cannot_follow_is_a_doubt() {
    for value in ["\"$(dirname $0)\"", "$XDG_CONFIG_HOME/zsh", "relative/zsh"] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshenv",
            &format!("export ZDOTDIR={value}\n"),
        );
        let message = warning(zsh(&fs));
        assert!(
            message.starts_with(
                "The check cannot tell whether zsh, the shell this command was typed into, \
                 writes each command line"
            ),
            "{value}: {message}"
        );
        assert!(
            message.contains("it cannot follow the ZDOTDIR that /home/alice/.zshenv sets"),
            "{message}"
        );
    }
}

#[test]
fn a_startup_file_the_check_cannot_read_is_a_doubt() {
    // There, but its content cannot be read.
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/etc/zshrc", true);
    let message = warning(zsh(&fs));
    assert!(
        message.contains("it could not read /etc/zshrc (entity not found)."),
        "{message}"
    );

    // A lookup that fails for any reason but a missing file.
    let fs = MockFilesystem::new();
    fs.mock_set_inode_error(
        std::path::Path::new("/home/alice/.bashrc"),
        std::io::ErrorKind::PermissionDenied,
    );
    let message = warning(bash(&fs));
    assert!(
        message.contains("it could not read /home/alice/.bashrc (permission denied)."),
        "{message}"
    );

    // Not a regular file, which the check never opens.
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/home/alice/.zshrc", crate::filesystem::PathKind::Dir);
    let message = warning(zsh(&fs));
    assert!(
        message.contains("/home/alice/.zshrc (not a regular file)"),
        "{message}"
    );

    // Larger than a startup file; one of the most it reads is read.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", "setopt share_history\n");
    fs.mock_set_file_size("/home/alice/.zshrc", 4 << 20);
    assert!(warning(zsh(&fs)).contains("/home/alice/.zshrc sets SHARE_HISTORY"));
    let fs = MockFilesystem::new();
    fs.mock_set_file_size("/etc/zsh/zshenv", 5 << 20);
    let message = warning(zsh(&fs));
    assert!(
        message.contains("/etc/zsh/zshenv (5242880 bytes, more than a startup file holds)"),
        "{message}"
    );

    // A doubt beside a finding is named after it.
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/etc/zshrc", true);
    seed(&fs, "/home/alice/.zshrc", "setopt share_history\n");
    let message = warning(zsh(&fs));
    assert!(
        message.contains("/home/alice/.zshrc sets SHARE_HISTORY"),
        "{message}"
    );
    assert!(
        message.contains("Beyond that, it could not read /etc/zshrc"),
        "{message}"
    );
}

#[test]
fn a_line_with_letters_beyond_ascii_is_read() {
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshenv",
        "alias ç='ls'\nexport café=1 ZDOTDIR=\"$HOME/.zsh\"\n",
    );
    seed(&fs, "/home/alice/.zsh/.zshrc", "setopt share_history # é\n");
    assert!(warning(zsh(&fs)).contains("/home/alice/.zsh/.zshrc sets SHARE_HISTORY"));
}

proptest::proptest! {
    /// No text in a startup file makes the check panic, read as zsh's or as
    /// bash's. (`just fuzz` runs this with many more cases.)
    #[test]
    fn fuzz_no_startup_file_text_makes_the_check_panic(
        text in "(setopt|unsetopt|set|[-+]o|source|\\.|oh-my-zsh\\.sh|ZDOTDIR=|XDG_CONFIG_HOME=|\
                 PROMPT_COMMAND=|history|-a|-w|#|;|&|[|(){}'\"`=~]|\\$HOME|\\$\\{|:-|\
                 <<-?|<<<|<<=|[<>=]\\(|\\(\\(|\\)\\)|for|>|EOF|2>&1|\\$'|\\$\\(|\\\\'|case|esac|\\$\\{\\||[ \\t\\n]|[a-zé_ç]|\\PC){0,48}"
    ) {
        let fs = MockFilesystem::new();
        for path in ["/home/alice/.zshenv", "/home/alice/.zshrc", "/home/alice/.bashrc"] {
            seed(&fs, path, &text);
        }
        let _ = zsh(&fs);
        let _ = bash(&fs);
    }
}

#[test]
fn a_file_that_is_not_utf8_is_read_all_the_same() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_bytes("/home/alice/.zshrc", b"# \xe9t\xe9\nsetopt share_history\n");
    assert!(warning(zsh(&fs)).contains("/home/alice/.zshrc sets SHARE_HISTORY"));
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
    seed(&fs, "/home/alice/.zshrc", "setopt APPEND_HISTORY\n");
    match zsh(&fs) {
        CheckResult::Pass(message) => assert_eq!(
            message,
            "zsh (the shell this command was typed into): no startup file the check reads turns \
             on INC_APPEND_HISTORY, INC_APPEND_HISTORY_TIME or SHARE_HISTORY"
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn ignores_commented_out_settings() {
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "# setopt INC_APPEND_HISTORY\nexport X=1 # setopt share_history\n",
    );
    assert!(matches!(zsh(&fs), CheckResult::Pass(_)));
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

    let operator = TargetUser::for_test(1000, 100, "alice", HOME, "/bin/zsh");
    seed(&fs, "/home/alice/.zshrc", "setopt share_history\n");
    assert!(
        warning(run(&fs, InspectedShell::login(&operator))).starts_with(&format!(
            "{NOT_TYPED}. zsh, the operator's login shell, writes"
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
                 runs `history -a` or `history -w` from PROMPT_COMMAND; zsh (a shell the \
                 operator may use): no startup file the check reads turns on \
                 INC_APPEND_HISTORY, INC_APPEND_HISTORY_TIME or SHARE_HISTORY"
            )
        ),
        other => panic!("{other:?}"),
    }

    // A login bash, and zsh's settings that a decoy zsh would follow.
    seed(&fs, "/etc/zshrc", "setopt SHARE_HISTORY\n");
    let message = warning(run(&fs, InspectedShell::login(&operator)));
    assert!(
        message.starts_with(&format!(
            "{NOT_TYPED}. zsh, a shell the operator may use, writes each command line to its \
             history file as you enter it: /etc/zshrc sets SHARE_HISTORY."
        )),
        "{message}"
    );

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

#[test]
fn a_turn_off_in_one_of_two_homes_does_not_hide_an_option() {
    // A root zsh that `sudo -i` opened reads /root/.zshrc, not the
    // operator's, though one that `sudo -s` opened can.
    let fs = MockFilesystem::new();
    seed(&fs, "/etc/zshrc", "setopt SHARE_HISTORY\n");
    seed(&fs, "/home/alice/.zshrc", "unsetopt share_history\n");
    let shell = InspectedShell {
        program: "zsh".to_string(),
        homes: vec![PathBuf::from("/root"), PathBuf::from(HOME)],
        argv: vec!["-zsh".to_string()],
        origin: ShellOrigin::Typed,
        login: None,
    };
    let message = warning(run(&fs, shell.clone()));
    assert!(
        message.contains("/etc/zshrc sets SHARE_HISTORY")
            && message.contains("at the end of the .zshrc in each home it can run with"),
        "{message}"
    );
    // The operator's own zsh reads it, and so does the root shell with
    // either home when both turn the option off.
    assert!(matches!(zsh(&fs), CheckResult::Pass(_)));
    seed(&fs, "/root/.zshrc", "unsetopt share_history\n");
    assert!(matches!(run(&fs, shell), CheckResult::Pass(_)));
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
    match run(&fs, likely("zsh")) {
        CheckResult::Pass(message) => assert_eq!(
            message,
            format!(
                "{LIKELY}: zsh (the shell this command was likely typed into): no startup file \
                 the check reads turns on INC_APPEND_HISTORY, INC_APPEND_HISTORY_TIME or \
                 SHARE_HISTORY; bash (a shell the operator may use): no startup file the check \
                 reads runs `history -a` or `history -w` from PROMPT_COMMAND"
            )
        ),
        other => panic!("{other:?}"),
    }

    // The operator's login shell and every other shell the check knows.
    seed(&fs, "/home/alice/.bashrc", "PROMPT_COMMAND='history -a'\n");
    let message = warning(run(&fs, likely("fish")));
    assert!(
        message.starts_with(&format!(
            "{LIKELY}. fish, the operator's login shell, writes"
        )) && message.contains("bash, a shell the operator may use, writes"),
        "{message}"
    );

    // Its command line is not taken to tell how it started, as the decoy
    // commands may have been typed into another zsh: a turn-off in a login
    // shell's file does not count.
    let fs = MockFilesystem::new();
    seed(&fs, "/etc/zshrc", "setopt SHARE_HISTORY\n");
    seed(&fs, "/home/alice/.zlogin", "unsetopt share_history\n");
    assert!(matches!(zsh(&fs), CheckResult::Pass(_)));
    let message = warning(run(&fs, likely("zsh")));
    assert!(
        message.starts_with(&format!(
            "{LIKELY}. zsh, the shell this command was likely typed into, writes"
        )),
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
                "NAILS reads the history settings of bash, zsh and fish only, so it cannot tell \
                 whether {program}, the shell this command was typed into, writes"
            )),
            "{message}"
        );
    }
}

#[test]
fn a_shell_a_nixos_wrapper_starts_is_judged_by_its_own_name() {
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", "setopt share_history\n");
    assert!(warning(run(&fs, typed(".zsh-wrapped", &["zsh"]))).contains("SHARE_HISTORY"));
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
    seed(&fs, "/home/alice/.zshrc", "setopt INC_APPEND_HISTORY\n");
    let check = IncrementalHistoryFlushCheck::disabled();
    assert!(matches!(
        PreFlightCheck::run(&check, &fs).unwrap(),
        CheckResult::Pass(_)
    ));
}

#[test]
fn missing_startup_files_pass() {
    let fs = MockFilesystem::new();
    assert!(matches!(zsh(&fs), CheckResult::Pass(_)));
    assert!(matches!(bash(&fs), CheckResult::Pass(_)));
}

/// Home Manager's `.zshrc` options block with `history.share` on.
const HOME_MANAGER_ZSHRC: &str = "\
# Set shell options
set_opts=(
  HIST_FCNTL_LOCK HIST_IGNORE_DUPS SHARE_HISTORY NO_APPEND_HISTORY
  NO_EXTENDED_HISTORY
)
for opt in \"${set_opts[@]}\"; do
  setopt \"$opt\"
done
unset opt set_opts
";

#[test]
fn home_manager_s_zsh_options_and_dot_dir_are_seen() {
    // In the home.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", HOME_MANAGER_ZSHRC);
    let message = warning(run(&fs, typed("zsh", &["zsh"])));
    assert!(
        message.contains("as you enter it: /home/alice/.zshrc sets SHARE_HISTORY."),
        "{message}"
    );

    // In a `dotDir`, whose `.zshenv` the home's sources and which sets
    // ZDOTDIR.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshenv",
        "source '/home/alice/.config/zsh/.zshenv'\n",
    );
    seed(
        &fs,
        "/home/alice/.config/zsh/.zshenv",
        "export ZDOTDIR=/home/alice/.config/zsh\n",
    );
    seed(&fs, "/home/alice/.config/zsh/.zshrc", HOME_MANAGER_ZSHRC);
    let message = warning(run(&fs, typed("zsh", &["zsh"])));
    assert!(
        message.contains("/home/alice/.config/zsh/.zshrc sets SHARE_HISTORY"),
        "{message}"
    );
}

#[test]
fn a_setting_continued_on_the_next_line_is_seen() {
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "setopt \\\n  HIST_IGNORE_DUPS \\\n  SHARE_HISTORY\n",
    );
    assert!(warning(run(&fs, typed("zsh", &["zsh"]))).contains(".zshrc sets SHARE_HISTORY"));

    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.bashrc",
        "PROMPT_COMMAND=\"history \\\n  -a\"\n",
    );
    assert!(warning(bash(&fs)).contains(".bashrc runs `history -a` from PROMPT_COMMAND"));
}

#[test]
fn a_turn_off_that_may_not_run_does_not_hide_an_option() {
    for (path, off) in [
        (
            "/home/alice/.zshrc",
            "alias quiet='unsetopt share_history'\n",
        ),
        ("/home/alice/.zshrc", "quiet() { unsetopt share_history }\n"),
        (
            "/home/alice/.zshrc",
            "[[ -n $QUIET ]] && unsetopt share_history\n",
        ),
        // A zsh that is no login shell reads no .zlogin.
        ("/home/alice/.zlogin", "unsetopt share_history\n"),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/etc/zshrc", "setopt SHARE_HISTORY\n");
        seed(&fs, path, off);
        let result = run(&fs, typed("zsh", &["zsh"]));
        assert!(
            matches!(&result, CheckResult::Warn(message) if message.contains("sets SHARE_HISTORY")),
            "{off}: {result:?}"
        );
    }
}

#[test]
fn a_shift_in_an_arithmetic_command_hides_no_sourced_file() {
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "(( bits = 1 << 2 ))\nsource ~/.zsh/history.zsh\n",
    );
    seed(
        &fs,
        "/home/alice/.zsh/history.zsh",
        "setopt share_history\n",
    );
    let message = warning(zsh(&fs));
    assert!(
        message.contains("/home/alice/.zsh/history.zsh sets SHARE_HISTORY"),
        "{message}"
    );
}

#[test]
fn a_quote_in_a_command_substitution_hides_no_sourced_file() {
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "x=$(echo \")\")\nsource ~/.zsh/history.zsh\n",
    );
    seed(
        &fs,
        "/home/alice/.zsh/history.zsh",
        "setopt share_history\n",
    );
    let message = warning(zsh(&fs));
    assert!(
        message.contains("/home/alice/.zsh/history.zsh sets SHARE_HISTORY"),
        "{message}"
    );
}

#[test]
fn an_ansi_c_string_hides_no_sourced_file() {
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "x=$'it\\'s'\nsource ~/.zsh/history.zsh\n# don't touch this\n",
    );
    seed(
        &fs,
        "/home/alice/.zsh/history.zsh",
        "setopt share_history\n",
    );
    let message = warning(zsh(&fs));
    assert!(
        message.contains("/home/alice/.zsh/history.zsh sets SHARE_HISTORY"),
        "{message}"
    );
}

#[test]
fn a_here_document_in_a_command_substitution_hides_no_sourced_file() {
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "x=$(cat <<EOF\nit's\nEOF\n)\nsource ~/.zsh/history.zsh\n# don't\ncase $TERM in\n  \
         dumb) ;;\nesac\n",
    );
    seed(
        &fs,
        "/home/alice/.zsh/history.zsh",
        "setopt share_history\n",
    );
    let message = warning(zsh(&fs));
    assert!(
        message.contains("/home/alice/.zsh/history.zsh sets SHARE_HISTORY"),
        "{message}"
    );
}

#[test]
fn without_a_typed_shell_a_zsh_beside_a_login_bash_is_read() {
    let operator = TargetUser::for_test(1000, 100, "alice", HOME, "/bin/bash");
    let fs = MockFilesystem::new();
    seed(&fs, "/etc/zshrc", "setopt SHARE_HISTORY\n");
    let message = warning(run(&fs, InspectedShell::login(&operator)));
    assert!(
        message.contains("/etc/zshrc sets SHARE_HISTORY"),
        "{message}"
    );
}
