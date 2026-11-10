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
        exe: None,
        environment: None,
        started: None,
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
            "zsh, the shell this command was typed into, may write each command line to its \
             history file as you enter it: /home/alice/.zshrc names INC_APPEND_HISTORY."
        ),
        "{message}"
    );
    assert!(
        message.ends_with(
            "Type the decoy commands in a zsh started as `zsh -f`, which reads no startup file \
             but /etc/zshenv and, on NixOS, /etc/zshenv.local."
        ),
        "{message}"
    );
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
            message.contains("/home/alice/.zshrc names SHARE_HISTORY"),
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
            message.contains(&format!("{path} names SHARE_HISTORY")),
            "{message}"
        );
    }
}

#[test]
fn a_turn_off_in_a_later_startup_file_does_not_pass() {
    // No reading of the files can show that a turn-off holds: zsh may stop
    // before it, or set the option again after it.
    for off in [
        "unsetopt SHARE_HISTORY",
        "setopt no_share_history",
        "setopt NOSHAREHISTORY",
        "set +o share_history",
        "unsetopt share_history inc_append_history inc_append_history_time",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/etc/zshrc", "setopt SHARE_HISTORY\n");
        seed(&fs, "/home/alice/.zshrc", &format!("{off}\n"));
        let message = warning(zsh(&fs));
        assert!(
            message.contains("/home/alice/.zshrc names SHARE_HISTORY"),
            "{off}: {message}"
        );
    }
    // In the order zsh reads them: a zlogin is read after the zshrc.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", "unsetopt INC_APPEND_HISTORY\n");
    seed(&fs, "/etc/zlogin", "setopt INC_APPEND_HISTORY\n");
    assert!(warning(zsh(&fs)).contains("/etc/zlogin names INC_APPEND_HISTORY"));
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
            "history file once the command ends: /home/alice/.zprofile names \
             INC_APPEND_HISTORY_TIME."
        ),
        "{message}"
    );

    // With an option that writes as a line is entered, that is what it says.
    seed(&fs, "/etc/zshenv", "setopt share_history\n");
    let message = warning(zsh(&fs));
    assert!(
        message.contains(
            "history file as you enter it: /etc/zshenv names SHARE_HISTORY; \
             /home/alice/.zprofile names INC_APPEND_HISTORY_TIME."
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

    // Turned off after it is loaded, it still counts as on.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "source \"${ZSH}/oh-my-zsh.sh\"\nunsetopt share_history\n",
    );
    let message = warning(zsh(&fs));
    assert!(
        message.contains("/home/alice/.zshrc names SHARE_HISTORY"),
        "{message}"
    );
}

#[test]
fn the_user_files_are_read_from_the_zdotdir_a_zshenv_sets() {
    // A shell whose environment holds no variable the check reads.
    let zsh = |fs: &MockFilesystem| {
        run(
            fs,
            InspectedShell {
                environment: Some(Vec::new()),
                ..typed("zsh", &["-zsh"])
            },
        )
    };
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
            message.contains("/home/alice/.config/zsh/.zshrc names SHARE_HISTORY"),
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
    assert!(warning(zsh(&fs)).contains("/home/alice/.zsh/.zshrc names SHARE_HISTORY"));
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshenv", "echo $ZDOTDIR=/nowhere\n");
    seed(&fs, "/home/alice/.zshrc", "setopt share_history\n");
    assert!(warning(zsh(&fs)).contains("/home/alice/.zshrc names SHARE_HISTORY"));

    // XDG_CONFIG_HOME as a startup file sets it.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/etc/zshenv",
        "export XDG_CONFIG_HOME=/home/alice/cfg\nexport ZDOTDIR=$XDG_CONFIG_HOME/zsh\n",
    );
    seed(&fs, "/home/alice/cfg/zsh/.zshenv", "setopt share_history\n");
    assert!(warning(zsh(&fs)).contains("/home/alice/cfg/zsh/.zshenv names SHARE_HISTORY"));
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
    assert!(warning(zsh(&fs)).contains("/home/alice/.zshrc names SHARE_HISTORY"));
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
        message.contains("/home/alice/.zshrc names SHARE_HISTORY"),
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
    assert!(warning(zsh(&fs)).contains("/home/alice/.zsh/.zshrc names SHARE_HISTORY"));
}

proptest::proptest! {
    /// No text in a startup file makes the check panic, read as zsh's or as
    /// bash's. (`just fuzz` runs this with many more cases.)
    #[test]
    fn fuzz_no_startup_file_text_makes_the_check_panic(
        text in "(setopt|unsetopt|set|[-+]o|source|\\.|oh-my-zsh\\.sh|ZDOTDIR=|XDG_CONFIG_HOME=|\
                 PROMPT_COMMAND=|history|-a|-w|#|;|&|[|(){}'\"`=~]|\\$HOME|\\$\\{|:-|\
                 <<-?|<<<|<<=|[<>=]\\(|\\(\\(|\\)\\)|for|>|EOF|2>&1|\\$'|\\$\\(|\\\\'|case|esac|\\$\\{\\||\\$\\$|\\(#|[ \\t\\n]|[a-zé_ç]|\\PC){0,48}"
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
    assert!(warning(zsh(&fs)).contains("/home/alice/.zshrc names SHARE_HISTORY"));
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
            "zsh (the shell this command was typed into): no startup file the check reads names \
             INC_APPEND_HISTORY, INC_APPEND_HISTORY_TIME or SHARE_HISTORY, or holds an `fc` that \
             writes the history file"
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
        "# setopt INC_APPEND_HISTORY\n  # setopt share_history\nexport X=1\n",
    );
    assert!(matches!(zsh(&fs), CheckResult::Pass(_)));
    // One at the end of a line counts, as the lines are read for what a
    // misread may hide.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "export X=1 # setopt share_history\n",
    );
    let message = warning(zsh(&fs));
    assert!(
        message.contains("/home/alice/.zshrc names SHARE_HISTORY"),
        "{message}"
    );
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
            exe: None,
            environment: None,
            started: None,
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
            "{NOT_TYPED}. zsh, the operator's login shell, may write"
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
                 operator may use): no startup file the check reads names \
                 INC_APPEND_HISTORY, INC_APPEND_HISTORY_TIME or SHARE_HISTORY, or holds an `fc` \
                 that writes the history file"
            )
        ),
        other => panic!("{other:?}"),
    }

    // A login bash, and zsh's settings that a decoy zsh would follow.
    seed(&fs, "/etc/zshrc", "setopt SHARE_HISTORY\n");
    let message = warning(run(&fs, InspectedShell::login(&operator)));
    assert!(
        message.starts_with(&format!(
            "{NOT_TYPED}. zsh, a shell the operator may use, may write each command line to \
             its history file as you enter it: /etc/zshrc names SHARE_HISTORY."
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
        exe: None,
        environment: None,
        started: None,
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
        exe: None,
        environment: None,
        started: None,
    };
    let message = warning(run(&fs, shell.clone()));
    assert!(
        message.contains("/etc/zshrc names SHARE_HISTORY"),
        "{message}"
    );
    // Turned off in both homes, it still counts as on.
    seed(&fs, "/root/.zshrc", "unsetopt share_history\n");
    let message = warning(run(&fs, shell));
    assert!(message.contains("names SHARE_HISTORY"), "{message}");
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
        exe: None,
        environment: None,
        started: None,
    };
    let fs = MockFilesystem::new();
    match run(&fs, likely("zsh")) {
        CheckResult::Pass(message) => assert_eq!(
            message,
            format!(
                "{LIKELY}: zsh (the shell this command was likely typed into): no startup file \
                 the check reads names INC_APPEND_HISTORY, INC_APPEND_HISTORY_TIME or \
                 SHARE_HISTORY, or holds an `fc` that writes the history file; bash (a shell the \
                 operator may use): no startup file the check reads runs `history -a` or \
                 `history -w` from PROMPT_COMMAND"
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
    // commands may have been typed into another zsh: a login shell's file
    // counts too.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zlogin", "setopt share_history\n");
    assert!(matches!(
        run(&fs, typed("zsh", &["zsh"])),
        CheckResult::Pass(_)
    ));
    let message = warning(run(
        &fs,
        InspectedShell {
            argv: vec!["zsh".to_string()],
            ..likely("zsh")
        },
    ));
    assert!(
        message.starts_with(&format!(
            "{LIKELY}. zsh, the shell this command was likely typed into, may write"
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
        message.contains("as you enter it: /home/alice/.zshrc names SHARE_HISTORY."),
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
        message.contains("/home/alice/.config/zsh/.zshrc names SHARE_HISTORY"),
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
    assert!(warning(run(&fs, typed("zsh", &["zsh"]))).contains(".zshrc names SHARE_HISTORY"));

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
            matches!(&result, CheckResult::Warn(message) if message.contains("names SHARE_HISTORY")),
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
        message.contains("/home/alice/.zsh/history.zsh names SHARE_HISTORY"),
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
        message.contains("/home/alice/.zsh/history.zsh names SHARE_HISTORY"),
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
        message.contains("/home/alice/.zsh/history.zsh names SHARE_HISTORY"),
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
        message.contains("/home/alice/.zsh/history.zsh names SHARE_HISTORY"),
        "{message}"
    );
}

/// NixOS's `/etc/zshenv`, as `programs.zsh` writes it.
const NIXOS_ZSHENV: &str = "\
# /etc/zshenv: DO NOT EDIT -- this file has been generated automatically.
# This file is read for all shells.

# Only execute this file once per shell.
if [ -n \"${__ETC_ZSHENV_SOURCED-}\" ]; then return; fi
__ETC_ZSHENV_SOURCED=1

if [ -z \"${__NIXOS_SET_ENVIRONMENT_DONE-}\" ]; then
    . /nix/store/00000000000000000000000000000000-set-environment
fi

HELPDIR=\"/nix/store/00000000000000000000000000000000-zsh-5.9/share/zsh/$ZSH_VERSION/help\"

# Tell zsh how to find installed completions.
for p in ${(z)NIX_PROFILES}; do
    fpath=($p/share/zsh/site-functions $p/share/zsh/$ZSH_VERSION/functions $p/share/zsh/vendor-completions $fpath)
done

# Read system-wide modifications.
if test -f /etc/zshenv.local; then
    . /etc/zshenv.local
fi
";

/// NixOS's `/etc/zshrc`, as `programs.zsh` writes it by default, with
/// `programs.zsh.setOptions` set to `options`.
fn nixos_zshrc(options: &str) -> String {
    format!(
        "\
# /etc/zshrc: DO NOT EDIT -- this file has been generated automatically.
# This file is read for interactive shells.

# Only execute this file once per shell.
if [ -n \"$__ETC_ZSHRC_SOURCED\" -o -n \"$NOSYSZSHRC\" ]; then return; fi
__ETC_ZSHRC_SOURCED=1

# Set zsh options.
setopt {options}

# Setup command line history.
SAVEHIST=2000
HISTSIZE=2000
HISTFILE=$HOME/.zsh_history

# Configure sane keyboard defaults.
. /etc/zinputrc

# Enable autocompletion.
autoload -U compinit && compinit

# Extra colors for directory listings.
eval \"$(/nix/store/00000000000000000000000000000000-coreutils-9.5/bin/dircolors -b)\"

# Setup aliases.
alias -- l='ls -alh'
alias -- ll='ls -l'
alias -- ls='ls --color=tty'

# Setup prompt.
autoload -U promptinit && promptinit && prompt suse && setopt prompt_sp

# Disable some features to support TRAMP.
if [ \"$TERM\" = dumb ]; then
    unsetopt zle prompt_cr prompt_subst
    unset RPS1 RPROMPT
    PS1='$ '
    PROMPT='$ '
fi

# Read system-wide modifications.
if test -f /etc/zshrc.local; then
    . /etc/zshrc.local
fi
"
    )
}

#[test]
fn a_warning_gives_the_fix_the_check_can_see() {
    let fix = "Type the decoy commands in a zsh started as `zsh -f`, which reads no startup \
               file but /etc/zshenv and, on NixOS, /etc/zshenv.local.";
    // A final unsetopt is no fix: it names the option all the same.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "eval \"$(zoxide init zsh)\"\n\
         unsetopt share_history inc_append_history inc_append_history_time\n",
    );
    let message = warning(zsh(&fs));
    assert!(
        message.contains("/home/alice/.zshrc names SHARE_HISTORY") && message.contains(fix),
        "{message}"
    );
    // A doubt alone gives the same fix.
    seed(&fs, "/home/alice/.zshrc", "eval \"$(zoxide init zsh)\"\n");
    let message = warning(zsh(&fs));
    assert!(
        message.starts_with("The check cannot tell whether zsh") && message.ends_with(fix),
        "{message}"
    );
    // NixOS's defaults turn SHARE_HISTORY on in /etc/zshrc. Taken out of
    // programs.zsh.setOptions, it is named no more, and the `eval` of what
    // dircolors prints is one the check knows; where it cannot read the
    // shell's program and environment, it cannot follow the directories
    // /etc/zshenv adds to fpath, so the fix is zsh -f there.
    let fs = MockFilesystem::new();
    zsh::seed_coreutils(&fs, "00000000000000000000000000000000-coreutils-9.5");
    seed(&fs, "/etc/zshenv", NIXOS_ZSHENV);
    seed(
        &fs,
        "/etc/zshrc",
        &nixos_zshrc("HIST_IGNORE_DUPS SHARE_HISTORY HIST_FCNTL_LOCK"),
    );
    let message = warning(zsh(&fs));
    assert!(
        message.contains("/etc/zshrc names SHARE_HISTORY")
            && message.contains(fix)
            && !message.contains("setOptions"),
        "{message}"
    );
    seed(
        &fs,
        "/etc/zshrc",
        &nixos_zshrc("HIST_IGNORE_DUPS HIST_FCNTL_LOCK"),
    );
    let message = warning(zsh(&fs));
    let dir = |dir: &str| {
        format!(
            "it cannot follow the directory that /etc/zshenv adds to fpath as `{dir}`, where zsh \
             looks for the functions the files autoload"
        )
    };
    assert_eq!(
        message,
        format!(
            "The check cannot tell whether zsh, the shell this command was typed into, writes \
             each command line to its history file as it runs: {}; {}; {}; it cannot read the \
             functions the files autoload that no directory they put in front of fpath holds \
             (`compinit` and `promptinit`), which zsh then finds in one it was built with or one \
             FPATH names; it cannot tell what the `eval` of what dircolors prints in /etc/zshrc \
             runs, as the check does not know the shell's environment, which may set ARGV0. If \
             it does, {ON_DISK}. {fix}",
            dir("$p/share/zsh/site-functions"),
            dir("$p/share/zsh/$ZSH_VERSION/functions"),
            dir("$p/share/zsh/vendor-completions"),
        )
    );
    // A zsh started so reads /etc/zshenv alone, which names none and
    // autoloads none: it passes, with SHARE_HISTORY in /etc/zshrc too.
    seed(
        &fs,
        "/etc/zshrc",
        &nixos_zshrc("HIST_IGNORE_DUPS SHARE_HISTORY HIST_FCNTL_LOCK"),
    );
    assert!(matches!(
        run(&fs, typed("zsh", &["zsh", "-f"])),
        CheckResult::Pass(_)
    ));
    // When what it reads names an option, the fix is there.
    seed(&fs, "/etc/zshenv.local", "setopt share_history\n");
    let message = warning(run(&fs, typed("zsh", &["zsh", "-f"])));
    assert!(
        message.contains("/etc/zshenv.local names SHARE_HISTORY")
            && message.contains(
                "A zsh started as `zsh -f` still reads /etc/zshenv, on NixOS \
                 /etc/zshenv.local too, and what they source, so take what the check names out \
                 of them."
            )
            && !message.contains(fix),
        "{message}"
    );
}

#[test]
fn an_fc_that_writes_the_history_file_is_named_in_the_warning() {
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", "precmd() { fc -AI }\n");
    assert_eq!(
        warning(zsh(&fs)),
        format!(
            "zsh, the shell this command was typed into, may write each command line to its \
             history file as you enter it: /home/alice/.zshrc names `fc -AI`. So {ON_DISK}. Type \
             the decoy commands in a zsh started as `zsh -f`, which reads no startup file but \
             /etc/zshenv and, on NixOS, /etc/zshenv.local."
        )
    );
}

#[test]
fn a_zsh_f_whose_command_line_or_zshenv_turns_more_on_warns() {
    // `zsh -f -o sharehistory`, with no /etc/zshenv.
    let fs = MockFilesystem::new();
    let message = warning(run(&fs, typed("zsh", &["zsh", "-f", "-o", "sharehistory"])));
    assert_eq!(
        message,
        format!(
            "zsh, the shell this command was typed into, may write each command line to its \
             history file as you enter it: its command line turns on SHARE_HISTORY. So \
             {ON_DISK}. Type the decoy commands in a zsh started as `zsh -f`, with nothing else \
             on its command line, which reads no startup file but /etc/zshenv and, on NixOS, \
             /etc/zshenv.local."
        )
    );
    // A zsh -f whose /etc/zshenv turns RCS on again reads ~/.zshrc too.
    seed(&fs, "/etc/zshenv", "setopt rcs\n");
    seed(&fs, "/home/alice/.zshrc", "setopt share_history\n");
    let message = warning(run(&fs, typed("zsh", &["zsh", "-f"])));
    assert!(
        message.contains("/home/alice/.zshrc names SHARE_HISTORY")
            && message.ends_with(
                "A zsh started as `zsh -f` still reads /etc/zshenv, on NixOS \
                 /etc/zshenv.local too, and what they source, and as they name RCS or \
                 GLOBAL_RCS, it may read the other startup files too: take that out of them."
            ),
        "{message}"
    );
    // With every file it reads clean, it passes.
    seed(&fs, "/home/alice/.zshrc", "HISTFILE=~/.zsh_history\n");
    assert!(matches!(
        run(&fs, typed("zsh", &["zsh", "-f"])),
        CheckResult::Pass(_)
    ));
}

#[test]
fn a_prompt_s_code_is_a_doubt_where_the_command_line_turns_prompt_subst_on() {
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", "PS1='$(git_branch) %# '\n");
    assert!(matches!(zsh(&fs), CheckResult::Pass(_)));
    let message = warning(run(&fs, typed("zsh", &["zsh", "-o", "promptsubst"])));
    assert!(
        message.contains(
            "it cannot follow the code that `PS1=$(git_branch) %# ` in /home/alice/.zshrc runs \
             as zsh shows the prompt, as PROMPT_SUBST may be on"
        ),
        "{message}"
    );
}

#[test]
fn a_prompt_in_a_typed_zsh_s_environment_is_code_where_prompt_subst_may_be_on() {
    // zsh 5.9.2 takes PS1 from its environment and runs `fc -AI` as it shows
    // it with `setopt prompt_subst` in ~/.zshrc, which appends each command
    // line to HISTFILE; one that is no UTF-8 holds the same code.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", "setopt prompt_subst\n");
    for bytes in [&b"PS1=$(fc -AI)%# \0"[..], &b"PS1=\xff$(fc -AI)%# \0"[..]] {
        let shell = InspectedShell {
            environment: environment(bytes),
            ..typed("zsh", &["-zsh"])
        };
        let message = warning(run(&fs, shell));
        assert!(
            message.contains(
                "it cannot follow the code that `PS1` in the shell's environment holds, which zsh \
                 runs as it shows the prompt unless a file sets it, as PROMPT_SUBST may be on"
            ),
            "{message}"
        );
    }
    // Without PROMPT_SUBST, it is a doubt where the command line turns it on.
    seed(&fs, "/home/alice/.zshrc", "");
    let shell = |argv: &[&str]| InspectedShell {
        environment: environment(b"RPROMPT=$(fc -AI)\0"),
        ..typed("zsh", argv)
    };
    assert!(matches!(run(&fs, shell(&["-zsh"])), CheckResult::Pass(_)));
    assert!(warning(run(&fs, shell(&["zsh", "-o", "promptsubst"]))).contains("`RPROMPT`"));
}

#[test]
fn without_a_typed_shell_a_zsh_beside_a_login_bash_is_read() {
    let operator = TargetUser::for_test(1000, 100, "alice", HOME, "/bin/bash");
    let fs = MockFilesystem::new();
    seed(&fs, "/etc/zshrc", "setopt SHARE_HISTORY\n");
    let message = warning(run(&fs, InspectedShell::login(&operator)));
    assert!(
        message.contains("/etc/zshrc names SHARE_HISTORY"),
        "{message}"
    );
}

#[test]
fn a_typed_zsh_is_read_with_its_program_and_environment() {
    use crate::filesystem::PathKind;
    // A zsh 5.9.2 from the Nix store, whose own directory holds promptinit
    // as a test takes the stock one, and a .zshrc that runs it.
    let zsh = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-zsh-5.9.2";
    let own = format!("{zsh}/share/zsh/5.9.2/functions");
    let fs = MockFilesystem::new();
    seed(&fs, &format!("{zsh}/bin/zsh"), &format!("\0{own}\0"));
    fs.mock_set_path_type(&own, PathKind::Dir);
    seed(
        &fs,
        &format!("{own}/promptinit"),
        "# The stock promptinit of a test.\ntypeset -A _i_test\n",
    );
    fs.mock_set_directory_contents(
        std::path::Path::new(&own),
        vec![PathBuf::from(format!("{own}/promptinit"))],
    );
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz promptinit && promptinit\n",
    );
    let shell = |environment: Option<Vec<(String, String)>>| InspectedShell {
        exe: Some(PathBuf::from(format!("{zsh}/bin/zsh"))),
        environment,
        ..typed("zsh", &["-zsh"])
    };
    assert!(
        matches!(run(&fs, shell(Some(Vec::new()))), CheckResult::Pass(_)),
        "{:?}",
        run(&fs, shell(Some(Vec::new())))
    );
    // Without its environment, where zsh may find promptinit is a doubt.
    assert!(warning(run(&fs, shell(None))).contains("(`promptinit`)"));
    // An FPATH there names where zsh finds it.
    let fpath = vec![("FPATH".to_string(), "/home/alice/.zfunc".to_string())];
    seed(
        &fs,
        "/home/alice/.zfunc/promptinit",
        "setopt share_history\n",
    );
    assert!(
        warning(run(&fs, shell(Some(fpath))))
            .contains("/home/alice/.zfunc/promptinit names SHARE_HISTORY")
    );
    // A compinit there is a doubt of what zsh runs as you complete a word.
    seed(
        &fs,
        &format!("{own}/compinit"),
        "# The compinit of a test.\n",
    );
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz compinit && compinit\n",
    );
    assert!(
        warning(run(&fs, shell(Some(Vec::new()))))
            .contains("it cannot tell what zsh runs as you complete a word")
    );
}

#[test]
fn a_shell_s_environment_keeps_the_variables_the_check_reads() {
    assert_eq!(
        environment(
            b"HOME=/home/alice\0FPATH=/a:/b\0USER=alice\0FPATH=/c\0TOKEN=x\0=y\0\
              NIX_PROFILES=/p q\0_compdir=/c\0ZDOTDIR=/z\0"
        ),
        Some(
            [
                ("HOME", "/home/alice"),
                ("FPATH", "/a:/b"),
                ("USER", "alice"),
                ("NIX_PROFILES", "/p q"),
                ("ZDOTDIR", "/z"),
            ]
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .to_vec()
        )
    );
    assert_eq!(environment(b""), Some(Vec::new()));
    // ARGV0 and MAILPATH are kept, and any variable of the dynamic loader as
    // `LD_` alone, without its value.
    assert_eq!(
        environment(b"LD_PRELOAD=/x.so\0ARGV0=ls\0LD_LIBRARY_PATH=\xff\0MAILPATH=/m?$(x)\0"),
        Some(
            [("LD_", ""), ("ARGV0", "ls"), ("MAILPATH", "/m?$(x)")]
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .to_vec()
        )
    );
    // A parameter zsh reads as arithmetic each time it uses it is kept, what
    // is no UTF-8 in it replaced, as the check reads it only for whether it
    // is a number.
    assert_eq!(
        environment(b"TMOUT=9\xff\0REPORTTIME=5\0"),
        Some(
            [("TMOUT", "9\u{fffd}"), ("REPORTTIME", "5")]
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .to_vec()
        )
    );
    assert_eq!(environment(b"OLD_PATH=/x\0").map(|env| env.len()), Some(0));
    // PATH is none the check keeps, in any form.
    assert_eq!(
        environment(b"PATH=/run/wrappers/bin::bin\0MANPATH=/m\0"),
        Some(Vec::new())
    );
    assert_eq!(
        environment(b"PATH=/home/alice/b\xffn:/usr/bin\0"),
        Some(Vec::new())
    );
    // The prompts zsh takes from its environment are kept, and a prompt's
    // or MAILPATH's value that is no UTF-8 with it replaced, as the check
    // reads it only for an expansion in it.
    assert_eq!(
        environment(
            b"PS1=%# \0RPROMPT=$(x)\0PROMPT_EOL_MARK=%\0PS4=\xff$(y)\0MAILPATH=\xff\0\
              NULLCMD=log\0READNULLCMD=\xff\0"
        ),
        Some(
            [
                ("PS1", "%# "),
                ("RPROMPT", "$(x)"),
                ("PROMPT_EOL_MARK", "%"),
                ("PS4", "\u{fffd}$(y)"),
                ("MAILPATH", "\u{fffd}"),
                ("NULLCMD", "log"),
                ("READNULLCMD", "\u{fffd}"),
            ]
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .to_vec()
        )
    );
    // A value that is no UTF-8 names a path the check cannot name, so the
    // environment counts as unknown; one of a variable it does not keep
    // does not count.
    assert_eq!(environment(b"FPATH=/home/alice/fn\xff\0USER=alice\0"), None);
    assert_eq!(
        environment(b"TOKEN=\xff\0USER=alice\0").map(|env| env.len()),
        Some(1)
    );
}

#[test]
fn a_typed_zsh_whose_files_changed_after_it_started_is_told_to_start_again() {
    use crate::filesystem::PathKind;
    use std::time::{Duration, UNIX_EPOCH};
    // zsh 5.9 to 5.9.2 keep SHARE_HISTORY on after it is taken out of
    // ~/.zshrc while they run.
    let fs = MockFilesystem::new();
    for dir in ["/", "/etc", "/home", HOME] {
        fs.mock_set_path_type(dir, PathKind::Dir);
    }
    seed(&fs, "/home/alice/.zshrc", "HISTSIZE=100\n");
    let started = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    fs.mock_set_change_time("/home/alice/.zshrc", started + Duration::from_secs(30));
    let shell = |started| InspectedShell {
        started,
        ..typed("zsh", &["-zsh"])
    };
    assert_eq!(
        warning(run(&fs, shell(Some(Ok(started))))),
        "The check cannot tell whether zsh, the shell this command was typed into, writes each \
         command line to its history file as it runs: it cannot tell what the shell read as it \
         started, as /home/alice/.zshrc changed after it started (a shell started now reads what \
         is there now). If it does, the commands typed in it are on the decoy disk once it writes \
         them, and killing the shells at activation cannot take them back. Type the decoy \
         commands in a zsh you start after the change, the way you started this one: it reads \
         the startup files as they are then."
    );
    // One started later, and a login shell, which may not run yet, pass.
    let later = started + Duration::from_secs(60);
    assert!(matches!(
        run(&fs, shell(Some(Ok(later)))),
        CheckResult::Pass(_)
    ));
    assert!(matches!(run(&fs, shell(None)), CheckResult::Pass(_)));
    // Beside another doubt, the fix is the one for that.
    seed(&fs, "/home/alice/.zshrc", "eval \"$x\"\n");
    let message = warning(run(&fs, shell(Some(Ok(started)))));
    assert!(message.ends_with(ZSH_FIX), "{message}");
}

#[test]
fn a_process_s_start_is_the_boot_time_and_its_clock_ticks() {
    use std::time::{Duration, UNIX_EPOCH};
    let stat = "cpu  1 2 3\nbtime 1700000000\nprocesses 5\n";
    assert_eq!(
        started_at(stat, 12_345),
        Some(UNIX_EPOCH + Duration::from_secs(1_700_000_123) + Duration::from_millis(450))
    );
    assert_eq!(started_at("cpu  1 2 3\n", 1), None);
    assert_eq!(started_at("btime x\n", 1), None);
    // The process running this test started after the boot, and not later
    // than now.
    let me = start_time(std::process::id()).unwrap();
    assert!(me <= std::time::SystemTime::now() + Duration::from_secs(1));
    assert!(start_time(u32::MAX).is_err());
}
