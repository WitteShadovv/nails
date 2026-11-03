// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::filesystem::MockFilesystem;

// The functions the startup files autoload, the directories they add to
// fpath, and the compiled code and expanded paths zsh may run.
#[path = "zsh_autoload_tests.rs"]
mod autoload;

// What zsh writes or turns on as it runs that no word of the files names as
// one of the options.
#[path = "zsh_runtime_tests.rs"]
mod runtime;

const HOME: &str = "/home/alice";

/// A login shell that reads every startup file.
const LOGIN: Start = Start {
    login: Some(true),
    rcs: true,
    global_rcs: true,
};

/// An interactive shell that is not a login shell.
const NOT_LOGIN: Start = Start {
    login: Some(false),
    rcs: true,
    global_rcs: true,
};

/// A shell the check cannot tell is a login shell.
const UNKNOWN: Start = Start {
    login: None,
    rcs: true,
    global_rcs: true,
};

/// A file of `text` at `path`.
fn seed(fs: &MockFilesystem, path: &str, text: &str) {
    fs.mock_set_file_content(path, text);
}

/// What `fs` sets for a zsh started as `start`, in the home.
fn scan(fs: &MockFilesystem, start: Start) -> Scan {
    zsh(fs, &[PathBuf::from(HOME)], start)
}

/// The settings `fs` turns on, as the warning names them.
fn on(fs: &MockFilesystem, start: Start) -> Vec<String> {
    scan(fs, start)
        .writes
        .into_iter()
        .map(|write| write.what)
        .collect()
}

/// NixOS's `/etc/zshrc` with `programs.zsh`'s default options, behind its
/// guard against a second read.
const NIXOS_ZSHRC: &str = "\
# /etc/zshrc: DO NOT EDIT -- this file has been generated automatically.
if [ -n \"$__ETC_ZSHRC_SOURCED\" -o -n \"$NOSYSZSHRC\" ]; then return; fi
__ETC_ZSHRC_SOURCED=1

# Set zsh options.
setopt HIST_IGNORE_DUPS SHARE_HISTORY HIST_FCNTL_LOCK

SAVEHIST=2000
HISTFILE=$HOME/.zsh_history
. /etc/zinputrc
";

/// Home Manager's options block, as its zsh module writes it, with
/// `history.share` on (`share`) or off.
fn home_manager_options(share: bool) -> String {
    let share = if share {
        "SHARE_HISTORY"
    } else {
        "NO_SHARE_HISTORY"
    };
    format!(
        "# Set shell options
set_opts=(
  HIST_FCNTL_LOCK HIST_IGNORE_DUPS {share} NO_APPEND_HISTORY
  NO_EXTENDED_HISTORY
)
for opt in \"${{set_opts[@]}}\"; do
  setopt \"$opt\"
done
unset opt set_opts
"
    )
}

#[test]
fn home_manager_s_options_are_read_item_by_item() {
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", &home_manager_options(true));
    let found = scan(&fs, NOT_LOGIN);
    assert_eq!(
        found.writes,
        vec![Write {
            what: "/home/alice/.zshrc names SHARE_HISTORY".to_string(),
            entered: true,
            option: true,
        }]
    );
    assert!(found.doubts.is_empty(), "{:?}", found.doubts);

    // With `history.share = false` it names the option all the same.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", &home_manager_options(false));
    assert_eq!(
        on(&fs, NOT_LOGIN),
        ["/home/alice/.zshrc names SHARE_HISTORY"]
    );
}

#[test]
fn home_manager_s_dot_dir_is_followed_through_the_zshenv_it_sources() {
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshenv",
        "source '/home/alice/.config/zsh/.zshenv'\n",
    );
    seed(
        &fs,
        "/home/alice/.config/zsh/.zshenv",
        "# Environment variables\n\
         . \"/nix/store/x-hm-session-vars/etc/profile.d/hm-session-vars.sh\"\n\
         export ZDOTDIR=/home/alice/.config/zsh\n",
    );
    seed(
        &fs,
        "/home/alice/.config/zsh/.zshrc",
        &home_manager_options(true),
    );
    assert_eq!(
        on(&fs, NOT_LOGIN),
        ["/home/alice/.config/zsh/.zshrc names SHARE_HISTORY"]
    );
}

#[test]
fn a_setopt_line_goes_on_after_a_backslash() {
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "setopt \\\n  HIST_IGNORE_DUPS \\\n  INC_APPEND_HISTORY\n",
    );
    assert_eq!(
        on(&fs, NOT_LOGIN),
        ["/home/alice/.zshrc names INC_APPEND_HISTORY"]
    );
}

#[test]
fn a_turn_off_that_may_not_run_leaves_the_option_on() {
    for off in [
        "alias quiet='unsetopt share_history'",
        "quiet() { unsetopt share_history }",
        "quiet() unsetopt share_history",
        "function quiet {\n  unsetopt share_history\n}",
        "[[ -n $QUIET ]] && unsetopt share_history",
        "[[ -z $QUIET ]] || unsetopt share_history",
        "if [[ -n $QUIET ]]; then\n  unsetopt share_history\nfi",
        "case $TERM in\n  dumb) unsetopt share_history ;;\nesac",
        "while false; do unsetopt share_history; done",
        "for name in $names; do unsetopt share_history; done",
        "( unsetopt share_history )",
        "unsetopt share_history | cat",
        "unsetopt share_history &",
        "[[ -n $QUIET ]] && return\nunsetopt share_history",
        "if true; then\nunsetopt share_history\n",
        // Text a command reads, not code.
        "cat <<EOF >> ~/.zsh_local\nunsetopt share_history\nEOF",
        "cat <<-'EOF' | zsh\n\tunsetopt share_history\n\tEOF",
        // An anonymous function, which can keep its options local.
        "() { setopt localoptions; unsetopt share_history }",
        "() {\n  emulate -L zsh\n  unsetopt share_history\n}",
        // A group or a loop in the background or a pipeline.
        "{ unsetopt share_history; } &",
        "{ unsetopt share_history } &!",
        "{\n  unsetopt share_history\n} 2>&1 &",
        "for name in share_history; do unsetopt $name; done | cat",
        "[[ -n $QUIET ]] && {\n  true\n  unsetopt share_history\n}",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/etc/zshrc", NIXOS_ZSHRC);
        seed(&fs, "/home/alice/.zshrc", &format!("{off}\n"));
        let found = on(&fs, NOT_LOGIN);
        assert_eq!(found.len(), 1, "{off}: {found:?}");
        assert!(
            found[0].ends_with("names SHARE_HISTORY"),
            "{off}: {found:?}"
        );
    }
}

#[test]
fn a_turn_off_never_counts() {
    // No reading of the files can show that a turn-off holds, so it names
    // the option as a turn-on does.
    for off in [
        "unsetopt share_history",
        "setopt no_share_history",
        "set +o sharehistory",
        "unsetopt share_history || true",
        "{ unsetopt share_history }",
        "for name in share_history; do unsetopt $name; done",
        "noglob unsetopt share_history 2>/dev/null",
        "{ unsetopt share_history } 2>/dev/null",
        "{ { unsetopt share_history } }",
        "for name in share_history; do { unsetopt $name } done",
        "cat <<EOF\nsetopt nothing\nEOF\nunsetopt share_history",
        "() { true }\nunsetopt share_history",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{off}\n"));
        assert_eq!(
            on(&fs, NOT_LOGIN),
            ["/home/alice/.zshrc names SHARE_HISTORY"],
            "{off}"
        );
    }
}

#[test]
fn a_path_is_resolved_in_every_home_and_config_home_it_may_be_in() {
    // `~` and `$HOME` in each home a root shell may run with.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", "source ~/.zsh/history.zsh\n");
    seed(
        &fs,
        "/home/alice/.zsh/history.zsh",
        "setopt share_history\n",
    );
    seed(&fs, "/etc/zshenv", "export ZDOTDIR=$HOME/.config/zsh\n");
    seed(
        &fs,
        "/home/alice/.config/zsh/.zshrc",
        "setopt inc_append_history\n",
    );
    let homes = [PathBuf::from("/root"), PathBuf::from(HOME)];
    let on_in_both = |fs: &MockFilesystem| -> Vec<String> {
        zsh(fs, &homes, NOT_LOGIN)
            .writes
            .into_iter()
            .map(|write| write.what)
            .collect()
    };
    assert_eq!(
        on_in_both(&fs),
        ["/home/alice/.config/zsh/.zshrc names INC_APPEND_HISTORY"]
    );
    seed(&fs, "/etc/zshenv", "");
    assert_eq!(
        on_in_both(&fs),
        ["/home/alice/.zsh/history.zsh names SHARE_HISTORY"]
    );

    // An XDG_CONFIG_HOME set under a condition, and the default beside it.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshenv",
        "[[ -d ~/.cfg ]] && export XDG_CONFIG_HOME=~/.cfg\n",
    );
    seed(
        &fs,
        "/home/alice/.zshrc",
        "source ${XDG_CONFIG_HOME:-$HOME/.config}/zsh/history.zsh\n",
    );
    seed(
        &fs,
        "/home/alice/.cfg/zsh/history.zsh",
        "setopt share_history\n",
    );
    seed(
        &fs,
        "/home/alice/.config/zsh/history.zsh",
        "setopt inc_append_history_time\n",
    );
    assert_eq!(
        on(&fs, NOT_LOGIN),
        [
            "/home/alice/.cfg/zsh/history.zsh names SHARE_HISTORY",
            "/home/alice/.config/zsh/history.zsh names INC_APPEND_HISTORY_TIME",
        ]
    );
}

#[test]
fn a_zdotdir_or_a_source_the_check_cannot_read_is_a_doubt() {
    for (line, doubt) in [
        (
            ": ${ZDOTDIR:=$HOME/.config/zsh}",
            "it cannot follow where `${ZDOTDIR:=$HOME/.config/zsh}` in /home/alice/.zshrc sets \
             ZDOTDIR",
        ),
        (
            "ZDOTDIR+=/zsh",
            "it cannot follow where `ZDOTDIR+=/zsh` in /home/alice/.zshrc sets ZDOTDIR",
        ),
        (
            "source <(mytool init zsh)",
            "it cannot follow the file /home/alice/.zshrc sources as `<(mytool init zsh)`",
        ),
        (
            ". =(mytool init zsh)",
            "it cannot follow the file /home/alice/.zshrc sources as `=(mytool init zsh)`",
        ),
        (
            "source",
            "it cannot tell what `source` in /home/alice/.zshrc reads",
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{line}\n"));
        assert_eq!(scan(&fs, NOT_LOGIN).doubts, [doubt], "{line}");
    }
}

#[test]
fn a_shift_in_an_arithmetic_command_opens_no_here_document() {
    for arithmetic in [
        "(( bits = 1 << 2 ))",
        "(( flags <<= 1 ))",
        "for (( i = 0; i < 3; i++ )); do (( m <<= 1 )); done",
        "if (( 1 << 2 )); then true; fi",
    ] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("{arithmetic}\nsource ~/.zsh/history.zsh\n"),
        );
        seed(
            &fs,
            "/home/alice/.zsh/history.zsh",
            "setopt share_history\n",
        );
        assert_eq!(
            scan(&fs, NOT_LOGIN).doubts,
            Vec::<String>::new(),
            "{arithmetic}"
        );
        assert_eq!(
            on(&fs, NOT_LOGIN),
            ["/home/alice/.zsh/history.zsh names SHARE_HISTORY"],
            "{arithmetic}"
        );
    }

    // The ZDOTDIR a line after one sets is followed.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshenv",
        "(( n = 1 << 3 ))\nexport ZDOTDIR=~/.config/zsh\n",
    );
    seed(
        &fs,
        "/home/alice/.config/zsh/.zshrc",
        "setopt share_history\n",
    );
    assert_eq!(
        on(&fs, NOT_LOGIN),
        ["/home/alice/.config/zsh/.zshrc names SHARE_HISTORY"]
    );

    // After one, a ZDOTDIR set at the top level moves where zsh reads, and
    // two subshells, `((...); ...)`, are no arithmetic command: one set in
    // them does not.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", "setopt share_history\n");
    seed(
        &fs,
        "/home/alice/.config/zsh/.zshrc",
        "setopt inc_append_history\n",
    );
    seed(
        &fs,
        "/home/alice/.zshenv",
        "(( x = 1 << 2 ))\nexport ZDOTDIR=~/.config/zsh\n",
    );
    assert_eq!(
        on(&fs, NOT_LOGIN),
        ["/home/alice/.config/zsh/.zshrc names INC_APPEND_HISTORY"]
    );
    seed(
        &fs,
        "/home/alice/.zshenv",
        "((cd /tmp); export ZDOTDIR=~/.config/zsh)\n",
    );
    assert_eq!(
        on(&fs, NOT_LOGIN),
        [
            "/home/alice/.config/zsh/.zshrc names INC_APPEND_HISTORY",
            "/home/alice/.zshrc names SHARE_HISTORY",
        ]
    );
}

#[test]
fn a_here_document_without_the_line_that_ends_it_is_a_doubt() {
    // Its body stays text: a source in it is not followed, and a turn-off
    // in it names the option.
    let fs = MockFilesystem::new();
    seed(&fs, "/etc/zshrc", NIXOS_ZSHRC);
    seed(
        &fs,
        "/home/alice/.zshrc",
        "cat <<EOF\nsource ~/.zsh/history.zsh\nunsetopt share_history\n",
    );
    seed(
        &fs,
        "/home/alice/.zsh/history.zsh",
        "setopt inc_append_history\n",
    );
    let found = scan(&fs, NOT_LOGIN);
    assert_eq!(
        found.doubts,
        [
            "it cannot tell where the here-document that /home/alice/.zshrc opens with `<<EOF` \
             ends",
            "it cannot follow a `source` or `.` that a line of /home/alice/.zshrc may run",
        ]
    );
    assert_eq!(
        on(&fs, NOT_LOGIN),
        ["/home/alice/.zshrc names SHARE_HISTORY"]
    );

    // One opened on the last line, and one with no word to end it.
    for (text, delimiter) in [("cat <<EOF", "EOF"), ("cat << ; true\n", "")] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", text);
        assert_eq!(
            scan(&fs, NOT_LOGIN).doubts,
            [format!(
                "it cannot tell where the here-document that /home/alice/.zshrc opens with \
                 `<<{delimiter}` ends"
            )],
            "{text:?}"
        );
    }
}

#[test]
fn a_quote_in_an_expansion_closes_nothing() {
    for line in [
        r#"x=$(echo ")")"#,
        "x=$(printf '%s)' y)",
        r#"y=${x//"}"/}"#,
        r#"(( $(echo ")") ))"#,
        // A `'` in a `${...}` in double quotes quotes nothing.
        r#"z="${x:-'}""#,
        r#"w=`echo ")"`"#,
    ] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("{line}\nsource ~/.zsh/history.zsh\n"),
        );
        seed(
            &fs,
            "/home/alice/.zsh/history.zsh",
            "setopt share_history\n",
        );
        assert_eq!(scan(&fs, NOT_LOGIN).doubts, Vec::<String>::new(), "{line}");
        assert_eq!(
            on(&fs, NOT_LOGIN),
            ["/home/alice/.zsh/history.zsh names SHARE_HISTORY"],
            "{line}"
        );
    }
}

#[test]
fn an_ansi_c_string_ends_at_its_first_quote_without_a_backslash() {
    for (first, third) in [
        (r"x=$'it\'s'", "# don't touch this"),
        (r"x=$'it\'s'", r"y=don\'t"),
        (r"x=$'it\'s'", r"y='a' z=it\'s"),
        (r"q=$'\''", "# it's here"),
        (r"x=$(print $'it\'s')", "# don't touch this"),
        (r"x=${y:-$'it\'s'}", "# don't touch this"),
        // In double quotes, `$'` is a `$` and a `'`.
        (r#"x="$'""#, "# don't touch this"),
    ] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("{first}\nsource ~/.zsh/history.zsh\n{third}\n"),
        );
        seed(
            &fs,
            "/home/alice/.zsh/history.zsh",
            "setopt share_history\n",
        );
        assert_eq!(scan(&fs, NOT_LOGIN).doubts, Vec::<String>::new(), "{first}");
        assert_eq!(
            on(&fs, NOT_LOGIN),
            ["/home/alice/.zsh/history.zsh names SHARE_HISTORY"],
            "{first}"
        );
    }
}

#[test]
fn a_here_document_or_a_comment_in_a_command_substitution_is_text() {
    for text in [
        // A `case` after it, whose pattern ends in a `)`.
        "x=$(cat <<EOF\nit's\nEOF\n)\ncase $TERM in\n  dumb) ;;\nesac\nsource ~/.zsh/history.zsh\n",
        // And with a quote further down, which closed the quote the body
        // seemed to open.
        "x=$(cat <<EOF\nit's\nEOF\n)\nsource ~/.zsh/history.zsh\n# don't\ncase $TERM in\n  dumb) ;;\nesac\n",
        "x=$(cat <<-'EOF'\n\tdon't\n\tEOF\n)\nsource ~/.zsh/history.zsh\ny=it\\'s\ncase $x in a) ;; esac\n",
        "x=$(  # don't\n  print hi\n)\nsource ~/.zsh/history.zsh\ny=it\\'s\ncase $x in a) ;; esac\n",
        // What is no here-document, comment or subshell there.
        "x=$(( 1 << 2 ))\nsource ~/.zsh/history.zsh\n",
        "x=$(print $(( 1 << 2 )))\nsource ~/.zsh/history.zsh\n",
        "x=$( (( n = 1 << 3 )) && print y )\nsource ~/.zsh/history.zsh\n",
        "x=$(cat <<< \"it's\")\nsource ~/.zsh/history.zsh\n",
        "x=$(cat <<EOF\na)\nEOF\n)\nsource ~/.zsh/history.zsh\n",
        "x=$(print \"#\" '#' a#b)\nsource ~/.zsh/history.zsh\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", text);
        seed(
            &fs,
            "/home/alice/.zsh/history.zsh",
            "setopt share_history\n",
        );
        assert_eq!(
            scan(&fs, NOT_LOGIN).doubts,
            Vec::<String>::new(),
            "{text:?}"
        );
        assert_eq!(
            on(&fs, NOT_LOGIN),
            ["/home/alice/.zsh/history.zsh names SHARE_HISTORY"],
            "{text:?}"
        );
    }
}

#[test]
fn what_an_expansion_holds_that_the_check_cannot_read_is_a_doubt() {
    for (line, opener, what) in [
        (
            "x=$(case $TERM in dumb) print d;; esac)",
            "`$(`",
            "a `case`",
        ),
        ("x=${ print hi }", "`${`", "a command"),
        ("x=${| REPLY=hi }", "`${`", "a command"),
    ] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("{line}\nsource ~/.zsh/history.zsh\n"),
        );
        assert_eq!(
            scan(&fs, NOT_LOGIN).doubts,
            [format!(
                "it cannot follow the {opener} that /home/alice/.zshrc opens, which holds {what}"
            )],
            "{line}"
        );
    }
}

/// The doubt of a quote that runs to the end of `/home/alice/.zshrc`.
const OPEN_QUOTE: &str = "it cannot tell where the `'` that /home/alice/.zshrc opens ends";

#[test]
fn what_zsh_reads_as_code_after_a_glob_flag_an_arithmetic_quote_or_a_pid_is_read() {
    for (text, doubts) in [
        // Glob flags and a pattern's parentheses start a word: no comment.
        (
            "[[ $HOST == (#i)nohost* ]] || source ~/.zsh/history.zsh\n",
            &[][..],
        ),
        ("[[ abc == (#i)A* ]] && source ~/.zsh/history.zsh\n", &[]),
        (
            "if [[ abc == (#i)A* ]]; then source ~/.zsh/history.zsh; fi\n",
            &[],
        ),
        (
            "print -l (#i)*.zsh(N) >/dev/null; source ~/.zsh/history.zsh\n",
            &[],
        ),
        ("[[ a == (#b)(*) ]]; source ~/.zsh/history.zsh\n", &[]),
        ("[[ $x == (a|b) ]] && source ~/.zsh/history.zsh\n", &[]),
        // In arithmetic a quote is a character.
        (
            "(( x ==$' 1 ))\nsource ~/.zsh/history.zsh\n'\n",
            &[OPEN_QUOTE],
        ),
        ("(( y == ' 1 ))\nsource ~/.zsh/history.zsh\n# it's\n", &[]),
        (
            "x=$(( y == ' 1 ))\nsource ~/.zsh/history.zsh\n# it's\n",
            &[],
        ),
        (
            "for (( i = 0\"; i < 1; i++ )); do :; done\nsource ~/.zsh/history.zsh\n'\n",
            &[OPEN_QUOTE],
        ),
        // `$$` is a parameter, the shell's process ID.
        ("x=\"$${\"\nsource ~/.zsh/history.zsh\ny=\"}\"\n", &[]),
        ("x=\"$${'a'\"\nsource ~/.zsh/history.zsh\n", &[]),
        // A `;` ends a word in a command substitution, open parentheses
        // and all.
        (
            "x=$(if true; then ech((o ')'; fi)\nsource ~/.zsh/history.zsh\n))\n",
            &[],
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", text);
        seed(
            &fs,
            "/home/alice/.zsh/history.zsh",
            "setopt share_history\n",
        );
        assert_eq!(scan(&fs, NOT_LOGIN).doubts, doubts, "{text:?}");
        assert_eq!(
            on(&fs, NOT_LOGIN),
            ["/home/alice/.zsh/history.zsh names SHARE_HISTORY"],
            "{text:?}"
        );
    }

    // The ZDOTDIR such a line sets is followed.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshenv",
        "[[ a == (#b)(*) ]]; export ZDOTDIR=~/.config/zsh\n",
    );
    seed(
        &fs,
        "/home/alice/.config/zsh/.zshrc",
        "setopt share_history\n",
    );
    assert_eq!(
        on(&fs, NOT_LOGIN),
        ["/home/alice/.config/zsh/.zshrc names SHARE_HISTORY"]
    );
}

#[test]
fn a_source_in_a_case_arm_a_short_form_or_after_a_descriptor_is_followed() {
    for body in [
        // In an arm of a `case`, which starts after the pattern's `)`.
        "case $TERM in\n  *) {} ;;\nesac",
        "case $TERM in\n  (*) {} ;;\nesac",
        "case $TERM in\n  a|*) {} ;;\nesac",
        "case $TERM in\n  a) : ;&\n  *) {} ;;\nesac",
        "case a in a) {};; esac",
        "case a { a) {} ;; }",
        // After the number of a descriptor a redirection takes.
        "2>/dev/null {}",
        "1>&2 {}",
        "3>/dev/null {}",
        "2>&1 >/dev/null {}",
        "X=1 2>/dev/null {}",
        // zsh's short forms, whose body is one command or group.
        "repeat 1 {}",
        "repeat 1 { {} }",
        "for x (a) {}",
        "for x in a; {}",
        "for ((i=0;i<1;i++)) {}",
        "if [[ -n 1 ]] {}",
        "if [[ -n 1 ]] { {} }",
        "if (( 1 )) {}",
        "n=0; while (( n++ < 1 )) {}",
        "foreach x (a) {}\nend",
        // An `eval` of words the walk can read.
        "eval '{}'",
        "builtin eval '{}'",
    ] {
        for source in ["source ~/.zsh/history.zsh", ". ~/.zsh/history.zsh"] {
            let text = format!("{}\n", body.replace("{}", source));
            let fs = MockFilesystem::new();
            seed(&fs, "/home/alice/.zshrc", &text);
            seed(
                &fs,
                "/home/alice/.zsh/history.zsh",
                "setopt share_history\n",
            );
            assert_eq!(
                scan(&fs, NOT_LOGIN).doubts,
                Vec::<String>::new(),
                "{text:?}"
            );
            assert_eq!(
                on(&fs, NOT_LOGIN),
                ["/home/alice/.zsh/history.zsh names SHARE_HISTORY"],
                "{text:?}"
            );
        }
    }
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "eval source ~/.zsh/history.zsh\n",
    );
    seed(
        &fs,
        "/home/alice/.zsh/history.zsh",
        "setopt share_history\n",
    );
    assert_eq!(
        on(&fs, NOT_LOGIN),
        ["/home/alice/.zsh/history.zsh names SHARE_HISTORY"]
    );

    // A short form's body ends with its line, so a ZDOTDIR set after it
    // moves where zsh reads; `foreach`'s body ends at `end`, so one set in it
    // may not.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", "setopt share_history\n");
    seed(
        &fs,
        "/home/alice/.config/zsh/.zshrc",
        "setopt inc_append_history\n",
    );
    seed(
        &fs,
        "/home/alice/.zshenv",
        "for x ($list) :\nexport ZDOTDIR=~/.config/zsh\n",
    );
    assert_eq!(
        on(&fs, NOT_LOGIN),
        ["/home/alice/.config/zsh/.zshrc names INC_APPEND_HISTORY"]
    );
    seed(
        &fs,
        "/home/alice/.zshenv",
        "foreach x ($list)\n  :\n  export ZDOTDIR=~/.config/zsh\nend\n",
    );
    assert_eq!(
        on(&fs, NOT_LOGIN),
        [
            "/home/alice/.config/zsh/.zshrc names INC_APPEND_HISTORY",
            "/home/alice/.zshrc names SHARE_HISTORY",
        ]
    );
}

#[test]
fn a_source_the_walk_cannot_follow_as_a_command_is_a_doubt() {
    let source_doubt =
        "it cannot follow a `source` or `.` that a line of /home/alice/.zshrc may run";
    let eval_doubt = "it cannot follow an `eval` that a line of /home/alice/.zshrc may run";
    let command =
        |text: &str| format!("it cannot tell what command `{text}` in /home/alice/.zshrc runs");
    for (text, doubts) in [
        // A command word that an expansion makes.
        (
            "${:-source} ~/.zsh/history.zsh",
            vec![command("${:-source}")],
        ),
        (
            "\"${:-source}\" ~/.zsh/history.zsh",
            vec![command("${:-source}")],
        ),
        (
            "$(print source) ~/.zsh/history.zsh",
            vec![command("$(print source)"), source_doubt.to_string()],
        ),
        (
            "`print source` ~/.zsh/history.zsh",
            vec![command("`print source`"), source_doubt.to_string()],
        ),
        (
            "c=source; $c ~/.zsh/history.zsh",
            vec![command("$c"), source_doubt.to_string()],
        ),
        // An alias that stands for a source.
        (
            "alias src=source\nsrc ~/.zsh/history.zsh",
            vec![source_doubt.to_string()],
        ),
        (
            "alias src='source ~/.zsh/history.zsh'\nsrc",
            vec![source_doubt.to_string()],
        ),
        (
            "alias src=.\nsrc ~/.zsh/history.zsh",
            vec![source_doubt.to_string()],
        ),
        (
            "alias src='. ~/.zsh/history.zsh'\nsrc",
            vec![source_doubt.to_string()],
        ),
        // An `eval` of what the walk cannot read.
        (
            "eval \"$(print source ~/.zsh/history.zsh)\"",
            vec![source_doubt.to_string(), eval_doubt.to_string()],
        ),
        (
            "x=eval; $x 'source ~/.zsh/history.zsh'",
            vec![
                command("$x"),
                source_doubt.to_string(),
                eval_doubt.to_string(),
            ],
        ),
        // What it costs: a source or eval in any text.
        (
            "print -r -- source ~/.zsh/history.zsh",
            vec![source_doubt.to_string()],
        ),
        ("print -r -- eval", vec![eval_doubt.to_string()]),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{text}\n"));
        seed(
            &fs,
            "/home/alice/.zsh/history.zsh",
            "setopt share_history\n",
        );
        assert_eq!(scan(&fs, NOT_LOGIN).doubts, doubts, "{text:?}");
    }
}

#[test]
fn a_dot_from_an_equals_expansion_an_alias_or_eval_is_followed_or_a_doubt() {
    let command =
        |text: &str| format!("it cannot tell what command `{text}` in /home/alice/.zshrc runs");
    let source_doubt =
        "it cannot follow a `source` or `.` that a line of /home/alice/.zshrc may run".to_string();
    for (text, doubts) in [
        ("c=.\n${=c} ~/.zsh/history.zsh", vec![command("${=c}")]),
        ("c=.\n$=c ~/.zsh/history.zsh", vec![command("$=c")]),
        ("${=:-.} ~/.zsh/history.zsh", vec![command("${=:-.}")]),
        (
            "alias src='builtin .'\nsrc ~/.zsh/history.zsh",
            vec![source_doubt.clone()],
        ),
        (
            "alias src='noglob .'\nsrc ~/.zsh/history.zsh",
            vec![source_doubt.clone()],
        ),
        (
            "alias src=\\.\nsrc ~/.zsh/history.zsh",
            vec![source_doubt.clone()],
        ),
        (
            "aliases[src]=.\nsrc ~/.zsh/history.zsh",
            vec![source_doubt.clone()],
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{text}\n"));
        seed(
            &fs,
            "/home/alice/.zsh/history.zsh",
            "setopt share_history\n",
        );
        assert_eq!(scan(&fs, NOT_LOGIN).doubts, doubts, "{text:?}");
    }
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "eval -- '. ~/.zsh/history.zsh'\n",
    );
    seed(
        &fs,
        "/home/alice/.zsh/history.zsh",
        "setopt share_history\n",
    );
    assert_eq!(scan(&fs, NOT_LOGIN).doubts, Vec::<String>::new());
    assert_eq!(
        on(&fs, NOT_LOGIN),
        ["/home/alice/.zsh/history.zsh names SHARE_HISTORY"]
    );
}

#[test]
fn a_final_turn_off_does_not_pass() {
    // zsh can still end with the option on: a redefined `unsetopt`, a trap
    // or a hook that sets it again, a `return` the check cannot see, or a
    // runtime error that stops the file before the line.
    let last = "unsetopt share_history inc_append_history inc_append_history_time\n";
    for before in [
        "",
        "eval \"$(starship init zsh)\"\n",
        "alias unsetopt=:\n",
        "\"unsetopt\"() { : }\n",
        "\\unsetopt() { : }\n",
        "c=unsetopt; functions[$c]=:\n",
        "TRAPDEBUG() { setopt share_history }\n",
        "precmd() { setopt share_history }\n",
        "autoload -Uz my_hook; add-zsh-hook precmd my_hook\n",
        "alias r=return\nr\n",
        "${:-return}\n",
        "for f in ~/.zsh/none/*.zsh; do source $f; done\n",
        "status=1\n",
        "export 1x=2\n",
        "(( x = 2#3 ))\n",
        "typeset -A map; map=(a)\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/etc/zshrc", NIXOS_ZSHRC);
        seed(&fs, "/home/alice/.zshrc", &format!("{before}{last}"));
        let found = on(&fs, NOT_LOGIN);
        assert!(
            found.contains(&"/home/alice/.zshrc names SHARE_HISTORY".to_string())
                && found.contains(&"/home/alice/.zshrc names INC_APPEND_HISTORY".to_string()),
            "{before:?}: {found:?}"
        );
    }

    // What names none of the options, and holds no doubt, passes.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "export EDITOR=vim\nalias ll='ls -l'\nsetopt hist_ignore_dups\n",
    );
    assert_eq!(scan(&fs, NOT_LOGIN), Scan::default());
}

#[test]
fn a_doubt_of_the_lexer_is_one_no_structure_can_take() {
    // A `for` header the walk cannot read takes the token after it for its
    // body, and the quote that runs to the end of the file is no token.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "for x\n'it\nsource ~/.zsh/history.zsh\n",
    );
    assert_eq!(
        scan(&fs, NOT_LOGIN).doubts,
        [
            OPEN_QUOTE,
            "it cannot follow a `source` or `.` that a line of /home/alice/.zshrc may run",
        ]
    );
}

#[test]
fn what_the_lines_name_beyond_what_the_walk_read_is_on_or_a_doubt() {
    // A source and a ZDOTDIR in a here-document's body, and an option in a
    // comment at the end of a line: the lines name them, the walk reads no
    // code there.
    for (text, doubts, on_line) in [
        (
            "cat <<EOF >/dev/null\nsource ~/.zsh/history.zsh\nEOF\n",
            &["it cannot follow a `source` or `.` that a line of /home/alice/.zshrc may run"][..],
            false,
        ),
        (
            "cat <<EOF >~/.zshenv.new\nexport ZDOTDIR=~/.config/zsh\nEOF\n",
            &["it cannot follow a ZDOTDIR that a line of /home/alice/.zshrc may set"],
            false,
        ),
        ("setopt hist_ignore_dups # inc_append_history\n", &[], true),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", text);
        let found = scan(&fs, NOT_LOGIN);
        assert_eq!(found.doubts, doubts, "{text:?}");
        assert_eq!(!found.writes.is_empty(), on_line, "{text:?}");
    }

    // What the walk reads as code adds nothing.
    for text in [
        "[[ -f ~/.p10k.zsh ]] && source ~/.p10k.zsh\n",
        "builtin . ~/.zsh/aliases.zsh; noglob source ~/.zsh/more.zsh\n",
        "export ZDOTDIR=~/.config/zsh\nexport ZDOTDIR\n",
        "print -r -- $ZDOTDIR ${ZDOTDIR:-$HOME} ${#ZDOTDIR}\n",
        "find . -name '*.zsh'; cd .\n",
        "setopt hist_ignore_dups\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", text);
        assert_eq!(
            scan(&fs, NOT_LOGIN).doubts,
            Vec::<String>::new(),
            "{text:?}"
        );
        assert!(scan(&fs, NOT_LOGIN).writes.is_empty(), "{text:?}");
    }
}

#[test]
fn a_construct_that_runs_to_the_end_of_the_file_is_a_doubt() {
    for (line, opener) in [
        (r"x=$'it\'s", "`$'`"),
        (r#"echo "oops"#, "`\"`"),
        ("x=$(echo", "`$(`"),
        ("x=${y", "`${`"),
        ("x=`echo", "backquote"),
        ("opts=(a", "`(`"),
        ("diff <(a", "`<(`"),
    ] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("{line}\nsource ~/.zsh/history.zsh\n"),
        );
        seed(
            &fs,
            "/home/alice/.zsh/history.zsh",
            "setopt share_history\n",
        );
        // The source it hides is a doubt too, as a line of the file names it.
        assert_eq!(
            scan(&fs, NOT_LOGIN).doubts,
            [
                format!("it cannot tell where the {opener} that /home/alice/.zshrc opens ends"),
                "it cannot follow a `source` or `.` that a line of /home/alice/.zshrc may run"
                    .to_string(),
            ],
            "{line}"
        );
    }
}

#[test]
fn a_login_shell_s_files_count_for_a_login_shell_only() {
    let fs = MockFilesystem::new();
    seed(&fs, "/etc/zshrc", NIXOS_ZSHRC);
    seed(&fs, "/home/alice/.zlogin", "unsetopt share_history\n");
    seed(&fs, "/home/alice/.zprofile", "setopt inc_append_history\n");

    // A login shell reads both, and a shell that may be one too.
    for start in [LOGIN, UNKNOWN] {
        assert_eq!(
            on(&fs, start),
            [
                "/home/alice/.zprofile names INC_APPEND_HISTORY",
                "/home/alice/.zlogin names SHARE_HISTORY",
            ]
        );
    }
    // A shell that is not one reads neither.
    assert_eq!(on(&fs, NOT_LOGIN), ["/etc/zshrc names SHARE_HISTORY"]);
}

#[test]
fn a_zsh_started_without_its_startup_files_reads_only_what_it_reads() {
    let start = |words: &[&str]| {
        Start::of(
            &words
                .iter()
                .map(|word| word.to_string())
                .collect::<Vec<_>>(),
        )
    };
    // Without RCS: /etc/zshenv alone, and what it sources.
    for argv in [
        &["zsh", "-f"][..],
        &["zsh", "--no-rcs"],
        &["zsh", "--norcs"],
        &["zsh", "-o", "norcs"],
        &["zsh", "-o", "NO_RCS"],
        &["zsh", "+o", "rcs"],
        &["zsh", "-fi"],
        &["zsh", "-if"],
    ] {
        let start = start(argv);
        assert!(!start.rcs && start.global_rcs, "{argv:?}");
        let fs = MockFilesystem::new();
        seed(&fs, "/etc/zshenv", "source /etc/zshenv.local\n");
        seed(&fs, "/etc/zshenv.local", "setopt share_history\n");
        seed(&fs, "/etc/zshrc", "setopt inc_append_history\n");
        seed(
            &fs,
            "/home/alice/.zshenv",
            "setopt inc_append_history_time\n",
        );
        seed(
            &fs,
            "/home/alice/.zshrc",
            "setopt inc_append_history_time\n",
        );
        assert_eq!(
            on(&fs, start),
            ["/etc/zshenv.local names SHARE_HISTORY"],
            "{argv:?}"
        );
    }
    // Without GLOBAL_RCS: /etc/zshenv and the user's own, no other in /etc.
    for argv in [
        &["zsh", "-d"][..],
        &["zsh", "--no-global-rcs"],
        &["zsh", "+o", "globalrcs"],
    ] {
        let start = start(argv);
        assert!(start.rcs && !start.global_rcs, "{argv:?}");
        let fs = MockFilesystem::new();
        seed(&fs, "/etc/zshenv", "setopt share_history\n");
        seed(&fs, "/etc/zshrc", "setopt inc_append_history\n");
        seed(
            &fs,
            "/home/alice/.zshrc",
            "setopt inc_append_history_time\n",
        );
        assert_eq!(
            on(&fs, start),
            [
                "/etc/zshenv names SHARE_HISTORY",
                "/home/alice/.zshrc names INC_APPEND_HISTORY_TIME",
            ],
            "{argv:?}"
        );
    }
}

#[test]
fn a_zsh_s_command_line_says_whether_it_is_a_login_shell() {
    let start = |words: &[&str]| {
        Start::of(
            &words
                .iter()
                .map(|word| word.to_string())
                .collect::<Vec<_>>(),
        )
    };
    assert_eq!(start(&["-zsh"]), LOGIN);
    assert_eq!(start(&["zsh", "-l"]), LOGIN);
    assert_eq!(start(&["zsh", "-il"]), LOGIN);
    assert_eq!(start(&["zsh", "--login"]), LOGIN);
    assert_eq!(start(&["zsh"]), NOT_LOGIN);
    assert_eq!(start(&["zsh", "-i", "--", "-l"]), NOT_LOGIN);
    assert_eq!(start(&["zsh", "-o", "login"]), LOGIN);
    assert_eq!(
        start(&["zsh", "-d"]),
        Start {
            login: Some(false),
            rcs: true,
            global_rcs: false
        }
    );
}

#[test]
fn a_setopt_the_check_cannot_list_is_a_doubt() {
    for line in [
        "setopt $HISTORY_OPTIONS",
        "for opt in $opts; do setopt \"$opt\"; done",
        "setopt -m '*share*'",
        "set -o $option",
        "unsetopt ${(k)off}",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{line}\n"));
        let found = scan(&fs, NOT_LOGIN);
        assert_eq!(found.doubts.len(), 1, "{line}: {found:?}");
        assert!(
            found.doubts[0].starts_with("it cannot tell which options `")
                && found.doubts[0].ends_with("` in /home/alice/.zshrc turns on"),
            "{line}: {found:?}"
        );
    }
}

#[test]
fn a_sourced_file_is_followed_where_its_path_resolves() {
    for (line, path) in [
        (
            "source /home/alice/.zsh/history.zsh",
            "/home/alice/.zsh/history.zsh",
        ),
        (". ~/.zsh/history.zsh", "/home/alice/.zsh/history.zsh"),
        (
            "source \"${ZDOTDIR:-$HOME}/.zsh/history.zsh\"",
            "/home/alice/.zsh/history.zsh",
        ),
        (
            "[[ -f $HOME/.zsh/history.zsh ]] && source $HOME/.zsh/history.zsh",
            "/home/alice/.zsh/history.zsh",
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{line}\n"));
        seed(&fs, path, "setopt share_history\n");
        assert_eq!(
            on(&fs, NOT_LOGIN),
            [format!("{path} names SHARE_HISTORY")],
            "{line}"
        );
    }

    // A turn-off in a file sourced under a condition does not count.
    let fs = MockFilesystem::new();
    seed(&fs, "/etc/zshrc", NIXOS_ZSHRC);
    seed(
        &fs,
        "/home/alice/.zshrc",
        "[[ -n $QUIET ]] && source ~/.quiet.zsh\n",
    );
    seed(&fs, "/home/alice/.quiet.zsh", "unsetopt share_history\n");
    assert_eq!(on(&fs, NOT_LOGIN).len(), 1);

    // A file that is not there holds nothing; one that sources itself or
    // another in a loop is read once.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "source ~/.missing.zsh\nsource ~/.a.zsh\n",
    );
    seed(&fs, "/home/alice/.a.zsh", "source ~/.b.zsh\n");
    seed(
        &fs,
        "/home/alice/.b.zsh",
        "source ~/.a.zsh\nsetopt inc_append_history_time\n",
    );
    let found = scan(&fs, NOT_LOGIN);
    assert!(found.doubts.is_empty(), "{found:?}");
    assert_eq!(
        on(&fs, NOT_LOGIN),
        ["/home/alice/.b.zsh names INC_APPEND_HISTORY_TIME"]
    );
}

#[test]
fn a_sourced_file_whose_path_does_not_resolve_is_a_doubt() {
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "source $ZSH_CUSTOM/history.zsh\n. relative.zsh\n",
    );
    let found = scan(&fs, NOT_LOGIN);
    assert_eq!(
        found.doubts,
        [
            "it cannot follow the file /home/alice/.zshrc sources as `$ZSH_CUSTOM/history.zsh`",
            "it cannot follow the file /home/alice/.zshrc sources as `relative.zsh`",
        ]
    );

    // Sourced files are followed so deep.
    let fs = MockFilesystem::new();
    for at in 0..=SOURCE_DEPTH {
        seed(
            &fs,
            &format!("/home/alice/.z{at}"),
            &format!("source /home/alice/.z{}\n", at + 1),
        );
    }
    seed(&fs, "/home/alice/.zshrc", "source /home/alice/.z0\n");
    let found = scan(&fs, NOT_LOGIN);
    assert_eq!(found.doubts.len(), 1, "{found:?}");
    assert!(found.doubts[0].starts_with("it follows sourced files 8 deep"));
}

#[test]
fn oh_my_zsh_turns_share_history_on_where_it_is_loaded() {
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "export ZSH=\"$HOME/.oh-my-zsh\"\nsource $ZSH/oh-my-zsh.sh\n",
    );
    assert_eq!(
        on(&fs, NOT_LOGIN),
        ["Oh My Zsh, which /home/alice/.zshrc loads, sets SHARE_HISTORY"]
    );
}

#[test]
fn any_other_word_that_names_an_option_turns_it_on() {
    for line in [
        "options[sharehistory]=on",
        "opts+=(SHARE_HISTORY)",
        "[[ -o share_history ]] && print shared",
        "zstyle ':prezto:module:history' options 'share_history'",
        "local opt=inc_append_history; setopt $opt",
        // Its `no` form too, as any mention counts.
        "opts=(NO_SHARE_HISTORY)",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{line}\n"));
        assert!(!on(&fs, NOT_LOGIN).is_empty(), "{line}");
    }
    // A line that is a comment and an unrelated name do not.
    for line in [
        "# setopt share_history",
        "  # setopt share_history",
        "HISTFILE=~/.zsh_history",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{line}\n"));
        assert_eq!(scan(&fs, NOT_LOGIN), Scan::default(), "{line}");
    }
    // A comment at the end of a line does, as the lines are read for what a
    // misread may hide.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "setopt hist_ignore_dups  # not share_history\n",
    );
    assert_eq!(
        on(&fs, NOT_LOGIN),
        ["/home/alice/.zshrc names SHARE_HISTORY"]
    );
}

#[test]
fn a_structure_the_check_cannot_follow_has_no_turn_off_count() {
    for text in [
        "fi\nunsetopt share_history\n",
        "{\nunsetopt share_history\n",
        "unsetopt share_history\ndone\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/etc/zshrc", NIXOS_ZSHRC);
        seed(&fs, "/home/alice/.zshrc", text);
        assert_eq!(on(&fs, NOT_LOGIN).len(), 1, "{text:?}");
    }
}

#[test]
fn a_zdotdir_set_under_a_condition_adds_where_zsh_may_look() {
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshenv",
        "[[ -d ~/.config/zsh ]] && export ZDOTDIR=~/.config/zsh\n",
    );
    seed(&fs, "/home/alice/.zshrc", "setopt share_history\n");
    seed(
        &fs,
        "/home/alice/.config/zsh/.zshrc",
        "setopt inc_append_history\n",
    );
    let found = on(&fs, NOT_LOGIN);
    assert_eq!(
        found,
        [
            "/home/alice/.config/zsh/.zshrc names INC_APPEND_HISTORY",
            "/home/alice/.zshrc names SHARE_HISTORY",
        ]
    );

    // One the check cannot follow stops the reads in the home, and is a
    // doubt.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshenv", "export ZDOTDIR=$(zdotdir)\n");
    seed(&fs, "/home/alice/.zshrc", "unsetopt share_history\n");
    let found = scan(&fs, NOT_LOGIN);
    assert!(found.writes.is_empty());
    assert_eq!(
        found.doubts,
        ["it cannot follow the ZDOTDIR that /home/alice/.zshenv sets (`$(zdotdir)`)"]
    );
}

#[test]
fn the_tokens_keep_expansions_whole_and_drop_comments() {
    let words = |text: &str| -> Vec<(String, bool)> {
        tokens(text)
            .into_iter()
            .filter_map(|token| match token {
                Token::Word(word) => Some((word.text, word.expands)),
                _ => None,
            })
            .collect()
    };
    assert_eq!(
        words("echo \"${a:-$(b; c)}\"x 'it''s' a\\ b # c d"),
        [
            ("echo".to_string(), false),
            ("${a:-$(b; c)}x".to_string(), true),
            ("its".to_string(), false),
            ("a b".to_string(), false),
        ]
    );
    assert_eq!(
        tokens("a=(x y\n z) # c\n"),
        [
            Token::Array(
                "a".to_string(),
                vec![
                    Word {
                        text: "x".to_string(),
                        expands: false
                    },
                    Word {
                        text: "y".to_string(),
                        expands: false
                    },
                    Word {
                        text: "z".to_string(),
                        expands: false
                    },
                ]
            ),
            Token::End(End::Line),
        ]
    );
    assert_eq!(
        words("cat <(a b) <<'EOF' >x\nsetopt c\nEOF\nd"),
        [
            ("cat".to_string(), false),
            ("<(a b)".to_string(), true),
            ("x".to_string(), false),
            ("d".to_string(), false),
        ]
    );
    assert!(
        tokens("cat <<-EOF; e\n\tsetopt c\n\tEOF\n")
            .contains(&Token::Text("\tsetopt c\n".to_string()))
    );
    assert_eq!(
        words("x=$(cat <<EOF\nit's\nEOF\n) y"),
        [
            ("x=$(cat <<EOF\nit's\nEOF\n)".to_string(), true),
            ("y".to_string(), false),
        ]
    );
    assert_eq!(
        words(r"x=$'it\'s' y"),
        [(r"x=$'it\'s'".to_string(), true), ("y".to_string(), false)]
    );
    assert_eq!(
        words(r#"x=$(echo ")") 'a)' "$(b ')')""#),
        [
            (r#"x=$(echo ")")"#.to_string(), true),
            ("a)".to_string(), false),
            ("$(b ')')".to_string(), true),
        ]
    );
    assert_eq!(
        tokens("(( a << (b) ))\nc"),
        [
            Token::Arithmetic("(( a << (b) ))".to_string()),
            Token::End(End::Line),
            Token::Word(Word {
                text: "c".to_string(),
                expands: false
            }),
        ]
    );
    assert_eq!(
        tokens("f() { x } && y || z | w &"),
        [
            Token::Word(Word {
                text: "f".to_string(),
                expands: false
            }),
            Token::Open,
            Token::Close,
            Token::Word(Word {
                text: "{".to_string(),
                expands: false
            }),
            Token::Word(Word {
                text: "x".to_string(),
                expands: false
            }),
            Token::Word(Word {
                text: "}".to_string(),
                expands: false
            }),
            Token::End(End::Condition),
            Token::Word(Word {
                text: "y".to_string(),
                expands: false
            }),
            Token::End(End::Condition),
            Token::Word(Word {
                text: "z".to_string(),
                expands: false
            }),
            Token::End(End::Pipe),
            Token::Word(Word {
                text: "w".to_string(),
                expands: false
            }),
            Token::End(End::Background),
        ]
    );
}
