// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The options of zsh the list of the commands the check knows to be
//! harmless holds ([`super`]): every option of zsh 5.9 to 5.9.2 by its name
//! but [`DOUBTED_OPTIONS`], each in either state.

/// The options of zsh 5.9 to 5.9.2 the list does not hold:
/// `CSH_JUNKIE_LOOPS`, with which zsh reads a loop's body to an `end` the
/// reader does not read so. (`ERR_EXIT`, with which zsh ends as a typed
/// command fails, and `SINGLE_COMMAND`, which zsh does not let a file change,
/// end zsh with no history file written: zsh 5.9 to 5.9.2 write none then.)
pub(in super::super) const DOUBTED_OPTIONS: &[&str] = &["cshjunkieloops"];

/// The options of zsh 5.9 to 5.9.2, as zsh compares their names: lower case,
/// without underscores (`zsh -fc 'print ${(k)options}'`).
const OPTION_NAMES: &str = "\
    aliases aliasfuncdef allexport alwayslastprompt alwaystoend appendcreate appendhistory \
    autocd autocontinue autolist automenu autonamedirs autoparamkeys autoparamslash autopushd \
    autoremoveslash autoresume badpattern banghist bareglobqual bashautolist bashrematch beep \
    bgnice braceccl braceexpand bsdecho caseglob casematch casepaths cbases cdablevars \
    cdsilent chasedots chaselinks checkjobs checkrunningjobs clobber clobberempty \
    combiningchars completealiases completeinword continueonerror correct correctall \
    cprecedences cshjunkiehistory cshjunkieloops cshjunkiequotes cshnullcmd cshnullglob \
    debugbeforecmd dotglob dvorak emacs equals errexit errreturn evallineno exec extendedglob \
    extendedhistory flowcontrol forcefloat functionargzero glob globalexport globalrcs \
    globassign globcomplete globdots globstarshort globsubst hashall hashcmds hashdirs \
    hashexecutablesonly hashlistall histallowclobber histappend histbeep histexpand \
    histexpiredupsfirst histfcntllock histfindnodups histignorealldups histignoredups \
    histignorespace histlexwords histnofunctions histnostore histreduceblanks histsavebycopy \
    histsavenodups histsubstpattern histverify hup ignorebraces ignoreclosebraces ignoreeof \
    incappendhistory incappendhistorytime interactive interactivecomments ksharrays \
    kshautoload kshglob kshoptionprint kshtypeset kshzerosubscript listambiguous listbeep \
    listpacked listrowsfirst listtypes localloops localoptions localpatterns localtraps log \
    login longlistjobs magicequalsubst mailwarn mailwarning markdirs menucomplete monitor \
    multibyte multifuncdef multios nomatch notify nullglob numericglobsort octalzeroes onecmd \
    overstrike pathdirs pathscript physical pipefail posixaliases posixargzero posixbuiltins \
    posixcd posixidentifiers posixjobs posixstrings posixtraps printeightbit printexitvalue \
    privileged promptbang promptcr promptpercent promptsp promptsubst promptvars \
    pushdignoredups pushdminus pushdsilent pushdtohome rcexpandparam rcquotes rcs recexact \
    rematchpcre restricted rmstarsilent rmstarwait sharehistory shfileexpansion shglob \
    shinstdin shnullcmd shoptionletters shortloops shortrepeat shwordsplit singlecommand \
    singlelinezle sourcetrace stdin sunkeyboardhack trackall transientrprompt trapsasync \
    typesetsilent typesettounset unset verbose vi warncreateglobal warnnestedvar xtrace zle";

/// The option `word` names, as zsh reads an option's name (case and
/// underscores aside, a `no` before it for its other state), when it is one
/// of zsh 5.9 to 5.9.2's ([`OPTION_NAMES`]).
fn option_name(word: &str) -> Option<String> {
    let name: String = word
        .chars()
        .filter(|c| *c != '_')
        .collect::<String>()
        .to_lowercase();
    let known = |name: &str| OPTION_NAMES.split_whitespace().any(|known| known == name);
    if known(&name) {
        return Some(name);
    }
    name.strip_prefix("no")
        .filter(|rest| known(rest))
        .map(str::to_string)
}

/// Why the option `word` names, as written, is none the list holds; `None`
/// for one it holds ([the module](self)).
pub(in super::super) fn option(word: &str) -> Option<String> {
    match option_name(word) {
        None => Some(format!(
            "`{word}` names no option of zsh 5.9 to 5.9.2 the check knows"
        )),
        Some(name) if DOUBTED_OPTIONS.contains(&name.as_str()) => Some(format!(
            "`{word}` names CSH_JUNKIE_LOOPS, with which zsh reads a loop's body otherwise than \
             the check does"
        )),
        Some(_) => None,
    }
}
