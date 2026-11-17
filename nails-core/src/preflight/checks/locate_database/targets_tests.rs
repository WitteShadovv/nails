// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

/// The assignments of `text`, one `Key=value` a line.
fn section(text: &str) -> Vec<Assignment> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| Assignment {
            key: key.to_string(),
            value: value.to_string(),
        })
        .collect()
}

/// The names `targets` give, `None` for one the host decides.
fn names(targets: &[Target]) -> Vec<Option<&str>> {
    targets.iter().map(Target::name).collect()
}

#[test]
fn the_specifiers_of_the_triggers_own_name_expand_as_systemd_expands_them() {
    let id = "foo-bar-baz@inst-x.socket";
    for (value, name) in [
        ("%n", "foo-bar-baz@inst-x.socket"),
        ("%N.service", "foo-bar-baz@inst-x.service"),
        ("%p.service", "foo-bar-baz.service"),
        ("%p@%i.service", "foo-bar-baz@inst-x.service"),
        ("%j.service", "baz.service"),
        ("a%%b", "a%b"),
        // A % before no letter or digit, and one at the end, stay.
        ("a%-b%", "a%-b%"),
    ] {
        assert_eq!(
            expand(value, id),
            Expanded::Name(name.to_string()),
            "{value}"
        );
    }
    // Without an instance %i is nothing, and %j is the whole prefix without a
    // dash.
    assert_eq!(
        expand("x%i.service", "tuned.timer"),
        Expanded::Name("x.service".to_string())
    );
    assert_eq!(
        expand("%j.service", "tuned.timer"),
        Expanded::Name("tuned.service".to_string())
    );
    // systemd expands %P, %I, %J and %f in commands, but not in a unit name,
    // and ignores the assignment, as for any other letter or digit it does
    // not know.
    for value in [
        "%P.service",
        "%I.service",
        "%J.service",
        "%f.service",
        "%y",
        "%0",
    ] {
        assert_eq!(expand(value, id), Expanded::Ignored, "{value}");
    }
    // And one that gives more than 256 bytes.
    assert_eq!(expand(&"a".repeat(257), id), Expanded::Ignored);
    assert!(matches!(expand(&"a".repeat(256), id), Expanded::Name(_)));
}

#[test]
fn a_specifier_the_host_fills_in_fits_every_name_the_rest_fits() {
    let Expanded::Host(target) = expand("audit%H.service", "kick.socket") else {
        panic!("a host's specifier");
    };
    assert_eq!(target.name(), None);
    assert!(target.fits("auditd.service"));
    assert!(target.fits("audit.service"), "the host's part may be empty");
    assert!(!target.fits("tuned.service"));
    assert!(!target.fits("auditd.socket"));
    let Expanded::Host(target) = expand("%p-%m@%H.service", "gpg-agent@x.socket") else {
        panic!("a host's specifier");
    };
    assert!(target.fits("gpg-agent-1@2.service"));
    assert!(!target.fits("auditd.service"));
    assert!(target.fits_template("gpg-agent-x@.service"));
    assert!(!target.fits_template("auditd@.service"));
    // A plain name fits itself alone.
    assert!(Target::named("a.service".to_string()).fits("a.service"));
    assert!(!Target::named("a.service".to_string()).fits("b.service"));
    assert!(Target::named("a@b.service".to_string()).fits_template("a@.service"));
    assert!(!Target::named("a.service".to_string()).fits_template("a@.service"));
}

/// The `[Socket]` sections of the gnupg units of Arch's gnupg-2.4.9-4,
/// `/usr/lib/systemd/system/gpg-agent-browser@.socket`,
/// `gpg-agent-extra@.socket` and `gpg-agent-ssh@.socket`, copied unchanged:
/// pacman-7.1.0 enables the instance of each for `/etc/pacman.d/gnupg`.
const ARCH_GPG_AGENT_SOCKETS: &[(&str, &str)] = &[
    (
        "gpg-agent-browser@etc-pacman.d-gnupg.socket",
        "ListenStream=%f/S.gpg-agent.browser\nFileDescriptorName=browser\n\
         Service=gpg-agent@%i.service\nSocketMode=0600\n",
    ),
    (
        "gpg-agent-extra@etc-pacman.d-gnupg.socket",
        "ListenStream=%f/S.gpg-agent.extra\nFileDescriptorName=extra\n\
         Service=gpg-agent@%i.service\nSocketMode=0600\n",
    ),
    (
        "gpg-agent-ssh@etc-pacman.d-gnupg.socket",
        "ListenStream=%f/S.gpg-agent.ssh\nFileDescriptorName=ssh\n\
         Service=gpg-agent@%i.service\nSocketMode=0600\n",
    ),
];

#[test]
fn arch_gnupg_sockets_start_the_agent_of_their_instance() {
    for (socket, text) in ARCH_GPG_AGENT_SOCKETS {
        assert_eq!(
            names(&socket_targets(&section(text), socket)),
            [Some("gpg-agent@etc-pacman.d-gnupg.service")],
            "{socket}"
        );
    }
}

#[test]
fn a_socket_starts_its_last_service_systemd_takes_or_the_one_of_its_own_name() {
    for (text, service) in [
        ("ListenStream=/run/x.sock", Some("tuned.service")),
        ("Service=firewalld.service", Some("firewalld.service")),
        ("Service=a.service\nService=b.service", Some("b.service")),
        ("Service=%N.service", Some("tuned.service")),
        // systemd ignores a value it cannot expand, one that is no service,
        // and a template, and keeps the one before it.
        ("Service=a.service\nService=%I.service", Some("a.service")),
        ("Service=a.service\nService=b.socket", Some("a.service")),
        ("Service=a.service\nService=b@.service", Some("a.service")),
        ("Service=a b.service", Some("tuned.service")),
    ] {
        assert_eq!(
            names(&socket_targets(&section(text), "tuned.socket")),
            [service],
            "{text:?}"
        );
    }
    // Accept=yes starts instances of tuned@.service instead, and a value
    // systemd cannot read as a boolean is ignored.
    for text in [
        "Accept=yes",
        "Accept=true\nService=x.service",
        "Accept=Y\nAccept=maybe",
    ] {
        assert!(
            socket_targets(&section(text), "tuned.socket").is_empty(),
            "{text:?}"
        );
    }
    assert_eq!(
        names(&socket_targets(
            &section("Accept=yes\nAccept=no"),
            "tuned.socket"
        )),
        [Some("tuned.service")]
    );
    // A later value the host decides may win, or be ignored for the one
    // before it.
    let targets = socket_targets(
        &section("Service=a.service\nService=%H.service"),
        "t.socket",
    );
    assert_eq!(names(&targets), [None, Some("a.service")]);
    assert_eq!(targets[0].written, "%H.service");
}

#[test]
fn a_timer_starts_its_first_unit_systemd_takes_or_the_service_of_its_own_name() {
    for (text, unit) in [
        ("OnBootSec=1min", "tuned.service"),
        ("Unit=a.service\nUnit=b.service", "a.service"),
        ("Unit=%p-x.target", "tuned-x.target"),
        // systemd skips a value it cannot expand, one of no unit type, a
        // template and the trigger itself, and takes the next.
        ("Unit=%f.service\nUnit=b.service", "b.service"),
        ("Unit=a\nUnit=b.path", "b.path"),
        ("Unit=a@.service\nUnit=b.service", "b.service"),
        ("Unit=tuned.timer\nUnit=%n\nUnit=b.service", "b.service"),
        ("Unit=@a.service", "tuned.service"),
    ] {
        assert_eq!(
            names(&timer_targets(&section(text), "tuned.timer", "tuned.timer")),
            [Some(unit)],
            "{text:?}"
        );
    }
    // The service of its own name is that of its id, where it runs by an
    // alias.
    assert_eq!(
        names(&timer_targets(&section(""), "real.timer", "alias.timer")),
        [Some("real.service")]
    );
    // A value the host decides may give the unit, or one systemd skips.
    let targets = timer_targets(
        &section("Unit=%H.service\nUnit=b.service"),
        "t.timer",
        "t.timer",
    );
    assert_eq!(names(&targets), [None, Some("b.service")]);
}

#[test]
fn a_timer_whose_unit_the_host_names_may_start_an_updatedb_that_fits_it() {
    use super::super::tests::{NIXOS_PRUNEPATHS, message, nixos};
    let mut pruned = NIXOS_PRUNEPATHS.to_vec();
    pruned.push("/mnt");
    let decoy = nixos(&pruned, &[]);
    decoy
        .file(
            "/etc/systemd/system/update-all.service",
            "[Service]\nExecStart=/run/current-system/sw/bin/updatedb\n",
        )
        .file(
            "/etc/systemd/system/odd.timer",
            "[Timer]\nOnCalendar=daily\nUnit=update-%H.service\n",
        )
        .enable("/etc/systemd/system", "odd.timer");
    let result = decoy.check(true);
    assert!(result.is_warn(), "{result:?}");
    assert!(
        message(&result).contains(
            "odd.timer may start updatedb, which NAILS cannot tell: odd.timer starts \
             update-%H.service or odd.service, which of them systemd decides by the host it runs \
             on"
        ),
        "{result:?}"
    );
    // One the name of no unit on the disk fits starts none of them.
    decoy.fs.mock_set_file_content(
        "/etc/systemd/system/odd.timer",
        "[Timer]\nOnCalendar=daily\nUnit=backup-%H.service\n",
    );
    let result = decoy.check(true);
    assert!(result.is_pass(), "{result:?}");
}
