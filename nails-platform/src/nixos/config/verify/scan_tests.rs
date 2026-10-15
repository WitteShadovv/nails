// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the attribute paths the reference check follows.

use super::*;

/// Every name `text` defines, as (line, text, what), the line counted from 1.
fn names(text: &str) -> Vec<(usize, String, Named)> {
    let mut scanner = Scanner::default();
    let lower = text.to_ascii_lowercase();
    let mut found = Vec::new();
    for (index, line) in lower.split('\n').enumerate() {
        for (range, named) in scanner.line(line.as_bytes()) {
            found.push((index + 1, line[range].to_string(), named));
        }
    }
    found
}

fn mapping(line: usize, text: &str) -> (usize, String, Named) {
    (line, text.to_string(), Named::Mapping)
}

/// Brackets and `;` inside a string, a `with` clause or a `let` block in a
/// value, and a bracket in a comment above a commented-out block do not hide
/// the entry that follows.
#[test]
fn an_entry_counts_after_what_could_derail_the_brackets() {
    for (text, line) in [
        (
            "{\n  programs.bash.promptInit = ''PS1=\"\\[\\e[1;32m\\]\\u@\\h\\[\\e[0m\\] \"'';\n  \
             boot.initrd.luks = {\n    devices.data.device = \"/dev/disk/by-uuid/1\";\n  };\n}\n",
            4,
        ),
        (
            "{ lib, ... }: {\n  boot.initrd.luks.devices = with lib; mkForce {\n    \
             data.device = \"/dev/disk/by-uuid/1\";\n  };\n}\n",
            3,
        ),
        (
            "{ }\n# keep [ for later\n# boot.initrd.luks = {\n#   devices.data.device = \
             \"/dev/disk/by-uuid/1\";\n# };\n",
            4,
        ),
        (
            "{\n  boot.initrd.luks.devices = {\n    root = { device = \"/dev/sda2\"; \
             postOpenCommands = ''echo \"{\"''; };\n    data.device = \"/dev/disk/by-uuid/1\";\n  \
             };\n}\n",
            4,
        ),
        (
            "{\n  boot.initrd.luks.devices = let key = \"/k\"; in {\n    data.keyFile = key;\n  \
             };\n}\n",
            3,
        ),
        (
            "{\n  x = \"a ${toString [ 1 ]} b { c\";\n  boot.initrd.luks.devices = {\n    \
             data.device = \"/dev/sdb2\";\n  };\n}\n",
            4,
        ),
        (
            "{\n  # a 5\" disk, see [1\n  boot.initrd.luks.devices = {\n    data.device = \
             \"/dev/sdb2\";\n  };\n}\n",
            4,
        ),
        (
            "{\n  /* keep { for later */\n  boot.initrd.luks.devices.data.device = \"/dev/sdb2\";\n}\n",
            3,
        ),
    ] {
        let found = names(text);
        assert!(found.contains(&mapping(line, "data")), "{text}: {found:?}");
        assert!(
            found
                .iter()
                .all(|(_, name, _)| name == "data" || name == "root"),
            "{text}: {found:?}"
        );
    }
}

/// A block commented out line by line is followed, indented as nixfmt
/// writes it, and the code after it is read as before.
#[test]
fn a_commented_out_block_is_followed_and_leaves_the_code_alone() {
    let text = "{\n  # boot.initrd.luks.devices = {\n  #   data = {\n  #     device = \
                \"/dev/sdb2\";\n  #   };\n  # };\n  services.x = {\n    vault = 1;\n  };\n}\n";
    assert_eq!(names(text), [mapping(3, "data")]);

    // A comment after code on its line ends with the line.
    let text = "{\n  x = 1; # luks.devices = [\n  boot.initrd.luks.devices.data.device = \
                \"/dev/sdb2\";\n}\n";
    assert_eq!(names(text), [mapping(3, "data")]);
}

/// The values that name a mapping or a filesystem label.
#[test]
fn values_that_name_a_mapping_or_a_label() {
    assert_eq!(
        names("{ boot.initrd.luks.devices = [ { name = \"data\"; device = \"/dev/sdb2\"; } ]; }"),
        [mapping(1, "data")]
    );
    assert_eq!(
        names("{ boot.initrd.luks.devices.vault.name = \"data\"; }"),
        [mapping(1, "vault"), mapping(1, "data")]
    );
    assert_eq!(
        names(
            "{ fileSystems.\"/srv\" = {\n  encrypted = { enable = true; label = \"data\"; };\n}; }"
        ),
        [mapping(2, "data")]
    );
    assert_eq!(
        names("{ boot.initrd.clevis.devices.data.secretFile = ./data.jwe; }"),
        [mapping(1, "data")]
    );
    assert_eq!(
        names(
            "{ swapDevices = [ { label = \"swap\"; } ];\n  fileSystems.\"/srv\".label = \"data\"; }"
        ),
        [
            (1, "swap".to_string(), Named::Label),
            (2, "data".to_string(), Named::Label)
        ]
    );
}

/// Names nothing: a `let` binding, an option that merely ends in `label` or
/// `name`, keywords inside a path, and attributes outside the entries.
#[test]
fn ordinary_definitions_name_nothing() {
    for text in [
        "let\n  data = 1;\nin\n{ x = data; }",
        "{ system.nixos.label = \"data\"; users.users.data.name = \"data\"; }",
        "{ imports = [ ./let/in.nix ./with/data.nix ]; }",
        "{ boot.initrd.luks.devices = { };\n  data = 1; }",
        "{ x = with lib; [ data ]; }",
    ] {
        assert_eq!(names(text), [], "{text}");
    }
}
