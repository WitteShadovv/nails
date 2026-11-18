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

    // A blank line commented out as an editor's `gc` writes it (`#`) and as
    // `sed 's/^/# /'` does (`# `) closes nothing.
    let text = "{\n  # boot.initrd.luks.devices = {\n  #\n  #   data = {\n  #     device = \
                \"/dev/disk/by-uuid/1234\";\n  #   };\n  # };\n}\n";
    assert_eq!(names(text), [mapping(4, "data")]);
    let text = "{\n#   boot.initrd.luks.devices = {\n# \n#     data.device = \
                \"/dev/disk/by-uuid/1234\";\n#   };\n}\n";
    assert_eq!(names(text), [mapping(4, "data")]);
    let text = "{\r\n  # boot.initrd.luks.devices = {\r\n  #\r\n  #   data.device = \
                \"/dev/sdb2\";\r\n  # };\r\n}\r\n";
    assert_eq!(names(text), [mapping(4, "data")]);

    // A block whose lines keep no indentation of their own, as code that was
    // never formatted is commented out, in either form of `luks.devices`.
    let text = "{ }\n# boot.initrd.luks = {\n# devices.data.device = \"/dev/sdb2\";\n# };\n";
    assert_eq!(names(text), [mapping(3, "data")]);
    let text = "{ }\n# boot.initrd.luks = {\n# devices = {\n# data.device = \"/dev/sdb2\";\n# \
                };\n# };\n";
    assert_eq!(names(text), [mapping(4, "data")]);
    let text = "{ }\n# boot.initrd.luks.devices = [\n# { name = \"data\"; device = \
                \"/dev/sdb2\"; }\n# ];\n";
    assert_eq!(names(text), [mapping(3, "data")]);

    // A bracket in prose still closes at the next line as deep, a blank
    // comment line between them or not.
    let text = "{ }\n# keep [ for later\n#\n# boot.initrd.luks.devices.data.device = \
                \"/dev/sdb2\";\n";
    assert_eq!(names(text), [mapping(4, "data")]);

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

/// Every place of `text`, read as the file spells it, as (line, text,
/// path joined by `.`, attribute).
fn places(text: &str) -> Vec<(usize, String, String, bool)> {
    let mut scanner = Scanner::default();
    let mut found = Vec::new();
    for (index, line) in text.split('\n').enumerate() {
        scanner.line(line.as_bytes());
        for place in scanner.places() {
            found.push((
                index + 1,
                line[place.range].to_string(),
                place.path.join("."),
                place.attribute,
            ));
        }
    }
    found
}

/// Each attribute name a definition makes, with the path it ends, and each
/// string the value of a definition holds whole on its line, with the
/// definition's path: in nested sets, after a function call, in a list, in
/// a comment, and with the case the file gives them.
#[test]
fn places_carry_the_path_of_their_definition() {
    let text = "{\n  fileSystems.\"/\" =\n    { device = \"/dev/vda2\";\n      options = [ \"subvol=@\" ];\n    };\n  boot.initrd.luks.devices.root.device = lib.mkForce \"/dev/sda2\";\n  # fileSystems.\"/home\".label = \"nixos\";\n}";
    let found = places(text);
    let strings: Vec<(usize, &str, &str)> = found
        .iter()
        .filter(|(_, _, _, attribute)| !attribute)
        .map(|(line, text, path, _)| (*line, text.as_str(), path.as_str()))
        .collect();
    assert_eq!(
        strings,
        [
            (3, "/dev/vda2", "fileSystems./.device"),
            (4, "subvol=@", "fileSystems./.options"),
            (6, "/dev/sda2", "boot.initrd.luks.devices.root.device"),
            (7, "nixos", "fileSystems./home.label"),
        ]
    );
    assert!(found.contains(&(
        6,
        "root".to_string(),
        "boot.initrd.luks.devices.root".to_string(),
        true
    )));
    assert!(found.contains(&(2, "/".to_string(), "fileSystems./".to_string(), true)));
}

/// A string that goes on over several lines is a place only on the line
/// that opens it, up to the end of that line, and not a whole one; one
/// inside an interpolation or a `let` binding is no place of the definition
/// around it: the interpolation's string has no path, the binding's its own.
#[test]
fn a_string_over_lines_or_in_an_interpolation_is_no_place_of_the_definition() {
    let text = "{\n  x.device = ''\n    /dev/vda2\n  '';\n  y.device = \"${\"/dev/vda2\"}\";\n  z = let d = \"/dev/vda2\"; in d;\n}";
    let found = places(text);
    let strings: Vec<(usize, String, String)> = found
        .into_iter()
        .filter(|(_, _, _, attribute)| !attribute)
        .map(|(line, text, path, _)| (line, text, path))
        .collect();
    assert_eq!(
        strings,
        [
            (2, String::new(), "x.device".to_string()),
            (5, "/dev/vda2".to_string(), String::new()),
            (5, "${\"/dev/vda2\"}".to_string(), "y.device".to_string()),
            (6, "/dev/vda2".to_string(), "d".to_string()),
        ]
    );
    // The binding's string is no definition of the configuration.
    let option = options(text);
    assert_eq!(option[1], [true, true, true]);
    assert_eq!(option[5], [true, false, false]);
}

/// Whether each place of each line of `text` is a definition of the
/// configuration ([`Place::option`]).
fn options(text: &str) -> Vec<Vec<bool>> {
    let mut scanner = Scanner::default();
    text.split('\n')
        .map(|line| {
            scanner.line(line.as_bytes());
            scanner.places().iter().map(|place| place.option).collect()
        })
        .collect()
}

/// A place in a comment or in a `let` block, also one a value opened, is no
/// definition of the configuration; one in code after the `in` is.
#[test]
fn a_place_in_a_comment_or_a_binding_is_no_option() {
    let text = "{\n  # a.device = \"/dev/vda2\";\n  b = let c.device = \"/dev/vda2\"; in 1;\n  d = let e = { f.device = \"x\"; }; in e;\n  g.device = \"/dev/vda2\"; # h = \"y\";\n}";
    let option = options(text);
    assert_eq!(option[1], [false, false, false]);
    assert_eq!(option[2], [true, false, false, false]);
    assert_eq!(option[3], [true, false, false, false, false]);
    assert_eq!(option[4], [true, true, true, false, false]);
}

/// The parts of each line of `text` that are no plain literal
/// ([`super::Unplain`]), with the path each stands in.
fn unplain(text: &str) -> Vec<(usize, String, String)> {
    let mut scanner = Scanner::default();
    let mut found = Vec::new();
    for (index, line) in text.split('\n').enumerate() {
        scanner.line(line.as_bytes());
        for part in scanner.unplain() {
            found.push((index, line[part.range].to_string(), part.path.join(".")));
        }
    }
    found
}

/// The form `nixos-generate-config` writes has no part that is no plain
/// literal: strings, lists of strings, sets, and `true`, `false` or a number
/// as a whole value. Code outside `fileSystems` and `luks.devices` is not
/// noted, nor is a comment.
#[test]
fn a_generated_entry_is_plain() {
    let text = "{ config, lib, pkgs, modulesPath, ... }:\n{\n  imports = [ (modulesPath + \"/installer/scan/not-detected.nix\") ];\n  fileSystems.\"/\" =\n    { device = \"/dev/disk/by-uuid/x\";\n      fsType = \"btrfs\";\n      options = [ \"subvol=@\" \"compress=zstd\" ];\n      neededForBoot = true; # needed (early)\n    };\n  boot.initrd.luks.devices.\"luks-x\".device = \"/dev/disk/by-uuid/y\";\n  boot.initrd.luks.devices.\"luks-x\".keyFileSize = 4096;\n  swapDevices = [ ];\n  networking.useDHCP = lib.mkDefault true;\n  /* fileSystems.\"/\".device = f x; */\n}";
    assert_eq!(unplain(text), []);
}

/// Every other part of a value below `fileSystems` or `luks.devices` is
/// noted, with the path it stands in: a reference, a call, an operator, a
/// parenthesis, an interpolation in a string or as a name, a path, a
/// `''…''` string, a string that goes on over the next line, a keyword, an
/// `inherit`, and `true` or a number in a list or as a `device`.
#[test]
fn every_other_part_of_an_entry_is_noted() {
    for (text, part, path) in [
        (
            "fileSystems.\"/\".device = lib.mkForce \"/dev/x\";",
            "lib.mkForce",
            "fileSystems./.device",
        ),
        (
            "fileSystems.\"/\".device = config.fileSystems.\"/\".device;",
            "config.fileSystems.",
            "fileSystems./.device",
        ),
        (
            "fileSystems.\"/\".options = [ (\"subvol=@va\") + \"ult\" ];",
            "(",
            "fileSystems./.options",
        ),
        (
            "fileSystems.\"/\".options = [ (if true then \"a\" else \"b\") ];",
            "(",
            "fileSystems./.options",
        ),
        (
            "fileSystems.\"/\".device = \"/dev/${x}\";",
            "${",
            "fileSystems./.device",
        ),
        (
            "fileSystems.\"/\" = { ${x} = \"a\"; };",
            "${",
            "fileSystems./",
        ),
        (
            "fileSystems.\"/\".device = /dev/x;",
            "/",
            "fileSystems./.device",
        ),
        (
            "fileSystems.\"/\".device = ''/dev/x'';",
            "''",
            "fileSystems./.device",
        ),
        (
            "fileSystems.\"/\".device = \"/dev/x",
            "/dev/x",
            "fileSystems./.device",
        ),
        (
            "fileSystems.\"/\" = let d = \"x\"; in { device = d; };",
            "let",
            "fileSystems./",
        ),
        (
            "fileSystems.\"/\" = { inherit device; };",
            "inherit",
            "fileSystems./",
        ),
        (
            "fileSystems.\"/\".options = [ true ];",
            "true",
            "fileSystems./.options",
        ),
        (
            "fileSystems.\"/\".device = true;",
            "true",
            "fileSystems./.device",
        ),
        ("fileSystems.\"/\".label = 5;", "5", "fileSystems./.label"),
        (
            "fileSystems = lib.mkForce { };",
            "lib.mkForce",
            "fileSystems",
        ),
        (
            "boot.initrd.luks.devices.x.device = \"/dev/sdb2\" + \"0\";",
            "+",
            "boot.initrd.luks.devices.x.device",
        ),
    ] {
        let found = unplain(text);
        assert_eq!(
            found.first(),
            Some(&(0, part.to_string(), path.to_string())),
            "{text}"
        );
    }
}
