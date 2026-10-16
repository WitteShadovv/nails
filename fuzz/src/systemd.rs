// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The names systemd gives the units it generates from an fstab or crypttab
//! line: `path_simplify()` and `path_is_normalized()` (src/basic/path-util.c),
//! `unit_name_from_path()` (src/basic/unit-name.c), and
//! `fstab_node_to_udev_node()` with `encode_devnode_name()`
//! (src/shared/fstab-util.c, src/basic/device-nodes.c), the functions
//! systemd-fstab-generator and systemd-cryptsetup-generator call.
//!
//! Left out: the generator resolves symlinks in a mount point first, which
//! needs the filesystem, and a name of 256 bytes or more is shortened with a
//! hash ([`UnitName::Hashed`]).

/// `NAME_MAX`: the longest path component.
const NAME_MAX: usize = 255;
/// `PATH_MAX`, with its NUL.
const PATH_MAX: usize = 4096;
/// `UNIT_NAME_MAX`, with its NUL.
const UNIT_NAME_MAX: usize = 256;

/// The unit systemd generates for a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitName {
    /// Its name.
    Name(String),
    /// A name too long for a unit, which systemd shortens with a hash.
    Hashed,
    /// None: the path holds a NUL, a `..` or an overlong component, or is too
    /// long, so the generator logs an error and skips the line.
    Refused,
}

/// `path_simplify()`: repeated and trailing slashes and `.` components
/// dropped, and `..` components at the start of an absolute path, which
/// cannot climb above `/`.
pub fn path_simplify(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let absolute = path.starts_with('/');
    let mut kept: Vec<&str> = Vec::new();
    for component in path.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if absolute && kept.is_empty() && component == ".." {
            continue;
        }
        kept.push(component);
    }
    let joined = kept.join("/");
    if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// `path_is_normalized()` for a path `path_simplify()` returned: no `..`
/// component, no component longer than `NAME_MAX`, shorter than `PATH_MAX`.
fn normalized(path: &str) -> bool {
    path != "."
        && path.len() < PATH_MAX
        && path
            .split('/')
            .all(|component| component != ".." && component.len() <= NAME_MAX)
}

/// `do_escape()`: `/` becomes `-`, a leading `.` and every byte outside
/// `[A-Za-z0-9:_.]` become `\xNN`.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (index, byte) in text.bytes().enumerate() {
        match byte {
            b'/' => out.push('-'),
            b'.' if index == 0 => out.push_str("\\x2e"),
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b':' | b'_' | b'.' => {
                out.push(char::from(byte));
            }
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out
}

/// `unit_name_from_path()`: the unit with `suffix` (`.mount`, `.swap`,
/// `.automount`) systemd generates for `path`.
pub fn unit_name_from_path(path: &str, suffix: &str) -> UnitName {
    // A C string ends at its first NUL; such a line never reaches systemd as
    // NAILS reads it.
    if path.contains('\0') {
        return UnitName::Refused;
    }
    let simple = path_simplify(path);
    let escaped = if simple.is_empty() || simple == "/" {
        "-".to_string()
    } else if !normalized(&simple) {
        return UnitName::Refused;
    } else {
        escape(simple.trim_matches('/'))
    };
    let name = format!("{escaped}{suffix}");
    if name.len() >= UNIT_NAME_MAX {
        UnitName::Hashed
    } else {
        UnitName::Name(name)
    }
}

/// `unichar_is_valid()` for a Unicode scalar value (src/basic/utf8.c).
fn unichar_is_valid(c: char) -> bool {
    let code = u32::from(c);
    !(0xfdd0..=0xfdef).contains(&code) && code & 0xfffe != 0xfffe
}

/// `encode_devnode_name()`: the name udev gives a link for `value`. A valid
/// multi-byte character is kept, so are ASCII letters, digits and `#+-.:=@_`;
/// every other byte, the backslash included, becomes `\xNN`.
pub fn encode_devnode_name(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if (c.len_utf8() > 1 && unichar_is_valid(c))
            || c.is_ascii_alphanumeric()
            || "#+-.:=@_".contains(c)
        {
            out.push(c);
        } else {
            let mut buf = [0u8; 4];
            for byte in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("\\x{byte:02x}"));
            }
        }
    }
    out
}

/// `unquote(value, QUOTES)`: one pair of matching outer quotes removed.
fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 && matches!(bytes[0], b'"' | b'\'') && bytes[bytes.len() - 1] == bytes[0] {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

/// `fstab_node_to_udev_node()`: the device node an fstab or crypttab spec
/// names, a `LABEL=`, `UUID=`, `PARTUUID=` or `PARTLABEL=` tag as the
/// `/dev/disk/by-*` link udev makes for it, anything else as it is.
pub fn fstab_node_to_udev_node(spec: &str) -> String {
    const TAGS: [(&str, &str); 4] = [
        ("LABEL=", "label"),
        ("UUID=", "uuid"),
        ("PARTUUID=", "partuuid"),
        ("PARTLABEL=", "partlabel"),
    ];
    for (tag, by) in TAGS {
        if let Some(value) = spec.strip_prefix(tag) {
            return format!("/dev/disk/by-{by}/{}", encode_devnode_name(unquote(value)));
        }
    }
    spec.to_string()
}
