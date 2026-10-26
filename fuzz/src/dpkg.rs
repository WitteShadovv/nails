// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! How dpkg splits its status file into stanzas and fields, written from
//! `parse_stanza()` and `pkg_parse_field()` (lib/dpkg/parse.c, dpkg 1.23),
//! for a status file, which dpkg reads with its lax stanza parser
//! (`pdb_parse_status`).
//!
//! The model keeps the stanza layer only: where each stanza, field name and
//! value starts and ends, and the errors that layer raises. What dpkg checks
//! of each field's syntax (a package name, a version, the three words of a
//! status) is not modelled; the target compares values as text. The cursor
//! walks the text as `ps->dataptr` walks dpkg's buffer, with
//! `parse_at_eof()`, `parse_getc()` and `parse_ungetc()`.

/// dpkg's `MSDOS_EOF_CHAR`, Ctrl+Z.
const MSDOS_EOF_CHAR: char = '\x1a';

/// `c_isspace()`.
fn c_isspace(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')
}

/// One field of a stanza, as `parse_stanza()` hands it to
/// `pkg_parse_field()`: its name and its value, trimmed at the end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// The field's name.
    pub name: String,
    /// Its value.
    pub value: String,
}

/// dpkg's buffer and `ps->dataptr`.
struct Parser {
    data: Vec<char>,
    at: usize,
}

impl Parser {
    fn parse_at_eof(&self) -> bool {
        self.at >= self.data.len()
    }

    fn parse_getc(&mut self) -> char {
        let c = self.data[self.at];
        self.at += 1;
        c
    }

    fn parse_ungetc(&mut self) {
        self.at -= 1;
    }

    /// `parse_stanza()`: `Ok(None)` when nothing is left, `Err(())` where it
    /// raises a parse error. A blank line inside a value is only a lax
    /// problem, a warning, for a status file.
    fn parse_stanza(&mut self) -> Result<Option<Vec<Field>>, ()> {
        let mut c = '\0';

        // Skip adjacent new lines.
        while !self.parse_at_eof() {
            c = self.parse_getc();
            if c != '\n' && c != MSDOS_EOF_CHAR {
                break;
            }
        }

        // Nothing relevant parsed, bail out.
        if self.parse_at_eof() {
            return Ok(None);
        }

        let mut fields = Vec::new();
        // Loop per field.
        loop {
            // Scan field name.
            let fieldstart = self.at - 1;
            while !self.parse_at_eof() && !c_isspace(c) && c != ':' && c != MSDOS_EOF_CHAR {
                c = self.parse_getc();
            }
            let fieldlen = self.at - fieldstart - 1;
            if fieldlen == 0 {
                return Err(()); // empty field name
            }
            if self.data[fieldstart] == '-' {
                return Err(()); // field name cannot start with hyphen
            }

            // Skip spaces before ':'.
            while !self.parse_at_eof() && c != '\n' && c_isspace(c) {
                c = self.parse_getc();
            }

            // Validate ':'.
            if self.parse_at_eof() || c == '\n' || c == MSDOS_EOF_CHAR || c != ':' {
                return Err(());
            }

            // Skip space after ':' but before value and EOL.
            while !self.parse_at_eof() {
                c = self.parse_getc();
                if c == '\n' || !c_isspace(c) {
                    break;
                }
            }
            if self.parse_at_eof() || c == MSDOS_EOF_CHAR {
                return Err(()); // missing final newline, or Ctrl+Z in value
            }

            let mut blank_line = false;

            // Scan field value.
            let valuestart = self.at - 1;
            loop {
                if c == '\n' || c == MSDOS_EOF_CHAR {
                    // A blank line in the value is a lax problem here.
                    if self.parse_at_eof() {
                        break;
                    }
                    c = self.parse_getc();

                    // Found double EOL, or start of new field.
                    if self.parse_at_eof() || c == '\n' || !c_isspace(c) {
                        break;
                    }

                    self.parse_ungetc();
                    blank_line = true;
                } else if blank_line && !c_isspace(c) {
                    blank_line = false;
                }

                if self.parse_at_eof() {
                    return Err(()); // end of file during value
                }

                c = self.parse_getc();
            }
            let mut valuelen = self.at - valuestart - 1;

            // Trim ending space on value.
            while valuelen > 0 && c_isspace(self.data[valuestart + valuelen - 1]) {
                valuelen -= 1;
            }

            fields.push(Field {
                name: self.data[fieldstart..fieldstart + fieldlen]
                    .iter()
                    .collect(),
                value: self.data[valuestart..valuestart + valuelen]
                    .iter()
                    .collect(),
            });

            if self.parse_at_eof() || c == '\n' || c == MSDOS_EOF_CHAR {
                break;
            }
        }

        Ok(Some(fields))
    }
}

/// `pkg_parse_field()`'s checks of the stanza layer, which apply to every
/// field: no field twice in a stanza (dpkg compares the names of the fields
/// it knows, and of the others, without regard to ASCII case), and no field
/// it does not know with a name shorter than two characters (every field it
/// knows has a longer one).
fn fields_accepted(fields: &[Field]) -> bool {
    fields.iter().enumerate().all(|(i, field)| {
        field.name.chars().count() >= 2
            && !fields[..i]
                .iter()
                .any(|earlier| earlier.name.eq_ignore_ascii_case(&field.name))
    })
}

/// The stanzas dpkg reads from the status file `text`: `None` where it
/// refuses the file at the stanza layer, or for a stanza without a
/// `Package` value (`parse_must_have_field()`; an empty name is no legal
/// one either).
pub fn stanzas(text: &str) -> Option<Vec<Vec<Field>>> {
    let mut parser = Parser {
        data: text.chars().collect(),
        at: 0,
    };
    let mut stanzas = Vec::new();
    while let Some(fields) = parser.parse_stanza().ok()? {
        if !fields_accepted(&fields) {
            return None;
        }
        let package = fields
            .iter()
            .find(|field| field.name.eq_ignore_ascii_case("Package"))?;
        if package.value.is_empty() {
            return None;
        }
        stanzas.push(fields);
    }
    Some(stanzas)
}
