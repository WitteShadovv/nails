// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The headers of the loops a file runs, as the walk reads them: a `for`'s,
//! a `foreach`'s or a `select`'s variables and list, a `repeat`'s count, and
//! how each one's body ends.

use super::super::lexer::{End, Token, is_name};
use super::{Closer, Frame, Walker};

impl Walker<'_> {
    /// The header of a `for`, `foreach` or `select` loop, read past its
    /// keyword: its variables and list, and how its body ends. Also whether
    /// the body is one command or group, as in zsh's short forms
    /// (`for x (a) cmd`).
    pub(super) fn for_header(&mut self, foreach: bool) -> (Frame, bool) {
        let mut var = match self.tokens.next() {
            Some(Token::Word(word)) if is_name(&word.text) => Some(word.text),
            // `for (( ...; ...; ... ))`, over nothing the check can list.
            Some(Token::Arithmetic(text)) => {
                self.mention_arithmetic(&text);
                let (closer, short) = self.body_closer(foreach);
                let frame = Frame::Loop {
                    var: None,
                    items: None,
                    closer,
                    profiles: false,
                };
                return (frame, short);
            }
            _ => {
                self.confused = true;
                None
            }
        };
        // More variables, as zsh takes them (`for key value in ...`).
        while self
            .tokens
            .next_if(|token| {
                matches!(token, Token::Word(word) if is_name(&word.text) && !matches!(word.text.as_str(), "in" | "do"))
            })
            .is_some()
        {
            var = None;
        }
        let mut list = Vec::new();
        let mut listed = false;
        match self.tokens.peek() {
            Some(Token::Word(word)) if word.text == "in" => {
                self.tokens.next();
                while let Some(Token::Word(word)) = self.tokens.next_if(
                    |token| matches!(token, Token::Word(word) if word.text != "do" && word.text != "{"),
                ) {
                    list.push(word);
                }
                listed = true;
            }
            Some(Token::Open) => {
                self.tokens.next();
                while let Some(Token::Word(word)) =
                    self.tokens.next_if(|token| matches!(token, Token::Word(_)))
                {
                    list.push(word);
                }
                listed = self.tokens.next_if_eq(&Token::Close).is_some();
            }
            _ => {}
        }
        for word in &list {
            let text = word.text.clone();
            self.mention(&text);
        }
        let items = if listed { self.list(&list) } else { None };
        let (closer, short) = self.body_closer(foreach);
        // NixOS's loop over the profiles, `for p in ${(z)NIX_PROFILES}; do`,
        // as its `/etc/zshenv` writes it.
        let profiles = !foreach
            && !short
            && closer == Closer::Done
            && var.as_deref() == Some("p")
            && matches!(list.as_slice(), [word] if word.text == "${(z)NIX_PROFILES}");
        (
            Frame::Loop {
                var,
                items,
                closer,
                profiles,
            },
            short,
        )
    }

    /// How the body of a loop whose header was read ends: `do ... done`,
    /// `{ ... }` or, for `foreach`, `... end`, past any line end, or with one
    /// command or group, as in zsh's short forms (then `true`).
    fn body_closer(&mut self, foreach: bool) -> (Closer, bool) {
        while self.tokens.next_if_eq(&Token::End(End::Line)).is_some() {}
        let (closer, short) = match self.tokens.peek() {
            Some(Token::Word(word)) if word.text == "do" => (Closer::Done, false),
            Some(Token::Word(word)) if word.text == "{" => (Closer::Brace, false),
            _ if foreach => (Closer::End, false),
            _ => (Closer::Done, true),
        };
        if !short && closer != Closer::End {
            self.tokens.next();
        }
        (closer, short)
    }

    /// Read `repeat`'s count and how its body ends.
    pub(super) fn repeat(&mut self) {
        if let Some(Token::Word(count)) =
            self.tokens.next_if(|token| matches!(token, Token::Word(_)))
        {
            self.mention_word(&count);
            self.arith(&count.text, super::Arith::Plain);
        }
        let closer = match self.tokens.peek() {
            Some(Token::Word(word)) if word.text == "do" => Some(Closer::Done),
            Some(Token::Word(word)) if word.text == "{" => Some(Closer::Brace),
            _ => None,
        };
        if closer.is_some() {
            self.tokens.next();
        }
        self.open(
            Frame::Loop {
                var: None,
                items: None,
                closer: closer.unwrap_or(Closer::Done),
                profiles: false,
            },
            false,
        );
        if closer.is_none() {
            self.short_body();
        }
    }
}
