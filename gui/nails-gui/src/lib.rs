// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! `nails-gui` is the window of NAILS.
//!
//! The window runs as the operator, never as root. It drives the static
//! `nails` engine through the engine's root helper, `nails helper --stdio`, on
//! one end of a private socket pair, with the protocol of
//! [`nails_api::protocol`]: the helper's hello, the window's hello (both name
//! one release and one protocol, or the window refuses), then one request at
//! a time, each answered with the envelope the CLI prints for the same command
//! under `--json`.
//!
//! This crate holds the window's end of that protocol; the window itself is
//! not drawn yet.
//!
//! - [`launch`] decides how the window reaches the helper: on the socket the
//!   launcher (`sudo <root>/nails gui`) hands it as its standard input, or, in
//!   a hidden session, by starting `pkexec <root>/nails helper --stdio`
//!   itself. Anywhere else it opens nothing.
//! - [`frames`] reads the helper's frames, bounded and strict;
//!   [`client`] speaks the protocol: the handshake, one request at a time,
//!   and an operation's plan, token and apply.
//! - [`worker`] runs the client on a thread of its own, so the window never
//!   waits on the pipe, and reports what happens as [`worker::Update`]s.

pub mod client;
pub mod frames;
pub mod launch;
pub mod worker;
