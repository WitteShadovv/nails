// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A request line from a window, as the engine's root helper decodes it
//! (`nails_api::protocol::decode_request`). The helper runs as root and the
//! window as the operator, so these are bytes from a less trusted process.
//!
//! The input is one line. The target checks that a line past the length limit
//! or holding a newline is always refused, that only a request of the
//! protocol's version with arguments of the right shape is accepted, and that
//! an accepted request, written back as the window writes it, is read again
//! as the same request.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_api::protocol::{MAX_LINE_BYTES, PROTOCOL_VERSION, decode_request, validate};

fuzz_target!(|data: &[u8]| {
    let decoded = decode_request(data);
    if data.len() > MAX_LINE_BYTES || data.contains(&b'\n') {
        assert!(
            decoded.is_err(),
            "an overlong or multi-line request was accepted"
        );
    }
    let Ok(request) = decoded else {
        return;
    };
    assert_eq!(request.v, PROTOCOL_VERSION);
    assert_eq!(validate(&request.op), Ok(()));
    let line = request.to_line();
    assert!(!line.contains('\n'), "{line}");
    assert_eq!(
        decode_request(line.as_bytes()).as_ref(),
        Ok(&request),
        "{line}"
    );
});
