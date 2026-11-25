// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The device-cgroup program of the write fence ([`crate::whole_root::fence`]).
//!
//! A `BPF_PROG_TYPE_CGROUP_DEVICE` program runs at every open and `mknod` of
//! a device node, and at every in-kernel open a process asks for (a mount, a
//! swap area, a device-mapper table), for every process in a cgroup whose
//! effective programs include it. Attached to the root of the cgroup2
//! hierarchy with `BPF_F_ALLOW_MULTI`, it is one of every process's effective
//! programs, and the programs systemd attaches below for `DevicePolicy=` still
//! attach and run beside it. It denies (returns 0) every access to the
//! devices in its [`Rules`] and allows the rest; a legacy attach keeps the
//! program after the process that attached it is gone, across the soft-reboot,
//! until the power-off.
//!
//! The program is a handful of instructions, assembled here as systemd
//! assembles its own: no helper calls, no maps, no BTF, so every kernel with
//! `CONFIG_CGROUP_BPF` loads it. It carries the name systemd gives its device
//! programs.

use crate::whole_root::disk_guard::DevNum;
use crate::whole_root::fence::{Program, Rules, SG_MAJOR};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

/// One BPF instruction, as `struct bpf_insn` lays it out.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    /// The opcode.
    pub code: u8,
    /// Destination register (low nibble) and source register (high nibble).
    pub regs: u8,
    /// The offset.
    pub off: i16,
    /// The immediate.
    pub imm: i32,
}

/// `BPF_LDX | BPF_W | BPF_MEM`: load a 32-bit word.
pub const LDX_W: u8 = 0x61;
/// `BPF_ALU | BPF_AND | BPF_K`.
pub const AND_K: u8 = 0x54;
/// `BPF_JMP | BPF_JEQ | BPF_K`.
pub const JEQ_K: u8 = 0x15;
/// `BPF_JMP | BPF_JNE | BPF_K`.
pub const JNE_K: u8 = 0x55;
/// `BPF_JMP | BPF_JA`.
pub const JA: u8 = 0x05;
/// `BPF_ALU64 | BPF_MOV | BPF_K`.
pub const MOV64_K: u8 = 0xb7;
/// `BPF_JMP | BPF_EXIT`.
pub const EXIT: u8 = 0x95;

/// `BPF_DEVCG_DEV_BLOCK`.
pub const DEV_BLOCK: u32 = 1;
/// `BPF_DEVCG_DEV_CHAR`.
pub const DEV_CHAR: u32 = 2;

/// The program's name: the one systemd gives its device programs, so a list
/// of the loaded programs shows nothing of its own.
pub const PROGRAM_NAME: &[u8] = b"sd_devices";

const fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn {
        code,
        regs: (src << 4) | (dst & 0x0f),
        off,
        imm,
    }
}

/// An instruction whose jump target is a label, fixed up once the layout is
/// known.
enum Op {
    Plain(Insn),
    Jump {
        code: u8,
        reg: u8,
        imm: i32,
        to: Label,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Label {
    Char,
    Allow,
    Deny,
}

fn imm(value: u32) -> i32 {
    // Device numbers are at most 20 bits; the kernel compares the register,
    // zero-extended from the 32-bit load, with the immediate sign-extended.
    i32::try_from(value).unwrap_or(i32::MAX)
}

/// The program for `rules`: block devices first, then character devices.
///
/// ```text
/// r2 = ctx->access_type & 0xffff   ; the device type
/// r3 = ctx->major; r4 = ctx->minor
/// if r2 != BLOCK goto char
///   (for each block device) if r3 != major goto +1; if r4 == minor goto deny
///   goto allow
/// char: if r2 != CHAR goto allow
///   if r3 == 21 goto deny          ; every sg node, when asked
///   (for each character device) as above
/// allow: r0 = 1; exit
/// deny:  r0 = 0; exit
/// ```
pub fn program(rules: &Rules) -> Vec<Insn> {
    let mut ops = vec![
        Op::Plain(insn(LDX_W, 2, 1, 0, 0)),
        Op::Plain(insn(AND_K, 2, 0, 0, 0xffff)),
        Op::Plain(insn(LDX_W, 3, 1, 4, 0)),
        Op::Plain(insn(LDX_W, 4, 1, 8, 0)),
        Op::Jump {
            code: JNE_K,
            reg: 2,
            imm: imm(DEV_BLOCK),
            to: Label::Char,
        },
    ];
    let pair = |ops: &mut Vec<Op>, dev: DevNum| {
        ops.push(Op::Plain(insn(JNE_K, 3, 0, 1, imm(dev.major))));
        ops.push(Op::Jump {
            code: JEQ_K,
            reg: 4,
            imm: imm(dev.minor),
            to: Label::Deny,
        });
    };
    for &dev in &rules.block {
        pair(&mut ops, dev);
    }
    ops.push(Op::Jump {
        code: JA,
        reg: 0,
        imm: 0,
        to: Label::Allow,
    });
    let char_at = ops.len();
    ops.push(Op::Jump {
        code: JNE_K,
        reg: 2,
        imm: imm(DEV_CHAR),
        to: Label::Allow,
    });
    if rules.sg {
        ops.push(Op::Jump {
            code: JEQ_K,
            reg: 3,
            imm: imm(SG_MAJOR),
            to: Label::Deny,
        });
    }
    for &dev in &rules.chars {
        pair(&mut ops, dev);
    }
    let allow_at = ops.len();
    ops.push(Op::Plain(insn(MOV64_K, 0, 0, 0, 1)));
    ops.push(Op::Plain(insn(EXIT, 0, 0, 0, 0)));
    // The verifier refuses a program with an instruction no path reaches: no
    // rule, no deny.
    let deny_at = ops.len();
    if !rules.block.is_empty() || !rules.chars.is_empty() || rules.sg {
        ops.push(Op::Plain(insn(MOV64_K, 0, 0, 0, 0)));
        ops.push(Op::Plain(insn(EXIT, 0, 0, 0, 0)));
    }
    ops.into_iter()
        .enumerate()
        .map(|(at, op)| match op {
            Op::Plain(insn) => insn,
            Op::Jump { code, reg, imm, to } => {
                let target = match to {
                    Label::Char => char_at,
                    Label::Allow => allow_at,
                    Label::Deny => deny_at,
                };
                let off = i16::try_from(target as i64 - at as i64 - 1).unwrap_or(i16::MAX);
                insn(code, reg, 0, off, imm)
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The bpf(2) calls

const BPF_PROG_LOAD: libc::c_long = 5;
const BPF_PROG_ATTACH: libc::c_long = 8;
const BPF_OBJ_GET_INFO_BY_FD: libc::c_long = 15;
/// `BPF_PROG_TYPE_CGROUP_DEVICE`.
pub const PROG_TYPE_CGROUP_DEVICE: u32 = 15;
/// `BPF_CGROUP_DEVICE`.
const ATTACH_CGROUP_DEVICE: u32 = 6;
/// `BPF_F_ALLOW_MULTI`.
const F_ALLOW_MULTI: u32 = 1 << 1;

/// The leading part of `union bpf_attr` for `BPF_PROG_LOAD`.
#[repr(C, align(8))]
#[derive(Default)]
struct LoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

/// The leading part of `union bpf_attr` for attach and detach.
#[repr(C, align(8))]
#[derive(Default)]
struct AttachAttr {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
}

/// The leading part of `union bpf_attr` for `BPF_OBJ_GET_INFO_BY_FD`.
#[repr(C, align(8))]
#[derive(Default)]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

/// The leading part of `struct bpf_prog_info`.
#[repr(C, align(8))]
#[derive(Default)]
struct ProgInfo {
    prog_type: u32,
    id: u32,
    tag: [u8; 8],
}

#[allow(unsafe_code)]
fn bpf<T>(cmd: libc::c_long, attr: &mut T) -> io::Result<libc::c_long> {
    // SAFETY: `attr` is a `#[repr(C)]` prefix of `union bpf_attr` for `cmd`,
    // valid for the size passed; the kernel reads (and for the info command
    // writes) only within it and through the pointers it holds, which point
    // to live buffers of the caller.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            std::ptr::from_mut(attr).cast::<libc::c_void>(),
            std::mem::size_of::<T>(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

#[allow(unsafe_code)]
fn owned(fd: libc::c_long) -> io::Result<OwnedFd> {
    let fd = i32::try_from(fd).map_err(|_| io::Error::other("file descriptor out of range"))?;
    // SAFETY: the kernel just returned this descriptor to this process, and
    // nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fd_u32(fd: &OwnedFd) -> u32 {
    u32::try_from(fd.as_raw_fd()).unwrap_or(u32::MAX)
}

/// Load the program for `rules`.
pub fn load(rules: &Rules) -> io::Result<OwnedFd> {
    let insns = program(rules);
    let license = b"GPL\0";
    let mut name = [0u8; 16];
    name[..PROGRAM_NAME.len()].copy_from_slice(PROGRAM_NAME);
    let mut attr = LoadAttr {
        prog_type: PROG_TYPE_CGROUP_DEVICE,
        insn_cnt: u32::try_from(insns.len()).map_err(|_| io::Error::other("program too long"))?,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        prog_name: name,
        ..LoadAttr::default()
    };
    owned(bpf(BPF_PROG_LOAD, &mut attr)?)
}

fn info(prog: &OwnedFd) -> io::Result<ProgInfo> {
    let mut info = ProgInfo::default();
    let mut attr = InfoAttr {
        bpf_fd: fd_u32(prog),
        info_len: u32::try_from(std::mem::size_of::<ProgInfo>()).unwrap_or(0),
        info: std::ptr::from_mut(&mut info) as u64,
    };
    bpf(BPF_OBJ_GET_INFO_BY_FD, &mut attr)?;
    Ok(info)
}

fn hex(tag: &[u8]) -> String {
    tag.iter().map(|b| format!("{b:02x}")).collect()
}

fn open_cgroup(root: &Path) -> io::Result<OwnedFd> {
    let dir = std::fs::File::open(root)?;
    Ok(OwnedFd::from(dir))
}

/// Load the program for `rules` and attach it to the cgroup2 hierarchy whose
/// root is mounted at `cgroup_root`.
pub fn attach(rules: &Rules, cgroup_root: &Path) -> io::Result<Program> {
    let prog = load(rules)?;
    let cgroup = open_cgroup(cgroup_root)?;
    let mut attr = AttachAttr {
        target_fd: fd_u32(&cgroup),
        attach_bpf_fd: fd_u32(&prog),
        attach_type: ATTACH_CGROUP_DEVICE,
        attach_flags: F_ALLOW_MULTI,
    };
    bpf(BPF_PROG_ATTACH, &mut attr)?;
    let info = info(&prog)?;
    Ok(Program {
        id: info.id,
        tag: hex(&info.tag),
    })
}

#[cfg(test)]
#[path = "fence_bpf_tests.rs"]
mod tests;
