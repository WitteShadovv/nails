// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

/// Run `prog` the way the kernel would for one access: a small interpreter
/// of the instructions [`program`] emits. Panics on anything else, on a jump
/// out of the program and on a run that does not end.
fn run(prog: &[Insn], dev_type: u32, access: u32, major: u32, minor: u32) -> u64 {
    let ctx = [(access << 16) | dev_type, major, minor];
    let mut regs = [0u64; 11];
    let mut pc = 0usize;
    for _ in 0..10_000 {
        let i = prog[pc];
        let dst = usize::from(i.regs & 0x0f);
        let src = usize::from(i.regs >> 4);
        let imm = i64::from(i.imm) as u64;
        let jump = |taken: bool| {
            if taken {
                usize::try_from(pc as i64 + 1 + i64::from(i.off)).expect("jump before the start")
            } else {
                pc + 1
            }
        };
        pc = match i.code {
            LDX_W => {
                assert_eq!(src, 1, "loads come from the context");
                let field = usize::try_from(i.off).unwrap() / 4;
                regs[dst] = u64::from(ctx[field]);
                pc + 1
            }
            AND_K => {
                regs[dst] = (regs[dst] & imm) & 0xffff_ffff;
                pc + 1
            }
            MOV64_K => {
                regs[dst] = imm;
                pc + 1
            }
            JEQ_K => jump(regs[dst] == imm),
            JNE_K => jump(regs[dst] != imm),
            JA => jump(true),
            EXIT => return regs[0],
            other => panic!("unexpected opcode {other:#x}"),
        };
        assert!(pc < prog.len(), "jump out of the program");
    }
    panic!("the program does not end");
}

fn dev(major: u32, minor: u32) -> DevNum {
    DevNum { major, minor }
}

const READ: u32 = 2;
const WRITE: u32 = 4;
const MKNOD: u32 = 1;

#[test]
fn an_empty_rule_set_allows_everything() {
    let prog = program(&Rules::default());
    for (t, major, minor) in [(DEV_BLOCK, 8, 0), (DEV_CHAR, 21, 0), (DEV_CHAR, 1, 3)] {
        assert_eq!(run(&prog, t, READ | WRITE, major, minor), 1);
    }
}

#[test]
fn every_access_to_a_listed_device_is_denied_and_nothing_else() {
    let rules = Rules {
        block: vec![dev(8, 0), dev(8, 1), dev(253, 0)],
        chars: vec![dev(240, 0), dev(239, 1)],
        sg: false,
    };
    let prog = program(&rules);
    for access in [READ, WRITE, READ | WRITE, MKNOD] {
        for &d in &rules.block {
            assert_eq!(run(&prog, DEV_BLOCK, access, d.major, d.minor), 0, "{d:?}");
        }
        for &d in &rules.chars {
            assert_eq!(run(&prog, DEV_CHAR, access, d.major, d.minor), 0, "{d:?}");
        }
    }
    // The same numbers of the other type, a neighbour, the hidden volume.
    assert_eq!(run(&prog, DEV_CHAR, READ, 8, 0), 1);
    assert_eq!(run(&prog, DEV_BLOCK, READ, 240, 0), 1);
    assert_eq!(run(&prog, DEV_BLOCK, WRITE, 8, 2), 1);
    assert_eq!(run(&prog, DEV_BLOCK, WRITE, 8, 16), 1);
    assert_eq!(run(&prog, DEV_BLOCK, WRITE, 254, 0), 1);
    assert_eq!(run(&prog, DEV_CHAR, READ, 21, 0), 1, "sg is not asked for");
}

#[test]
fn the_sg_rule_denies_every_scsi_generic_node() {
    let prog = program(&Rules {
        block: vec![dev(8, 0)],
        chars: Vec::new(),
        sg: true,
    });
    for minor in [0, 1, 7, 255] {
        assert_eq!(run(&prog, DEV_CHAR, READ, SG_MAJOR, minor), 0);
    }
    assert_eq!(run(&prog, DEV_BLOCK, READ, SG_MAJOR, 0), 1);
    assert_eq!(run(&prog, DEV_CHAR, READ, 4, 1), 1);
}

#[test]
fn the_program_is_small_and_ends_on_every_path() {
    let rules = Rules {
        block: (0..40).map(|m| dev(8, m)).collect(),
        chars: (0..10).map(|m| dev(240, m)).collect(),
        sg: true,
    };
    let prog = program(&rules);
    assert_eq!(prog.len(), 5 + 2 * 40 + 1 + 1 + 1 + 2 * 10 + 4);
    assert_eq!(prog.iter().filter(|i| i.code == EXIT).count(), 2);
    assert!(
        prog.iter().all(|i| i.regs >> 4 <= 1),
        "no source register but the context"
    );
}

#[test]
fn the_name_fits_the_kernel_s_sixteen_bytes() {
    assert!(PROGRAM_NAME.len() < 16);
    assert!(!String::from_utf8_lossy(PROGRAM_NAME).contains("nails"));
}

#[test]
fn the_attribute_prefixes_match_the_kernel_s_layout() {
    assert_eq!(std::mem::offset_of!(LoadAttr, insns), 8);
    assert_eq!(std::mem::offset_of!(LoadAttr, license), 16);
    assert_eq!(std::mem::offset_of!(LoadAttr, log_buf), 32);
    assert_eq!(std::mem::offset_of!(LoadAttr, prog_name), 48);
    assert_eq!(std::mem::offset_of!(LoadAttr, expected_attach_type), 68);
    assert_eq!(std::mem::offset_of!(AttachAttr, attach_flags), 12);
    assert_eq!(std::mem::offset_of!(InfoAttr, info), 8);
    assert_eq!(std::mem::offset_of!(ProgInfo, tag), 8);
    assert_eq!(std::mem::size_of::<Insn>(), 8);
}

#[test]
fn tags_print_as_hex() {
    assert_eq!(hex(&[0, 0xab, 0x10]), "00ab10");
}

/// Every instruction is reached by some path, as the verifier demands, and
/// every jump lands inside the program.
fn assert_all_reachable(prog: &[Insn]) {
    let mut seen = vec![false; prog.len()];
    let mut todo = vec![0usize];
    while let Some(pc) = todo.pop() {
        if seen[pc] {
            continue;
        }
        seen[pc] = true;
        let i = prog[pc];
        let target = || usize::try_from(pc as i64 + 1 + i64::from(i.off)).unwrap();
        match i.code {
            EXIT => {}
            JA => todo.push(target()),
            JEQ_K | JNE_K => {
                todo.push(target());
                todo.push(pc + 1);
            }
            _ => todo.push(pc + 1),
        }
        assert!(
            todo.iter().all(|&t| t < prog.len()),
            "a jump leaves the program"
        );
    }
    assert!(seen.iter().all(|s| *s), "unreachable: {seen:?}");
}

#[test]
fn no_instruction_is_unreachable_whatever_the_rules() {
    for rules in [
        Rules::default(),
        Rules {
            block: vec![dev(8, 0)],
            ..Rules::default()
        },
        Rules {
            chars: vec![dev(240, 0)],
            ..Rules::default()
        },
        Rules {
            sg: true,
            ..Rules::default()
        },
        Rules {
            block: vec![dev(8, 0), dev(8, 1)],
            chars: vec![dev(240, 0)],
            sg: true,
        },
    ] {
        assert_all_reachable(&program(&rules));
    }
}
