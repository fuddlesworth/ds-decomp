use unarm::{Ins, LdrStrOffset, Op2, Op2Shift, Reg, ShiftImm};

pub fn is_valid_function_start_arm(ins: &Ins) -> bool {
    match ins {
        Ins::Illegal => false,
        Ins::Eor { rd, rn, op2: Op2::ShiftImm(ShiftImm { rm, .. }), .. }
            if rd == rn || rd == rm || rn == rm =>
        {
            // Weird EOR instruction
            false
        }
        _ => true,
    }
}

/// Returns the register number of the data operand of a Thumb data operation: the register after the destination in
/// divided syntax (`rm` of `and rd, rm`, `rn` of `add rd, rn, #imm`), or `None` if that operand is an immediate or the
/// instruction is no data operation. This is the operand that dsd checked with unarm 1.9. unarm 2.2's `Ins::rn` is
/// the destination of a two-operand instruction instead, and the encoding tells the two-operand forms apart from the
/// three-operand ones that have `rd == rn`, which the decoded instruction does not.
fn thumb_data_operand(code: u16) -> Option<u16> {
    match code {
        // lsl/lsr/asr rd, rm, #imm; add/sub rd, rn, rm; add/sub rd, rn, #imm
        0x0000..=0x1fff => Some((code >> 3) & 7),
        // Data processing, except tst, cmp, cmn and mvn
        0x4000..=0x43ff => match (code >> 6) & 0xf {
            0x8 | 0xa | 0xb | 0xf => None,
            _ => Some((code >> 3) & 7),
        },
        // add rd, rm with high registers
        0x4400..=0x44ff => Some((code >> 3) & 0xf),
        _ => None,
    }
}

pub fn is_valid_function_start_thumb(ins: &Ins, code: u16) -> bool {
    if let Some(reg) = thumb_data_operand(code)
        && !matches!(reg, 0..=3 | 13 | 15)
    {
        // Data operand must be an argument register, SP or PC
        return false;
    }

    match ins {
        Ins::Illegal => false,
        Ins::Mov { rd, op2: Op2::ShiftImm(ShiftImm { rm, .. }), .. } if rd == rm => {
            // Useless mov
            false
        }
        Ins::Lsl { rd, rn, op2: Op2Shift::Imm(0), .. } if rd == rn => {
            // Useless data op
            false
        }
        Ins::Lsr { op2: Op2Shift::Imm(shift), .. }
            if (shift % 4) == 0 && *shift != 16 && *shift != 24 =>
        {
            // Table of bytes with values 0-7 got interpreted as Thumb code
            // Shift by 16 or 24 is allowed since they may be used for integer type casts
            false
        }
        Ins::Ldr { addr, .. }
        | Ins::Ldrb { addr, .. }
        | Ins::Str { addr, .. }
        | Ins::Strb { addr, .. }
            if !matches!(addr.rn(), Reg::R0 | Reg::R1 | Reg::R2 | Reg::R3 | Reg::Sp | Reg::Pc) =>
        {
            // Load/store base must be an argument register, SP or PC
            false
        }
        Ins::Ldrh { addr, .. }
        | Ins::Ldrsh { addr, .. }
        | Ins::Ldrsb { addr, .. }
        | Ins::Strh { addr, .. }
            if !matches!(addr.rn(), Reg::R0 | Reg::R1 | Reg::R2 | Reg::R3 | Reg::Sp | Reg::Pc) =>
        {
            // Load/store base must be an argument register, SP or PC
            false
        }
        Ins::Strh { rd, addr, .. } if *rd == addr.rn() => {
            // Weird self reference:
            // *ptr = (u16) ptr;
            false
        }
        Ins::Strb { rd, addr, .. } if *rd == addr.rn() => {
            // Weird self reference:
            // *ptr = (u8) ptr;
            false
        }
        Ins::Ldr { addr, .. } | Ins::Ldrb { addr, .. }
            if let LdrStrOffset::Reg { rm, .. } = addr.offset()
                && !matches!(rm, Reg::R0 | Reg::R1 | Reg::R2 | Reg::R3) =>
        {
            // Offset register must be an argument register
            false
        }
        _ => true,
    }
}

/// `code` is the instruction's first halfword or word.
pub fn is_valid_function_start(ins: &Ins, code: u32, thumb: bool) -> bool {
    if ins.is_conditional() {
        return false;
    }
    if thumb {
        is_valid_function_start_thumb(ins, code as u16)
    } else {
        is_valid_function_start_arm(ins)
    }
}
