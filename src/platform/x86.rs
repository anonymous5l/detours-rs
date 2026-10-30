use crate::inst::{Disassembler, Inst};
use crate::platform::{detour_2gb_above, detour_2gb_below, encode_jmp_rel32};
use std::ops::RangeInclusive;

const X86_JMP_SIZE: usize = 5;
pub const NEEDED_BYTES: usize = X86_JMP_SIZE;

#[inline]
pub fn detour_gen_jmp_immediate(pb_code: *mut u8, pb_jmp_val: *mut u8) -> *mut u8 {
    let bytes = encode_jmp_rel32(pb_code as usize, pb_jmp_val as usize);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), pb_code, bytes.len());
    }
    pb_code.wrapping_byte_add(X86_JMP_SIZE)
}

#[inline]
pub fn detour_find_jmp_bounds(dis: &Disassembler, inst: &Inst) -> RangeInclusive<usize> {
    let code = inst.addr();
    let mut lo = detour_2gb_below(code);
    let mut hi = detour_2gb_above(code);
    if let Some(m) = inst.jmp_rm(dis) {
        if m < code {
            hi = detour_2gb_above(m);
        } else {
            lo = detour_2gb_below(m);
        }
    }
    lo..=hi
}
