use crate::inst::{Disassembler, Inst};
use crate::platform::{detour_2gb_above, detour_2gb_below, vcopy};
use std::ops::RangeInclusive;

const AARCH64_JMP_SIZE: usize = 8;

pub const NEEDED_BYTES: usize = AARCH64_JMP_SIZE;

#[inline]
#[cfg(target_os = "macos")]
pub fn detour_gen_jmp_immediate(pb_code: *mut u8, pb_jmp_val: *mut u8) {
    let delta =
        (pb_jmp_val.addr() as isize).saturating_sub(pb_code.addr().saturating_add(8) as isize);
    let mut buf = [0u32; 2];

    unsafe {
        *buf.as_mut_ptr() = (0x58000011 | ((delta / 4) << 5)) as u32;
        *buf.as_mut_ptr().add(1) = 0xd61f0000 | (17 << 5);
    }
    // 失败说明目标页不可写，调用方无从补救（与 C++ 该路径一致：不检查返回值）。
    let _ = vcopy(pb_code.cast(), buf.as_ptr().cast(), 8);
}

#[inline]
pub fn detour_find_jmp_bounds(_dis: &Disassembler, inst: &Inst) -> RangeInclusive<usize> {
    let code = inst.addr();
    let lo = detour_2gb_below(code);
    let hi = detour_2gb_above(code);
    lo..=hi
}
