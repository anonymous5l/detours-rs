//! x86_64 平台层。
//!
//! 与 x86 的关键差异：x64 下 detour 函数与目标函数的距离常常远超 rel32 的
//! ±2GB 可达范围，无法在目标处直接 `jmp rel32` 到 detour。因此目标处只写一个
//! 跳到 trampoline 内 `jmp [rip+disp32]` thunk 的 rel32 跳转，再由该 thunk
//! 从槽位取地址完成到 detour 的间接跳转。对应 C++ 的
//! `detour_gen_jmp_immediate` / `detour_gen_jmp_indirect` 组合。

use crate::inst::{Disassembler, Inst};
use crate::platform::{
    detour_2gb_above, detour_2gb_below, encode_jmp_rel32, encode_jmp_rip_indirect,
};
use std::ffi::c_void;
use std::ops::RangeInclusive;

pub const JMP_SIZE: usize = 5;
/// `jmp [rip+disp32]` 的编码长度：`ff 25` + disp32。
pub const JMP_INDIRECT_SIZE: usize = 6;

pub const NEEDED_BYTES: usize = JMP_SIZE;

/// 写入 `jmp rel32` 到 `pb_jmp_val`，返回写入后的下一个字节地址。
#[inline]
pub fn detour_gen_jmp_immediate(pb_code: *mut u8, pb_jmp_val: *mut u8) -> *mut u8 {
    let bytes = encode_jmp_rel32(pb_code as usize, pb_jmp_val as usize);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), pb_code, bytes.len());
    }
    pb_code.wrapping_byte_add(JMP_SIZE)
}

/// 写入 `jmp qword ptr [rip+disp32]`，跳转目标从 `slot` 处读取，
/// 不受 rel32 可达范围限制。返回写入后的下一个字节地址。
#[inline]
pub fn detour_gen_jmp_indirect(pb_code: *mut u8, slot: *const c_void) -> *mut u8 {
    let bytes = encode_jmp_rip_indirect(pb_code as usize, slot as usize);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), pb_code, bytes.len());
    }
    pb_code.wrapping_byte_add(JMP_INDIRECT_SIZE)
}

#[inline]
pub fn detour_find_jmp_bounds(dis: &Disassembler, inst: &Inst) -> RangeInclusive<usize> {
    let code = inst.addr();
    let mut lo = detour_2gb_below(code);
    let mut hi = detour_2gb_above(code);

    // trampoline 既要落在代码 ±2GB 内，也要落在它所引用的跳转向量 ±2GB 内。
    if let Some(m) = inst.jmp_rm(dis) {
        if m < code {
            hi = detour_2gb_above(m);
        } else {
            lo = detour_2gb_below(m);
        }
    } else if let Some((_, target)) = inst.jmp_imm(dis) {
        if target < code {
            hi = detour_2gb_above(target);
        } else {
            lo = detour_2gb_below(target);
        }
    }

    lo..=hi
}
