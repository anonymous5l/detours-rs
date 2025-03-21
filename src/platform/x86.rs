use crate::inst;
use iced_x86::Code::Jmp_rel32_32;
use iced_x86::{Code, Instruction};
use std::ops::{Range, RangeInclusive};
use std::ptr;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_IAT;
#[cfg(any(target_pointer_width = "32"))]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
#[cfg(any(target_pointer_width = "64"))]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;
use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
};

const X86_JMP_SIZE: usize = 5;
pub const NEEDED_BYTES: usize = X86_JMP_SIZE;

#[inline]
pub fn detour_2gb_below(addr: usize) -> usize {
    if addr > 0x7ff80000 {
        addr - 0x7ff80000
    } else {
        0x80000
    }
}

#[inline]
pub fn detour_2gb_above(addr: usize) -> usize {
    #[cfg(target_pointer_width = "64")]
    if addr < 0xffffffff80000000 {
        addr + 0x7ff80000
    } else {
        0xfffffffffff80000
    }

    #[cfg(target_pointer_width = "32")]
    if addr < 0x80000000 {
        addr + 0x7ff80000
    } else {
        0xfff80000
    }
}

#[inline]
unsafe fn get_iat_range(nt_headers_addr: *mut core::ffi::c_void) -> Option<Range<usize>> {
    let header = unsafe { ptr::read::<IMAGE_NT_HEADERS>(nt_headers_addr as *const _) };
    if header.Signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    let iat = header
        .OptionalHeader
        .DataDirectory
        .get(IMAGE_DIRECTORY_ENTRY_IAT as usize)?;

    Some(iat.VirtualAddress as usize..iat.VirtualAddress as usize + iat.Size as usize)
}

#[inline]
pub fn detour_is_imported<T>(address: *const T, target: *const T) -> bool {
    let mut mbi = unsafe { std::mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
    if (unsafe {
        VirtualQuery(
            address as *const _,
            &mut mbi as *mut _,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    }) == 0
    {
        return false;
    }
    let header = unsafe { ptr::read::<IMAGE_DOS_HEADER>(mbi.AllocationBase as *const _) };
    if header.e_magic != IMAGE_DOS_SIGNATURE {
        return false;
    }
    let Some(range) = (unsafe { get_iat_range(mbi.AllocationBase.add(header.e_lfanew as usize)) })
    else {
        return false;
    };
    if !range.contains(&(target as usize).saturating_sub(mbi.AllocationBase as usize)) {
        return false;
    }
    true
}

#[inline]
pub fn detour_skip_jmp(mut inst: Instruction) -> usize {
    let mut code = inst.ip() as usize;

    if inst.code() == Code::Jmp_rm32 {
        let target = inst.memory_displacement32() as usize;
        if detour_is_imported(
            code as *const core::ffi::c_void,
            target as *const core::ffi::c_void,
        ) {
            // maybe out of mem bounds
            inst = unsafe { inst::decode_instruction::<2>(target) };
            code = target;
        }
    }

    if inst.code() == Code::Jmp_rel8_32 {
        code = inst.memory_displacement32() as usize;
        let code_original = code;

        let inst = unsafe { inst::decode_instruction::<6>(code) };
        if inst.code() == Code::Jmp_rm32 {
            let target = inst.memory_displacement32() as usize;
            if detour_is_imported(
                code as *const core::ffi::c_void,
                target as *const core::ffi::c_void,
            ) {
                // maybe out of mem bounds
                code = target;
            }
        } else if inst.code() == Jmp_rel32_32 {
            code = inst.memory_displacement32() as usize;
            let inst = unsafe { inst::decode_instruction::<6>(code) };
            if inst.code() == Code::Jmp_rm32 {
                if inst.memory_displacement32() as usize == code.saturating_add(0x1000) {
                    code = code_original;
                }
            }
        }
    }

    code
}

#[inline]
pub fn detour_find_jmp_bounds(inst: &Instruction) -> RangeInclusive<usize> {
    let code = inst.ip() as usize;
    let mut lo = detour_2gb_below(code);
    let mut hi = detour_2gb_above(code);
    if inst.code() == Jmp_rel32_32 {
        let new = inst.memory_displacement32() as usize;
        if new < code {
            hi = detour_2gb_above(new);
        } else {
            lo = detour_2gb_below(new);
        }
    }
    lo..=hi
}

#[inline]
pub fn detour_gen_jmp_immediate(pb_code: *mut u8, pb_jmp_val: *mut u8) {
    let pb_jmp_src = pb_code.wrapping_byte_add(X86_JMP_SIZE);
    unsafe {
        *pb_code = 0xe9;
        ptr::write(
            pb_code.wrapping_byte_add(1).cast::<i32>(),
            (pb_jmp_val as i32) - pb_jmp_src as i32,
        );
    }
}
