use crate::Error;
use crate::inst::Disassembler;
use crate::platform::comm::{MemoryAllocType, MemoryBasicInfo, PageProtectionFlag};
#[cfg(target_arch = "aarch64")]
use capstone::arch::arm64::Arm64Reg::ARM64_REG_X16;
use std::ffi::c_void;
use std::ops::Range;
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_DYNAMIC_CODE_BLOCKED, GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_IAT;
#[cfg(target_pointer_width = "32")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
#[cfg(target_pointer_width = "64")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_FREE, MEM_RELEASE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree, VirtualProtect, VirtualQuery,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

pub const MEM_TYPE_COMMIT: MemoryAllocType = MEM_COMMIT;
pub const MEM_TYPE_FREE: MemoryAllocType = MEM_FREE;
pub const MEM_TYPE_RESERVE: MemoryAllocType = MEM_RESERVE;

pub const PAGE_FLAG_EXECUTE_READWRITE: PageProtectionFlag = PAGE_EXECUTE_READWRITE;
pub const PAGE_FLAG_EXECUTE_READ: PageProtectionFlag = PAGE_EXECUTE_READ;

pub fn vquery(addr: *const c_void) -> Option<MemoryBasicInfo> {
    let mut mbi = unsafe { std::mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
    if (unsafe {
        VirtualQuery(
            addr,
            &mut mbi as *mut _,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    }) == 0
    {
        return None;
    }

    Some(MemoryBasicInfo {
        base_address: mbi.BaseAddress,
        allocation_base: mbi.AllocationBase,
        region_size: mbi.RegionSize,
        state: mbi.State,
    })
}

pub fn vprotect<T>(
    addr: *const T,
    size: usize,
    flag: PageProtectionFlag,
) -> Result<PageProtectionFlag, Error> {
    let mut out_flag = 0;
    if (unsafe { VirtualProtect(addr.cast(), size, flag, &mut out_flag) }) == 0 {
        Err(Error::ErrorCode(unsafe { GetLastError() as usize }))
    } else {
        Ok(out_flag)
    }
}

pub fn valloc(
    addr: *const c_void,
    size: usize,
    alloc_type: MemoryAllocType,
) -> Option<*const c_void> {
    let ptr = unsafe { VirtualAlloc(addr as *const _, size, alloc_type, PAGE_EXECUTE_READWRITE) };
    if ptr.is_null() {
        return None;
    }
    Some(ptr)
}

/// 释放 `VirtualAlloc` 保留的整个区域。
///
/// `size` 在这里不使用：`MEM_RELEASE` 要求 size 为 0 且释放整块保留区，
/// 参数保留是为了与其他平台（macOS 需要真实长度）签名一致。
pub fn vfree(addr: *mut c_void, _size: usize) -> Result<(), Error> {
    // MEM_RELEASE 才是「解除映射」的 flag（MEM_FREE 是 VirtualQuery 的状态值，
    // 误用它会让 VirtualFree 直接失败，trampoline 区域永远不会真正释放）。
    if (unsafe { VirtualFree(addr, 0, MEM_RELEASE) }) == 0 {
        Err(Error::ErrorCode(unsafe { GetLastError() as usize }))
    } else {
        Ok(())
    }
}

pub fn get_current_process() -> *const c_void {
    unsafe { GetCurrentProcess() }
}

pub fn flush_instruction_cache(
    process: *const c_void,
    addr: *const c_void,
    size: usize,
) -> Result<(), Error> {
    if (unsafe { FlushInstructionCache(process as HANDLE, addr, size) }) != 0 {
        Ok(())
    } else {
        Err(Error::ErrorCode(unsafe { GetLastError() as usize }))
    }
}

pub fn check_dynamic_code_blocked() -> bool {
    (unsafe { GetLastError() }) == ERROR_DYNAMIC_CODE_BLOCKED
}

#[inline]
unsafe fn get_iat_range(nt_headers_addr: *mut c_void) -> Option<Range<usize>> {
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

#[cfg(target_arch = "x86")]
pub fn detour_skip_jmp(dis: &mut Disassembler, addr: usize) -> usize {
    let Some(mut inst) = dis.disasm_one(addr) else {
        return addr;
    };
    if !inst.is_jmp() {
        return addr;
    }

    if let Some(m) = inst.jmp_rm(dis) {
        if detour_is_imported(
            inst.addr() as *const core::ffi::c_void,
            m as *const core::ffi::c_void,
        ) {
            let Some(i) = dis.disasm_one(m) else {
                return addr;
            };
            inst = i;
        }
    }

    let Some((bit, imm)) = inst.jmp_imm(dis) else {
        return addr;
    };
    if bit == 8 {
        let code_original = imm;

        let Some(inst) = dis.disasm_one(imm) else {
            return addr;
        };
        if !inst.is_jmp() {
            return addr;
        }

        if let Some(m) = inst.jmp_rm(dis) {
            if detour_is_imported(imm as *const c_void, m as *const c_void) {
                return m;
            }
        } else if let Some((bit, imm)) = inst.jmp_imm(dis) {
            if bit != 32 {
                return addr;
            }
            let cmp_addr = imm + 0x1000;
            let Some(inst) = dis.disasm_one(imm) else {
                return addr;
            };
            if let Some(m) = inst.jmp_rm(dis) {
                if m == cmp_addr {
                    return code_original;
                }
            }
        }
    }

    addr
}

#[cfg(target_arch = "x86_64")]
pub fn detour_skip_jmp(_dis: &mut Disassembler, addr: usize) -> usize {
    #[inline]
    fn read_u8(p: usize) -> u8 {
        unsafe { ptr::read_unaligned(p as *const u8) }
    }

    #[inline]
    fn read_i32(p: usize) -> i32 {
        unsafe { ptr::read_unaligned(p as *const i32) }
    }

    #[inline]
    fn read_ptr(p: usize) -> usize {
        unsafe { ptr::read_unaligned(p as *const usize) }
    }

    /// `jmp [rip+disp32]` 的解析目标（IAT 槽位）。
    #[inline]
    fn jmp_rip_target(p: usize) -> usize {
        (p as i64 + 6 + read_i32(p + 2) as i64) as usize
    }

    if addr == 0 {
        return addr;
    }

    let mut pb_code = addr;

    // 先跳过 import 向量表跳转：jmp [rip+disp32] → IAT 槽位中的真实函数地址。
    if read_u8(pb_code) == 0xff && read_u8(pb_code + 1) == 0x25 {
        let pb_target = jmp_rip_target(pb_code);
        if detour_is_imported(pb_code as *const c_void, pb_target as *const c_void) {
            pb_code = read_ptr(pb_target);
        }
    }

    // 再跳过 patch 短跳：jmp rel8。
    if read_u8(pb_code) == 0xeb {
        pb_code = (pb_code as i64 + 2 + read_u8(pb_code + 1) as i8 as i64) as usize;
        let pb_code_original = pb_code;

        if read_u8(pb_code) == 0xff && read_u8(pb_code + 1) == 0x25 {
            let pb_target = jmp_rip_target(pb_code);
            if detour_is_imported(pb_code as *const c_void, pb_target as *const c_void) {
                pb_code = read_ptr(pb_target);
            }
        } else if read_u8(pb_code) == 0xe9 {
            pb_code = (pb_code as i64 + 5 + read_i32(pb_code + 1) as i64) as usize;

            // 系统热补丁（HPAT）会跳到 `ip + PAGE_SIZE - 6` 处的 `jmp [rip+0xffa]`。
            // 这种情况要在长跳本体处下钩子（那里才有足够 5 字节），而不是短跳目标。
            if read_u8(pb_code) == 0xff
                && read_u8(pb_code + 1) == 0x25
                && read_i32(pb_code + 2) == 0xffa
            {
                pb_code = pb_code_original;
            }
        }
    }

    pb_code
}

#[cfg(target_arch = "aarch64")]
pub fn detour_skip_jmp(dis: &mut Disassembler, addr: usize) -> usize {
    let Some(adrp) = dis.disasm_one(addr) else {
        return addr;
    };
    if adrp.id().0 != capstone::arch::arm64::Arm64Insn::ARM64_INS_ADRP as u32 {
        return addr;
    }
    if !adrp.has_reg(ARM64_REG_X16 as u16, &dis) {
        return addr;
    }
    let Some(ldr) = dis.next() else {
        return addr;
    };
    if adrp.id().0 != capstone::arch::arm64::Arm64Insn::ARM64_INS_LDR as u32 {
        return addr;
    }
    if !ldr.has_reg(ARM64_REG_X16 as u16, &dis) {
        return addr;
    }
    let Some(br) = dis.next() else {
        return addr;
    };
    if adrp.id().0 != capstone::arch::arm64::Arm64Insn::ARM64_INS_BR as u32 {
        return addr;
    }
    if !br.has_reg(ARM64_REG_X16 as u16, &dis) {
        return addr;
    }
    let Some(target) = adrp.disp(&dis).and_then(|a| ldr.disp(&dis).map(|x| a + x)) else {
        return addr;
    };
    if detour_is_imported(addr as *const c_void, target as *const c_void) {
        return target;
    }
    addr
}
