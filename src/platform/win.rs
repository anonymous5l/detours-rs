use crate::Error;
use crate::platform::comm::{MemoryAllocType, MemoryBasicInfo, PageProtectionFlag};
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{ERROR_DYNAMIC_CODE_BLOCKED, GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_FREE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree, VirtualProtect, VirtualQuery,
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

pub fn vfree(addr: *mut c_void) -> Result<(), Error> {
    if (unsafe { VirtualFree(addr, 0, MEM_FREE) }) == 0 {
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
    if (unsafe { GetLastError() }) == ERROR_DYNAMIC_CODE_BLOCKED {
        true
    } else {
        false
    }
}
