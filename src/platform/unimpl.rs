use crate::Error;
use crate::platform::comm::{MemoryAllocType, MemoryBasicInfo, PageProtectionFlag};
use iced_x86::Instruction;
use std::ffi::c_void;
use std::ops::RangeInclusive;

pub const MEM_TYPE_COMMIT: MemoryAllocType = 0;
pub const MEM_TYPE_FREE: MemoryAllocType = 0;
pub const MEM_TYPE_RESERVE: MemoryAllocType = 0;

pub const PAGE_FLAG_EXECUTE_READWRITE: PageProtectionFlag = 0;
pub const PAGE_FLAG_EXECUTE_READ: PageProtectionFlag = 0;

pub fn vquery(_addr: *const c_void) -> Option<MemoryBasicInfo> {
    unimplemented!()
}

pub fn vprotect<T>(
    _addr: *const T,
    _size: usize,
    _flag: PageProtectionFlag,
) -> Result<PageProtectionFlag, Error> {
    unimplemented!()
}

pub fn valloc(
    _addr: *const c_void,
    _size: usize,
    _alloc_type: MemoryAllocType,
) -> Option<*const c_void> {
    unimplemented!()
}

pub fn vfree(_addr: *mut c_void) -> Result<(), Error> {
    unimplemented!()
}

pub const NEEDED_BYTES: usize = 0;

pub fn detour_gen_jmp_immediate(_pb_code: *mut u8, _pb_jmp_val: *mut u8) {
    unimplemented!()
}

pub fn detour_find_jmp_bounds(_inst: &Instruction) -> RangeInclusive<usize> {
    unimplemented!()
}

pub fn detour_skip_jmp(_inst: Instruction) -> usize {
    unimplemented!()
}
