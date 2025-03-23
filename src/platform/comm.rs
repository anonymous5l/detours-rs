use crate::Error;
use crate::platform::{PAGE_FLAG_EXECUTE_READWRITE, vprotect};
use std::ffi::c_void;
use std::ptr;

pub type MemoryAllocType = u32;
pub type PageProtectionFlag = u32;

pub struct MemoryBasicInfo {
    pub base_address: *const c_void,
    pub allocation_base: *const c_void,
    pub region_size: usize,
    pub state: MemoryAllocType,
}

pub struct MemoryProtector {
    addr: usize,
    size: usize,
    old_flag: PageProtectionFlag,
}

impl MemoryProtector {
    pub fn new(addr: usize, size: usize) -> Result<MemoryProtector, Error> {
        vprotect(addr as *const c_void, size, PAGE_FLAG_EXECUTE_READWRITE).map(|old_flag| {
            MemoryProtector {
                addr,
                size,
                old_flag,
            }
        })
    }

    pub fn new_with<T: Sized>(addr: usize) -> Result<MemoryProtector, Error> {
        Self::new(addr, size_of::<T>())
    }

    pub fn write_override<T>(&mut self, value: T) -> usize {
        let t_size = size_of_val(&value);
        if t_size > self.size {
            return 0;
        }
        unsafe {
            ptr::write(self.addr as *mut T, value);
        }
        t_size
    }

    pub unsafe fn write_from_with_size<T>(&mut self, from: *const T, size: usize) -> usize {
        unsafe { ptr::copy(from, self.addr as *mut T, size) };
        size
    }
}

impl Drop for MemoryProtector {
    fn drop(&mut self) {
        let _ = vprotect(self.addr as *const c_void, self.size, self.old_flag);
    }
}
