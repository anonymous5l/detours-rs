use crate::Error;
use crate::platform::vprotect;
use std::ffi::c_void;

pub type MemoryAllocType = u32;
pub type PageProtectionFlag = u32;

pub struct MemoryBasicInfo {
    pub base_address: *const c_void,
    pub allocation_base: *const c_void,
    pub region_size: usize,
    pub state: MemoryAllocType,
}

pub struct VirtualProtectGuard<T> {
    addr: *const T,
    size: usize,
    restore: PageProtectionFlag,
}

impl<T> VirtualProtectGuard<T> {
    pub fn guard(
        addr: *const T,
        size: usize,
        flag: PageProtectionFlag,
    ) -> Result<VirtualProtectGuard<T>, Error> {
        let restore = vprotect(addr, size, flag)?;
        Ok(VirtualProtectGuard {
            addr,
            size,
            restore,
        })
    }
}

impl<T> Drop for VirtualProtectGuard<T> {
    fn drop(&mut self) {
        let _ = vprotect(self.addr, self.size, self.restore);
    }
}
