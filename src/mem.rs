use crate::Error;
use crate::inst::Disassembler;
#[cfg(target_os = "windows")]
use crate::platform;
use crate::platform::{
    MEM_TYPE_COMMIT, MEM_TYPE_FREE, MEM_TYPE_RESERVE, MemoryProtector, PAGE_FLAG_EXECUTE_READ,
    PAGE_FLAG_EXECUTE_READWRITE, valloc, vfree, vprotect, vquery,
};
#[cfg(target_os = "windows")]
use crate::platform::{flush_instruction_cache, get_current_process};
use std::ffi::c_void;
use std::ops::{Range, RangeInclusive};
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

pub(crate) const DETOUR_REGION_SIZE: usize = 0x10000;

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const SYSTEM_REGION_BOUND: RangeInclusive<usize> = 0x70000000..=0x80000000;

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn detour_alloc_round_down_to_region(pb_try: usize) -> usize {
    let extra = pb_try & (DETOUR_REGION_SIZE - 1);
    if extra != 0 { pb_try - extra } else { pb_try }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn detour_alloc_round_up_to_region(pb_try: usize) -> usize {
    let extra = pb_try & (DETOUR_REGION_SIZE - 1);
    if extra != 0 {
        pb_try + DETOUR_REGION_SIZE - extra
    } else {
        pb_try
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn detour_alloc_region_from_hi(range: Range<usize>) -> Option<usize> {
    let mut pb_try = detour_alloc_round_down_to_region(range.end - DETOUR_REGION_SIZE);
    while pb_try > range.start {
        if SYSTEM_REGION_BOUND.contains(&pb_try) {
            pb_try -= 0x08000000;
            continue;
        }

        let Some(mbi) = vquery(pb_try as *const _) else {
            break;
        };

        if mbi.state == MEM_TYPE_FREE && mbi.region_size >= DETOUR_REGION_SIZE {
            if let Some(pv) = valloc(
                pb_try as *const _,
                DETOUR_REGION_SIZE,
                MEM_TYPE_COMMIT | MEM_TYPE_RESERVE,
            ) {
                #[cfg(target_os = "windows")]
                if platform::check_dynamic_code_blocked() {
                    return None;
                }
                return Some(pv as _);
            }
            pb_try -= DETOUR_REGION_SIZE;
        } else {
            pb_try = detour_alloc_round_down_to_region(
                mbi.allocation_base.wrapping_byte_sub(DETOUR_REGION_SIZE) as usize,
            );
        }
    }
    None
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn detour_alloc_region_from_lo(range: Range<usize>) -> Option<usize> {
    let mut pb_try = detour_alloc_round_up_to_region(range.start);
    while pb_try < range.end {
        if SYSTEM_REGION_BOUND.contains(&pb_try) {
            pb_try += 0x08000000;
            continue;
        }

        let Some(mbi) = vquery(pb_try as *const _) else {
            break;
        };

        if mbi.state == MEM_TYPE_FREE && mbi.region_size >= DETOUR_REGION_SIZE {
            if let Some(pv) = valloc(
                pb_try as *const _,
                DETOUR_REGION_SIZE,
                MEM_TYPE_COMMIT | MEM_TYPE_RESERVE,
            ) {
                #[cfg(target_os = "windows")]
                if platform::check_dynamic_code_blocked() {
                    return None;
                }
                return Some(pv as _);
            }
            pb_try += DETOUR_REGION_SIZE;
        } else {
            pb_try = detour_alloc_round_up_to_region(
                mbi.base_address.wrapping_byte_add(mbi.region_size) as usize,
            );
        }
    }
    None
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn detour_alloc_trampoline_allocate_new(
    target: usize,
    range: &RangeInclusive<usize>,
) -> Option<usize> {
    let mut pb_try = None;

    // 64 位下先在目标 ±1GB 附近试探，尽量贴近目标以保持 ASLR 熵。
    // 顺序对齐 C++ `detour_alloc_trampoline_allocate_new` 的四个尝试。
    #[cfg(target_pointer_width = "64")]
    {
        // 1GB 以下或更低。
        if pb_try.is_none() && target > 0x40000000 {
            pb_try = detour_alloc_region_from_hi(*range.start()..target - 0x40000000);
        }
        // 1GB 以上或更高。
        if pb_try.is_none() && target < 0xffffffff40000000 {
            pb_try = detour_alloc_region_from_lo(target + 0x40000000..*range.end());
        }
        // 1GB 以下或更高。
        if pb_try.is_none() && target > 0x40000000 {
            pb_try = detour_alloc_region_from_lo(target - 0x40000000..target);
        }
        // 1GB 以上或更低。
        if pb_try.is_none() && target < 0xffffffff40000000 {
            pb_try = detour_alloc_region_from_hi(target..target + 0x40000000);
        }
    }

    // 退而求其次：在边界内任意位置找。
    if pb_try.is_none() {
        pb_try = detour_alloc_region_from_hi(*range.start()..target);
    }
    if pb_try.is_none() {
        pb_try = detour_alloc_region_from_lo(target..*range.end());
    }

    pb_try
}

pub struct Block<T>(AtomicPtr<T>);

impl<T> Default for Block<T> {
    fn default() -> Self {
        Self(AtomicPtr::default())
    }
}

/// 克隆只是复制地址句柄——`Block` 本身不拥有内存（内存归属 `Regions`，
/// 由其 `Drop` 统一释放），因此不会造成双重释放。
impl<T> Clone for Block<T> {
    fn clone(&self) -> Self {
        Self(AtomicPtr::new(self.0.load(Ordering::Relaxed)))
    }
}

impl<T> AsRef<T> for Block<T> {
    fn as_ref(&self) -> &T {
        unsafe { self.0.load(Ordering::Relaxed).as_ref().unwrap() }
    }
}

impl<T> AsMut<T> for Block<T> {
    fn as_mut(&mut self) -> &mut T {
        unsafe { self.0.load(Ordering::Relaxed).as_mut().unwrap() }
    }
}

pub struct RegionData<const N: usize> {
    free: Option<usize>,
    range: Range<usize>,
    state: [bool; N],
}

impl<const N: usize> RegionData<N> {
    fn get_free_addr<T>(&self) -> Option<usize> {
        self.free
            .map(|index| self.range.start + index * size_of::<T>())
    }

    fn find_free_index(&self) -> Option<usize> {
        self.state
            .iter()
            .enumerate()
            .find(|(_, b)| !**b)
            .map(|(index, _)| index)
    }

    fn next_free_block<T>(&mut self) -> Option<Block<T>> {
        let block = self.free.take().or(self.find_free_index()).map(|index| {
            let block = Block(AtomicPtr::new(
                (self.range.start + index * size_of::<T>()) as *mut T,
            ));
            self.state[index] = true;
            block
        })?;
        self.free = self.find_free_index();
        Some(block)
    }

    fn free_block<T>(&mut self, block: &mut Block<T>) {
        let addr = block.0.load(Ordering::Relaxed).addr();
        if self.range.contains(&addr) {
            let free = (addr - self.range.start) / size_of::<T>();
            self.state[free] = false;
            self.free.replace(free);
        }
    }
}

impl<const N: usize> Drop for RegionData<N> {
    fn drop(&mut self) {
        // 必须传真实长度：macOS 的 mach_vm_deallocate 传 0 会什么都不释放。
        let _ = vfree(
            self.range.start as *mut c_void,
            self.range.end - self.range.start,
        );
    }
}

// memory layout first chunk is region information then trampoline thunk
pub struct Regions<const N: usize> {
    regions: Vec<RegionData<N>>,
    current: Option<usize>,
}

impl<const N: usize> Regions<N> {
    pub fn new() -> Regions<N> {
        Regions {
            regions: vec![],
            current: None,
        }
    }

    /// 把全部 trampoline 区域改为可读写可执行，供事务期间写入使用。
    pub fn unlock(&self) -> Result<(), Error> {
        for x in self.regions.iter() {
            // 长度必须是 `end - start`；早期误传 `range.end`（绝对地址），
            // 会去改一段远大于本区域的区间，波及无关内存。
            vprotect(
                x.range.start as *const (),
                x.range.end - x.range.start,
                PAGE_FLAG_EXECUTE_READWRITE,
            )?;
        }
        Ok(())
    }

    pub fn lock(&self) -> Result<(), Error> {
        #[cfg(target_os = "windows")]
        let process = get_current_process();
        for x in self.regions.iter() {
            vprotect(
                x.range.start as *const (),
                x.range.end - x.range.start,
                PAGE_FLAG_EXECUTE_READ,
            )?;
            #[cfg(target_os = "windows")]
            flush_instruction_cache(
                process,
                x.range.start as *const c_void,
                x.range.end - x.range.start,
            )?;
        }
        Ok(())
    }

    fn alloc_region(
        &mut self,
        bound: &RangeInclusive<usize>,
        expect: usize,
    ) -> Option<RegionData<N>> {
        let target = expect - (expect & 0xffff);
        let block_ptr = detour_alloc_trampoline_allocate_new(target, bound)?;
        Some(RegionData {
            free: Some(0),
            range: block_ptr..block_ptr + DETOUR_REGION_SIZE,
            state: std::array::from_fn(|_| false),
        })
    }

    #[cfg(target_os = "windows")]
    pub fn alloc_block<T>(
        &mut self,
        dis: &mut Disassembler,
        expect: *const c_void,
    ) -> Option<Block<T>> {
        let inst = dis.disasm_one(expect.addr())?;
        let bound = platform::detour_find_jmp_bounds(dis, &inst);
        self.current
            .and_then(|index| self.regions[index].get_free_addr::<T>().map(|x| (index, x)))
            .and_then(|(index, addr)| {
                if bound.contains(&addr) {
                    Some(index)
                } else {
                    None
                }
            })
            .and_then(|index| self.regions[index].next_free_block::<T>())
            .or_else(|| {
                let region = self.alloc_region(&bound, expect.addr())?;
                self.regions.push(region);
                let index = self.regions.len() - 1;
                self.current = Some(index);
                self.regions[index].next_free_block()
            })
    }

    #[cfg(not(target_os = "windows"))]
    pub fn alloc_block<T>(
        &mut self,
        _dis: &mut Disassembler,
        _expect: *const c_void,
    ) -> Option<Block<T>> {
        let region = valloc(
            std::ptr::null(),
            DETOUR_REGION_SIZE,
            MEM_TYPE_COMMIT | MEM_TYPE_RESERVE,
        )
        .map(|addr| RegionData {
            free: Some(0),
            range: addr.addr()..addr.addr() + DETOUR_REGION_SIZE,
            state: std::array::from_fn(|_| false),
        })?;
        self.regions.push(region);
        let index = self.regions.len() - 1;
        self.current = Some(index);
        self.regions[index].next_free_block()
    }

    pub fn free_block<T>(&mut self, block: &mut Block<T>) -> bool {
        if let Some(region) = self
            .regions
            .iter_mut()
            .find(|x| x.range.contains(&block.0.load(Ordering::Relaxed).addr()))
        {
            region.free_block(block);
            true
        } else {
            false
        }
    }
}

pub fn raw_write<T: Sized>(addr: usize, data: T) -> usize {
    if let Ok(mut guard) = MemoryProtector::new_with::<T>(addr) {
        guard.write_override(data)
    } else {
        0
    }
}

pub fn raw_read<T: Sized>(ptr: usize) -> T {
    unsafe { ptr::read::<T>(ptr as *const T) }
}
