use crate::platform::{
    MEM_TYPE_COMMIT, MEM_TYPE_FREE, MEM_TYPE_RESERVE, PAGE_FLAG_EXECUTE_READ,
    PAGE_FLAG_EXECUTE_READWRITE, VirtualProtectGuard, valloc, vfree, vprotect, vquery,
};
#[cfg(target_os = "windows")]
use crate::platform::{flush_instruction_cache, get_current_process};
use crate::{Error, inst, platform};
use std::ffi::c_void;
use std::ops::{Range, RangeInclusive};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::{mem, ptr};

pub(crate) const DETOUR_REGION_SIZE: usize = 0x10000;

const SYSTEM_REGION_BOUND: RangeInclusive<usize> = 0x70000000..=0x80000000;

fn detour_alloc_round_down_to_region(pb_try: usize) -> usize {
    let extra = pb_try & (DETOUR_REGION_SIZE - 1);
    if extra != 0 { pb_try - extra } else { pb_try }
}

fn detour_alloc_round_up_to_region(pb_try: usize) -> usize {
    let extra = pb_try & (DETOUR_REGION_SIZE - 1);
    if extra != 0 {
        pb_try + DETOUR_REGION_SIZE - extra
    } else {
        pb_try
    }
}

fn detour_alloc_region_from_hi(range: Range<usize>) -> Option<usize> {
    let mut pb_try = detour_alloc_round_down_to_region(range.end - DETOUR_REGION_SIZE);
    while pb_try > range.start {
        if SYSTEM_REGION_BOUND.contains(&pb_try) {
            pb_try = pb_try - 0x08000000;
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
            pb_try = pb_try - DETOUR_REGION_SIZE;
        } else {
            pb_try = detour_alloc_round_down_to_region(
                mbi.allocation_base.wrapping_byte_sub(DETOUR_REGION_SIZE) as usize,
            );
        }
    }
    None
}

fn detour_alloc_region_from_lo(range: Range<usize>) -> Option<usize> {
    let mut pb_try = detour_alloc_round_up_to_region(range.start);
    while pb_try < range.end {
        if SYSTEM_REGION_BOUND.contains(&pb_try) {
            pb_try = pb_try + 0x08000000;
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
            pb_try = pb_try + DETOUR_REGION_SIZE;
        } else {
            pb_try = detour_alloc_round_up_to_region(
                mbi.base_address.wrapping_byte_add(mbi.region_size) as usize,
            );
        }
    }
    None
}

fn detour_alloc_trampoline_allocate_new(
    target: usize,
    range: &RangeInclusive<usize>,
) -> Option<usize> {
    let mut pb_try = None;

    #[cfg(target_pointer_width = "64")]
    let _ = {
        // Try looking 1GB below or lower.
        if pb_try.is_none() && target > 0x40000000 {
            pb_try = detour_alloc_region_from_hi(*range.start()..target - 0x40000000);
        }
        // Try looking 1GB above or higher.
        if pb_try.is_none() && target < 0xffffffff40000000 {
            pb_try = detour_alloc_region_from_lo(target + 0x40000000..*range.end());
        }
        if pb_try.is_none() && target < 0xffffffff40000000 {
            pb_try = detour_alloc_region_from_lo(target + 0x40000000..*range.end());
        }
        // Try looking 1GB below or higher.
        if pb_try.is_none() && target > 0x40000000 {
            pb_try = detour_alloc_region_from_lo(target - 0x40000000..target);
        }
        // Try looking 1GB above or lower.
        if pb_try.is_none() && target < 0xffffffff40000000 {
            pb_try = detour_alloc_region_from_hi(target..target + 0x40000000);
        }
    };

    // Try anything below.
    if pb_try.is_none() {
        pb_try = detour_alloc_region_from_hi(*range.start()..target);
    }
    // try anything above.
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

impl<T> AsRef<T> for Block<T> {
    fn as_ref(&self) -> &T {
        unsafe { self.0.load(Ordering::Relaxed).as_ref().unwrap() }
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
            let block = Block(AtomicPtr::new(unsafe {
                mem::transmute::<_, *mut T>(self.range.start + index * size_of::<T>())
            }));
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
        let _ = vfree(unsafe { mem::transmute(self.range.start) });
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

    pub fn unlock(&self) -> Result<(), Error> {
        for x in self.regions.iter() {
            vprotect(
                x.range.start as *const (),
                x.range.end,
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

    pub fn alloc_block<T>(&mut self, expect: *const c_void) -> Option<Block<T>> {
        let inst = inst::decoder(expect).decode();
        let bound = platform::detour_find_jmp_bounds(&inst);

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

pub fn raw_write<T: Sized>(ptr: usize, data: T) {
    let _guard =
        VirtualProtectGuard::guard(ptr as *const T, size_of::<T>(), PAGE_FLAG_EXECUTE_READWRITE);
    unsafe { ptr::write(ptr as *mut T, data) }
}

pub fn raw_read<T: Sized>(ptr: usize) -> T {
    unsafe { ptr::read::<T>(ptr as *const T) }
}
