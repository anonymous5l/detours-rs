use crate::ext::Pointer;
use crate::mem::{Block, DETOUR_REGION_SIZE, Regions};
use crate::platform::{NEEDED_BYTES, PAGE_FLAG_EXECUTE_READWRITE, detour_gen_jmp_immediate};
use crate::platform::{VirtualProtectGuard, detour_skip_jmp};
use crate::{Error, inst};
use fnv::FnvHashMap;
use std::ffi::c_void;
use std::ops::Deref;
use std::ptr;

pub struct Detours {
    regions: Regions<BLOCK_COUNT>,
    detours: FnvHashMap<usize, Detour>,
}

impl Detours {
    pub fn new() -> Detours {
        Detours {
            regions: Regions::new(),
            detours: FnvHashMap::default(),
        }
    }

    pub fn get(&self, address: &usize) -> Option<&Detour> {
        self.detours.get(&address)
    }

    pub fn lock(&mut self) -> Result<DetoursGuard<'_>, Error> {
        DetoursGuard::new(self)
    }
}

impl Drop for Detours {
    fn drop(&mut self) {
        let Ok(mut guard) = DetoursGuard::new(self) else {
            return;
        };
        guard.detach_all();
    }
}

const PREFETCH_INST_SIZE: usize = 0x20;

const BLOCK_COUNT: usize = DETOUR_REGION_SIZE / size_of::<Trampoline>();

#[repr(C)]
pub struct Trampoline([u8; PREFETCH_INST_SIZE]);

pub struct Detour {
    target: usize,
    fetch: usize,
    block: Block<Trampoline>,
}

impl Detour {
    pub(crate) fn patch(
        target: *const c_void,
        detour: *const c_void,
        block: Block<Trampoline>,
    ) -> Result<Detour, Error> {
        let mut fetch: usize = 0;

        let mut decoder = inst::decoder_with_size(target, PREFETCH_INST_SIZE);
        for inst in decoder.iter() {
            // FIXME depends arch find ret, jmp branch before accumulate then check NEEDED_BYTES is requirement
            fetch += inst.len();
            if fetch >= NEEDED_BYTES {
                break;
            }
        }

        let rb_code = (block.as_ref() as *const Trampoline).cast_mut();

        unsafe {
            ptr::copy(target.cast::<u8>(), rb_code.cast(), fetch);
        }

        let rb_code = rb_code.wrapping_byte_add(fetch);

        detour_gen_jmp_immediate(rb_code.cast(), target.wrapping_byte_add(fetch) as *mut _);

        let _guard_origin = VirtualProtectGuard::guard(target, fetch, PAGE_FLAG_EXECUTE_READWRITE)?;

        detour_gen_jmp_immediate(target as *mut _, detour as *mut _);

        Ok(Detour {
            target: target.addr(),
            block,
            fetch,
        })
    }

    pub fn trampoline<T>(&self) -> &T {
        unsafe { std::mem::transmute::<_, &T>(&self.block.as_ref()) }
    }
}

pub struct DetoursGuard<'a> {
    detours: &'a mut Detours,
}

impl DetoursGuard<'_> {
    fn new(detours: &'_ mut Detours) -> Result<DetoursGuard, Error> {
        detours.regions.unlock()?;
        Ok(DetoursGuard { detours })
    }

    pub(crate) fn internal_detach(regions: &mut Regions<BLOCK_COUNT>, detour: &mut Detour) {
        let target = unsafe { std::mem::transmute::<_, &mut ()>(detour.target) };

        let Ok(_guard_origin) =
            VirtualProtectGuard::guard(target, detour.fetch, PAGE_FLAG_EXECUTE_READWRITE)
        else {
            return;
        };

        unsafe {
            ptr::copy(
                (detour.block.as_ref() as *const Trampoline).cast_mut(),
                (target as *mut ()).cast(),
                detour.fetch,
            );
        }

        regions.free_block(&mut detour.block);
    }

    pub fn attach_ptr<const ADDR: usize, T>(
        &mut self,
        target: Pointer<ADDR, T>,
        detour: *const c_void,
    ) -> Result<(), Error> {
        self.attach(unsafe { std::mem::transmute(target.raw_addr()) }, detour)
    }

    pub fn attach(&mut self, target: *const c_void, detour: *const c_void) -> Result<(), Error> {
        if target.is_null() || detour.is_null() {
            return Err(Error::InvalidAddress);
        }

        let target = detour_skip_jmp(inst::decoder(target).decode()) as *const c_void;
        let detour = detour_skip_jmp(inst::decoder(detour).decode()) as *const c_void;

        if target.addr() == detour.addr() {
            return Err(Error::InvalidAddress);
        }

        let target_addr = target.addr();

        self.detach(&target_addr);

        let Some(block) = self.detours.regions.alloc_block(target.cast()) else {
            return Err(Error::NotEnoughMemory);
        };

        let detour = Detour::patch(target, detour, block);
        self.detours.detours.insert(target.addr(), detour?);
        Ok(())
    }

    pub fn detach(&mut self, address: &usize) {
        if let Some(mut detour) = self.detours.detours.remove(&address) {
            DetoursGuard::internal_detach(&mut self.detours.regions, &mut detour);
        }
    }

    pub(crate) fn detach_all(&mut self) {
        std::mem::replace(&mut self.detours.detours, FnvHashMap::default())
            .into_values()
            .for_each(|mut x| DetoursGuard::internal_detach(&mut self.detours.regions, &mut x));
    }
}

impl Drop for DetoursGuard<'_> {
    fn drop(&mut self) {
        let _ = self.detours.regions.lock();
    }
}
