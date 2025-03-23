use crate::mem::{raw_read, raw_write};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

#[macro_export]
macro_rules! transmute_void {
    ($v:ident, $ty:ty) => {
        unsafe { std::mem::transmute::<$ty, *const std::ffi::c_void>($v) }
    };
    ($v:ident) => {
        unsafe { std::mem::transmute::<_, *const std::ffi::c_void>($v) }
    };
}

#[repr(transparent)]
#[derive(Clone)]
pub struct Pointer<const ADDR: usize, T: 'static>(&'static NonNull<T>);

impl<const ADDR: usize, T: 'static> Default for Pointer<ADDR, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const ADDR: usize, T: 'static> Pointer<ADDR, T> {
    pub const fn new() -> Pointer<ADDR, T> {
        Pointer(unsafe { std::mem::transmute::<&usize, &NonNull<T>>(&ADDR) })
    }

    /// make 'static lifetime ref pointer address
    ///
    /// equals (void**)
    ///
    /// usually use for function pointer
    ///
    pub const fn new_ref() -> Pointer<ADDR, T> {
        Pointer(unsafe { std::mem::transmute::<&&usize, &NonNull<T>>(&&ADDR) })
    }

    pub const fn raw_addr(&self) -> usize {
        ADDR
    }

    /// DO NOT USE THIS FUNCTION IN SELF MEMORY SPACE
    pub fn raw_write(&self, val: T) -> usize {
        self.raw_write_for(val)
    }

    pub fn raw_write_for<F: Sized>(&self, val: F) -> usize {
        raw_write(unsafe { *self.0.as_ptr().cast() }, val)
    }

    pub fn raw_read(&self) -> T {
        self.raw_read_for()
    }

    pub fn raw_read_for<F>(&self) -> F {
        raw_read(unsafe { *self.0.as_ptr().cast() })
    }
}

impl<const ADDR: usize, T> Deref for Pointer<ADDR, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { std::mem::transmute(*self.0) }
    }
}

impl<const ADDR: usize, T> DerefMut for Pointer<ADDR, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::mem::transmute(*self.0) }
    }
}
