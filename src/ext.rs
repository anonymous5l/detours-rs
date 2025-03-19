use crate::platform::windows::{PAGE_FLAG_EXECUTE_READWRITE, VirtualProtectGuard};
use std::ops::{Deref, DerefMut};
use std::ptr;

#[macro_export]
macro_rules! transmute_void {
    ($v:ident, $ty:ty) => {
        unsafe { std::mem::transmute::<$ty, *const std::ffi::c_void>($v) }
    };
    ($v:ident) => {
        unsafe { std::mem::transmute::<_, *const std::ffi::c_void>($v) }
    };
}

// ptr -> ptr -> T
#[derive(Clone)]
pub struct FunctionPointer<const ADDR: usize, T: 'static>(&'static *const T);

impl<const ADDR: usize, T: 'static> FunctionPointer<ADDR, T> {
    pub const fn new() -> FunctionPointer<ADDR, T> {
        FunctionPointer(unsafe { std::mem::transmute(&ADDR) })
    }

    pub const fn addr(&self) -> usize {
        ADDR
    }
}
impl<const ADDR: usize, T> Deref for FunctionPointer<ADDR, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { std::mem::transmute(self.0) }
    }
}

// ptr -> ptr -> ptr -> T
#[repr(transparent)]
#[derive(Clone)]
pub struct DoublePointer<const ADDR: usize, T: 'static>(&'static *const *mut T);

impl<const ADDR: usize, T: 'static> DoublePointer<ADDR, T> {
    pub const fn new() -> DoublePointer<ADDR, T> {
        DoublePointer(unsafe { std::mem::transmute(&ADDR) })
    }

    pub const fn addr(&self) -> usize {
        ADDR
    }
}

impl<const ADDR: usize, T> Deref for DoublePointer<ADDR, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { std::mem::transmute(**self.0) }
    }
}

impl<const ADDR: usize, T> DerefMut for DoublePointer<ADDR, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::mem::transmute(**self.0) }
    }
}

// ptr -> T
#[repr(transparent)]
#[derive(Clone)]
pub struct Pointer<const ADDR: usize, T: 'static>(&'static *mut T);

impl<const ADDR: usize, T: 'static> Pointer<ADDR, T> {
    pub const fn new() -> Pointer<ADDR, T> {
        Pointer(unsafe { std::mem::transmute(&ADDR) })
    }

    pub const fn addr(&self) -> usize {
        ADDR
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

pub fn write<T: Sized>(ptr: usize, data: T) {
    let _guard =
        VirtualProtectGuard::guard(ptr as *const T, size_of::<T>(), PAGE_FLAG_EXECUTE_READWRITE);
    unsafe { ptr::write(ptr as *mut T, data) }
}

pub fn read<T: Sized>(ptr: usize) -> T {
    unsafe { ptr::read::<T>(ptr as *const T) }
}
