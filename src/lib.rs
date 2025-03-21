//! Pure rust version `Detours` library currently only supported windows platform and arch x86
//!
//! # Example
//!
//! As DLL hook address function
//!
//! use detours_rs::ext::Pointer;
//! use detours_rs::{Detours, transmute_void};
//! use parking_lot::RwLock;
//! use std::ffi::c_void;
//! use std::sync::OnceLock;
//! use windows_sys::Win32::Foundation::HINSTANCE;
//! use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
//!
//! static DETOURS: OnceLock<RwLock<Detours>> = OnceLock::new();
//!
//! struct HookStruct;
//!
//! type FuncHook = extern "thiscall" fn(&HookStruct);
//!
//! const FUNC_HOOK_PTR: Pointer<0x123456, FuncHook> = Pointer::new_ref();
//!
//! #[allow(non_snake_case)]
//! extern "thiscall" fn DetourHook(this: &HookStruct) {
//!     let Some(detours) = DETOURS.get() else {
//!         return;
//!     };
//!     let guard = detours.read();
//!     if let Some(detour) = guard.get(&FUNC_HOOK_PTR.addr()) {
//!         detour.trampoline::<FuncHook>()(this);
//!     }
//! }
//!
//! #[unsafe(no_mangle)]
//! #[allow(non_snake_case)]
//! extern "system" fn DllMain(_module: HINSTANCE, call_reason: u32, _reserved: *mut c_void) -> bool {
//!     if call_reason == DLL_PROCESS_ATTACH {
//!         let detours = DETOURS.get_or_init(|| RwLock::new(Detours::new()));
//!         let mut detours_guard = detours.write();
//!         let Ok(mut guard) = detours_guard.lock() else {
//!             return false;
//!         };
//!         guard
//!             .attach_ptr(FUNC_HOOK_PTR, transmute_void!(DetourHook, FuncHook))
//!             .expect("failed");
//!     }
//!     true
//! }
//!

mod detours;
mod error;
mod inst;
#[macro_use]
pub mod ext;
mod mem;
pub use mem::{raw_read, raw_write};
pub(crate) mod platform;

pub use detours::{Detour, Detours, DetoursGuard};
pub use error::Error;
