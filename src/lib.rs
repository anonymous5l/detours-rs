//! Pure rust version `Detours` library, supports Windows platform on arch x86 and x86_64
//!
//! # 线程安全
//!
//! 改写函数开头的字节不是原子操作。若其他线程此刻正执行到该处，可能取到
//! 「一半旧、一半新」的指令。因此先用 [`Detours::transaction`] 开启事务，
//! 通过 [`DetourTransaction::update_thread`] 显式挂起相关线程，再 `commit` 统一写入。
//! 库**不会**自动枚举线程（与 C++ Detours 一致）。
//!
//! ```
//! # use detours_rs::{Detours, Error};
//! # fn demo(detours: &mut Detours, thread: detours_rs::ThreadHandle,
//! #         target: *const std::ffi::c_void, hook: *const std::ffi::c_void) -> Result<(), Error> {
//! let mut tx = detours.transaction()?;
//! tx.update_thread(thread)?;   // 挂起可能执行目标函数的线程（可多次调用）
//! tx.attach(target, hook)?;    // 只登记，不写内存
//! tx.commit()?;                // 统一写入 + 修正线程 IP + 恢复线程
//! # Ok(())
//! # }
//! ```
//!
//! 事务在 `drop` 时未提交会自动回滚并恢复线程，因此 `?` 提前返回是安全的。
//!
//! # Example
//!
//! 作为 DLL 按地址挂 hook。该示例依赖 `parking_lot` 与 `windows-sys`，
//! 不属于本 crate 的依赖，故标记为 `text` 不参与编译。
//!
//! ```text
//! use detours_rs::ext::Pointer;
//! use detours_rs::{Detours, transmute_void};
//! use parking_lot::RwLock;
//! use std::ffi::c_void;
//! use std::sync::OnceLock;
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
//! /// 在普通线程中调用。**不要**在 `DllMain` 里做 attach——那里持有 loader lock，
//! /// 挂起其它线程可能死锁。
//! fn install(hook_thread: detours_rs::ThreadHandle) -> Result<(), detours_rs::Error> {
//!     let detours = DETOURS.get_or_init(|| RwLock::new(Detours::new()));
//!     let mut detours_guard = detours.write();
//!
//!     let mut tx = detours_guard.transaction()?;
//!     tx.update_thread(hook_thread)?;
//!     tx.attach(
//!         FUNC_HOOK_PTR.raw_addr() as *const c_void,
//!         transmute_void!(DetourHook, FuncHook),
//!     )?;
//!     tx.commit()
//! }
//! ```
//!

#[doc(hidden)]
macro_rules! not_support_arch {
    ($($block:tt)*) => {
        #[cfg(not(any(
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "aarch64"
        )))]
        $($block)*
    };
}

mod detours;
mod error;
mod inst;
#[macro_use]
pub mod ext;
mod mem;
pub use mem::{raw_read, raw_write};
pub(crate) mod platform;

/// 线程句柄，用于 [`DetourTransaction::update_thread`]。
///
/// Windows 下即 `HANDLE`；其他平台为 `()`，仅用于保持签名统一。
pub use platform::ThreadHandle;

pub use detours::{Detour, DetourTransaction, Detours, DetoursGuard};
pub use error::Error;
