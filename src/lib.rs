//! Pure rust version of Microsoft [Detours]: an inline hook / trampoline library
//! for user-mode Windows on `x86` and `x86_64`.
//!
//! 本 crate 通过改写目标函数开头的几个字节为跳转，把调用重定向到你的函数；
//! 被覆盖的原始指令会被搬移（并重定位）到一块可执行的 trampoline 中，
//! 你可以从 hook 里调用它来执行原逻辑。
//!
//! [Detours]: https://github.com/microsoft/Detours
//!
//! # 快速开始
//!
//! 最短路径是 [`Detours::lock`] + [`DetoursGuard::attach`]，它会**立即**改写
//! 目标代码。仅适用于单线程、或目标函数此刻确定不会被执行的安全时机。
//!
//! ```
//! # use detours_rs::{Detours, Error};
//! # use std::ffi::c_void;
//! # fn demo(detours: &mut Detours, target: *const c_void, hook: *const c_void) -> Result<(), Error> {
//! let mut guard = detours.lock()?;
//! guard.attach(target, hook)?;
//! # Ok(())
//! # }
//! ```
//!
//! # 线程安全（推荐）
//!
//! 改写函数开头的字节不是原子操作。若其他线程此刻正执行到该处，可能取到
//! 「一半旧、一半新」的指令而崩溃。此时应改用事务：
//!
//! ```
//! # use detours_rs::{Detours, Error};
//! # use std::ffi::c_void;
//! # fn demo(
//! #     detours: &mut Detours,
//! #     thread: detours_rs::ThreadHandle,
//! #     other: detours_rs::ThreadHandle,
//! #     target: *const c_void,
//! #     hook: *const c_void,
//! # ) -> Result<(), Error> {
//! let mut tx = detours.transaction()?;
//! tx.update_thread(thread)?;   // 挂起可能执行目标函数的线程（可多次调用）
//! tx.update_thread(other)?;
//! tx.attach(target, hook)?;    // 只登记，不写内存
//! tx.commit()?;                // 统一写入 + 修正线程 IP + 恢复线程
//! # Ok(())
//! # }
//! ```
//!
//! 库**不会**自动枚举进程内线程（与 C++ Detours 一致），必须显式
//! [`update_thread`](DetourTransaction::update_thread)。漏掉的线程在写入瞬间
//! 仍可能执行到被改写的指令。
//!
//! 事务在 `drop` 时若未提交会自动回滚并恢复已挂起的线程，因此用 `?` 提前
//! 返回是安全的：
//!
//! ```
//! # use detours_rs::{Detours, Error};
//! # use std::ffi::c_void;
//! # fn demo(detours: &mut Detours, t: detours_rs::ThreadHandle,
//! #         target: *const c_void, hook: *const c_void) -> Result<(), Error> {
//! let mut tx = detours.transaction()?;
//! tx.update_thread(t)?;
//! tx.attach(target, hook)?;
//! if some_check_fails() {
//!     return Ok(());          // tx 在此 drop：线程被恢复、块被回收
//! }
//! tx.commit()?;
//! # Ok(())
//! # }
//! # fn some_check_fails() -> bool { false }
//! ```
//!
//! 也可以显式放弃：
//!
//! ```
//! # use detours_rs::{Detours, Error};
//! # fn demo(detours: &mut Detours) -> Result<(), Error> {
//! let mut tx = detours.transaction()?;
//! // ... 登记了一些操作，但决定不做
//! tx.abort();
//! # Ok(())
//! # }
//! ```
//!
//! # 从 hook 中调用原函数
//!
//! 被覆盖的原始指令在 trampoline 中，用 [`Detour::trampoline`] 以原函数类型
//! 取回它。通常配合一个全局表，按目标地址查找对应的 detour：
//!
//! ```
//! # use detours_rs::{Detours, Error};
//! # type Func = extern "C" fn(i32) -> i32;
//! # fn demo(detours: &Detours, target_addr: usize, arg: i32) -> Option<i32> {
//! let detour = detours.get(&target_addr)?;
//! let original: &Func = detour.trampoline::<Func>();
//! Some(original(arg))     // 调用原函数
//! # }
//! ```
//!
//! 注意 [`Detour::trampoline`] 不做类型检查，`T` 必须与目标函数的真实签名一致。
//!
//! # 编译期地址：[`Pointer`](ext::Pointer)
//!
//! [`ext::Pointer`] 把地址编码进类型，`const` 上下文即可构造，适合在全局
//! 常量里指向某个已知地址。两种构造方式语义不同：
//!
//! - [`Pointer::new`](ext::Pointer::new) —— 值语义：把 `ADDR` 处的内存本身当作 `T`。
//! - [`Pointer::new_ref`](ext::Pointer::new_ref) —— 指针槽位语义（等价 `void**`）：把 `ADDR` 处
//!   存放的**指针**当作 `T`，即需要先解引用一层才能得到真正的函数地址。
//!   挂 hook 时通常用这个。
//!
//! ```
//! use detours_rs::ext::Pointer;
//!
//! type Func = extern "C" fn(i32) -> i32;
//!
//! // 值语义：0x1234 处的内容就是 Func
//! const SLOT: Pointer<0x1234, Func> = Pointer::new();
//! // 指针槽位：0x1234 处存放的是指向 Func 的指针（(void**)，函数指针槽位）
//! const SLOT_REF: Pointer<0x1234, Func> = Pointer::new_ref();
//!
//! assert_eq!(SLOT.raw_addr(), 0x1234);
//! assert_eq!(SLOT_REF.raw_addr(), 0x1234);
//! ```
//!
//! 配合 [`DetoursGuard::attach_ptr`] 可以直接用 `Pointer` 挂 hook，省去手写
//! `as *const c_void`：
//!
//! ```
//! # use detours_rs::{Detours, Error};
//! # use detours_rs::ext::Pointer;
//! # type Func = extern "C" fn();
//! # fn demo(detours: &mut Detours, hook: *const std::ffi::c_void) -> Result<(), Error> {
//! const TARGET: Pointer<0x1234, Func> = Pointer::new_ref();
//! let mut guard = detours.lock()?;
//! guard.attach_ptr(TARGET, hook)?;
//! # Ok(())
//! # }
//! ```
//!
//! # 原始内存读写
//!
//! 在 hook 里常需要改目标进程内的某个全局变量。[`raw_write`] / [`raw_read`]
//! 绕过页保护读取写入，`Pointer` 上也有对应方法。
//!
//! 下面标 `no_run`：示例描述的是运行期行为，但地址 `0x2000` 在文档测试环境里
//! 并不存在，实际执行会崩溃。
//!
//! ```no_run
//! use detours_rs::ext::Pointer;
//! use detours_rs::{raw_read, raw_write};
//!
//! const GLOBAL: Pointer<0x2000, u32> = Pointer::new();
//!
//! // 直接读写（会自动处理页保护）
//! # fn demo() {
//! let _old: u32 = GLOBAL.raw_read();
//! GLOBAL.raw_write(42u32);
//!
//! // 也可以按地址读写任意类型
//! let _value: u32 = raw_read(0x2000);
//! raw_write(0x2000, 7u32);
//! # }
//! ```
//!
//! [`raw_read`] 不做任何检查，地址无效时会直接崩溃——调用方必须保证地址有效。
//!
//! # 取消 hook
//!
//! [`DetoursGuard::detach`] 以目标地址为键还原原始字节并回收 trampoline：
//!
//! ```
//! # use detours_rs::{Detours, Error};
//! # use std::ffi::c_void;
//! # fn demo(detours: &mut Detours, target: *const c_void) -> Result<(), Error> {
//! let addr = target as usize;
//! let mut guard = detours.lock()?;
//! guard.detach(&addr);        // 若该地址没有 detour 则什么也不做
//! # Ok(())
//! # }
//! ```
//!
//! [`Detours`] 析构时也会还原所有 detour。
//!
//! # 在 DLL 中使用
//!
//! **不要**在 `DllMain` 的 `DLL_PROCESS_ATTACH` 里直接挂 hook：那里持有
//! loader lock，挂起其它线程可能导致死锁。只做初始化，把真正的安装放到
//! 普通线程：
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
//! /// 在普通线程中调用，不要在 `DllMain` 里做 attach。
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
//! # 平台支持
//!
//! 仅有 Windows 提供真实实现；`x86` 与 `x86_64` 已支持，其他架构会在编译期
//! 落到 `not_support_arch!` 的占位分支。线程挂起 / 指令指针修正只有 Windows
//! 有实现，其他平台为安全占位。

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
