//! 线程挂起 / 上下文修正原语。
//!
//! 事务提交时需要在「所有可能执行目标函数的线程都已停住」的前提下改写代码，
//! 并且要把这些线程的指令指针从被改写的代码区重定向到对应新位置（或反向），
//! 否则恢复执行的线程会执行到被改写了一半的指令。
//!
//! 只有 Windows 有真实实现；其他平台为安全占位（返回不支持 / 空操作），
//! 语义上与 C++ Detours 只在 Windows 提供该能力一致。

#[cfg(not(target_os = "windows"))]
use std::ffi::c_void;

/// 不透明线程句柄。
///
/// Windows 下即 `HANDLE`；其他平台为 `()`，仅用于保持签名统一。
#[cfg(target_os = "windows")]
pub type ThreadHandle = windows_sys::Win32::Foundation::HANDLE;

#[cfg(not(target_os = "windows"))]
pub type ThreadHandle = *mut c_void;

/// 取得当前线程句柄（用于与 `update_thread` 的参数比较）。
#[cfg(target_os = "windows")]
pub fn current_thread_handle() -> ThreadHandle {
    use windows_sys::Win32::System::Threading::GetCurrentThread;
    unsafe { GetCurrentThread() }
}

#[cfg(not(target_os = "windows"))]
pub fn current_thread_handle() -> ThreadHandle {
    std::ptr::null_mut()
}

/// 挂起指定线程。返回挂起前的挂起计数。
#[cfg(target_os = "windows")]
pub fn suspend_thread(thread: ThreadHandle) -> Option<u32> {
    use windows_sys::Win32::System::Threading::SuspendThread;
    let prev = unsafe { SuspendThread(thread) };
    // (DWORD)-1 表示失败。
    (prev != u32::MAX).then_some(prev)
}

#[cfg(not(target_os = "windows"))]
pub fn suspend_thread(_thread: ThreadHandle) -> Option<u32> {
    None
}

/// 恢复指定线程。
#[cfg(target_os = "windows")]
pub fn resume_thread(thread: ThreadHandle) {
    use windows_sys::Win32::System::Threading::ResumeThread;
    // 失败也无能为力，调用方无法补救，故不返回错误。
    unsafe { ResumeThread(thread) };
}

#[cfg(not(target_os = "windows"))]
pub fn resume_thread(_thread: ThreadHandle) {}

/// 读取线程当前的指令指针（x64 为 `Rip`）。
///
/// `CONTEXT` 的 flag 常量在 windows-sys 里带架构后缀，需按目标架构选择。
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod ctx_flags {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        CONTEXT_CONTROL_AMD64, CONTEXT_FLAGS, CONTEXT_INTEGER_AMD64,
    };

    pub const FLAGS: CONTEXT_FLAGS = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64;
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub fn get_thread_ip(thread: ThreadHandle) -> Option<usize> {
    use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT, GetThreadContext};

    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.ContextFlags = ctx_flags::FLAGS;
    if unsafe { GetThreadContext(thread, &mut ctx) } == 0 {
        return None;
    }
    Some(ctx.Rip as usize)
}

/// 写入线程的指令指针，返回是否成功。
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub fn set_thread_ip(thread: ThreadHandle, ip: usize) -> bool {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        CONTEXT, GetThreadContext, SetThreadContext,
    };

    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.ContextFlags = ctx_flags::FLAGS;
    if unsafe { GetThreadContext(thread, &mut ctx) } == 0 {
        return false;
    }
    ctx.Rip = ip as u64;
    (unsafe { SetThreadContext(thread, &ctx) }) != 0
}

#[cfg(all(target_os = "windows", target_arch = "x86"))]
mod ctx_flags {
    use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT_CONTROL_X86, CONTEXT_FLAGS};

    pub const FLAGS: CONTEXT_FLAGS = CONTEXT_CONTROL_X86;
}

/// 读取线程当前的指令指针（32 位 `Eip`）。
#[cfg(all(target_os = "windows", target_arch = "x86"))]
pub fn get_thread_ip(thread: ThreadHandle) -> Option<usize> {
    use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT, GetThreadContext};

    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.ContextFlags = ctx_flags::FLAGS;
    if unsafe { GetThreadContext(thread, &mut ctx) } == 0 {
        return None;
    }
    Some(ctx.Eip as usize)
}

/// 写入线程的指令指针（32 位），返回是否成功。
#[cfg(all(target_os = "windows", target_arch = "x86"))]
pub fn set_thread_ip(thread: ThreadHandle, ip: usize) -> bool {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        CONTEXT, GetThreadContext, SetThreadContext,
    };

    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.ContextFlags = ctx_flags::FLAGS;
    if unsafe { GetThreadContext(thread, &mut ctx) } == 0 {
        return false;
    }
    ctx.Eip = ip as u32;
    (unsafe { SetThreadContext(thread, &ctx) }) != 0
}

#[cfg(not(all(
    target_os = "windows",
    any(target_arch = "x86", target_arch = "x86_64")
)))]
pub fn get_thread_ip(_thread: ThreadHandle) -> Option<usize> {
    None
}

#[cfg(not(all(
    target_os = "windows",
    any(target_arch = "x86", target_arch = "x86_64")
)))]
pub fn set_thread_ip(_thread: ThreadHandle, _ip: usize) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_windows_thread_ops_are_inert() {
        #[cfg(not(target_os = "windows"))]
        {
            let h = std::ptr::null_mut();
            assert_eq!(suspend_thread(h), None, "非 Windows 平台不应声称挂起成功");
            assert_eq!(get_thread_ip(h), None);
            assert!(!set_thread_ip(h, 0x1000));
            // resume 是空操作，不应 panic
            resume_thread(h);
        }
    }
}
