## detours-rs

Windows platform x86 / x86_64 hook library

Currently supported: Windows platform with arch x86 and x86_64.

code translate from [Microsoft/Detours](https://github.com/microsoft/Detours)

## 线程安全

改写目标函数开头的几个字节不是原子操作。如果其他线程此刻正执行到这段代码，
可能取到「一半旧、一半新」的指令而崩溃。Detours 的做法是：在事务开启后**显式**
挂起所有可能执行目标函数的线程，写入完成后再恢复，并把停在被改写区间内的
线程指令指针重定向到等价位置。

```rust
use detours_rs::Detours;

// 1) 开启事务
let mut tx = detours.transaction()?;

// 2) 挂起其它线程（每个可能执行目标函数的线程都要调用一次）
tx.update_thread(thread_handle)?;

// 3) 登记操作（此时还不写内存）
tx.attach(target as *const _, hook as *const _)?;

// 4) 统一写入 + 修正线程 IP + 刷新指令缓存 + 恢复线程
tx.commit()?;
```

事务在 `drop` 时若未提交会自动回滚并恢复线程，因此 `?` 提前返回是安全的。

**必须显式调用 `update_thread`**——库不会自动枚举进程内线程（与 C++ Detours
一致）。漏掉某个线程，它在写入瞬间仍可能执行到被改写的指令。

> **不要**在 `DllMain` 里直接做 attach。`DllMain` 持有 loader lock，此时挂起
> 其它线程可能死锁。推荐在初始化完成后，从普通线程里执行事务。

## Example

Hook address

```rust
use detours_rs::ext::Pointer;
use detours_rs::{Detours, transmute_void};
use parking_lot::RwLock;
use std::ffi::c_void;
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::HINSTANCE;
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

static DETOURS: OnceLock<RwLock<Detours>> = OnceLock::new();

struct HookStruct;

type FuncHook = extern "thiscall" fn(&HookStruct);

const FUNC_HOOK_PTR: Pointer<0x123456, FuncHook> = Pointer::new_ref();

#[allow(non_snake_case)]
extern "thiscall" fn DetourHook(this: &HookStruct) {
    let Some(detours) = DETOURS.get() else {
        return;
    };
    let guard = detours.read();
    if let Some(detour) = guard.get(&FUNC_HOOK_PTR.addr()) {
        detour.trampoline::<FuncHook>()(this);
    }
}

/// 在普通线程里调用，不要在 `DllMain` 中调用（见上文「线程安全」）。
fn install(hook_thread: detours_rs::ThreadHandle) -> Result<(), detours_rs::Error> {
    let detours = DETOURS.get_or_init(|| RwLock::new(Detours::new()));
    let mut detours_guard = detours.write();

    let mut tx = detours_guard.transaction()?;
    tx.update_thread(hook_thread)?;
    tx.attach(
        FUNC_HOOK_PTR.raw_addr() as *const c_void,
        transmute_void!(DetourHook, FuncHook),
    )?;
    tx.commit()
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
extern "system" fn DllMain(_module: HINSTANCE, call_reason: u32, _reserved: *mut c_void) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        // 仅做初始化；真正的 hook 安装放到普通线程（见 install）。
        DETOURS.get_or_init(|| RwLock::new(Detours::new()));
    }
    true
}
```
