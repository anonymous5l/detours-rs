# detours-rs

Microsoft [Detours](https://github.com/microsoft/Detours) 的 Rust 移植：Windows x86 用户态 API Hook 库（inline detour / trampoline）。C++ 参考实现在 `/Users/anonymous/Documents/Projects/CPlusPlus/Detours`（`src/detours.cpp`、`src/disasm.cpp`、`src/disolx86.cpp` 为主要对照点），移植时保持函数与结构语义一一对应，命名沿用 C++ 侧的 `detour_*` 前缀。

## Commands

```bash
cargo check --all-targets          # 日常检查
cargo test                         # 46 个单测 + 2 个 doctest
cargo fmt --check                  # 提交前必须通过
cargo clippy --all-targets         # 已无功能性 warning，不要新增
```

测试能跑在本机 aarch64 上，是因为关键算法（disp32 推算、rel 分支解算、jmp 编码、filler 识别）都抽成了与架构无关的纯函数。**新增重定位/编码逻辑时保持这个结构**，否则测试只能靠 xwin 交叉编译，无法在本机验证行为。

Windows 目标（交叉编译，**改平台层后必须验**）：

```bash
cargo xwin check --target i686-pc-windows-msvc   # x86 主目标，已验证通过
cargo xwin check --target x86_64-pc-windows-msvc # x64，已验证通过
cargo xwin clippy --target x86_64-pc-windows-msvc
cargo check --target i686-pc-windows-gnu         # 备选：mingw 工具链
```

必须走 `cargo xwin`：裸 `cargo check --target <windows-msvc>` 会因 `capstone-sys` 找不到 `stdio.h` 失败（缺 MSVC SDK/CRT），这是依赖的 C 代码要编译，不是 Rust 代码问题。

`aarch64-unknown-linux-gnu` 等目标缺 C 工具链，属预期失败，别试图靠改 Rust 代码修掉。

## Architecture

- `src/lib.rs` — crate 根，导出 `Detours` / `Detour` / `DetourTransaction` / `DetoursGuard` / `Error` / `ThreadHandle` / `raw_read` / `raw_write` / `ext`；定义 `not_support_arch!` 用于落空未支持架构。
- `src/detours.rs` — 核心。两条路径：
  - `Detours::lock()` → `DetoursGuard`：`attach` **立即**改写目标代码。适合单线程场景。
  - `Detours::transaction()` → `DetourTransaction`：`update_thread` / `attach` / `detach` 只登记，`commit` 时才统一写入。对齐 C++ `DetourTransactionBegin/UpdateThread/Commit`。
  `Detour` 保存 target、`fetch`（被覆盖字节数）、`written`（trampoline 实际字节数）、块句柄、detour 地址。`Detour::prepare` 只搬移与备份，`Detour::install` 才写目标——这个拆分是事务能原子提交的前提。
  `Trampoline` 布局按架构分化：x86 只需搬移指令 + `jmp rel32` 回跳；x64 额外带 `remain` / `detour` 两个 8 字节槽位和 `code_in` thunk（`jmp [rip+disp32]`），因为 x64 的 detour 与 target 常超出 rel32 的 ±2GB 范围——目标处先 `jmp rel32` 到同块的 `code_in`，再由它经槽位间接跳转。
  `restore[32]` 保存**被覆盖前的原始字节**，是 detach 的唯一正确来源（`code` 里是重定位后的指令，写回会破坏原函数）。
- `src/mem.rs` — trampoline 内存管理：`Regions` / `RegionData` 按 `DETOUR_REGION_SIZE`(0x10000) 分块，`detour_alloc_trampoline_allocate_new` 在目标 ±2GB 内寻找空闲区以让 rel32 jmp 可达；对应 C++ `creatwth.cpp`。`RegionData::drop` 调 `vfree`，**两平台都必须传真实长度**。
- `src/inst.rs` — 基于 capstone 的 `Disassembler` / `Inst`，架构相关指令判定（`is_jmp` / `is_ret` / `is_end`、`jmp_rm` / `jmp_imm`）用 `const _: () = { ... }` 按 `target_arch` 门控，避免在另一架构下出现无效 import。x86 与 x86_64 共用同一套 `X86Operand` 实现，仅 capstone 的 `ArchMode` 不同（`Mode32` / `Mode64`）。**指令重定位在此实现**：`move_inst()` 搬移单条指令（rel8→rel32 扩宽、RIP 相对重算），`fix_branch()` 第二遍回填位移；`is_code_filler()` 识别 1~11 字节 NOP 与 int3。`Inst` 持有 `OwnedInsn<'static>`——该类型实际自持数据，`'static` 由一处带 SAFETY 注释的 transmute 得到，避免 `Inst` 长期占用 `Disassembler` 的所有权。
- `src/ext.rs` — `Pointer<const ADDR, T>` 编译期地址指针（`new()` / `new_ref()`）与 `transmute_void!` 宏，是公开 API 的主要入口形式。
- `src/platform/` — 平台层，`mod.rs` 按 `target_os` / `target_arch` 组合各文件：
  - `comm.rs`：与架构无关的纯函数（`MemoryProtector`、`clamp_copy_size`、`detour_2gb_*`、`encode_jmp_rel32` / `encode_jmp_rip_indirect`）。
  - `thread.rs`：`suspend_thread` / `resume_thread` / `get_thread_ip` / `set_thread_ip`。**只有 Windows 是真实现**，其他平台为安全占位。
  - `win.rs` / `macos.rs`：OS 内存与模块操作。`x86.rs` / `x64.rs` / `aarch64.rs`：架构相关的 jmp 生成与边界计算。

## Conventions

- `edition = "2024"`：写 unsafe 块必须用 `unsafe { }`，FFI 声明用 `unsafe extern "C"`；`DllMain` 用 `#[unsafe(no_mangle)]`。
- 平台差异优先用 `#[cfg(target_os = ...)]` / `#[cfg(target_arch = ...)]` 在 `platform/` 下增文件，不要在 `detours.rs`、`mem.rs` 里堆分支；`mem.rs` 里仅有的 `cfg` 例外是 `alloc_block`。
- 错误统一走 `src/error.rs` 的 `Error` 枚举，不用 `anyhow`/`thiserror`；平台层把 Win32 `GetLastError()` 包成 `Error::ErrorCode`。
- 新平台/新架构要同时提供 `NEEDED_BYTES`、`detour_gen_jmp_immediate`、`detour_find_jmp_bounds`、`detour_skip_jmp`、`vquery/vprotect/valloc/vfree`，否则 `platform::*` 通配导出会缺符号。x64 额外提供 `detour_gen_jmp_indirect`。
- `detour_gen_jmp_immediate` / `detour_gen_jmp_indirect` 返回写入后的下一个字节地址，便于连续拼接；改动时保持该签名。
- 重定位与线程安全均已实现。与 C++ 仍存的差异：C++ 是逐指令表驱动复制（`disasm.cpp` 里那张庞大 opcode 表），本移植用 capstone 解码 + 语义等价搬移。
- **padding（NOP/int3）只扩大 patch 覆盖范围，不复制进 trampoline**——见 `detours.rs` 里 filler 消费那段。改成复制会让 jmp 踩到未备份代码、detach 无法完整恢复。
- 事务提交时用 `AlignEntry` 表把被挂起线程的 IP 在「target 偏移 ↔ trampoline 偏移」间换算。`Span` 必须分别记录 `target_len`(fetch) 与 `tramp_len`(written)——rel8→rel32 扩宽后两者不等，detach 方向判断 trampoline 区间要用后者，有回归测试守着。
- 内存探针一律通过 `MemoryProtector`（RAII 恢复旧页属性），不要直接 `VirtualProtect` / `mach_vm_protect`。
- 只有 4 处允许 `unwrap()/expect()`（`inst.rs` capstone 构建、`mem.rs` `Block` 的原子指针），新增代码用 `?` + `Error`。
- 改动目标代码必须走 `Detour::install()`（内部用 `MemoryProtector` 并 flush icache），不要自己 `VirtualProtect` 后裸写。
- 新增失败路径时想清楚块归属：`alloc_block` 拿到的 `Block` 若 `prepare`/`install` 失败必须 `free_block` 归还，否则 trampoline 区域泄漏。`commit` 的失败回滚要撤销**已 install** 的改动，不只是未处理的那些。
- 文档示例同时写在 `src/lib.rs` 的 `//!` 和 README，改一个要同步另一个。依赖外部 crate（`parking_lot` / `windows-sys`）的示例用 ` ```text ` 标注，避免被当作 doctest 编译。

## Notes

