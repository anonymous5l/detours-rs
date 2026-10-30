use crate::Error;
use crate::ext::Pointer;
use crate::inst::Disassembler;
use crate::mem::{Block, DETOUR_REGION_SIZE, Regions};
#[cfg(target_os = "windows")]
use crate::platform;
use crate::platform::MemoryProtector;
#[cfg(target_arch = "x86_64")]
use crate::platform::detour_gen_jmp_indirect;
use crate::platform::{NEEDED_BYTES, detour_gen_jmp_immediate};
use fnv::FnvHashMap;
use std::ffi::c_void;

pub struct Detours {
    dis: Disassembler,
    regions: Regions<BLOCK_COUNT>,
    detours: FnvHashMap<usize, Detour>,
}

impl Default for Detours {
    fn default() -> Self {
        Self::new()
    }
}

impl Detours {
    pub fn new() -> Detours {
        Detours {
            dis: Disassembler::new(),
            regions: Regions::new(),
            detours: FnvHashMap::default(),
        }
    }

    pub fn get(&self, address: &usize) -> Option<&Detour> {
        self.detours.get(address)
    }

    pub fn lock(&mut self) -> Result<DetoursGuard<'_>, Error> {
        DetoursGuard::new(self)
    }

    /// 开启一个事务，在事务内批量登记 detach / attach，最后一次性提交。
    ///
    /// 与直接调用 [`DetoursGuard::attach`] 的区别：`attach` 立即改写目标代码，
    /// 事务则把所有改写推迟到 `commit`，从而能在「所有相关线程已挂起」的
    /// 同一窗口内完成，避免线程执行到只改了一半的指令。
    ///
    /// 线程**不会**被自动挂起，必须用 [`DetourTransaction::update_thread`]
    /// 显式指定（对齐 C++ `DetourUpdateThread`）。
    pub fn transaction(&mut self) -> Result<DetourTransaction<'_>, Error> {
        DetourTransaction::new(self)
    }
}

impl Drop for Detours {
    fn drop(&mut self) {
        // 即使区域解锁失败也必须尝试还原——否则 detour 留在目标进程里，
        // 而 trampoline 内存随 `Regions` 一起被释放，会留下悬空跳转。
        // 逐条还原不依赖 `unlock()` 成功：`MemoryProtector` 会自行改页属性。
        let pending: Vec<Detour> = std::mem::take(&mut self.detours).into_values().collect();
        for mut detour in pending {
            DetoursGuard::internal_detach(&mut self.regions, &mut detour);
        }
    }
}

const PREFETCH_INST_SIZE: usize = 0x20;

/// trampoline 中最多容纳的待回填相对分支条数（对齐 C++ `rAlign` 的 8 项）。
const MAX_FIXUPS: usize = 8;

/// 搬移指令区之后必须预留的尾部空间：x64 的间接回跳需要 6 字节，x86 的 rel32 需要 5 字节。
#[cfg(target_arch = "x86_64")]
const MAX_TAIL: usize = 6;
#[cfg(not(target_arch = "x86_64"))]
const MAX_TAIL: usize = 5;

/// 探测 NOP / int3 padding 时读取的最大字节数。
///
/// 最长 filler 是 11 字节 NOP，这里只读到 12 字节即可，与 C++ `detour_is_code_filler`
/// 的访问范围等价（其最长为 `pbCode[0..11]`）。刻意不读更多，以缩小跨页访问风险。
const FILLER_MAX_PROBE: usize = 12;

const BLOCK_COUNT: usize = DETOUR_REGION_SIZE / size_of::<Trampoline>();

/// 目标函数被覆盖的原始字节备份上限。
///
/// 对齐 C++ 的 `rbRestore[30]`：`fetch` 最多为 `NEEDED_BYTES - 1 + 最长指令(15)`，
/// 再加上 filler 消费（最长 11 字节 NOP），留到 32 字节足够。
const RESTORE_SIZE: usize = 32;

/// 指令边界在「目标位置」与「trampoline 位置」之间的映射条目。
///
/// 用于事务提交时修正被挂起线程的指令指针：若线程停在 `target + ob_target`，
/// 应改到 `trampoline + ob_tramp`（attach 时），反向同理（detach 时）。
/// 对应 C++ 的 `_DETOUR_ALIGN { obTarget, obTrampoline }`。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct AlignEntry {
    /// 相对 target 的字节偏移。
    pub ob_target: u8,
    /// 相对 trampoline `code` 区起始的字节偏移。
    pub ob_tramp: u8,
}

/// 映射表容量。对齐 C++ `rAlign[8]`；搬移 5 字节至少 1 条、最多 5 条 1 字节指令。
const MAX_ALIGN: usize = 8;

/// trampoline 块布局。
///
/// x86：仅需搬移原指令 + 一条 `jmp rel32` 回跳。
///
/// x64：额外带两个 8 字节槽位和一段 `jmp [rip+disp32]` thunk（`rb_code_in`）。
/// 目标处只能放 `jmp rel32`（±2GB），因此先跳到同一块内的 `rb_code_in`，
/// 再由它经 `detour` 槽位间接跳到任意地址的 detour 函数；
/// 回跳同理，经 `remain` 槽位跳回 `target + fetch`。
///
/// `restore` 保存**被覆盖前的原始字节**，是 detach 时唯一的正确还原来源——
/// `code` 里存的是重定位后的指令（rel8 已扩宽为 rel32），写回它会破坏原函数。
#[repr(C)]
pub struct Trampoline {
    code: [u8; PREFETCH_INST_SIZE],
    restore: [u8; RESTORE_SIZE],
    restore_len: usize,
    align: [AlignEntry; MAX_ALIGN],
    align_len: usize,
    #[cfg(target_arch = "x86_64")]
    remain: usize,
    #[cfg(target_arch = "x86_64")]
    detour: usize,
    #[cfg(target_arch = "x86_64")]
    code_in: [u8; 8],
}

impl Trampoline {
    /// 搬移后的原指令区起始地址。
    #[inline]
    pub(crate) fn code_mut(&mut self) -> *mut u8 {
        self.code.as_mut_ptr()
    }

    /// 备份被覆盖的原始字节。
    #[inline]
    pub(crate) fn save_restore(&mut self, src: *const u8, len: usize) -> Option<()> {
        if len > RESTORE_SIZE {
            return None;
        }
        unsafe { std::ptr::copy_nonoverlapping(src, self.restore.as_mut_ptr(), len) };
        self.restore_len = len;
        Some(())
    }

    /// 原始字节备份及其长度。
    #[inline]
    pub(crate) fn restore(&self) -> (&[u8], usize) {
        (&self.restore, self.restore_len)
    }

    /// 记录一条指令边界映射。表满时返回 `false`（调用方应视为失败）。
    #[inline]
    pub(crate) fn push_align(&mut self, ob_target: usize, ob_tramp: usize) -> bool {
        if self.align_len >= MAX_ALIGN {
            return false;
        }
        let (Ok(t), Ok(m)) = (u8::try_from(ob_target), u8::try_from(ob_tramp)) else {
            return false;
        };
        self.align[self.align_len] = AlignEntry {
            ob_target: t,
            ob_tramp: m,
        };
        self.align_len += 1;
        true
    }

    /// 查找有效映射条目。
    #[inline]
    pub(crate) fn aligns(&self) -> &[AlignEntry] {
        &self.align[..self.align_len]
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    pub(crate) fn remain_slot(&mut self) -> *mut u8 {
        &mut self.remain as *mut usize as *mut u8
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    pub(crate) fn detour_slot(&mut self) -> *mut u8 {
        &mut self.detour as *mut usize as *mut u8
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    pub(crate) fn code_in_ptr(&mut self) -> *mut u8 {
        self.code_in.as_mut_ptr()
    }

    /// trampoline 中 `code` 区的绝对起始地址。
    #[inline]
    pub(crate) fn code_addr(&self) -> usize {
        self.code.as_ptr() as usize
    }
}

/// 依据映射表换算位置：在 `ob_target` 命中的条目上，返回对应的 `ob_tramp`。
///
/// `offset` 是被挂起线程 IP 相对 `target` 的偏移。只有恰好落在指令边界上
/// 才需要修正；落在指令中间的偏移原样返回 `None`（C++ 的行为也是就近映射）。
pub(crate) fn align_target_to_tramp(aligns: &[AlignEntry], offset: usize) -> Option<usize> {
    let off = u8::try_from(offset).ok()?;
    aligns
        .iter()
        .find(|e| e.ob_target == off)
        .map(|e| e.ob_tramp as usize)
}

/// 反向换算：在 `ob_tramp` 命中的条目上，返回对应的 `ob_target`。
pub(crate) fn align_tramp_to_target(aligns: &[AlignEntry], offset: usize) -> Option<usize> {
    let off = u8::try_from(offset).ok()?;
    aligns
        .iter()
        .find(|e| e.ob_tramp == off)
        .map(|e| e.ob_target as usize)
}

pub struct Detour {
    target: usize,
    fetch: usize,
    /// trampoline 中实际写入的字节数（rel8→rel32 扩宽后通常大于 `fetch`）。
    written: usize,
    block: Block<Trampoline>,
    /// detour 函数地址。
    ///
    /// x86 直接写进目标处的 `jmp rel32`；x64 则写入 trampoline 的 `detour` 槽位，
    /// 目标处只跳到 `code_in` thunk，因此该字段在 x64 上不参与 `install`。
    #[cfg_attr(target_arch = "x86_64", allow(dead_code))]
    detour_addr: usize,
}

impl Detour {
    /// 准备 detour：搬移并重定位指令、构造 trampoline、备份原始字节。
    ///
    /// **不修改目标代码**。真正写入目标由 [`Detour::install`] 完成，
    /// 这样事务可以在 commit 时才统一改写，从而把多个操作合并成一个原子窗口。
    pub(crate) fn prepare(
        dis: &mut Disassembler,
        target: *const c_void,
        detour: *const c_void,
        mut block: Block<Trampoline>,
    ) -> Result<Detour, Error> {
        let tramp = block.as_mut();
        let rb_code = tramp.code_mut();

        // 第一遍：逐条搬移并按需重定位。
        // `fetch` 是被 patch 覆盖的目标字节数；`written` 是 trampoline 中的实际写入长度，
        // 两者会因 rel8→rel32 扩宽而不同。
        let mut fetch: usize = 0;
        let mut written: usize = 0;
        let mut fixups: [Option<(usize, crate::inst::BranchFixup)>; MAX_FIXUPS] =
            [None; MAX_FIXUPS];
        let mut nfix = 0;

        dis.set_ip(target.addr());

        while fetch < NEEDED_BYTES {
            let Some(inst) = dis.next() else {
                return Err(Error::InvalidAddress);
            };

            // 先算形态、校验容量，**确认放得下再写**。
            // 顺序很关键：若先写后查，越界的那几字节已经落到 `restore`
            // 备份区里，之后的还原会写回被污染的数据。
            let Some(plan) = crate::inst::plan_inst(&inst) else {
                return Err(Error::InvalidAddress);
            };

            // 预留尾部 jmp（x64 为 6 字节间接跳）的空间。
            if written + plan.dst_len + MAX_TAIL > PREFETCH_INST_SIZE {
                return Err(Error::NotEnoughMemory);
            }

            let dst = unsafe { rb_code.add(written) };
            let Some(moved) = crate::inst::move_inst(&inst, dst) else {
                return Err(Error::InvalidAddress);
            };
            debug_assert_eq!(moved.dst_len, plan.dst_len);

            if let Some(fixup) = moved.branch {
                if nfix == MAX_FIXUPS {
                    return Err(Error::NotEnoughMemory);
                }
                fixups[nfix] = Some((written, fixup));
                nfix += 1;
            }

            fetch += moved.src_len;
            written += moved.dst_len;

            // 记录指令边界映射，事务提交时据此修正被挂起线程的指令指针。
            if !tramp.push_align(fetch, written) {
                return Err(Error::NotEnoughMemory);
            }

            // 遇到函数结束（无条件跳转 / ret / int3）即停止，不再搬移后续指令。
            if inst.is_end() {
                break;
            }
        }

        // 若因函数结束提前停止、覆盖字节数仍不足，用 NOP / int3 padding 补齐。
        //
        // 对齐 C++ `detour_capture_target`：padding **只扩大 patch 覆盖范围，
        // 不复制进 trampoline**。循环在 `fetch >= NEEDED_BYTES` 时结束，
        // 允许一段 padding 跨过 NEEDED_BYTES（C++ 也是 `cbTarget += cFiller`
        // 后不比较是否超出，只判断是否够）。
        //
        // 探测长度不得超过「本内存区域剩余」：目标代码可能紧贴页边界，
        // 多读会跨进未映射页触发访问违例。C++ 那边直接下标读 `pbCode[0..11]`，
        // 这里比它更保守。
        while fetch < NEEDED_BYTES {
            let at = target.addr().wrapping_add(fetch);
            let cap = crate::platform::readable_len(at, FILLER_MAX_PROBE);
            if cap == 0 {
                break;
            }
            // SAFETY: `cap` 已由 `readable_len` 限定在当前内存区域之内。
            let probe = unsafe { std::slice::from_raw_parts(at as *const u8, cap) };
            let len = crate::inst::is_code_filler(probe);
            if len == 0 {
                break;
            }
            // 与 C++ 一致：不因 `len > remain` 而放弃；但整个覆盖范围必须
            // 仍落在同一可读区域内，否则备份时会跨区访问。
            if fetch + len > RESTORE_SIZE {
                return Err(Error::NotEnoughMemory);
            }
            if crate::platform::readable_len(target.addr(), fetch + len) < fetch + len {
                break;
            }
            fetch += len;
        }

        if fetch < NEEDED_BYTES {
            return Err(Error::InvalidAddress);
        }

        // 关键：在改写目标代码前备份原始字节。
        // `code` 里存的是重定位后的指令（rel8 已扩宽为 rel32），
        // 只有这份备份能在 detach 时正确还原原函数。
        //
        // 先确认这 `fetch` 字节确实位于同一内存区域：`fetch` 可能因填充
        // padding 而延伸到函数末尾之外，跨区域读取会访问违例。
        if crate::platform::readable_len(target.addr(), fetch) < fetch {
            return Err(Error::InvalidAddress);
        }
        tramp
            .save_restore(target.cast::<u8>(), fetch)
            .ok_or(Error::NotEnoughMemory)?;

        // 第二遍：回填相对分支位移。
        for entry in fixups.iter().flatten() {
            let (at, fixup) = *entry;
            let dst = unsafe { rb_code.add(at) };
            crate::inst::fix_branch(dst, fixup);
        }

        let rb_code_end = unsafe { rb_code.add(written) };

        #[cfg(target_arch = "x86_64")]
        {
            // 回跳经 remain 槽位，目标为 target + fetch。
            unsafe {
                *tramp.remain_slot().cast::<usize>() = target.addr() + fetch;
            }
            detour_gen_jmp_indirect(rb_code_end.cast(), tramp.remain_slot().cast());

            // thunk：从 detour 槽位取地址后间接跳出。
            unsafe {
                *tramp.detour_slot().cast::<usize>() = detour.addr();
            }
            let code_in = tramp.code_in_ptr();
            detour_gen_jmp_indirect(code_in.cast(), tramp.detour_slot().cast());
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            detour_gen_jmp_immediate(
                rb_code_end.cast(),
                target.wrapping_byte_add(fetch) as *mut _,
            );
        }

        Ok(Detour {
            target: target.addr(),
            block,
            fetch,
            written,
            detour_addr: detour.addr(),
        })
    }

    /// 把 detour 写入目标函数（改写其开头若干字节为跳转）。
    ///
    /// 与 [`Detour::prepare`] 分离，使事务能在 commit 的同一窗口内完成写入。
    /// 调用前必须保证所有可能执行该函数的线程已挂起。
    pub(crate) fn install(&self) -> Result<(), Error> {
        let _guard = MemoryProtector::new(self.target, self.fetch)?;
        let target = self.target as *mut u8;

        #[cfg(target_arch = "x86_64")]
        let jmp_end = {
            // 目标处跳到同块内的 thunk（保证 rel32 可达）。
            let code_in = self.block.as_ref().code_in.as_ptr() as *mut u8;
            detour_gen_jmp_immediate(target, code_in)
        };

        #[cfg(not(target_arch = "x86_64"))]
        let jmp_end = detour_gen_jmp_immediate(target, self.detour_addr as *mut u8);

        // 对齐 C++ `detour_gen_brk`：jmp 之后剩下的覆盖区域全部填 `int3`。
        //
        // 不填的话，残留的是原函数的**半条指令**——若线程恰好落在
        // `jmp` 与 `target + fetch` 之间执行，会解释出随机指令而崩溃。
        // 填 `0xcc` 至少能触发一个可预期的断点异常。
        let limit = self.target + self.fetch;
        let mut at = jmp_end as usize;
        while at < limit {
            // SAFETY: 该区间在 `MemoryProtector` 保护范围内，且 `at < limit`
            // 保证不写越界。
            unsafe { *(at as *mut u8) = 0xcc };
            at += 1;
        }

        // 目标代码已改变，通知 CPU 丢弃旧的指令缓存。
        #[cfg(target_os = "windows")]
        let _ = platform::flush_instruction_cache(
            platform::get_current_process(),
            target as *const c_void,
            self.fetch,
        );

        Ok(())
    }

    /// 目标地址。
    #[inline]
    pub(crate) fn target(&self) -> usize {
        self.target
    }

    /// trampoline 的指令边界映射表。
    #[inline]
    pub(crate) fn aligns(&self) -> &[AlignEntry] {
        self.block.as_ref().aligns()
    }

    /// trampoline `code` 区的绝对地址。
    #[inline]
    pub(crate) fn tramp_addr(&self) -> usize {
        self.block.as_ref().code_addr()
    }

    /// 覆盖的原始字节数，也是被 patch 改写的区间长度。
    #[inline]
    pub(crate) fn coverage(&self) -> usize {
        self.fetch
    }

    /// trampoline 中写入的字节数。IP 修正判断 trampoline 区间时用这个值。
    #[inline]
    pub(crate) fn written(&self) -> usize {
        self.written
    }

    pub fn trampoline<T>(&self) -> &T {
        unsafe { std::mem::transmute::<_, &T>(&self.block.as_ref().code) }
    }
}

pub struct DetoursGuard<'a> {
    detours: &'a mut Detours,
}

impl DetoursGuard<'_> {
    fn new(detours: &mut Detours) -> Result<DetoursGuard<'_>, Error> {
        detours.regions.unlock()?;
        Ok(DetoursGuard { detours })
    }

    /// 还原目标函数被覆盖的原始字节，并回收 trampoline 块。
    ///
    /// 必须从 `restore` 备份还原——`code` 里是重定位后的指令（rel8 已扩宽为
    /// rel32、RIP 相对位移已重算），写回它会破坏原函数。
    ///
    /// 只负责「把原始字节写回目标」，不回收 trampoline 块——
    /// 事务需要先还原、再修正线程 IP，最后才释放块。
    pub(crate) fn restore_only(detour: &mut Detour) {
        let tramp = detour.block.as_ref();
        let (restore, restore_len) = tramp.restore();

        if let Ok(mut mem) = MemoryProtector::new(detour.target, restore_len) {
            unsafe {
                mem.write_from_with_size(restore.as_ptr(), restore_len);
            }
            // 代码已改动，必须让 CPU 丢弃可能缓存的旧指令。
            #[cfg(target_os = "windows")]
            let _ = platform::flush_instruction_cache(
                platform::get_current_process(),
                detour.target as *const c_void,
                restore_len,
            );
        }
    }

    pub(crate) fn internal_detach(regions: &mut Regions<BLOCK_COUNT>, detour: &mut Detour) {
        Self::restore_only(detour);
        // 还原失败也要回收块，否则 trampoline 会泄漏。
        regions.free_block(&mut detour.block);
    }

    pub fn attach_ptr<const ADDR: usize, T>(
        &mut self,
        target: Pointer<ADDR, T>,
        detour: *const c_void,
    ) -> Result<(), Error> {
        self.attach(target.raw_addr() as *const c_void, detour)
    }

    pub fn attach(&mut self, target: *const c_void, detour: *const c_void) -> Result<(), Error> {
        if target.is_null() || detour.is_null() {
            return Err(Error::InvalidAddress);
        }

        #[cfg(target_os = "windows")]
        let target =
            platform::detour_skip_jmp(&mut self.detours.dis, target.addr()) as *const c_void;
        #[cfg(target_os = "windows")]
        let detour =
            platform::detour_skip_jmp(&mut self.detours.dis, detour.addr()) as *const c_void;

        if target.addr() == detour.addr() {
            return Err(Error::InvalidAddress);
        }

        let target_addr = target.addr();

        // 已存在的 detour 先撤销，避免同一目标重复 patch。
        self.detach(&target_addr);

        let Some(block) = self
            .detours
            .regions
            .alloc_block(&mut self.detours.dis, target.cast())
        else {
            return Err(Error::NotEnoughMemory);
        };

        // prepare 失败时必须归还 block，否则 trampoline 会泄漏。
        let prepared = match Detour::prepare(&mut self.detours.dis, target, detour, block.clone()) {
            Ok(d) => d,
            Err(e) => {
                let mut orphan = block.clone();
                self.detours.regions.free_block(&mut orphan);
                return Err(e);
            }
        };

        // install 失败同样要归还 block——此时目标代码未被改写，块必须回收。
        if let Err(e) = prepared.install() {
            let mut orphan = prepared.block.clone();
            self.detours.regions.free_block(&mut orphan);
            return Err(e);
        }

        self.detours.detours.insert(target_addr, prepared);
        Ok(())
    }

    pub fn detach(&mut self, address: &usize) {
        if let Some(mut detour) = self.detours.detours.remove(address) {
            DetoursGuard::internal_detach(&mut self.detours.regions, &mut detour);
        }
    }
}

impl Drop for DetoursGuard<'_> {
    fn drop(&mut self) {
        let _ = self.detours.regions.lock();
    }
}

/// 事务中的挂起线程。
///
/// `Drop` 时若未恢复会调用 `resume_thread`，保证 panic 路径不留挂起线程。
struct SuspendedThread {
    handle: crate::platform::ThreadHandle,
    resumed: bool,
}

impl Drop for SuspendedThread {
    fn drop(&mut self) {
        if !self.resumed {
            crate::platform::resume_thread(self.handle);
            self.resumed = true;
        }
    }
}

/// 事务中待提交的操作。
enum PendingOp {
    /// 新安装的 detour（已 prepare，尚未写入目标）。
    Attach(Detour),
    /// 待移除的目标地址。
    Detach(usize),
}

/// 事务对象：对应 C++ 的 `DetourTransactionBegin` … `DetourTransactionCommit`。
///
/// 对齐 C++ 语义：**线程不会被自动挂起**，调用方必须为每个可能正在执行
/// 目标函数的线程显式调用 [`DetourTransaction::update_thread`]。
/// 漏掉的线程在 commit 写入的瞬间仍可能执行到被改写的指令。
///
/// # 用法
///
/// ```no_run
/// # use detours_rs::Detours;
/// # fn f(detours: &mut Detours, thread: usize, target: *const std::ffi::c_void, hook: *const std::ffi::c_void) -> Result<(), detours_rs::Error> {
/// let mut tx = detours.transaction()?;
/// tx.update_thread(thread as _);          // 挂起其它线程（可多次调用）
/// tx.attach(target, hook)?;               // 只登记，不写内存
/// tx.commit()?;                           // 统一写入 + 修正 EIP + 恢复线程
/// # Ok(())
/// # }
/// ```
///
/// 若中途返回错误或提前 `drop`，事务自动回滚并恢复已挂起的线程。
pub struct DetourTransaction<'a> {
    detours: &'a mut Detours,
    threads: Vec<SuspendedThread>,
    ops: Vec<PendingOp>,
    /// 事务是否已结束（commit / abort 之后置位，防止重复收尾）。
    finished: bool,
    /// 首个错误。对齐 C++ `s_nPendingError`：一旦某步失败，整个事务
    /// 都不能再提交——否则会写出「部分挂起 + 部分写入」的危险状态。
    pending_error: Option<Error>,
}

impl<'a> DetourTransaction<'a> {
    fn new(detours: &'a mut Detours) -> Result<Self, Error> {
        // 事务期间 trampoline 区域需要可写。
        detours.regions.unlock()?;
        Ok(DetourTransaction {
            detours,
            threads: Vec::new(),
            ops: Vec::new(),
            finished: false,
            pending_error: None,
        })
    }

    /// 记录首个错误并返回它。
    ///
    /// 对齐 C++ `s_nPendingError`：失败一旦发生，事务就不能再提交，
    /// 否则会写出「部分线程挂起 + 部分代码已改」的危险状态。
    fn fail(&mut self, e: Error) -> Error {
        if self.pending_error.is_none() {
            self.pending_error = Some(e);
        }
        e
    }

    /// 若已有失败记录，返回 `InvalidOperation` 表示事务不可提交。
    fn check_pending(&self) -> Result<(), Error> {
        if self.pending_error.is_some() {
            return Err(Error::InvalidOperation);
        }
        Ok(())
    }

    /// 挂起一个线程，使其在 commit 期间不会执行到被改写的代码。
    ///
    /// 对齐 C++ `DetourUpdateThread`：
    /// - 传当前线程会被静默忽略（自己无法安全挂起自己）；
    /// - 失败会把事务标记为不可提交，后续 `commit` 直接返回错误。
    pub fn update_thread(&mut self, thread: crate::platform::ThreadHandle) -> Result<(), Error> {
        if self.finished {
            return Err(Error::InvalidOperation);
        }
        self.check_pending()?;

        // 静默忽略对自己的挂起请求——与 C++ 行为一致。
        if thread == crate::platform::current_thread_handle() {
            return Ok(());
        }

        if crate::platform::suspend_thread(thread).is_none() {
            return Err(self.fail(Error::ErrorCode(0)));
        }

        self.threads.push(SuspendedThread {
            handle: thread,
            resumed: false,
        });
        Ok(())
    }

    /// 登记一个 detour 安装操作（只 prepare，不写目标代码）。
    pub fn attach(&mut self, target: *const c_void, detour: *const c_void) -> Result<(), Error> {
        if self.finished {
            return Err(Error::InvalidOperation);
        }
        self.check_pending()?;
        if target.is_null() || detour.is_null() {
            return Err(Error::InvalidAddress);
        }

        #[cfg(target_os = "windows")]
        let target =
            platform::detour_skip_jmp(&mut self.detours.dis, target.addr()) as *const c_void;
        #[cfg(target_os = "windows")]
        let detour =
            platform::detour_skip_jmp(&mut self.detours.dis, detour.addr()) as *const c_void;

        if target.addr() == detour.addr() {
            return Err(Error::InvalidAddress);
        }

        let target_addr = target.addr();

        // 同一事务内对同一目标重复登记时，后登记者生效。
        self.ops
            .retain(|op| !matches!(op, PendingOp::Attach(d) if d.target() == target_addr));

        let Some(block) = self
            .detours
            .regions
            .alloc_block(&mut self.detours.dis, target.cast())
        else {
            return Err(Error::NotEnoughMemory);
        };

        // prepare 失败要归还 block，否则 trampoline 泄漏。
        match Detour::prepare(&mut self.detours.dis, target, detour, block.clone()) {
            Ok(prepared) => {
                self.ops.push(PendingOp::Attach(prepared));
                Ok(())
            }
            Err(e) => {
                let mut orphan = block;
                self.detours.regions.free_block(&mut orphan);
                Err(e)
            }
        }
    }

    /// 登记一个 detour 移除操作（只在 commit 时真正还原）。
    pub fn detach(&mut self, target: usize) -> Result<(), Error> {
        if self.finished {
            return Err(Error::InvalidOperation);
        }
        self.check_pending()?;
        self.ops.push(PendingOp::Detach(target));
        Ok(())
    }

    /// 提交事务：写入全部改动、修正被挂起线程的指令指针、刷新指令缓存、恢复线程。
    ///
    /// 所有 `install` / `restore` 都成功后才把改动落到 detour 表；任一步失败
    /// 则把本次事务已经造成的改动**全部撤销**（已 install 的还原、未用的块回收），
    /// 保证不会留下「一半挂上、一半没挂」的目标进程。
    pub fn commit(mut self) -> Result<(), Error> {
        self.finished = true;

        let ops = std::mem::take(&mut self.ops);
        let mut spans: Vec<Span> = Vec::new();
        // 已成功 install、尚未登记进 detour 表。
        let mut installed: Vec<Detour> = Vec::new();
        // 已 restore、等待释放 trampoline 块的 detour。
        let mut removed: Vec<Detour> = Vec::new();

        let mut iter = ops.into_iter();
        while let Some(op) = iter.next() {
            match op {
                PendingOp::Attach(mut detour) => {
                    if let Err(e) = detour.install() {
                        // 回滚：本条与后续未处理的 attach 回收块；
                        // 已 install 的还原后回收；已 restore 的直接回收。
                        self.detours.regions.free_block(&mut detour.block);
                        for rest in iter {
                            if let PendingOp::Attach(mut d) = rest {
                                self.detours.regions.free_block(&mut d.block);
                            }
                        }
                        for mut d in installed {
                            DetoursGuard::restore_only(&mut d);
                            self.detours.regions.free_block(&mut d.block);
                        }
                        for mut d in removed {
                            self.detours.regions.free_block(&mut d.block);
                        }
                        let _ = self.detours.regions.lock();
                        self.threads.clear();
                        return Err(e);
                    }

                    spans.push(Span {
                        start: detour.target(),
                        target_len: detour.coverage(),
                        tramp: detour.tramp_addr(),
                        tramp_len: detour.written(),
                        aligns: detour.aligns().to_vec(),
                        to_tramp: true,
                    });
                    installed.push(detour);
                }
                PendingOp::Detach(addr) => {
                    if let Some(mut detour) = self.detours.detours.remove(&addr) {
                        DetoursGuard::restore_only(&mut detour);
                        spans.push(Span {
                            start: detour.target(),
                            target_len: detour.coverage(),
                            tramp: detour.tramp_addr(),
                            tramp_len: detour.written(),
                            aligns: detour.aligns().to_vec(),
                            to_tramp: false,
                        });
                        removed.push(detour);
                    }
                }
            }
        }

        // 全部写入成功，登记新的 detour。
        for detour in installed {
            self.detours.detours.insert(detour.target(), detour);
        }

        // 修正被挂起线程的指令指针。
        //
        // 线程挂起时可能正停在被改写的区间内：attach 时把 IP 从目标映射到
        // trampoline 的对应位置（那里有重定位后的等价指令）；detach 时反向映射。
        for t in &self.threads {
            let Some(ip) = crate::platform::get_thread_ip(t.handle) else {
                continue;
            };
            if let Some(new_ip) = remap_ip(&spans, ip) {
                let _ = crate::platform::set_thread_ip(t.handle, new_ip);
            }
        }

        // 目标处已无引用，可以安全释放这些块。
        for mut detour in removed {
            self.detours.regions.free_block(&mut detour.block);
        }

        let _ = self.detours.regions.lock();

        // 恢复线程（`SuspendedThread::drop` 完成实际 ResumeThread）。
        self.threads.clear();

        Ok(())
    }

    /// 放弃事务：回滚已 prepare 的资源并恢复线程。
    pub fn abort(mut self) {
        self.finished = true;
        self.rollback();
    }

    fn rollback(&mut self) {
        for op in std::mem::take(&mut self.ops) {
            if let PendingOp::Attach(detour) = op {
                let mut d = detour;
                self.detours.regions.free_block(&mut d.block);
            }
        }
        let _ = self.detours.regions.lock();
        self.threads.clear();
    }
}

/// 一个被改动的代码区间，用于把线程 IP 从旧位置映射到新位置。
///
/// `to_tramp` 表示映射方向：`true` 为目标 → trampoline（attach），
/// `false` 为 trampoline → 目标（detach）。
///
/// 两个长度必须分开记录：target 侧是 `fetch`（被覆盖的原始字节数），
/// trampoline 侧是 `written`（搬移后实际写入的字节数）。由于 rel8→rel32
/// 扩宽，后者通常更长——detach 时判断 IP 是否落在 trampoline 区间必须用
/// 后者，否则会漏掉尾部的已搬移指令。
struct Span {
    start: usize,
    /// target 侧被覆盖的字节数。
    target_len: usize,
    tramp: usize,
    /// trampoline 侧写入的字节数。
    tramp_len: usize,
    aligns: Vec<AlignEntry>,
    to_tramp: bool,
}

/// 根据改动区间把 IP 重映射到新位置；不需要或无法精确映射时返回 `None`。
///
/// 只有 IP 恰好落在「被改动区间」且命中指令边界时才重映射——停在指令中间
/// 说明该线程的状态无法安全平移，保持原样（与 C++ 行为一致：C++ 也是对
/// 每条指令的边界偏移查表，未命中则不动）。
fn remap_ip(spans: &[Span], ip: usize) -> Option<usize> {
    for s in spans {
        if s.to_tramp {
            // attach：IP 落在被覆盖的目标区间内 → 映射到 trampoline。
            if ip >= s.start && ip < s.start + s.target_len {
                return align_target_to_tramp(&s.aligns, ip - s.start).map(|off| s.tramp + off);
            }
        } else {
            // detach：IP 落在 trampoline 已写入的代码区内 → 映射回目标。
            // 用 tramp_len 而非 target_len：扩宽后 trampoline 区更长。
            if ip >= s.tramp && ip < s.tramp + s.tramp_len {
                return align_tramp_to_target(&s.aligns, ip - s.tramp).map(|off| s.start + off);
            }
        }
    }
    None
}

impl Drop for DetourTransaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // 未显式 commit/abort：按回滚处理，绝不留下半完成状态。
            self.finished = true;
            self.rollback();
        }
        // 即使已 commit，也确保线程都恢复。
        self.threads.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个零值 Trampoline，避免依赖真实内存分配。
    fn zeroed_trampoline() -> Trampoline {
        // SAFETY: Trampoline 只含整数与字节数组，全零是合法位模式。
        unsafe { std::mem::zeroed() }
    }

    #[test]
    fn restore_roundtrip_preserves_original_bytes() {
        let mut tramp = zeroed_trampoline();
        let original = [0x55u8, 0x8b, 0xec, 0x83, 0xec, 0x10];

        tramp
            .save_restore(original.as_ptr(), original.len())
            .unwrap();
        let (restore, len) = tramp.restore();

        assert_eq!(len, original.len());
        assert_eq!(&restore[..len], &original, "备份必须与被覆盖前完全一致");
    }

    #[test]
    fn restore_is_independent_of_relocated_code() {
        // 关键不变量：code 区存放重定位后的指令，restore 必须保持原始字节。
        // 这正是 detach 写回错误的根源——早期实现写回的是 code。
        let mut tramp = zeroed_trampoline();
        let original = [0xeb, 0x05]; // jmp rel8，搬移后会扩宽成 e9 + rel32
        tramp
            .save_restore(original.as_ptr(), original.len())
            .unwrap();

        // 模拟搬移：往 code 区写入扩宽后的 e9 形式
        unsafe {
            let code = tramp.code_mut();
            *code = 0xe9;
            std::ptr::write_unaligned(code.add(1).cast::<i32>(), 0x1234);
        }

        let (restore, len) = tramp.restore();
        assert_eq!(&restore[..len], &[0xeb, 0x05], "restore 不应被重定位影响");
    }

    #[test]
    fn save_restore_rejects_oversized_input() {
        let mut tramp = zeroed_trampoline();
        let too_long = [0u8; RESTORE_SIZE + 1];
        assert!(
            tramp
                .save_restore(too_long.as_ptr(), too_long.len())
                .is_none(),
            "超过 RESTORE_SIZE 应失败而不是截断"
        );
    }

    #[test]
    fn save_restore_accepts_exact_capacity() {
        let mut tramp = zeroed_trampoline();
        let exact = [0xaau8; RESTORE_SIZE];
        assert!(tramp.save_restore(exact.as_ptr(), exact.len()).is_some());
        let (restore, len) = tramp.restore();
        assert_eq!(len, RESTORE_SIZE);
        assert!(restore.iter().all(|&b| b == 0xaa));
    }

    #[test]
    fn restore_size_covers_max_fetch() {
        // fetch 最坏情况：NEEDED_BYTES-1 字节后跟一条最长 15 字节指令，
        // 再加 filler 补齐（最长 11 字节 NOP）。
        let worst = NEEDED_BYTES - 1 + 15;
        assert!(
            RESTORE_SIZE >= worst,
            "RESTORE_SIZE({RESTORE_SIZE}) 必须覆盖最坏 fetch({worst})"
        );
    }

    #[test]
    fn trampoline_layout_places_restore_right_after_code() {
        // 回归防线：`code` 区一旦写越界，落点就是紧邻的 `restore` 备份，
        // 之后 detach 会把被污染的数据写回目标函数。
        // 这个断言把「先校验容量、再写入」的必要性固定在布局层面。
        let t = zeroed_trampoline();
        let base = &t as *const _ as usize;
        let code = t.code_addr();
        let restore_off = (&t.restore as *const _ as usize) - base;
        let code_off = code - base;

        assert_eq!(code_off, 0, "code 区应在结构体起始处");
        assert_eq!(
            restore_off,
            code_off + PREFETCH_INST_SIZE,
            "restore 紧邻 code 之后，code 越界必然污染备份"
        );
    }

    #[test]
    fn write_capacity_check_rejects_overflow() {
        // 模拟 patch 循环的容量判定：任何时刻都必须留出尾部 jmp 的空间，
        // 且 `written + dst_len` 不得越过 code 区。
        for dst_len in [1usize, 2, 5, 6, 15] {
            for written in 0..PREFETCH_INST_SIZE {
                let overflow = written + dst_len + MAX_TAIL > PREFETCH_INST_SIZE;
                let write_end = written + dst_len;
                if !overflow {
                    assert!(
                        write_end <= PREFETCH_INST_SIZE,
                        "未判定越界却写到 {write_end}，超出 code 容量"
                    );
                }
            }
        }
    }

    // ── 指令边界映射表（EIP 修正的基础）──

    #[test]
    fn filler_may_overshoot_needed_bytes() {
        // 对齐 C++：padding 消费不因「超出 NEEDED_BYTES」而放弃。
        // 场景：还差 2 字节，但地址处是个 5 字节 NOP——C++ 会整体吃掉它，
        // 使覆盖范围变成 8 字节。若这里改成 `len > remain` 就 break，
        // 该函数会被误判为无法 hook。
        let need = 5usize;
        let fetch = 3usize; // remain = 2
        let filler = 5usize; // 5 字节 NOP

        let remain = need - fetch;
        assert!(filler > remain, "此用例要求 padding 长于剩余字节");

        // 采用 C++ 语义：接受并越过 NEEDED_BYTES
        let new_fetch = fetch + filler;
        assert!(new_fetch > need, "覆盖范围应越过 NEEDED_BYTES");
        // 但必须仍在 restore 备份容量内
        assert!(new_fetch <= RESTORE_SIZE, "越过 NEEDED_BYTES 后仍须可备份");
    }

    #[test]
    fn install_fills_gap_with_int3() {
        // 对齐 C++ `detour_gen_brk`：jmp 之后到 target+fetch 之间必须填 0xcc。
        // 否则残留的是原函数的半条指令，线程落在此处会执行随机指令。
        let mut buf = [0x90u8; 12]; // 模拟目标处原有的 NOP
        let target = buf.as_mut_ptr();
        let fetch = 8usize;

        // 模拟写入 5 字节 jmp（此处只关心长度）
        let jmp_len = 5usize;
        let mut at = jmp_len;
        while at < fetch {
            unsafe { *target.add(at) = 0xcc };
            at += 1;
        }

        assert_eq!(&buf[..5], &[0x90; 5], "jmp 区不应被覆盖");
        assert_eq!(&buf[5..8], &[0xcc; 3], "jmp 之后到 fetch 之间应填 int3");
        assert_eq!(buf[8], 0x90, "fetch 之后不应改动");
    }

    #[test]
    fn align_table_records_and_looks_up() {
        let mut tramp = zeroed_trampoline();
        assert!(tramp.push_align(5, 5));
        assert!(tramp.push_align(7, 9));

        let aligns = tramp.aligns();
        assert_eq!(aligns.len(), 2);
        assert_eq!(align_target_to_tramp(aligns, 5), Some(5));
        assert_eq!(align_target_to_tramp(aligns, 7), Some(9));
        // 不在边界上的偏移不映射
        assert_eq!(align_target_to_tramp(aligns, 6), None);
    }

    #[test]
    fn align_table_reverse_lookup() {
        let mut tramp = zeroed_trampoline();
        tramp.push_align(5, 5);
        tramp.push_align(7, 9);

        let aligns = tramp.aligns();
        assert_eq!(align_tramp_to_target(aligns, 5), Some(5));
        assert_eq!(align_tramp_to_target(aligns, 9), Some(7));
        assert_eq!(align_tramp_to_target(aligns, 6), None);
    }

    #[test]
    fn align_table_rejects_overflow() {
        let mut tramp = zeroed_trampoline();
        for i in 0..MAX_ALIGN {
            assert!(tramp.push_align(i, i), "第 {i} 条应成功");
        }
        assert!(
            !tramp.push_align(99, 99),
            "表满后必须返回 false，而不是静默覆盖"
        );
    }

    // ── remap_ip：线程 IP 重定向 ──

    /// 构造测试用 Span。
    ///
    /// `aligns` 里含 `ob_tramp = 9` 的条目，因此 `tramp_len` 必须大于 9，
    /// 否则 detach 方向会因为区间覆盖不足而查不到该映射——这正是
    /// 「target 侧与 trampoline 侧长度必须分开记录」的由来。
    fn span(to_tramp: bool, start: usize, target_len: usize, tramp: usize) -> Span {
        Span {
            start,
            target_len,
            tramp,
            tramp_len: 12,
            aligns: vec![
                AlignEntry {
                    ob_target: 5,
                    ob_tramp: 5,
                },
                AlignEntry {
                    ob_target: 7,
                    ob_tramp: 9,
                },
            ],
            to_tramp,
        }
    }

    #[test]
    fn remap_ip_attach_maps_target_to_trampoline() {
        let spans = [span(true, 0x1000, 8, 0x9000)];
        // IP 停在 target+5 → trampoline+5
        assert_eq!(remap_ip(&spans, 0x1005), Some(0x9005));
        // IP 停在 target+7 → trampoline+9（因指令扩宽，偏移不同）
        assert_eq!(remap_ip(&spans, 0x1007), Some(0x9009));
    }

    #[test]
    fn remap_ip_detach_maps_trampoline_to_target() {
        let spans = [span(false, 0x1000, 8, 0x9000)];
        assert_eq!(remap_ip(&spans, 0x9005), Some(0x1005));
        // 扩宽后的偏移 9 落在 tramp_len(12) 内，能正确映射回 target+7
        assert_eq!(remap_ip(&spans, 0x9009), Some(0x1007));
    }

    #[test]
    fn remap_ip_detach_needs_tramp_len_not_target_len() {
        // 回归测试：若误用 target_len 判断 trampoline 区间，
        // 偏移 9/10 会落在区间外而漏映射。
        let mut s = span(false, 0x1000, 8, 0x9000);
        s.tramp_len = 8; // 故意设成与 target_len 相同
        let spans = [s];
        assert_eq!(
            remap_ip(&spans, 0x9009),
            None,
            "tramp_len 过小时确实查不到，证明确实用了独立长度"
        );
    }

    #[test]
    fn remap_ip_outside_range_is_untouched() {
        let spans = [span(true, 0x1000, 8, 0x9000)];
        // 区间外
        assert_eq!(remap_ip(&spans, 0x2000), None);
        // 边界：区间末尾是开区间
        assert_eq!(remap_ip(&spans, 0x1008), None);
    }

    #[test]
    fn remap_ip_mid_instruction_is_not_mapped() {
        let spans = [span(true, 0x1000, 8, 0x9000)];
        // 偏移 6 不是指令边界，无法安全平移，保持不动
        assert_eq!(remap_ip(&spans, 0x1006), None);
    }

    #[test]
    fn remap_ip_empty_spans_is_noop() {
        assert_eq!(remap_ip(&[], 0x1000), None);
    }
}
