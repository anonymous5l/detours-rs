use capstone::OwnedInsn;
#[cfg(target_arch = "aarch64")]
use capstone::arch::arm64::Arm64Insn;
use std::ptr;

const ONE_INSTRUCTION_MAX_SIZE: usize = 0x10;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn capstone() -> capstone::Capstone {
    use capstone::arch::x86::ArchMode;
    use capstone::prelude::BuildsCapstone;

    #[cfg(target_arch = "x86")]
    const MODE: ArchMode = ArchMode::Mode32;
    #[cfg(target_arch = "x86_64")]
    const MODE: ArchMode = ArchMode::Mode64;

    capstone::Capstone::new()
        .x86()
        .mode(MODE)
        .detail(true)
        .build()
        .unwrap()
}

#[cfg(target_arch = "aarch64")]
pub fn capstone() -> capstone::Capstone {
    use capstone::arch::arm64::ArchMode;
    use capstone::prelude::BuildsCapstone;

    capstone::Capstone::new()
        .arm64()
        .mode(ArchMode::Arm)
        .detail(true)
        .build()
        .unwrap()
}

not_support_arch! {
    pub fn capstone() -> capstone::Capstone {
        panic!("unexpected arch")
    }
}

/// 一条相对分支指令的编码信息，用于 trampoline 重定位。
///
/// 非 x86/x64 架构下也会定义（字段不会被填充），以便 [`Inst`] 无需条件编译。
#[derive(Debug, Clone, Copy)]
pub struct RelBranch {
    /// 分支操作码之前的 legacy 前缀长度。
    pub prefix_len: usize,
    /// 位移字段在指令内的字节偏移。
    pub offset: usize,
    /// 位移字段宽度：1（rel8）或 4（rel32）。
    pub size: usize,
    /// 分支的绝对目标地址。
    pub target: usize,
}

/// 单条指令的搬移结果。
#[derive(Debug, Clone, Copy)]
pub(crate) struct Moved {
    /// 原指令字节数。
    pub src_len: usize,
    /// trampoline 中写入的字节数（rel8 扩展为 rel32 后会变长）。
    pub dst_len: usize,
    /// 待第二遍修正的相对分支。
    pub branch: Option<BranchFixup>,
}

/// 尚未修正位移的相对分支。
#[derive(Debug, Clone, Copy)]
pub(crate) struct BranchFixup {
    /// 位移字段在 trampoline 指令内的偏移。
    pub disp_off: usize,
    /// 搬移后该分支指令的字节长度（rel8 扩宽后会变长）。
    pub dst_len: usize,
    /// 分支的原始绝对目标。
    pub target: usize,
}

/// 判定 legacy 前缀（段/操作数/地址/rep/lock 前缀）。
///
/// 纯字节判定，与目标架构无关，便于在任何平台单测。
#[inline]
pub(crate) fn is_legacy_prefix(b: u8) -> bool {
    matches!(
        b,
        0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 | 0x66 | 0x67
    )
}

/// 推算 ModR/M 之后 disp32 的起始偏移。
///
/// capstone 未暴露 `cs_x86.encoding.disp_offset`，这里按 x86 编码规则自行推算：
/// `[legacy 前缀] [REX | VEX | EVEX] opcode ModR/M`，disp32 紧跟 ModR/M。
///
/// 纯字节推算，与目标架构无关，便于在任何平台单测。
#[inline]
pub(crate) fn modrm_disp_offset(bytes: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < bytes.len() && is_legacy_prefix(bytes[i]) {
        i += 1;
    }
    let b = *bytes.get(i)?;

    // VEX/EVEX 把前缀字节与 opcode 合在一起。
    let modrm = match b {
        0xc5 => i + 3, // VEX2：C5 + 1 字节 + opcode
        0xc4 => i + 4, // VEX3：C4 + 2 字节 + opcode
        0x62 => i + 5, // EVEX：62 + 3 字节 + opcode
        _ => {
            if (0x40..=0x4f).contains(&b) {
                i += 1; // REX
            }
            let op = *bytes.get(i)?;
            if op == 0x0f {
                match *bytes.get(i + 1)? {
                    0x38 | 0x3a => i + 3,
                    _ => i + 2,
                }
            } else {
                i + 1
            }
        }
    };

    Some(modrm + 1)
}

/// 从指令字节直接解算相对分支的目标地址。
///
/// 纯字节解算，与目标架构无关，便于在任何平台单测。
pub(crate) fn decode_rel_branch(bytes: &[u8], addr: usize) -> Option<RelBranch> {
    // 先跳过 legacy 前缀，分支操作码在前缀之后。
    let mut p = 0;
    while p < bytes.len() && is_legacy_prefix(bytes[p]) {
        p += 1;
    }

    let (offset, size) = match *bytes.get(p)? {
        0xeb => (p + 1, 1),        // jmp rel8
        0xe8 | 0xe9 => (p + 1, 4), // call/jmp rel32
        0x70..=0x7f => (p + 1, 1), // jcc rel8
        0x0f => match *bytes.get(p + 1)? {
            0x80..=0x8f => (p + 2, 4), // jcc rel32
            _ => return None,
        },
        _ => return None,
    };

    let next = addr + bytes.len();
    let target = if size == 1 {
        next.wrapping_add(*bytes.get(offset)? as i8 as isize as usize)
    } else {
        let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
        next.wrapping_add(i32::from_le_bytes(raw) as isize as usize)
    };

    Some(RelBranch {
        prefix_len: p,
        offset,
        size,
        target,
    })
}

/// 计算搬移后 RIP 相对寻址的新 disp32。
///
/// 原目标 = `src_addr + len + old_disp`；新位移 = 原目标 - (`dst_addr + len`)。
/// 化简后即 `old_disp + (src_addr - dst_addr)`。
#[inline]
pub(crate) fn relocate_rip_disp(old_disp: i32, src_addr: usize, dst_addr: usize) -> Option<i32> {
    i32::try_from(old_disp as i64 + src_addr as i64 - dst_addr as i64).ok()
}

/// 计算搬移后相对分支的新 disp。
///
/// 分支位移始终相对「该分支指令的下一条指令」，因此：
/// `new_disp = target - (dst_addr + dst_len)`。
#[inline]
pub(crate) fn relocate_branch_disp(target: usize, dst_addr: usize, dst_len: usize) -> i32 {
    (target as i64 - (dst_addr + dst_len) as i64) as i32
}

/// 识别 1～11 字节的 NOP padding 与 `int3` filler，返回其长度；不是 filler 时返回 0。
///
/// 对齐 C++ `detour_is_code_filler`。用于在目标函数结尾处补齐被 patch 的字节数时
/// **跳过**而非**复制** padding，避免 trampoline 中重复 padding。
pub(crate) fn is_code_filler(bytes: &[u8]) -> usize {
    // 1-byte through 11-byte NOPs。
    const NOP_PATTERNS: [&[u8]; 11] = [
        &[0x90],
        &[0x66, 0x90],
        &[0x0f, 0x1f, 0x00],
        &[0x0f, 0x1f, 0x40, 0x00],
        &[0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
        &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x66, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[
            0x66, 0x66, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
    ];

    // 长模式优先匹配：`66 90` 必须先于 `90` 判断，否则会被当成 1 字节 NOP。
    for pat in NOP_PATTERNS.iter().rev() {
        if bytes.starts_with(pat) {
            return pat.len();
        }
    }

    // int 3
    if bytes.starts_with(&[0xcc]) {
        return 1;
    }

    0
}

/// 解码时提取 RIP 相对寻址的 disp32 偏移。
///
/// x86（32 位）没有 RIP 相对寻址，一律返回 `None`。
#[cfg(target_arch = "x86_64")]
fn detect_rip_disp(insn: &OwnedInsn, cap: &capstone::Capstone) -> Option<usize> {
    use capstone::RegId;
    use capstone::arch::x86::X86OperandType;
    use capstone::arch::x86::X86Reg;
    use capstone::prelude::DetailsArchInsn;

    let detail = cap.insn_detail(insn).ok()?;
    let arch_detail = detail.arch_detail();
    let x = arch_detail.x86()?;

    let rip = RegId(X86Reg::X86_REG_RIP as u16);
    let disp = x.operands().find_map(|op| match op.op_type {
        X86OperandType::Mem(m) if m.base() == rip => Some(m.disp()),
        _ => None,
    })?;

    let bytes = insn.bytes();
    let off = modrm_disp_offset(bytes)?;
    let raw: [u8; 4] = bytes.get(off..off + 4)?.try_into().ok()?;
    // 交叉校验，避免前缀/编码推算偏差导致写坏指令。
    (i32::from_le_bytes(raw) as i64 == disp).then_some(off)
}

#[cfg(target_arch = "x86")]
fn detect_rip_disp(_insn: &OwnedInsn, _cap: &capstone::Capstone) -> Option<usize> {
    None
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn detect_rip_disp(_insn: &OwnedInsn, _cap: &capstone::Capstone) -> Option<usize> {
    None
}

/// 解码时提取相对分支（`call`/`jmp`/`jcc` 的 rel8 / rel32）信息。
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn detect_rel_branch(insn: &OwnedInsn, cap: &capstone::Capstone) -> Option<RelBranch> {
    use capstone::arch::x86::X86OperandType;
    use capstone::prelude::DetailsArchInsn;

    // 字节解算统一走 decode_rel_branch，避免两处规则各自演化而不一致。
    let br = decode_rel_branch(insn.bytes(), insn.address() as usize)?;

    // 与 capstone 交叉校验，确认没有把带前缀的普通指令误判成分支。
    let detail = cap.insn_detail(insn).ok()?;
    let arch_detail = detail.arch_detail();
    let x = arch_detail.x86()?;
    let capstone_target = x.operands().find_map(|op| match op.op_type {
        X86OperandType::Imm(v) => Some(v as usize),
        _ => None,
    })?;

    (capstone_target == br.target).then_some(br)
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn detect_rel_branch(_insn: &OwnedInsn, _cap: &capstone::Capstone) -> Option<RelBranch> {
    None
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const _: () = {
    use capstone::arch::x86::X86Operand;
    use capstone::arch::x86::X86OperandType;
    use capstone::prelude::DetailsArchInsn;

    impl Inst {
        fn disp(op: X86Operand) -> Option<usize> {
            match op.op_type {
                X86OperandType::Imm(imm) => Some(imm as usize),
                X86OperandType::Mem(m) => Some(m.disp() as usize),
                _ => None,
            }
        }

        #[inline(always)]
        pub fn is_end(&self) -> bool {
            self.is_jmp() || self.is_ret() || self.is_int3()
        }

        #[inline(always)]
        pub fn is_int3(&self) -> bool {
            self.insn.id().0 == capstone::arch::x86::X86Insn::X86_INS_INT3 as u32
        }

        #[inline(always)]
        pub fn is_ret(&self) -> bool {
            self.insn.id().0 == capstone::arch::x86::X86Insn::X86_INS_RET as u32
                || self.insn.id().0 == capstone::arch::x86::X86Insn::X86_INS_RETF as u32
                || self.insn.id().0 == capstone::arch::x86::X86Insn::X86_INS_RETFQ as u32
                || self.insn.id().0 == capstone::arch::x86::X86Insn::X86_INS_IRET as u32
                || self.insn.id().0 == capstone::arch::x86::X86Insn::X86_INS_IRETD as u32
                || self.insn.id().0 == capstone::arch::x86::X86Insn::X86_INS_IRETQ as u32
        }

        #[inline(always)]
        pub fn is_jmp(&self) -> bool {
            self.insn.id().0 == capstone::arch::x86::X86Insn::X86_INS_JMP as u32
        }

        pub fn jmp_rm(&self, dis: &Disassembler) -> Option<usize> {
            if self.is_jmp() {
                return None;
            }
            let detail = dis.cap.insn_detail(&self.insn).ok()?;
            let arch_detail = detail.arch_detail();

            for op in arch_detail.x86()?.operands() {
                if let disp @ Some(_) = Self::disp(op) {
                    return disp;
                }
            }
            None
        }

        pub fn jmp_imm(&self, dis: &Disassembler) -> Option<(u8, usize)> {
            if self.is_jmp() {
                return None;
            }
            let detail = dis.cap.insn_detail(&self.insn).ok()?;
            let arch_detail = detail.arch_detail();
            let x = arch_detail.x86()?;
            for op in x.operands() {
                if let disp @ Some(_) = Self::disp(op) {
                    let bit = if x.opcode()[0] == 0xeb { 8 } else { 32 };
                    return disp.map(|x| (bit, x));
                }
            }
            None
        }
    }
};

#[cfg(target_arch = "aarch64")]
const _: () = {
    use capstone::arch::arm64::Arm64OperandType;
    use capstone::prelude::DetailsArchInsn;

    impl Inst {
        pub fn disp(&self, dis: &Disassembler) -> Option<usize> {
            let detail = dis.cap.insn_detail(&self.insn).ok()?;
            let arch_detail = detail.arch_detail();
            let arm_detail = arch_detail.arm64()?;
            arm_detail.operands().find_map(|x| match x.op_type {
                Arm64OperandType::Imm(imm) => Some(imm as usize),
                Arm64OperandType::Mem(mem) => Some(mem.disp() as usize),
                _ => None,
            })
        }

        pub fn has_reg(&self, reg: u16, dis: &Disassembler) -> bool {
            // 注意：`detail` 必须绑定到局部变量——`arch_detail()` 借用它，
            // 若写成临时值链式调用会在语句结束时被释放。
            let Ok(detail) = dis.cap.insn_detail(&self.insn) else {
                return false;
            };
            let arch_detail = detail.arch_detail();
            let Some(arm_detail) = arch_detail.arm64() else {
                return false;
            };
            arm_detail
                .operands()
                .find_map(|x| {
                    if let Arm64OperandType::Reg(id) = x.op_type {
                        Some(id.0 == reg)
                    } else {
                        None
                    }
                })
                .unwrap_or(false)
        }

        #[inline(always)]
        pub fn is_end(&self) -> bool {
            self.insn.id().0 == Arm64Insn::ARM64_INS_BR as u32
                || self.insn.id().0 == Arm64Insn::ARM64_INS_B as u32
        }
    }
};

/// 一条已解码指令，附带重定位所需的预计算信息。
///
/// 重定位信息在解码时一次性提取，因此 [`move_inst`] 只需 `&Inst`，
/// 不必再借 `Disassembler`，避免与 `Disassembler::next()` 的 `&mut` 借用冲突。
///
/// 内部持有 `OwnedInsn<'static>`：`OwnedInsn` 实际**自持**数据——`bytes` 是定长
/// 数组 `[u8; 24]`，`detail` 由 `Box` 拥有并在其 `Drop` 中释放，`'a` 仅用于
/// `PhantomData` 标记。因此这里不保留该虚假生命周期，避免 `Inst` 长期占用
/// `Disassembler` 的借用，导致 `mem.rs` 等处出现 `&mut`/`&` 冲突。
pub struct Inst {
    insn: OwnedInsn<'static>,
    /// RIP 相对寻址的 disp32 字节偏移（仅 x64）。
    rip_disp: Option<usize>,
    /// 相对分支的编码信息。
    branch: Option<RelBranch>,
}

impl Inst {
    pub fn addr(&self) -> usize {
        self.insn.address() as usize
    }

    /// 指令的原始字节。
    pub fn bytes(&self) -> &[u8] {
        self.insn.bytes()
    }

    /// RIP 相对寻址的 disp32 字段偏移（仅 x64 有效）。
    #[allow(dead_code)]
    pub fn rip_disp_offset(&self) -> Option<usize> {
        self.rip_disp
    }

    /// 相对分支的编码信息。
    #[allow(dead_code)]
    pub fn rel_branch(&self) -> Option<RelBranch> {
        self.branch
    }
}

/// 一条指令搬移后的形态：写入长度与需要回填的相对分支。
///
/// 由 [`plan_inst`] 先算出来，调用方据此检查 trampoline 容量，**确认放得下**
/// 之后才调用 [`move_inst`] 真正写入——避免先写后查导致越界。
#[derive(Debug, Clone, Copy)]
pub(crate) struct MovePlan {
    /// 原指令字节数。
    pub src_len: usize,
    /// 将要写入的字节数。
    pub dst_len: usize,
    /// 待第二遍修正的相对分支。
    pub branch: Option<BranchFixup>,
}

/// 计算搬移形态，不写任何内存。
///
/// 这是 [`move_inst`] 的纯计算部分，调用方必须在写入前用它的 `dst_len`
/// 校验目标缓冲区容量。
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn plan_inst(inst: &Inst) -> Option<MovePlan> {
    let src_len = inst.bytes().len();

    if let Some(br) = inst.rel_branch() {
        let (disp_off, dst_len) = if br.size == 1 {
            // rel8 扩宽为 rel32：eb → e9（2→5），7x → 0f 8x（2→6）
            match inst.bytes().get(br.prefix_len)? {
                0xeb => (1, 5),
                _ => (2, 6),
            }
        } else {
            (br.offset, src_len)
        };
        return Some(MovePlan {
            src_len,
            dst_len,
            branch: Some(BranchFixup {
                disp_off,
                dst_len,
                target: br.target,
            }),
        });
    }

    Some(MovePlan {
        src_len,
        dst_len: src_len,
        branch: None,
    })
}

/// 把一条指令搬移到 trampoline 的 `dst`，并按需重定位。
///
/// 对齐 C++ `CDetourDis::CopyInstruction` 的行为：
/// - rel8 分支扩宽为 rel32（`eb` → `e9`，`7x` → `0f 8x`），保证搬移后仍可达；
/// - RIP 相对寻址重算 disp32；
/// - rel32 分支的位移在第二遍由 [`fix_branch`] 修正。
///
/// **调用方必须先通过 [`plan_inst`] 确认 `dst` 处至少有 `dst_len` 字节可写。**
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn move_inst(inst: &Inst, dst: *mut u8) -> Option<Moved> {
    let bytes = inst.bytes();
    let src_len = bytes.len();

    // 形态判定统一走 plan_inst，确保与调用方的容量检查用同一套长度。
    let plan = plan_inst(inst)?;

    // 1) 相对分支：按需扩宽编码。
    if let Some(br) = inst.rel_branch() {
        let mk = |disp_off, dst_len| {
            Some(Moved {
                src_len,
                dst_len,
                branch: Some(BranchFixup {
                    disp_off,
                    dst_len,
                    target: br.target,
                }),
            })
        };

        if br.size == 1 {
            let op = *bytes.get(br.prefix_len)?;
            let (disp_off, dst_len) = if op == 0xeb {
                // jmp rel8 → jmp rel32
                unsafe { *dst = 0xe9 };
                (1, 5)
            } else {
                // jcc rel8 → jcc rel32（7x → 0f 8x）
                unsafe {
                    *dst = 0x0f;
                    *dst.add(1) = 0x80 | (op & 0x0f);
                }
                (2, 6)
            };
            return mk(disp_off, dst_len);
        }

        // rel32：原样拷贝，位移留待第二遍修正。
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), dst, src_len) };
        return mk(br.offset, src_len);
    }

    // 2) 普通指令：整条拷贝。
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), dst, src_len) };

    // 3) 含 RIP 相对寻址时重算 disp32。
    #[cfg(target_arch = "x86_64")]
    if let Some(off) = inst.rip_disp_offset() {
        let raw: [u8; 4] = bytes.get(off..off + 4)?.try_into().ok()?;
        let old_disp = i32::from_le_bytes(raw);
        let new_disp = relocate_rip_disp(old_disp, inst.addr(), dst as usize)?;
        unsafe {
            ptr::write_unaligned(dst.add(off).cast::<i32>(), new_disp);
        }
    }

    Some(Moved {
        src_len,
        dst_len: src_len,
        branch: None,
    })
}

/// 第二遍：修正 rel32 位移，使其重新指向原始绝对目标。
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn fix_branch(dst: *mut u8, fixup: BranchFixup) {
    let disp = relocate_branch_disp(fixup.target, dst as usize, fixup.dst_len);
    unsafe {
        ptr::write_unaligned(dst.add(fixup.disp_off).cast::<i32>(), disp);
    }
}

/// 未支持重定位的架构：仅原样拷贝。
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) fn move_inst(inst: &Inst, dst: *mut u8) -> Option<Moved> {
    let bytes = inst.bytes();
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };
    Some(Moved {
        src_len: bytes.len(),
        dst_len: bytes.len(),
        branch: None,
    })
}

/// 未支持重定位的架构：不做重定位，写入长度等于原指令长度。
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) fn plan_inst(inst: &Inst) -> Option<MovePlan> {
    let len = inst.bytes().len();
    Some(MovePlan {
        src_len: len,
        dst_len: len,
        branch: None,
    })
}

/// 未支持重定位的架构无相对分支需要回填。
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) fn fix_branch(_dst: *mut u8, _fixup: BranchFixup) {
    unreachable!("no relocatable branch on unsupported arch")
}

pub struct Disassembler {
    cap: capstone::Capstone,
    ip: usize,
}

impl Disassembler {
    pub fn new() -> Disassembler {
        Disassembler {
            cap: capstone(),
            ip: 0,
        }
    }

    #[inline(always)]
    pub fn set_ip(&mut self, ip: usize) {
        self.ip = ip;
    }

    #[inline(always)]
    pub fn next(&mut self) -> Option<Inst> {
        self.disasm_one(self.ip)
    }

    pub fn disasm_one(&mut self, ip: usize) -> Option<Inst> {
        if ip == 0 {
            return None;
        }

        // x86 单条指令最长 15 字节，故最多读 16 字节。但不能闭眼读满：
        // 目标地址可能紧贴页边界，跨页读会触发访问违例。
        // 先问出本地址所在内存区域的剩余长度，再据此切片。
        let avail = crate::platform::readable_len(ip, ONE_INSTRUCTION_MAX_SIZE);
        if avail == 0 {
            return None;
        }

        let insn = unsafe { ptr::slice_from_raw_parts(ip as *const u8, avail).as_ref() }
            .and_then(|b| self.cap.disasm_count(b, self.ip as u64, 1).ok())
            .and_then(|insts| insts.iter().next().map(OwnedInsn::from))?;

        // SAFETY: `OwnedInsn` 自持全部数据——`bytes` 是定长数组 `[u8; 24]`，
        // `detail` 由 `Box` 拥有并在其 `Drop` 中释放，生命周期参数只用于
        // `PhantomData` 标记（见 capstone 的 `OwnedInsn` 定义与 `Drop` 实现）。
        // 因此把局部 `insns` 的借用放宽为 `'static` 不会产生悬垂引用；
        // 这样做是为了不让 `Inst` 长期占用 `Disassembler` 的借用。
        let insn: OwnedInsn<'static> = unsafe { std::mem::transmute(insn) };

        self.ip = ip + insn.len();

        // 重定位信息在这里一次性提取，使 move_inst 不必再借 Disassembler。
        let rip_disp = detect_rip_disp(&insn, &self.cap);
        let branch = detect_rel_branch(&insn, &self.cap);

        Some(Inst {
            insn,
            rip_disp,
            branch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── modrm_disp_offset：按编码规则推算 disp32 位置 ──

    #[test]
    fn disp_offset_matches_known_encodings() {
        // mov rax, [rip+0x1234] => 48 8b 05 34 12 00 00
        assert_eq!(
            modrm_disp_offset(&[0x48, 0x8b, 0x05, 0x34, 0x12, 0x00, 0x00]),
            Some(3)
        );
        // mov eax, [rip+0] => 8b 05 00 00 00 00
        assert_eq!(
            modrm_disp_offset(&[0x8b, 0x05, 0x00, 0x00, 0x00, 0x00]),
            Some(2)
        );
        // mov word [rip+d], imm16 => 66 c7 05 .. .. .. .. ..
        assert_eq!(
            modrm_disp_offset(&[0x66, 0xc7, 0x05, 0x10, 0x00, 0x00, 0x00, 0x34, 0x12]),
            Some(3)
        );
        // movdqa xmm0, [rip+d] => 66 0f 6f 05 ...
        assert_eq!(
            modrm_disp_offset(&[0x66, 0x0f, 0x6f, 0x05, 0x10, 0x00, 0x00, 0x00]),
            Some(4)
        );
        // movsd xmm0, [rip+d] => f2 0f 10 05 ...
        assert_eq!(
            modrm_disp_offset(&[0xf2, 0x0f, 0x10, 0x05, 0x10, 0x00, 0x00, 0x00]),
            Some(4)
        );
        // VEX2 vmovups => c5 f8 10 05 ...
        assert_eq!(
            modrm_disp_offset(&[0xc5, 0xf8, 0x10, 0x05, 0x10, 0x00, 0x00, 0x00]),
            Some(4)
        );
        // VEX3 => c4 e1 78 10 05 ...
        assert_eq!(
            modrm_disp_offset(&[0xc4, 0xe1, 0x78, 0x10, 0x05, 0x10, 0x00, 0x00, 0x00]),
            Some(5)
        );
        // 0f 38 xx => 三字节 opcode
        assert_eq!(
            modrm_disp_offset(&[0x0f, 0x38, 0xf0, 0x05, 0x10, 0x00, 0x00, 0x00]),
            Some(4)
        );
        // 0f 3a xx
        assert_eq!(
            modrm_disp_offset(&[0x0f, 0x3a, 0x0f, 0x05, 0x10, 0x00, 0x00, 0x00, 0x11]),
            Some(4)
        );
        // 地址长度前缀 + REX
        assert_eq!(
            modrm_disp_offset(&[0x67, 0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00]),
            Some(4)
        );
    }

    // ── decode_rel_branch：从字节解算分支目标 ──

    #[test]
    fn rel_branch_jmp_rel32() {
        // e9 10 00 00 00 @ 0x1000 → 目标 0x1015
        let br = decode_rel_branch(&[0xe9, 0x10, 0x00, 0x00, 0x00], 0x1000).unwrap();
        assert_eq!((br.offset, br.size, br.target), (1, 4, 0x1015));
    }

    #[test]
    fn rel_branch_call_rel32_negative() {
        // e8 f0 ff ff ff @ 0x1000 → 0x1005 - 0x10 = 0xff5
        let br = decode_rel_branch(&[0xe8, 0xf0, 0xff, 0xff, 0xff], 0x1000).unwrap();
        assert_eq!((br.offset, br.size, br.target), (1, 4, 0xff5));
    }

    #[test]
    fn rel_branch_jmp_rel8() {
        // eb 10 @ 0x1000 → 0x1002 + 0x10
        let br = decode_rel_branch(&[0xeb, 0x10], 0x1000).unwrap();
        assert_eq!((br.offset, br.size, br.target), (1, 1, 0x1012));
    }

    #[test]
    fn rel_branch_jcc_rel8_and_rel32() {
        // je rel8: 74 10 @ 0x1000
        let br = decode_rel_branch(&[0x74, 0x10], 0x1000).unwrap();
        assert_eq!((br.offset, br.size, br.target), (1, 1, 0x1012));

        // je rel32: 0f 84 10 00 00 00 @ 0x1000
        let br = decode_rel_branch(&[0x0f, 0x84, 0x10, 0x00, 0x00, 0x00], 0x1000).unwrap();
        assert_eq!((br.offset, br.size, br.target), (2, 4, 0x1016));
    }

    #[test]
    fn rel_branch_negative_rel8() {
        // eb f0 @ 0x1000 → 0x1002 - 0x10
        let br = decode_rel_branch(&[0xeb, 0xf0], 0x1000).unwrap();
        assert_eq!(br.target, 0xff2);
    }

    #[test]
    fn rel_branch_skips_legacy_prefix() {
        // 66 e9 .. （操作数前缀 + jmp rel32）
        let br = decode_rel_branch(&[0x66, 0xe9, 0x10, 0x00, 0x00, 0x00], 0x1000).unwrap();
        assert_eq!(br.prefix_len, 1);
        assert_eq!((br.offset, br.size, br.target), (2, 4, 0x1016));
    }

    #[test]
    fn rel_branch_rejects_non_branch() {
        assert!(decode_rel_branch(&[0x90], 0x1000).is_none());
        assert!(decode_rel_branch(&[0xc3], 0x1000).is_none());
        assert!(decode_rel_branch(&[0x8b, 0x05, 0x00, 0x00, 0x00, 0x00], 0x1000).is_none());
    }

    // ── relocate_rip_disp：RIP 相对位移重算 ──

    #[test]
    fn rip_disp_identity_when_not_moved() {
        // 不搬移时位移不变
        assert_eq!(relocate_rip_disp(0x100, 0x2000, 0x2000), Some(0x100));
    }

    #[test]
    fn rip_disp_preserves_absolute_target() {
        let src = 0x1000usize;
        let dst = 0x8000usize;
        let old = 0x40i32;

        // 原目标 = src + len + old（下一条指令起算）
        let len = 7usize;
        let target = src as i64 + len as i64 + old as i64;

        let new = relocate_rip_disp(old, src, dst).unwrap();
        let new_target = dst as i64 + len as i64 + new as i64;

        assert_eq!(new_target, target, "搬移后 RIP 相对寻址仍指向同一绝对地址");
    }

    #[test]
    fn rip_disp_negative_source() {
        let src = 0x9000usize;
        let dst = 0x1000usize;
        let old = -0x50i32;
        let len = 6usize;

        let target = src as i64 + len as i64 + old as i64;
        let new = relocate_rip_disp(old, src, dst).unwrap();
        assert_eq!(dst as i64 + len as i64 + new as i64, target);
    }

    #[test]
    fn rip_disp_overflow_is_rejected() {
        // 位移超出 i32 表示范围时应返回 None，而不是静默截断
        assert!(relocate_rip_disp(i32::MAX, 0, usize::MAX / 2).is_none());
    }

    // ── relocate_branch_disp：相对分支位移重算 ──

    #[test]
    fn branch_disp_preserves_absolute_target() {
        let target = 0x5000usize;
        let dst = 0x10000usize;
        let dst_len = 5usize;

        let disp = relocate_branch_disp(target, dst, dst_len);
        let resolved = (dst as i64 + dst_len as i64 + disp as i64) as usize;
        assert_eq!(resolved, target);
    }

    #[test]
    fn branch_disp_backward() {
        let target = 0x1000usize;
        let dst = 0x9000usize;
        let dst_len = 6usize;

        let disp = relocate_branch_disp(target, dst, dst_len);
        assert!(disp < 0, "反向分支位移应为负");
        assert_eq!((dst as i64 + dst_len as i64 + disp as i64) as usize, target);
    }

    // ── is_code_filler：NOP / int3 padding 识别 ──

    #[test]
    fn filler_recognizes_all_nop_lengths() {
        // 1..=11 字节的标准 NOP 序列
        let cases: [(&[u8], usize); 11] = [
            (&[0x90], 1),
            (&[0x66, 0x90], 2),
            (&[0x0f, 0x1f, 0x00], 3),
            (&[0x0f, 0x1f, 0x40, 0x00], 4),
            (&[0x0f, 0x1f, 0x44, 0x00, 0x00], 5),
            (&[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00], 6),
            (&[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00], 7),
            (&[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00], 8),
            (&[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00], 9),
            (
                &[0x66, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
                10,
            ),
            (
                &[
                    0x66, 0x66, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                11,
            ),
        ];

        for (bytes, want) in cases {
            assert_eq!(
                is_code_filler(bytes),
                want,
                "{bytes:02x?} 应识别为 {want} 字节 filler"
            );
        }
    }

    #[test]
    fn filler_prefers_longest_match() {
        // 66 90 是 2 字节 NOP，不能被当成 1 字节 90 之后的多余字节
        assert_eq!(is_code_filler(&[0x66, 0x90]), 2);
        // 更长的 66 66 0f 1f 序列不能被短模式抢先匹配
        assert_eq!(
            is_code_filler(&[0x66, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]),
            10
        );
    }

    #[test]
    fn filler_recognizes_int3() {
        assert_eq!(is_code_filler(&[0xcc]), 1);
        // 连续 int3 每次消费 1 字节
        assert_eq!(is_code_filler(&[0xcc, 0xcc, 0xcc]), 1);
    }

    #[test]
    fn filler_rejects_real_instructions() {
        assert_eq!(
            is_code_filler(&[0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00]),
            0
        );
        assert_eq!(is_code_filler(&[0xc3]), 0, "ret 不是 filler");
        assert_eq!(
            is_code_filler(&[0xe9, 0x00, 0x00, 0x00, 0x00]),
            0,
            "jmp 不是 filler"
        );
        assert_eq!(is_code_filler(&[0x55]), 0, "push rbp 不是 filler");
        assert_eq!(is_code_filler(&[]), 0, "空切片不是 filler");
    }

    // ── is_legacy_prefix ──

    #[test]
    fn legacy_prefix_recognition() {
        for b in [
            0xf0u8, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0x66, 0x67,
        ] {
            assert!(is_legacy_prefix(b), "{b:#x} 应识别为 legacy 前缀");
        }
        for b in [0x48u8, 0x90, 0x0f, 0xe8, 0xeb, 0x40] {
            assert!(!is_legacy_prefix(b), "{b:#x} 不应识别为 legacy 前缀");
        }
    }
}
