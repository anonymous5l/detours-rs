use crate::Error;
use crate::platform::{PAGE_FLAG_EXECUTE_READWRITE, vprotect};
use std::ffi::c_void;
use std::ptr;

pub type MemoryAllocType = u32;
pub type PageProtectionFlag = u32;

/// 计算实际可安全拷贝的字节数：不得超过目标区间长度。
///
/// 独立成纯函数，便于在任何平台单测「不会越界写」这一不变量。
#[inline]
pub(crate) fn clamp_copy_size(requested: usize, capacity: usize) -> usize {
    requested.min(capacity)
}

pub struct MemoryBasicInfo {
    pub base_address: *const c_void,
    pub allocation_base: *const c_void,
    pub region_size: usize,
    pub state: MemoryAllocType,
}

pub struct MemoryProtector {
    addr: usize,
    size: usize,
    old_flag: PageProtectionFlag,
}

impl MemoryProtector {
    pub fn new(addr: usize, size: usize) -> Result<MemoryProtector, Error> {
        vprotect(addr as *const c_void, size, PAGE_FLAG_EXECUTE_READWRITE).map(|old_flag| {
            MemoryProtector {
                addr,
                size,
                old_flag,
            }
        })
    }

    pub fn new_with<T: Sized>(addr: usize) -> Result<MemoryProtector, Error> {
        Self::new(addr, size_of::<T>())
    }

    pub fn write_override<T>(&mut self, value: T) -> usize {
        let t_size = size_of_val(&value);
        if t_size > self.size {
            return 0;
        }
        // 目标可能是任意用户地址，不保证按 `T` 对齐；`ptr::write` 要求对齐，
        // 否则是未定义行为。改用 `write_unaligned`。
        unsafe {
            ptr::write_unaligned(self.addr as *mut T, value);
        }
        t_size
    }

    /// 从 `from` 拷贝 `size` **字节**到受保护地址。
    ///
    /// 注意：`size` 是字节数而非 `T` 的元素个数——与 Win32 `CopyMemory` 语义一致。
    /// 早期版本误把它当元素个数，导致按 `size_of::<T>()` 倍数越界写入。
    ///
    /// # Safety
    ///
    /// `from` 必须可读至少 `size` 字节，且 `size` 不超过构造时声明的可写长度。
    pub unsafe fn write_from_with_size<T>(&mut self, from: *const T, size: usize) -> usize {
        let copied = clamp_copy_size(size, self.size);
        if copied == 0 {
            return 0;
        }
        unsafe { ptr::copy_nonoverlapping(from.cast::<u8>(), self.addr as *mut u8, copied) };
        copied
    }
}

impl Drop for MemoryProtector {
    fn drop(&mut self) {
        let _ = vprotect(self.addr as *const c_void, self.size, self.old_flag);
    }
}

#[inline]
pub fn detour_2gb_below(addr: usize) -> usize {
    if addr > 0x7ff80000 {
        addr - 0x7ff80000
    } else {
        0x80000
    }
}

#[inline]
pub fn detour_2gb_above(addr: usize) -> usize {
    #[cfg(target_pointer_width = "64")]
    if addr < 0xffffffff80000000 {
        addr + 0x7ff80000
    } else {
        0xfffffffffff80000
    }

    #[cfg(target_pointer_width = "32")]
    if addr < 0x80000000 {
        addr + 0x7ff80000
    } else {
        0xfff80000
    }
}

/// `jmp rel32` 的编码长度。
pub const JMP_REL32_SIZE: usize = 5;
/// `jmp qword ptr [rip+disp32]` 的编码长度。
pub const JMP_RIP_INDIRECT_SIZE: usize = 6;

/// 计算从 `addr` 起**可安全连续读取**的字节数，上限为 `want`。
///
/// 目标代码的末尾常常紧贴页边界，直接 `from_raw_parts(addr, 16)` 会跨进
/// 未映射页触发访问违例。这里查出所在内存区域的剩余长度并据此截断；
/// 查询失败时保守返回 0，让调用方放弃而不是冒险读。
///
/// 结果始终不超过 `want`，也不跨越区域边界。
pub(crate) fn readable_len(addr: usize, want: usize) -> usize {
    if addr == 0 || want == 0 {
        return 0;
    }
    let Some(mbi) = crate::platform::vquery(addr as *const c_void) else {
        return 0;
    };

    let base = mbi.base_address as usize;
    let end = base.saturating_add(mbi.region_size);
    let avail = end.saturating_sub(addr);
    avail.min(want)
}

/// 编码 `jmp rel32`（`e9` + 相对位移）。
///
/// 位移相对「下一条指令」，即 `from + 5`。
/// 纯字节计算，与目标架构无关，便于在任何平台单测。
#[inline]
pub(crate) fn encode_jmp_rel32(from: usize, to: usize) -> [u8; JMP_REL32_SIZE] {
    let disp = (to as i64 - (from as i64 + JMP_REL32_SIZE as i64)) as i32;
    let mut out = [0u8; JMP_REL32_SIZE];
    out[0] = 0xe9;
    out[1..].copy_from_slice(&disp.to_le_bytes());
    out
}

/// 编码 `jmp qword ptr [rip+disp32]`（`ff 25` + 相对位移）。
///
/// 位移相对「下一条指令」，即 `from + 6`；跳转时从 `slot` 处取 8 字节目标地址，
/// 因此不受 rel32 的 ±2GB 可达范围限制。
/// 纯字节计算，与目标架构无关，便于在任何平台单测。
#[inline]
pub(crate) fn encode_jmp_rip_indirect(from: usize, slot: usize) -> [u8; JMP_RIP_INDIRECT_SIZE] {
    let disp = (slot as i64 - (from as i64 + JMP_RIP_INDIRECT_SIZE as i64)) as i32;
    let mut out = [0u8; JMP_RIP_INDIRECT_SIZE];
    out[0] = 0xff;
    out[1] = 0x25;
    out[2..].copy_from_slice(&disp.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── encode_jmp_rel32 ──

    #[test]
    fn jmp_rel32_encoding_shape() {
        let out = encode_jmp_rel32(0x1000, 0x1010);
        assert_eq!(out.len(), JMP_REL32_SIZE);
        assert_eq!(out[0], 0xe9, "操作码应为 jmp rel32");
    }

    #[test]
    fn jmp_rel32_disp_is_relative_to_next_instruction() {
        // from=0x1000, 下一条指令在 0x1005；目标 0x1010 → disp = 0xB
        let out = encode_jmp_rel32(0x1000, 0x1010);
        let disp = i32::from_le_bytes(out[1..5].try_into().unwrap());
        assert_eq!(disp, 0xB);
        // 反向验证：from + 5 + disp == to
        assert_eq!(0x1000i64 + 5 + disp as i64, 0x1010);
    }

    #[test]
    fn jmp_rel32_backward_is_negative() {
        let out = encode_jmp_rel32(0x9000, 0x1000);
        let disp = i32::from_le_bytes(out[1..5].try_into().unwrap());
        assert!(disp < 0, "向后跳转位移应为负");
        assert_eq!(0x9000i64 + 5 + disp as i64, 0x1000);
    }

    #[test]
    fn jmp_rel32_round_trip_many_offsets() {
        for delta in [-0x1000i64, -5, 0, 5, 0x100, 0x7fff_0000] {
            let from = 0x400000usize;
            let to = (from as i64 + delta) as usize;
            let out = encode_jmp_rel32(from, to);
            let disp = i32::from_le_bytes(out[1..5].try_into().unwrap());
            assert_eq!(from as i64 + 5 + disp as i64, to as i64, "delta={delta}");
        }
    }

    // ── encode_jmp_rip_indirect ──

    #[test]
    fn jmp_rip_indirect_encoding_shape() {
        let out = encode_jmp_rip_indirect(0x1000, 0x2000);
        assert_eq!(out.len(), JMP_RIP_INDIRECT_SIZE);
        assert_eq!(&out[0..2], &[0xff, 0x25], "应为 jmp [rip+disp32]");
    }

    #[test]
    fn jmp_rip_indirect_disp_points_at_slot() {
        let from = 0x1000usize;
        let slot = 0x2000usize;
        let out = encode_jmp_rip_indirect(from, slot);
        let disp = i32::from_le_bytes(out[2..6].try_into().unwrap());
        // rip 在解码时已指向下一条指令，故 slot = from + 6 + disp
        assert_eq!(from as i64 + 6 + disp as i64, slot as i64);
    }

    #[test]
    fn jmp_rip_indirect_negative_disp() {
        // 槽位在指令之前（Trampoline 中 detour 槽位位于 code_in 之前）
        let from = 0x9000usize;
        let slot = 0x1000usize;
        let out = encode_jmp_rip_indirect(from, slot);
        let disp = i32::from_le_bytes(out[2..6].try_into().unwrap());
        assert!(disp < 0);
        assert_eq!(from as i64 + 6 + disp as i64, slot as i64);
    }

    // ── detour_2gb_below / above ──

    #[test]
    fn jmp_bounds_ordering() {
        let addr = 0x1000_0000usize;
        assert!(detour_2gb_below(addr) < addr);
        assert!(detour_2gb_above(addr) > addr);
    }

    #[test]
    fn detour_2gb_below_has_floor() {
        // 地址很小的时候不能下溢到 0 附近
        assert_eq!(detour_2gb_below(0), 0x80000);
        assert_eq!(detour_2gb_below(0x100), 0x80000);
    }

    // ── clamp_copy_size：防止越界写 ──

    #[test]
    fn copy_size_never_exceeds_capacity() {
        // 这是早期 bug 的回归测试：把「元素个数」当「字节数」会放大写入量。
        // 修复后无论请求多大，最多只拷贝 capacity 字节。
        assert_eq!(clamp_copy_size(5, 5), 5);
        assert_eq!(clamp_copy_size(1, 5), 1);
        assert_eq!(clamp_copy_size(280, 5), 5, "超出容量必须被夹到容量");
        assert_eq!(clamp_copy_size(usize::MAX, 5), 5);
    }

    #[test]
    fn copy_size_zero_capacity_writes_nothing() {
        assert_eq!(clamp_copy_size(0, 0), 0);
        assert_eq!(clamp_copy_size(10, 0), 0);
    }

    // ── readable_len：防止跨页读取 ──

    #[test]
    fn readable_len_rejects_null_and_zero() {
        // 空指针与零长度请求都不能放行
        assert_eq!(readable_len(0, 16), 0);
        assert_eq!(readable_len(0x1000, 0), 0);
    }

    #[test]
    fn readable_len_never_exceeds_request() {
        // 无论区域多大，返回都不得超过调用方请求的长度
        // （用栈上变量取得一个真实可查询的地址）
        let buf = [0u8; 64];
        let addr = buf.as_ptr() as usize;
        assert!(readable_len(addr, 16) <= 16);
        assert!(readable_len(addr, 1) <= 1);
    }
}
