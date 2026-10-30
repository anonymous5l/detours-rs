use crate::Error;
use crate::platform::{MemoryAllocType, MemoryBasicInfo, PageProtectionFlag};
use std::ffi::c_void;
use std::mem::MaybeUninit;

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
mod mach_sys {
    pub type mach_port_t = std::ffi::c_uint;
    pub type kern_return_t = std::ffi::c_int;
    pub type natural_t = std::ffi::c_uint;
    pub type mach_msg_type_number_t = natural_t;
    pub type vm_region_info_t = *mut std::ffi::c_int;
    pub type vm_region_recurse_info_t = *mut std::ffi::c_int;
    pub type vm_region_flavor_t = std::ffi::c_int;
    pub type mach_vm_size_t = usize;
    pub type mach_vm_address_t = usize;
    pub type vm_task_entry_t = mach_port_t;
    pub type vm_map_read_t = mach_port_t;
    pub type vm_map_t = mach_port_t;
    pub type vm_prot_t = std::ffi::c_int;
    pub type vm_inherit_t = std::ffi::c_uint;
    pub type boolean_t = std::ffi::c_int;
    pub type vm_behavior_t = std::ffi::c_int;
    pub type vm32_object_id_t = u32;
    pub type memory_object_offset_t = std::ffi::c_ulonglong;
    pub type mach_vm_offset_t = usize;
    pub type integer_t = std::ffi::c_int;
    pub type vm_page_info_flavor_t = std::ffi::c_int;
    pub type vm_page_info_t = *mut std::ffi::c_int;
    pub type vm_object_id_t = std::ffi::c_ulonglong;
    pub type mem_entry_name_port_t = mach_port_t;

    /*
     * The following behaviors affect the memory region's future behavior
     * and are stored in the VM map entry data structure.
     */
    pub const VM_BEHAVIOR_DEFAULT: vm_behavior_t = 0; /* default */
    pub const VM_BEHAVIOR_RANDOM: vm_behavior_t = 1; /* random */
    pub const VM_BEHAVIOR_SEQUENTIAL: vm_behavior_t = 2; /* forward sequential */
    pub const VM_BEHAVIOR_RSEQNTL: vm_behavior_t = 3; /* reverse sequential */

    /*
     * The following "behaviors" affect the memory region only at the time of the
     * call and are not stored in the VM map entry.
     */
    pub const VM_BEHAVIOR_WILLNEED: vm_behavior_t = 4; /* will need in near future */
    pub const VM_BEHAVIOR_DONTNEED: vm_behavior_t = 5; /* dont need in near future */
    pub const VM_BEHAVIOR_FREE: vm_behavior_t = 6; /* free memory without write-back */
    pub const VM_BEHAVIOR_ZERO_WIRED_PAGES: vm_behavior_t = 7; /* zero out the wired pages of an entry if it is being deleted without unwiring them first */
    pub const VM_BEHAVIOR_REUSABLE: vm_behavior_t = 8;
    pub const VM_BEHAVIOR_REUSE: vm_behavior_t = 9;
    pub const VM_BEHAVIOR_CAN_REUSE: vm_behavior_t = 10;
    pub const VM_BEHAVIOR_PAGEOUT: vm_behavior_t = 11; /* force page-out of the pages in range (development only) */
    pub const VM_BEHAVIOR_ZERO: vm_behavior_t = 12; /* zero pages without faulting in additional pages */

    #[derive(Debug)]
    #[repr(C)]
    pub struct vm_region_submap_info {
        pub protection: vm_prot_t,
        pub max_protection: vm_prot_t,
        pub inheritance: vm_inherit_t,
        pub offset: u32,
        pub user_tag: std::ffi::c_uint,
        pub pages_resident: std::ffi::c_uint,
        pub pages_shared_now_private: std::ffi::c_uint,
        pub pages_swapped_out: std::ffi::c_uint,
        pub pages_dirtied: std::ffi::c_uint,
        pub ref_count: std::ffi::c_uint,
        pub shadow_depth: std::ffi::c_ushort,
        pub external_pager: std::ffi::c_uchar,
        pub share_mode: std::ffi::c_uchar,
        pub is_submap: boolean_t,
        pub behavior: vm_behavior_t,
        pub object_id: vm32_object_id_t,
        pub user_wired_count: std::ffi::c_ushort,
    }

    pub const VM_REGION_SUBMAP_INFO_COUNT: mach_msg_type_number_t =
        (size_of::<vm_region_submap_info>() / size_of::<natural_t>()) as mach_msg_type_number_t;

    #[derive(Debug)]
    #[repr(C)]
    pub struct vm_region_basic_info_64 {
        pub protection: vm_prot_t,
        pub max_protection: vm_prot_t,
        pub inheritance: vm_inherit_t,
        pub shared: boolean_t,
        pub reserved: boolean_t,
        pub offset: memory_object_offset_t,
        pub behavior: vm_behavior_t,
        pub user_wired_count: u16,
    }
    pub const VM_REGION_BASIC_INFO_64: vm_region_flavor_t = 9;
    pub const VM_REGION_BASIC_INFO_COUNT_64: mach_msg_type_number_t =
        (size_of::<vm_region_basic_info_64>() / size_of::<std::ffi::c_int>())
            as mach_msg_type_number_t;

    #[derive(Debug)]
    #[repr(C)]
    pub struct vm_page_info_basic {
        pub disposition: std::ffi::c_int,
        pub ref_count: std::ffi::c_int,
        pub object_id: vm_object_id_t,
        pub offset: memory_object_offset_t,
        pub depth: std::ffi::c_int,
        pub __pad: std::ffi::c_int,
    }
    pub const VM_PAGE_INFO_BASIC: vm_page_info_flavor_t = 1;
    pub const VM_PAGE_INFO_BASIC_COUNT: mach_msg_type_number_t =
        (size_of::<vm_page_info_basic>() / size_of::<std::ffi::c_int>()) as mach_msg_type_number_t;

    pub const VM_PROT_READ: vm_prot_t = 0x01;
    pub const VM_PROT_WRITE: vm_prot_t = 0x02;
    pub const VM_PROT_EXECUTE: vm_prot_t = 0x04;
    pub const VM_PROT_COPY: vm_prot_t = 0x10;
    pub const VM_FLAGS_FIXED: std::ffi::c_uint = 0x00000000;
    pub const VM_FLAGS_ANYWHERE: std::ffi::c_uint = 0x00000001;
    pub const VM_FLAGS_PURGABLE: std::ffi::c_uint = 0x00000002;
    pub const VM_FLAGS_4GB_CHUNK: std::ffi::c_uint = 0x00000004;
    pub const VM_FLAGS_RANDOM_ADDR: std::ffi::c_uint = 0x00000008;
    pub const VM_FLAGS_NO_CACHE: std::ffi::c_uint = 0x00000010;
    pub const VM_FLAGS_RESILIENT_CODESIGN: std::ffi::c_uint = 0x00000020;
    pub const VM_FLAGS_RESILIENT_MEDIA: std::ffi::c_uint = 0x00000040;
    pub const VM_FLAGS_PERMANENT: std::ffi::c_uint = 0x00000080;
    pub const VM_FLAGS_TPRO: std::ffi::c_uint = 0x00001000;
    pub const VM_FLAGS_OVERWRITE: std::ffi::c_uint = 0x00004000; /* delete any existing mappings first */
    /*
     * VM_FLAGS_SUPERPAGE_MASK
     *	3 bits that specify whether large pages should be used instead of
     *	base pages (!=0), as well as the requested page size.
     */
    pub const VM_FLAGS_SUPERPAGE_MASK: std::ffi::c_uint = 0x00070000; /* bits 0x10000, 0x20000, 0x40000 */
    pub const VM_FLAGS_RETURN_DATA_ADDR: std::ffi::c_uint = 0x00100000; /* Return address of target data, rather than base of page */
    pub const VM_FLAGS_RETURN_4K_DATA_ADDR: std::ffi::c_uint = 0x00800000; /* Return 4K aligned address of target data */
    pub const VM_FLAGS_ALIAS_MASK: std::ffi::c_uint = 0xFF000000;

    unsafe extern "C" {
        static mach_task_self_: mach_port_t;

        pub fn mach_vm_region(
            target_task: vm_map_read_t,
            address: &mut mach_vm_address_t,
            size: &mut mach_vm_size_t,
            flavor: vm_region_flavor_t,
            info: vm_region_info_t,
            infoCnt: &mut mach_msg_type_number_t,
            object_name: &mut mach_port_t,
        ) -> kern_return_t;

        pub fn mach_vm_region_recurse(
            target_task: vm_map_read_t,
            address: &mut mach_vm_address_t,
            size: &mut mach_vm_size_t,
            nesting_depth: &mut natural_t,
            info: vm_region_recurse_info_t,
            infoCnt: &mut mach_msg_type_number_t,
        ) -> kern_return_t;

        pub fn mach_vm_page_query(
            target_map: vm_map_read_t,
            offset: mach_vm_offset_t,
            disposition: &mut integer_t,
            ref_count: &mut integer_t,
        ) -> kern_return_t;

        pub fn mach_vm_page_range_query(
            target_map: vm_map_read_t,
            address: mach_vm_offset_t,
            size: mach_vm_size_t,
            dispositions: mach_vm_address_t,
            dispositions_count: &mut mach_vm_size_t,
        ) -> kern_return_t;

        pub fn mach_vm_page_info(
            target_task: vm_map_read_t,
            address: mach_vm_address_t,
            flavor: vm_page_info_flavor_t,
            info: vm_page_info_t,
            infoCnt: &mut mach_msg_type_number_t,
        ) -> kern_return_t;

        pub fn mach_vm_protect(
            target_task: vm_map_t,
            address: mach_vm_address_t,
            size: mach_vm_size_t,
            set_maximum: boolean_t,
            new_protection: vm_prot_t,
        ) -> kern_return_t;

        pub fn mach_vm_allocate(
            target: vm_map_t,
            address: &mut mach_vm_address_t,
            size: mach_vm_size_t,
            flags: std::ffi::c_uint,
        ) -> kern_return_t;

        pub fn mach_vm_deallocate(
            target: vm_map_t,
            address: mach_vm_address_t,
            size: mach_vm_size_t,
        ) -> kern_return_t;

        pub fn mach_vm_map(
            target_task: vm_map_t,
            address: &mut mach_vm_address_t,
            size: mach_vm_size_t,
            mask: mach_vm_offset_t,
            flags: std::ffi::c_uint,
            object: mem_entry_name_port_t,
            offset: memory_object_offset_t,
            copy: boolean_t,
            cur_protection: vm_prot_t,
            max_protection: vm_prot_t,
            inheritance: vm_inherit_t,
        ) -> kern_return_t;

        pub fn mach_vm_copy(
            target_task: vm_map_t,
            source_address: mach_vm_address_t,
            size: mach_vm_size_t,
            dest_address: mach_vm_address_t,
        ) -> kern_return_t;

    }

    pub fn mach_task_self() -> mach_port_t {
        unsafe { mach_task_self_ }
    }
}

pub const MEM_TYPE_COMMIT: MemoryAllocType = 1;
pub const MEM_TYPE_FREE: MemoryAllocType = 2;
pub const MEM_TYPE_RESERVE: MemoryAllocType = 3;

pub const PAGE_FLAG_EXECUTE_READWRITE: PageProtectionFlag =
    (mach_sys::VM_PROT_COPY | mach_sys::VM_PROT_READ | mach_sys::VM_PROT_WRITE)
        as PageProtectionFlag;
pub const PAGE_FLAG_EXECUTE_READ: PageProtectionFlag =
    (mach_sys::VM_PROT_EXECUTE | mach_sys::VM_PROT_READ) as PageProtectionFlag;

fn low_level_vquery(
    task: mach_sys::vm_map_read_t,
    addr: *const c_void,
) -> Option<(
    mach_sys::mach_vm_address_t,
    mach_sys::mach_vm_size_t,
    mach_sys::vm_region_basic_info_64,
)> {
    let mut address = addr.addr() as mach_sys::mach_vm_address_t;
    let mut size = 0;
    let mut info_cnt = mach_sys::VM_REGION_BASIC_INFO_COUNT_64;
    let mut info: MaybeUninit<mach_sys::vm_region_basic_info_64> = MaybeUninit::zeroed();
    let mut object_name = 0;

    let ret = unsafe {
        mach_sys::mach_vm_region(
            task,
            &mut address,
            &mut size,
            mach_sys::VM_REGION_BASIC_INFO_64,
            info.as_mut_ptr().cast(),
            &mut info_cnt,
            &mut object_name,
        )
    };
    if ret != 0 {
        return None;
    }
    Some((address, size, unsafe { info.assume_init() }))
}

pub fn vquery(addr: *const c_void) -> Option<MemoryBasicInfo> {
    let task = mach_sys::mach_task_self();

    let (address, size, info) = low_level_vquery(task, addr)?;

    let mut state = 0;
    if info.behavior == mach_sys::VM_BEHAVIOR_FREE {
        state |= MEM_TYPE_FREE;
    } else {
        state |= MEM_TYPE_COMMIT;
    }

    if info.reserved != 0 {
        state |= MEM_TYPE_RESERVE;
    }

    Some(MemoryBasicInfo {
        base_address: address as *const c_void,
        allocation_base: address as *const c_void,
        region_size: size,
        state,
    })
}

pub fn vprotect<T>(
    addr: *const T,
    size: usize,
    flag: PageProtectionFlag,
) -> Result<PageProtectionFlag, Error> {
    let task = mach_sys::mach_task_self();
    let (_, _, info) = low_level_vquery(task, addr.cast()).ok_or(Error::InvalidAddress)?;
    let ret = unsafe {
        mach_sys::mach_vm_protect(task, addr.addr(), size, 0, flag as mach_sys::vm_prot_t)
    };
    if ret != 0 {
        return Err(Error::ErrorCode(ret as usize));
    }
    Ok(info.protection as PageProtectionFlag)
}

pub fn valloc(
    addr: *const c_void,
    size: usize,
    _alloc_type: MemoryAllocType,
) -> Option<*const c_void> {
    let mut address = addr.addr();
    let task = mach_sys::mach_task_self();

    // let ret = unsafe {
    //     mach_sys::mach_vm_map(
    //         task,
    //         &mut address,
    //         size,
    //         0,
    //         mach_sys::VM_FLAGS_FIXED,
    //         0,
    //         0,
    //         0,
    //         PAGE_FLAG_EXECUTE_READ as vm_prot_t,
    //         PAGE_FLAG_EXECUTE_READWRITE as vm_prot_t,
    //         1,
    //     )
    // };

    let ret = unsafe {
        mach_sys::mach_vm_allocate(task, &mut address, size, mach_sys::VM_FLAGS_ANYWHERE)
    };
    if ret != 0 {
        return None;
    }
    Some(address as *const c_void)
}

pub fn vfree(addr: *mut c_void, size: usize) -> Result<(), Error> {
    let address = addr.addr();
    let task = mach_sys::mach_task_self();
    // `mach_vm_deallocate` 必须传真实长度；传 0 会什么都不释放（区域泄漏）。
    let ret = unsafe { mach_sys::mach_vm_deallocate(task, address, size) };
    if ret != 0 {
        return Err(Error::ErrorCode(ret as usize));
    }
    Ok(())
}

pub fn vcopy(dst: *mut c_void, src: *const c_void, size: usize) -> Result<(), Error> {
    let task = mach_sys::mach_task_self();
    let ret = unsafe { mach_sys::mach_vm_copy(task, src.addr(), size, dst.addr()) };
    if ret != 0 {
        return Err(Error::ErrorCode(ret as usize));
    }
    Ok(())
}
