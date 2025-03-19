#[cfg(target_pointer_width = "16")]
const BITNESS: u32 = 16;
#[cfg(target_pointer_width = "32")]
const BITNESS: u32 = 32;
#[cfg(target_pointer_width = "64")]
const BITNESS: u32 = 64;

mod __private {
    use crate::disassembly::BITNESS;
    use iced_x86::{Decoder, DecoderOptions, Instruction};
    use std::ptr::slice_from_raw_parts;

    pub unsafe fn decode_instruction<const N: usize>(addr: usize) -> Instruction {
        let raw_inst = unsafe { core::ptr::read::<[u8; N]>(addr as *const _) };
        let mut decoder = Decoder::with_ip(BITNESS, &raw_inst, addr as u64, DecoderOptions::NONE);
        if !decoder.can_decode() {
            return Instruction::default();
        }
        decoder.decode()
    }

    pub fn decoder<T>(addr: *const T) -> Decoder<'static> {
        decoder_with_size(addr, 0xe)
    }

    pub fn decoder_with_size<T>(addr: *const T, size: usize) -> Decoder<'static> {
        let data = slice_from_raw_parts(addr.cast::<u8>(), size);
        Decoder::with_ip(
            super::BITNESS,
            unsafe { &*data },
            addr as u64,
            DecoderOptions::NONE,
        )
    }
}

pub use __private::*;
