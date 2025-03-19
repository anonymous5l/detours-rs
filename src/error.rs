use std::fmt::{Debug, Display, Formatter};

pub enum Error {
    InvalidAddress,
    InvalidSignature(usize, usize),
    ErrorCode(usize),
    NotEnoughMemory,
    EncodeInstruction,
    LockPoison,
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            Error::InvalidAddress => {
                write!(f, "invalid address")
            }
            Error::InvalidSignature(a, b) => {
                write!(f, "invalid signature {a} != {b}")
            }
            Error::ErrorCode(code) => {
                write!(f, "error code: {}", code)
            }
            Error::NotEnoughMemory => {
                write!(f, "not enough memory")
            }
            Error::EncodeInstruction => {
                write!(f, "encode instruction failed")
            }
            Error::LockPoison => {
                write!(f, "lock poison")
            }
        }
    }
}

impl std::error::Error for Error {}
