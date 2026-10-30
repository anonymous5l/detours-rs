use std::fmt::{Debug, Display, Formatter};

#[derive(Clone, Copy)]
pub enum Error {
    InvalidAddress,
    InvalidSignature(usize, usize),
    ErrorCode(usize),
    NotEnoughMemory,
    /// 操作与当前事务状态冲突（例如事务已结束仍继续改动）。
    InvalidOperation,
    /// 当前平台不支持该操作（例如非 Windows 平台的线程挂起）。
    NotSupported,
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
            Error::InvalidOperation => {
                write!(f, "invalid operation")
            }
            Error::NotSupported => {
                write!(f, "operation not supported on this platform")
            }
        }
    }
}

impl std::error::Error for Error {}
