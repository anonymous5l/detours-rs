#[cfg(target_os = "windows")]
mod win;
#[cfg(target_os = "windows")]
pub use win::*;

#[cfg(not(target_os = "windows"))]
mod unimpl;
#[cfg(not(target_os = "windows"))]
pub use unimpl::*;

#[cfg(target_arch = "x86")]
mod x86;
#[cfg(target_arch = "x86")]
pub use x86::*;

mod comm;
pub use comm::*;
