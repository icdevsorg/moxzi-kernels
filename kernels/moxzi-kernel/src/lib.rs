//! The moxzi native-kernel ABI, version 1 (see kernels/README.md).
//!
//! A kernel is a `no_std` crate built by `scripts/build-kernel.sh`. Its exported functions are
//! `#[no_mangle] pub unsafe extern "C" fn`s whose parameters follow the Motoko declaration:
//! a `Blob` or `Text` argument arrives as `(ptr: *const u8, len: usize)` (borrowed for the call,
//! never written, never kept), a `Nat64` or `Bool` as a `u64`. Results:
//!  - `Bool`: return `u32` (0 or 1);
//!  - `Blob` with `result_bytes = n`: the last parameter is `out: *mut u8` with room for n bytes;
//!  - `Blob`, `Text`, `?Blob`, `?Text`: return [`output`] / [`text`] (or [`NONE`] for null).
//!
//! Depending on this crate gives the kernel a global allocator (scratch memory that lives for
//! the call), and a panic handler that traps the message with the panic's text.
#![no_std]

use core::alloc::{GlobalAlloc, Layout};

extern "C" {
    fn kernel_alloc(size: usize, align: usize) -> *mut u8;
    fn kernel_trap(ptr: *const u8, len: usize) -> !;
}

/// Scratch memory from the program; nothing is freed during a call, and the program's collector
/// reclaims all of it after the call returns.
pub struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        kernel_alloc(layout.size(), layout.align())
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

/// Trap the current message with `message`.
pub fn trap(message: &[u8]) -> ! {
    unsafe { kernel_trap(message.as_ptr(), message.len()) }
}

struct Buf { bytes: [u8; 256], len: usize }

impl core::fmt::Write for Buf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.bytes.len() - self.len);
        self.bytes[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let mut buf = Buf { bytes: [0; 256], len: 0 };
    let _ = core::fmt::write(&mut buf, format_args!("native kernel panicked: {}", info.message()));
    trap(&buf.bytes[..buf.len])
}

/// The bytes of a `Blob`/`Text` argument.
///
/// # Safety
/// `ptr`/`len` must be the pair the glue passed for that argument.
pub unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 { &[] } else { core::slice::from_raw_parts(ptr, len) }
}

/// A `Blob` / `?Blob` result: `[len: u64][bytes]` in scratch, returned as its address.
pub fn output(data: &[u8]) -> u64 {
    unsafe {
        let p = kernel_alloc(8 + data.len(), 8);
        core::ptr::write(p as *mut u64, data.len() as u64);
        core::ptr::copy_nonoverlapping(data.as_ptr(), p.add(8), data.len());
        p as u64
    }
}

/// A `Text` / `?Text` result (the glue checks it is UTF-8).
pub fn text(s: &str) -> u64 { output(s.as_bytes()) }

/// `null`, for a `?Blob` / `?Text` result.
pub const NONE: u64 = 0;
