//! Native stand-ins for the two functions a kernel imports from the program, and the harness
//! the check crates call kernels through (shared with `#[path]`; see transform.rs).
//!
//! `kernel_alloc` follows the program's definition (CompileEnhanced.mo `defineKernelAlloc`): the
//! alignment must be a power of two in 1..=65536 and the size at most 64 MiB, or the call traps.
//! Each request is its own allocation of exactly `size` bytes, so Miri reports any access past
//! its end; the harness frees them after the call (the program's collector does it there).
//! `kernel_trap` unwinds with the message (the program traps the message); [`run`] catches it.
use std::alloc::Layout;
use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};

thread_local! {
    static SCRATCH: RefCell<Vec<(*mut u8, Layout)>> = const { RefCell::new(Vec::new()) };
}

/// The payload of a native `kernel_trap`.
pub struct Trap(pub Vec<u8>);

#[no_mangle]
pub extern "C-unwind" fn kernel_alloc(size: usize, align: usize) -> *mut u8 {
    if align == 0 || !align.is_power_of_two() || align > 65536 || size > 64 << 20 {
        std::panic::panic_any(Trap(format!("kernel_alloc({size}, {align}) refused").into_bytes()));
    }
    let layout = Layout::from_size_align(size.max(1), align).unwrap();
    let p = unsafe { std::alloc::alloc(layout) };
    assert!(!p.is_null());
    SCRATCH.with(|s| s.borrow_mut().push((p, layout)));
    p
}

#[no_mangle]
pub extern "C-unwind" fn kernel_trap(ptr: *const u8, len: usize) -> ! {
    let msg = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
    std::panic::panic_any(Trap(msg))
}

/// How a kernel call ended other than by returning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// `kernel_trap` (the message).
    Trap(String),
    /// A Rust panic (the real kernel traps with "native kernel panicked: <message>").
    Panic(String),
}

fn quiet_traps() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if info.payload().downcast_ref::<Trap>().is_none() && std::env::var_os("MOXZI_CHECK_PANICS").is_some() {
                default(info)
            }
        }));
    });
}

/// Run one kernel call. Scratch from earlier calls must have been released ([`free_scratch`]).
pub fn run<R>(f: impl FnOnce() -> R) -> Result<R, Stop> {
    quiet_traps();
    catch_unwind(AssertUnwindSafe(f)).map_err(|e| {
        if let Some(Trap(m)) = e.downcast_ref::<Trap>() {
            Stop::Trap(String::from_utf8_lossy(m).into_owned())
        } else if let Some(s) = e.downcast_ref::<&str>() {
            Stop::Panic(s.to_string())
        } else if let Some(s) = e.downcast_ref::<String>() {
            Stop::Panic(s.clone())
        } else {
            Stop::Panic("(non-string panic payload)".into())
        }
    })
}

/// Free every `kernel_alloc` allocation of the last call.
pub fn free_scratch() {
    SCRATCH.with(|s| {
        for (p, l) in s.borrow_mut().drain(..) {
            unsafe { std::alloc::dealloc(p, l) }
        }
    });
}

/// Number of live `kernel_alloc` allocations.
pub fn scratch_count() -> usize {
    SCRATCH.with(|s| s.borrow().len())
}

/// A variable-size result: 0 is null; anything else must be the START of a `kernel_alloc`
/// allocation holding `[len: u64][len bytes]` (what the glue checks before copying). Panics --
/// a test failure -- otherwise.
pub fn take_output(r: u64) -> Option<Vec<u8>> {
    if r == 0 {
        return None;
    }
    SCRATCH.with(|s| {
        let s = s.borrow();
        let &(p, l) = s
            .iter()
            .find(|(p, _)| p.addr() as u64 == r)
            .unwrap_or_else(|| panic!("result {r:#x} is not a kernel_alloc pointer"));
        assert!(l.size() >= 8 && l.align() >= 8, "result block {l:?} cannot hold its length");
        let n = unsafe { (p as *const u64).read() } as usize;
        assert!(n <= l.size() - 8, "result length {n} overruns its {}-byte block", l.size());
        Some(unsafe { std::slice::from_raw_parts(p.add(8), n) }.to_vec())
    })
}

/// A fixed-size result buffer of exactly `n` bytes in its own allocation (so Miri sees a write
/// past it), with guard bytes around it natively (which a plain test run checks).
pub struct OutBuf {
    buf: Vec<u8>,
    n: usize,
}

const GUARD: usize = if cfg!(miri) { 0 } else { 32 };

impl OutBuf {
    pub fn new(n: usize) -> Self {
        Self::filled(n, 0x5a)
    }
    /// The buffer starts out as `fill` (a second call with another fill shows whether the
    /// kernel wrote all of it).
    pub fn filled(n: usize, fill: u8) -> Self {
        let mut buf = vec![0xa5u8; n + 2 * GUARD];
        buf[GUARD..GUARD + n].fill(fill);
        OutBuf { buf, n }
    }
    pub fn ptr(&mut self) -> *mut u8 {
        unsafe { self.buf.as_mut_ptr().add(GUARD) }
    }
    /// The result, after checking the guards.
    pub fn bytes(&self) -> &[u8] {
        assert!(self.buf[..GUARD].iter().all(|&b| b == 0xa5), "kernel wrote before its result buffer");
        assert!(self.buf[GUARD + self.n..].iter().all(|&b| b == 0xa5), "kernel wrote past its {}-byte result buffer", self.n);
        &self.buf[GUARD..GUARD + self.n]
    }
}

/// An argument as the glue passes it: a Blob/Text payload (pointer, length) or a Nat64/Bool.
#[derive(Clone, Debug, PartialEq)]
pub enum Arg {
    Bytes(Vec<u8>),
    Int(u64),
}

impl Arg {
    /// The payload pointer. An empty Blob's payload pointer is never null in the program (it
    /// points just past the Blob's header), so the empty case is a dangling, non-null pointer.
    pub fn ptr(&self) -> *const u8 {
        match self {
            Arg::Bytes(b) => b.as_ptr(),
            Arg::Int(_) => panic!("not a Blob/Text argument"),
        }
    }
    pub fn len(&self) -> usize {
        match self {
            Arg::Bytes(b) => b.len(),
            Arg::Int(_) => panic!("not a Blob/Text argument"),
        }
    }
    pub fn int(&self) -> u64 {
        match self {
            Arg::Int(v) => *v,
            Arg::Bytes(_) => panic!("not a Nat64/Bool argument"),
        }
    }
}

/// A deterministic byte stream for test inputs (splitmix64).
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut a = [0u8; N];
        for b in a.iter_mut() {
            *b = self.next() as u8;
        }
        a
    }
}

/// `native` iterations natively, `miri` under Miri (crypto under Miri is ~10^4x slower).
pub const fn iters(native: usize, miri: usize) -> usize {
    if cfg!(miri) { miri } else { native }
}
