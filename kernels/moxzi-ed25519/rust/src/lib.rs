//! Ed25519 kernels for the `moxzi-ed25519` Motoko package (ABI 1, see moxzi-kernel), on
//! `ed25519-dalek` / `curve25519-dalek`. The Motoko declarations in ../src/Ed25519.mo are the
//! specification: every function here accepts, rejects and traps exactly as the Motoko body
//! (mo:ic-agent's RFC 8032 implementation).
//!
//! Verification is RFC 8032 5.1.7 with the cofactorless equation [s]B = R + [k]A, and strict
//! decoding: A and R must be canonical encodings (y < p, no "negative zero" x), s < L, and a
//! small-order A is refused. It is NOT ZIP 215 (which accepts non-canonical encodings and
//! uses the cofactored equation). Small-order R is not refused (RFC 8032 does not ask it).
//!
//! Built with curve25519-dalek's 32-bit backend (Cargo.toml): measured at 2026-10-23 against
//! the 64-bit default, publicKey 1,706,261 -> 887,309 instructions, sign 3,468,652 ->
//! 1,815,572, verify 6,684,873 -> 2,168,369 (verify also lost two field inversions, see
//! ops::decode).
#![no_std]
mod ops;
use moxzi_kernel::{bytes, trap};

unsafe fn put(out: *mut u8, d: &[u8]) {
    core::ptr::copy_nonoverlapping(d.as_ptr(), out, d.len());
}

fn seed<'a>(b: &'a [u8], err: &[u8]) -> &'a [u8; 32] {
    let Ok(s) = <&[u8; 32]>::try_from(b) else { trap(err) };
    s
}

#[no_mangle]
pub unsafe extern "C" fn public_key(s: *const u8, sn: usize, out: *mut u8) {
    let k = seed(bytes(s, sn), b"Ed25519.publicKey: the seed must be 32 bytes");
    put(out, &ops::public_key(k));
}

#[no_mangle]
pub unsafe extern "C" fn sign(s: *const u8, sn: usize, m: *const u8, mn: usize, out: *mut u8) {
    let k = seed(bytes(s, sn), b"Ed25519.sign: the seed must be 32 bytes");
    put(out, &ops::sign(k, bytes(m, mn)));
}

#[no_mangle]
pub unsafe extern "C" fn verify(k: *const u8, kn: usize, m: *const u8, mn: usize, g: *const u8, gn: usize) -> u32 {
    ops::verify(bytes(k, kn), bytes(m, mn), bytes(g, gn)) as u32
}
